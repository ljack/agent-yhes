//! Bounded ciphertext transport. A broker ACK never confirms a Git operation.
//! The caller reconciles authoritative Git history before exposing deliveries.
use crate::Failure;
use async_nats::jetstream::{
    self,
    consumer::{self, PullConsumer},
    stream,
};
use futures_util::StreamExt;
use std::{net::IpAddr, path::PathBuf, time::Duration};
use yhes_wire::Digest;

pub const MAX_PACKET: usize = 1 << 20;
const MAX_MESSAGES: i64 = 4096;
const MAX_BYTES: i64 = 64 << 20;
const MAX_AGE: Duration = Duration::from_secs(7 * 86400);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Only explicit local configuration selects the endpoint, token or CA.
/// Do not derive these from a received message or an unverified Git artifact.
pub struct Config {
    url: String,
    token: String,
    ca: Option<PathBuf>,
    tls: bool,
}
impl Config {
    pub fn new(url: &str, token: &str, ca: Option<PathBuf>) -> Result<Self, Failure> {
        let invalid = || {
            Failure::new("broker_configuration", "use a TLS broker URL, or a literal loopback nats:// address; supply credentials separately")
        };
        let parsed = url::Url::parse(url).map_err(|_| invalid())?;
        let host = parsed.host_str().ok_or_else(invalid)?;
        let loopback = host
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
        if !matches!(parsed.scheme(), "nats" | "tls")
            || (parsed.scheme() == "nats" && !loopback)
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || !matches!(parsed.path(), "" | "/")
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || token.is_empty()
            || token.len() > 4096
            || token.chars().any(char::is_control)
        {
            return Err(invalid());
        }
        if ca.as_ref().is_some_and(|p| !p.is_file()) {
            return Err(Failure::new(
                "broker_configuration",
                "the configured broker CA file is missing",
            ));
        }
        Ok(Self {
            url: url.into(),
            token: token.into(),
            ca,
            tls: parsed.scheme() == "tls",
        })
    }
}

pub struct Broker {
    runtime: tokio::runtime::Runtime,
    context: jetstream::Context,
    stream: String,
    subject: String,
}
pub struct Received {
    message: jetstream::Message,
}
impl Received {
    pub fn bytes(&self) -> &[u8] {
        &self.message.payload
    }
}
fn failure(code: &str, message: &str) -> Failure {
    Failure::new(code, message)
}
impl Broker {
    /// Scope includes the authority fingerprint so unrelated projects with the
    /// same display name never share a stream by default.
    pub fn names(project: &str, group: &str, authority_key: &str) -> (String, String) {
        let binding =
            serde_json::to_vec(&("agent-yhes/secure-broker/v1", project, group, authority_key))
                .expect("string tuple encodes");
        let digest = Digest::of(&binding).to_hex();
        (
            format!("YHES_SECURE_{}", &digest[..32]),
            format!("yhes.secure.v1.{digest}.application"),
        )
    }
    pub fn connect(
        config: Config,
        project: &str,
        group: &str,
        authority_key: &str,
    ) -> Result<Self, Failure> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| failure("broker_unavailable", "cannot start the broker client"))?;
        let mut options = async_nats::ConnectOptions::new()
            .token(config.token)
            .require_tls(config.tls)
            .ignore_discovered_servers()
            .connection_timeout(REQUEST_TIMEOUT)
            .request_timeout(Some(REQUEST_TIMEOUT));
        if let Some(ca) = config.ca {
            options = options.add_root_certificates(ca);
        }
        let client = runtime
            .block_on(async {
                tokio::time::timeout(REQUEST_TIMEOUT, options.connect(config.url)).await
            })
            .map_err(|_| failure("broker_timeout", "the broker connection timed out"))?
            .map_err(|_| {
                failure(
                    "broker_unavailable",
                    "broker authentication, TLS or connection failed",
                )
            })?;
        let (stream, subject) = Self::names(project, group, authority_key);
        let context = {
            let _runtime = runtime.enter();
            jetstream::new(client)
        };
        Ok(Self {
            runtime,
            context,
            stream,
            subject,
        })
    }
    fn stream_config(&self) -> stream::Config {
        stream::Config {
            name: self.stream.clone(),
            subjects: vec![self.subject.clone()],
            retention: stream::RetentionPolicy::Limits,
            storage: stream::StorageType::File,
            discard: stream::DiscardPolicy::Old,
            max_messages: MAX_MESSAGES,
            max_bytes: MAX_BYTES,
            max_age: MAX_AGE,
            max_message_size: MAX_PACKET as i32,
            duplicate_window: Duration::from_secs(120),
            num_replicas: 1,
            ..Default::default()
        }
    }
    fn validate_stream(&self, actual: &stream::Config) -> Result<(), Failure> {
        if actual.name != self.stream
            || actual.subjects != [self.subject.clone()]
            || actual.retention != stream::RetentionPolicy::Limits
            || actual.storage != stream::StorageType::File
            || actual.max_messages != MAX_MESSAGES
            || actual.max_bytes != MAX_BYTES
            || actual.max_age != MAX_AGE
            || actual.max_message_size != MAX_PACKET as i32
            || actual.num_replicas != 1
            || actual.no_ack
            || actual.discard != stream::DiscardPolicy::Old
            || actual.discard_new_per_subject
            || actual.mirror.is_some()
            || actual.sources.as_ref().is_some_and(|s| !s.is_empty())
            || actual.republish.is_some()
            || actual.subject_transform.is_some()
            || actual.allow_rollup
        {
            return Err(failure(
                "broker_configuration",
                "the existing stream does not match this pilot's bounded ciphertext stream",
            ));
        }
        Ok(())
    }
    /// Explicit operator action. Normal sends/listens never create a stream.
    pub fn initialize(&self) -> Result<serde_json::Value, Failure> {
        let stream = self
            .runtime
            .block_on(self.context.get_or_create_stream(self.stream_config()))
            .map_err(|_| {
                failure(
                    "broker_configuration",
                    "cannot create or inspect the ciphertext stream",
                )
            })?;
        self.validate_stream(&stream.cached_info().config)?;
        Ok(serde_json::json!({"stream":self.stream, "subject":self.subject}))
    }
    fn stream(&self) -> Result<stream::Stream, Failure> {
        let stream = self.runtime.block_on(self.context.get_stream(&self.stream))
            .map_err(|_| failure("broker_configuration", "the ciphertext stream is unavailable; initialize it once with team-broker-init"))?;
        self.validate_stream(&stream.cached_info().config)?;
        Ok(stream)
    }
    pub fn publish(&self, packet: &[u8]) -> Result<serde_json::Value, Failure> {
        if packet.is_empty() || packet.len() > MAX_PACKET {
            return Err(failure(
                "broker_packet",
                "ciphertext packet exceeds broker bounds",
            ));
        }
        self.stream()?;
        let digest = Digest::of(packet).to_hex();
        let mut headers = async_nats::HeaderMap::new();
        headers.insert("Nats-Msg-Id", digest.as_str());
        headers.insert("Nats-Expected-Stream", self.stream.as_str());
        let ack = self.runtime.block_on(async {
            let pending = self.context.publish_with_headers(self.subject.clone(), headers, packet.to_vec().into()).await
                .map_err(|_| failure("broker_unavailable", "ciphertext notification could not be published; its Git record remains saved"))?;
            tokio::time::timeout(REQUEST_TIMEOUT, pending).await
                .map_err(|_| failure("broker_timeout", "broker acknowledgment timed out; retry the same packet"))?
                .map_err(|_| failure("broker_unavailable", "broker acknowledgment failed; retry the same packet"))
        })?;
        if ack.stream != self.stream {
            return Err(failure(
                "broker_configuration",
                "broker acknowledged an unexpected stream",
            ));
        }
        Ok(
            serde_json::json!({"sequence":ack.sequence,"duplicate":ack.duplicate,"packet_digest":digest}),
        )
    }
    pub fn consumer(&self, principal: &str) -> Result<PullConsumer, Failure> {
        let stream = self.stream()?;
        let digest = Digest::of(principal.as_bytes()).to_hex();
        let name = format!("p_{}", &digest[..32]);
        let config = consumer::pull::Config {
            durable_name: Some(name.clone()),
            filter_subject: self.subject.clone(),
            ack_policy: consumer::AckPolicy::Explicit,
            ack_wait: Duration::from_secs(30),
            max_ack_pending: 64,
            max_deliver: -1,
            ..Default::default()
        };
        let consumer = self
            .runtime
            .block_on(stream.get_or_create_consumer(&name, config))
            .map_err(|_| {
                failure(
                    "broker_unavailable",
                    "cannot open the durable ciphertext consumer",
                )
            })?;
        let actual = &consumer.cached_info().config;
        if actual.durable_name.as_deref() != Some(&name)
            || actual.filter_subject != self.subject
            || actual.ack_policy != consumer::AckPolicy::Explicit
            || actual.max_ack_pending != 64
            || actual.deliver_policy != consumer::DeliverPolicy::All
        {
            return Err(failure(
                "broker_configuration",
                "the existing consumer has unexpected delivery settings",
            ));
        }
        Ok(consumer)
    }
    pub fn fetch(&self, consumer: &PullConsumer, wait: Duration) -> Result<Vec<Received>, Failure> {
        let wait = wait.clamp(Duration::from_millis(100), Duration::from_secs(5));
        self.runtime.block_on(async {
            let mut stream = consumer
                .fetch()
                .max_messages(16)
                .max_bytes(4 * MAX_PACKET)
                .expires(wait)
                .messages()
                .await
                .map_err(|_| {
                    failure(
                        "broker_unavailable",
                        "cannot fetch ciphertext notifications",
                    )
                })?;
            let mut messages = Vec::new();
            while let Some(item) = stream.next().await {
                let message = item.map_err(|_| {
                    failure(
                        "broker_unavailable",
                        "ciphertext stream was interrupted; reconnect and reconcile Git",
                    )
                })?;
                messages.push(Received { message });
                if messages.len() >= 16 {
                    break;
                }
            }
            Ok(messages)
        })
    }
    /// Call only after Git reconciliation and durable recipient handling, or an
    /// explicit rejection of an invalid notification. This is transport ACK only.
    pub fn acknowledge(&self, message: Received) -> Result<(), Failure> {
        self.runtime
            .block_on(message.message.double_ack())
            .map_err(|_| {
                failure(
                    "broker_unavailable",
                    "notification acknowledgment failed; delivery may repeat",
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn endpoint_and_credentials_are_explicit() {
        for endpoint in [
            "nats://example.com:4222",
            "nats://localhost:4222",
            "tls://user:secret@example.com",
            "tls://example.com/other",
            "tls://example.com?x=y",
            "http://example.com",
        ] {
            assert!(Config::new(endpoint, "test", None).is_err());
        }
        assert!(Config::new("tls://example.com:4222", "test", None).is_ok());
        assert!(Config::new("nats://127.0.0.1:4222", "test", None).is_ok());
        assert!(Config::new("nats://[::1]:4222", "test", None).is_ok());
        assert!(Config::new("tls://example.com", "", None).is_err());
    }
    #[test]
    fn stream_scope_binds_project_group_and_authority() {
        let a = Broker::names("project", "team", "key-a");
        assert_ne!(a, Broker::names("other", "team", "key-a"));
        assert_ne!(a, Broker::names("project", "other", "key-a"));
        assert_ne!(a, Broker::names("project", "team", "key-b"));
        assert_eq!(a, Broker::names("project", "team", "key-a"));
    }
}
