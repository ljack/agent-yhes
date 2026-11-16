//! Pinned authority configuration and monotonic, signed registry storage.
use crate::{Error, Result};
use rusqlite::{Connection, OptionalExtension};
use yhes_wire::{Digest, Policy, PublicKey, Registry, RegistryCheckpoint, TrustAnchors};

pub struct ProjectTrust {
    pub(crate) project: String,
    pub(crate) anchors: TrustAnchors,
    fingerprint: String,
}
impl ProjectTrust {
    /// Authorities come from an out-of-band approval, never the repository being
    /// authenticated. The fingerprint is locked into the protected vault.
    pub fn new(project: &str, mut authorities: Vec<PublicKey>, threshold: usize) -> Result<Self> {
        authorities.sort_by_key(PublicKey::key_id);
        let anchors = TrustAnchors::new(project, authorities.clone(), threshold).map_err(wire)?;
        let bytes = serde_json::to_vec(&(
            "agent-yhes/trust/v1",
            project,
            threshold,
            authorities
                .iter()
                .map(|k| k.key_id().to_string())
                .collect::<Vec<_>>(),
        ))
        .map_err(|_| Error::Storage)?;
        Ok(Self {
            project: project.to_owned(),
            anchors,
            fingerprint: Digest::of(&bytes).to_hex(),
        })
    }
    pub(crate) fn bind(&self, db: &Connection) -> Result<()> {
        let project: Vec<u8> = db
            .query_row("SELECT value FROM yhes_meta WHERE key='project'", [], |r| {
                r.get(0)
            })
            .map_err(|_| Error::Storage)?;
        if project != self.project.as_bytes() {
            return Err(Error::Verification("trust project mismatch".into()));
        }
        let stored: Option<Vec<u8>> = db
            .query_row("SELECT value FROM yhes_meta WHERE key='trust'", [], |r| {
                r.get(0)
            })
            .optional()
            .map_err(|_| Error::Storage)?;
        if let Some(stored) = stored {
            if stored != self.fingerprint.as_bytes() {
                return Err(Error::Verification(
                    "pinned authority configuration changed".into(),
                ));
            }
        } else {
            db.execute(
                "INSERT INTO yhes_meta VALUES ('trust',?)",
                [self.fingerprint.as_bytes()],
            )
            .map_err(|_| Error::Storage)?;
        }
        Ok(())
    }
    fn history(&self, db: &Connection) -> Result<(Option<RegistryCheckpoint>, Option<Vec<u8>>)> {
        let mut q = db
            .prepare("SELECT envelope FROM yhes_registry ORDER BY generation")
            .map_err(|_| Error::Storage)?;
        let mut rows = q.query([]).map_err(|_| Error::Storage)?;
        let mut prior = None;
        let mut last = None;
        while let Some(row) = rows.next().map_err(|_| Error::Storage)? {
            let bytes: Vec<u8> = row.get(0).map_err(|_| Error::Storage)?;
            let current =
                RegistryCheckpoint::advance(&bytes, &self.anchors, prior.as_ref()).map_err(wire)?;
            if prior.is_none() && current.generation() != 1 {
                return Err(Error::Verification(
                    "registry must start at generation one".into(),
                ));
            }
            prior = Some(current);
            last = Some(bytes);
        }
        Ok((prior, last))
    }
    pub(crate) fn install(&self, db: &Connection, envelope: &[u8], now: u64) -> Result<Registry> {
        let (prior, _) = self.history(db)?;
        if prior.is_none() {
            return Err(Error::Verification(
                "bootstrap requires an externally pinned registry head".into(),
            ));
        }
        let next = Registry::verify(
            envelope,
            &self.anchors,
            prior.as_ref(),
            &Policy::default(),
            now,
        )
        .map_err(wire)?;
        if prior.is_none() && next.generation() != 1 {
            return Err(Error::Verification(
                "registry must start at generation one".into(),
            ));
        }
        db.execute(
            "INSERT OR IGNORE INTO yhes_registry VALUES (?,?,?)",
            rusqlite::params![next.generation(), next.digest().to_hex(), envelope],
        )
        .map_err(|_| Error::Storage)?;
        Ok(next)
    }
    pub(crate) fn bootstrap(
        &self,
        db: &Connection,
        chain: &[&[u8]],
        expected_head: Digest,
        now: u64,
    ) -> Result<Registry> {
        if chain.is_empty() || chain.len() > 4096 {
            return Err(Error::Conflict(
                "registry bootstrap requires an empty vault and a bounded chain".into(),
            ));
        }
        if let Some(existing) = self.history(db)?.0 {
            if existing.digest() != expected_head {
                return Err(Error::Conflict(
                    "registry already bootstrapped with another head".into(),
                ));
            }
            // The stored chain is already authenticated. Only an identical
            // explicitly pinned current head can complete a retried bootstrap.
            let current = Registry::verify(
                chain.last().unwrap(),
                &self.anchors,
                Some(&existing),
                &Policy::default(),
                now,
            )
            .map_err(wire)?;
            if current.digest() != expected_head {
                return Err(Error::Verification(
                    "bootstrap retry changed its approved head".into(),
                ));
            }
            return Ok(current);
        }
        let mut prior = None;
        for bytes in chain {
            let next =
                RegistryCheckpoint::advance(bytes, &self.anchors, prior.as_ref()).map_err(wire)?;
            if prior.is_none() && next.generation() != 1 {
                return Err(Error::Verification(
                    "registry chain must begin at one".into(),
                ));
            }
            if prior
                .as_ref()
                .is_some_and(|p: &RegistryCheckpoint| p.generation() == next.generation())
            {
                return Err(Error::Verification("duplicate registry generation".into()));
            }
            storage_insert(db, next.generation(), next.digest(), bytes)?;
            prior = Some(next);
        }
        if prior.as_ref().unwrap().digest() != expected_head {
            return Err(Error::Verification(
                "registry head differs from approved bootstrap".into(),
            ));
        }
        let registry = Registry::verify(
            chain.last().unwrap(),
            &self.anchors,
            prior.as_ref(),
            &Policy::default(),
            now,
        )
        .map_err(wire)?;
        db.execute(
            "INSERT INTO yhes_meta VALUES ('bootstrap_registry',?)",
            [expected_head.to_hex().as_bytes()],
        )
        .map_err(|_| Error::Storage)?;
        Ok(registry)
    }
    pub(crate) fn current(&self, db: &Connection, now: u64) -> Result<Registry> {
        let (prior, last) = self.history(db)?;
        let last =
            last.ok_or_else(|| Error::Verification("no trusted registry installed".into()))?;
        Registry::verify(
            &last,
            &self.anchors,
            prior.as_ref(),
            &Policy::default(),
            now,
        )
        .map_err(wire)
    }
}
fn storage_insert(db: &Connection, generation: u64, digest: Digest, envelope: &[u8]) -> Result<()> {
    db.execute(
        "INSERT INTO yhes_registry VALUES (?,?,?)",
        rusqlite::params![generation, digest.to_hex(), envelope],
    )
    .map_err(|_| Error::Storage)?;
    Ok(())
}
pub(crate) fn wire(_: yhes_wire::Error) -> Error {
    // Keep parser errors and arbitrary event text out of transport logs.
    Error::Verification("signed record rejected".into())
}
