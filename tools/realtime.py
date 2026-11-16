#!/usr/bin/env python3
"""v0.3: NATS JetStream notifications over the v0.2 Git protocol.

Git confirms work; the broker prompts fresh reads. No peer payload is executed.
Use broker-init once, ordinary commands to publish, flush to retry notifications,
and listen for a bounded stream of verified inbox snapshots.
"""
from __future__ import annotations

import asyncio
import contextlib
import fcntl
import hashlib
import inspect
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import sys
import time
from urllib.parse import urlsplit

import coop
from remote import Remote, Unavailable, encode, read_json, save_json
from coop import Conflict, Invalid, check_id

try:
    import nats
    from nats.errors import TimeoutError as NatsTimeout
    from nats.js.api import AckPolicy, ConsumerConfig, DeliverPolicy, RetentionPolicy, StorageType, StreamConfig
    from nats.js.errors import NotFoundError
except ImportError:
    nats = None

HINT_PROTOCOL = "local-agent-cooperation.realtime"
MAX_HINT = 4096
ACK_WAIT = 30


class BrokerUnavailable(Exception):
    pass


def channel_identity(project, ref):
    check_id(project, "p")
    digest = hashlib.sha256(encode([project, ref])).hexdigest()
    return {"id": digest, "subject": "yhes.v03." + digest + ".changed", "stream": "YHES_V03_" + digest[:24]}


def validate_hint(data, project, ref):
    if len(data) > MAX_HINT:
        raise Invalid("broker hint exceeds size limit")
    try:
        hint = json.loads(data, object_pairs_hook=coop.pairs)
        if set(hint) != {"protocol", "version", "type", "project", "ref", "operation_id"}:
            raise Invalid("unexpected broker hint fields")
        if hint["protocol"] != HINT_PROTOCOL or hint["version"] != "0.3" or hint["type"] != "channel.changed":
            raise Invalid("unsupported broker hint")
        if hint["project"] != project or hint["ref"] != ref:
            raise Invalid("broker hint belongs to another channel")
        check_id(hint["operation_id"], "o")
        return hint
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
        raise Invalid("invalid broker hint") from exc


class NatsBroker:
    def __init__(self, url=None, token=None, ca=None):
        self.url = url or os.environ.get("YHES_BROKER_URL", "nats://127.0.0.1:4222")
        self.token = token if token is not None else os.environ.get("YHES_BROKER_TOKEN")
        ca = ca or os.environ.get("YHES_BROKER_CA")
        try:
            parsed = urlsplit(self.url)
            port = parsed.port
        except ValueError as exc:
            raise Invalid("invalid broker endpoint") from exc
        if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
            raise Invalid("use a broker host/port URL and pass its token through YHES_BROKER_TOKEN")
        if not parsed.hostname or parsed.scheme not in {"nats", "tls"} or (port is not None and not 1 <= port <= 65535):
            raise Invalid("broker endpoint must use nats:// or tls://")
        try:
            loopback = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            loopback = parsed.hostname == "localhost"
        if parsed.scheme != "tls" and not loopback:
            raise Invalid("remote broker connections require tls://")
        self.tls = ssl.create_default_context(cafile=ca) if parsed.scheme == "tls" else None
        self.key = hashlib.sha256(self.url.encode()).hexdigest()[:24]
        self.nc = None
        self.js = None

    async def connect(self):
        if nats is None:
            raise BrokerUnavailable("install requirements-broker.txt for realtime mode")
        async def quiet_error(_error):
            # Connection URLs and credentials must not leak through client logs.
            pass
        try:
            self.nc = nats.NATS()
            await asyncio.wait_for(self.nc.connect(servers=[self.url], token=self.token, tls=self.tls,
                name="agent-yhes-v03", error_cb=quiet_error, connect_timeout=1,
                allow_reconnect=True, max_reconnect_attempts=2, reconnect_time_wait=0.25,
                pending_size=64 * 1024), timeout=3)
            self.js = self.nc.jetstream(timeout=2)
        except Exception as exc:
            await self.close()
            raise BrokerUnavailable("broker connection unavailable; check endpoint, credentials and TLS") from exc

    async def close(self):
        if self.nc:
            with contextlib.suppress(Exception):
                await self.nc.close()
        self.nc, self.js = None, None

    async def provision(self, channel):
        try:
            info = await self.js.stream_info(channel["stream"])
        except NotFoundError:
            info = await self.js.add_stream(StreamConfig(name=channel["stream"], subjects=[channel["subject"]],
                storage=StorageType.FILE, retention=RetentionPolicy.LIMITS, max_msgs=10000,
                max_bytes=8 * 1024 * 1024, max_msg_size=MAX_HINT, max_age=86400,
                duplicate_window=120, max_consumers=128, num_replicas=1))
        config = info.config
        if config.subjects != [channel["subject"]] or config.storage != StorageType.FILE or config.retention != RetentionPolicy.LIMITS:
            raise Invalid("existing stream has incompatible subjects, storage or retention; reconcile it as operator")
        return {"stream": channel["stream"], "subject": channel["subject"], "storage": "file"}

    async def publish(self, channel, hint):
        msgid = channel["id"] + ":" + hint["operation_id"]
        try:
            result = await self.js.publish(channel["subject"], encode(hint), timeout=2,
                                            headers={"Nats-Msg-Id": msgid, "Nats-Expected-Stream": channel["stream"]})
            return {"sequence": result.seq, "duplicate": result.duplicate}
        except Exception as exc:
            raise BrokerUnavailable("broker did not confirm notification storage") from exc

    async def subscribe(self, channel, node, session):
        name = "YHES_" + hashlib.sha256(encode([channel["id"], node, session])).hexdigest()[:32]
        try:
            return await self.js.pull_subscribe(channel["subject"], durable=name, stream=channel["stream"],
                config=ConsumerConfig(durable_name=name, filter_subject=channel["subject"],
                    deliver_policy=DeliverPolicy.ALL, ack_policy=AckPolicy.EXPLICIT,
                    ack_wait=ACK_WAIT, max_ack_pending=64), pending_msgs_limit=64, pending_bytes_limit=64 * 1024)
        except Exception as exc:
            raise BrokerUnavailable("broker consumer unavailable; initialize the stream and check permissions") from exc


class Realtime:
    def __init__(self, remote, broker=None):
        self.remote = remote
        self.broker = broker or NatsBroker()

    def _channel(self):
        with self.remote.locked():
            path = self.remote.home / "observed.json"
            if not path.exists():
                raise Invalid("fetch or initialize the Git channel first")
            project = read_json(path)["project"]
            return project, channel_identity(project, self.remote.ref)

    def _outbox(self, preferred=None, limit=32):
        with self.remote.locked():
            project = read_json(self.remote.home / "observed.json")["project"]
            home = self.remote.home / "notifications" / self.broker.key
            home.mkdir(parents=True, exist_ok=True)
            rows = [read_json(path) for path in sorted((self.remote.home / "pending").glob("o_*.json"))]
            rows = [row for row in rows if row["status"] == "confirmed" and not (home / (row["id"] + ".json")).exists()]
            rows.sort(key=lambda row: row["id"] != preferred)
            hints = [{"protocol": HINT_PROTOCOL, "version": "0.3", "type": "channel.changed",
                      "project": project, "ref": self.remote.ref, "operation_id": row["id"]} for row in rows[:limit]]
            return home, hints, max(0, len(rows) - limit)

    async def flush(self, preferred=None, limit=32):
        if not 1 <= limit <= 1000:
            raise Invalid("notification limit must be 1..1000")
        _project, channel = await asyncio.to_thread(self._channel)
        home, hints, remaining = await asyncio.to_thread(self._outbox, preferred, limit)
        if not hints:
            return {"state": "stored", "notifications": 0, "remaining": remaining}
        await self.broker.connect()
        stored = 0
        try:
            for hint in hints:
                receipt = await self.broker.publish(channel, hint)
                save_json(home / (hint["operation_id"] + ".json"), receipt)
                stored += 1
        finally:
            await self.broker.close()
        return {"state": "stored", "notifications": stored, "remaining": remaining}

    async def execute(self, operation, operation_id=None, **arguments):
        result = await asyncio.to_thread(self.remote.execute, operation, operation_id=operation_id, **arguments)
        if isinstance(result, dict) and result.get("delivery") == "confirmed":
            try:
                result["realtime"] = await self.flush(preferred=result["operation_id"])
            except (BrokerUnavailable, OSError, Invalid) as exc:
                # Git success remains success. The saved confirmed request is
                # the notification outbox and will be discovered by flush.
                result["realtime"] = {"state": "pending", "reason": type(exc).__name__}
        return result

    async def provision(self):
        await asyncio.to_thread(self.remote.execute, "sessions")
        _project, channel = await asyncio.to_thread(self._channel)
        await self.broker.connect()
        try:
            return await self.broker.provision(channel)
        except Invalid:
            raise
        except Exception as exc:
            raise BrokerUnavailable("broker stream setup unavailable; check server and operator permissions") from exc
        finally:
            await self.broker.close()

    @contextlib.contextmanager
    def _listener_lock(self, session):
        check_id(session, "s")
        home = self.remote.home / "listeners"
        home.mkdir(exist_ok=True)
        with (home / (session + ".lock")).open("a+b") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise Conflict("a listener already owns this session on this clone") from exc
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    async def listen(self, session, emit, seconds=30, reconcile_every=30):
        if not 0 < seconds <= 300 or not 0.25 <= reconcile_every <= 60:
            raise Invalid("listen seconds must be 0..300 and reconciliation interval 0.25..60")
        roster = await asyncio.to_thread(self.remote.execute, "sessions")
        own = next((s for s in roster["result"] if s["id"] == session), None)
        if not own or own["node"] != self.remote.node:
            raise Invalid("listen requires a session registered on this clone; resume with a new session if needed")
        project, channel = await asyncio.to_thread(self._channel)
        stats = {"notifications": 0, "invalid": 0, "snapshots": 0, "broker_errors": 0, "git_errors": 0}
        last_commit = None
        async def sync(reason):
            nonlocal last_commit
            snapshot = await asyncio.to_thread(self.remote.execute, "inbox", session=session)
            if snapshot["observed_commit"] != last_commit:
                result = emit({"type": "channel.changed", "reason": reason, "session": session,
                               "observed_commit": snapshot["observed_commit"], "inbox": snapshot["result"]})
                if inspect.isawaitable(result):
                    await result
                last_commit = snapshot["observed_commit"]
                stats["snapshots"] += 1
        with self._listener_lock(session):
            await sync("startup")
            deadline = time.monotonic() + seconds
            next_reconcile = time.monotonic() + reconcile_every
            retry_at = 0
            subscription = None
            try:
                while time.monotonic() < deadline:
                    if time.monotonic() >= next_reconcile:
                        try:
                            await sync("reconcile")
                        except (Unavailable, Conflict):
                            stats["git_errors"] += 1
                        next_reconcile = time.monotonic() + reconcile_every
                    if subscription is None:
                        if time.monotonic() >= retry_at:
                            try:
                                await self.broker.connect()
                                subscription = await self.broker.subscribe(channel, self.remote.node, session)
                            except BrokerUnavailable:
                                stats["broker_errors"] += 1
                                await self.broker.close()
                                retry_at = time.monotonic() + 2
                        await asyncio.sleep(0.05)
                        continue
                    try:
                        batch = await subscription.fetch(batch=16, timeout=max(0.05, min(0.5, deadline - time.monotonic())))
                    except NatsTimeout:
                        continue
                    except Exception:
                        stats["broker_errors"] += 1
                        await self.broker.close()
                        subscription, retry_at = None, time.monotonic() + 2
                        continue
                    valid = []
                    for message in batch:
                        try:
                            validate_hint(message.data, project, self.remote.ref)
                            valid.append(message)
                        except Invalid:
                            stats["invalid"] += 1
                            try:
                                await message.term()
                            except Exception:
                                stats["broker_errors"] += 1
                    if valid:
                        try:
                            await sync("broker")
                        except (Unavailable, Conflict):
                            stats["git_errors"] += 1
                            for message in valid:
                                with contextlib.suppress(Exception):
                                    await message.nak(delay=2)
                        else:
                            for message in valid:
                                try:
                                    await message.ack_sync(timeout=2)
                                    stats["notifications"] += 1
                                except Exception:
                                    stats["broker_errors"] += 1
                                    await self.broker.close()
                                    subscription, retry_at = None, time.monotonic() + 2
                                    break
                        # Coalesce bursts and cap Git refresh work. Each read
                        # gets the current tip, so one notice can cover a batch.
                        await asyncio.sleep(min(0.25, max(0, deadline - time.monotonic())))
            finally:
                await self.broker.close()
        return stats


async def run_cli(args):
    options = {key: args.pop(key) for key in ("root", "remote", "branch", "timeout", "attempts")}
    operation, opid = args.pop("operation"), args.pop("operation_id")
    realtime = Realtime(Remote(**options))
    if operation == "broker-init":
        result = await realtime.provision()
    elif operation == "flush":
        result = await realtime.flush(**args)
    elif operation == "listen":
        result = await realtime.listen(emit=lambda event: print(json.dumps(event, ensure_ascii=False), flush=True), **args)
        result = {"type": "listen.finished", **result}
        print(json.dumps(result, ensure_ascii=False), flush=True)
        return
    else:
        result = await realtime.execute(operation, operation_id=opid, **args)
    print(json.dumps(result, ensure_ascii=False, indent=2))


def main():
    # Keep the remote command grammar in one place for both transport frontends.
    from remote import build_parser
    parser, commands = build_parser(__doc__)
    commands.add_parser("broker-init", help="create or verify this channel's JetStream stream")
    p = commands.add_parser("flush", help="retry confirmed Git operations whose notifications remain pending")
    p.add_argument("--limit", type=int, default=32)
    p = commands.add_parser("listen", help="emit fresh Git inbox snapshots as JSON when the channel changes")
    p.add_argument("--session", required=True)
    p.add_argument("--seconds", type=float, default=30)
    p.add_argument("--reconcile-every", type=float, default=30)
    try:
        asyncio.run(run_cli(vars(parser.parse_args())))
        return 0
    except (Invalid, Conflict, Unavailable, BrokerUnavailable, OSError) as exc:
        print(json.dumps({"error": str(exc), "kind": type(exc).__name__}), file=sys.stderr)
        return 4 if isinstance(exc, (Unavailable, BrokerUnavailable)) else (3 if isinstance(exc, Conflict) else 2)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
