"""HTTP client for the Prosentriq control plane (stdlib only + cryptography).

Reliability properties a sensor needs and gets here:
  * batching (<= 1,000 events), gzip, per-event idempotency (metadata.uid), so
    retries after a timeout can never double-count;
  * exponential backoff with jitter on 429/5xx/network errors, honouring
    Retry-After;
  * a bounded on-disk spool: if the platform is unreachable, batches are
    persisted and replayed in order when it comes back (local detection keeps
    running regardless -- the engine never depends on this).
"""
from __future__ import annotations

import base64
import gzip
import http.client
import json
import os
import random
import socket
import threading
import time
import urllib.error
import urllib.request
import zlib
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

USER_AGENT = "prosentriq-sdk/2.0.0"
MAX_BATCH = 1000
MAX_RESPONSE_BYTES = 512 * 1024 * 1024   # decompressed; the largest immunity feed is far below this


class ApiError(Exception):
    def __init__(self, status: int, body: Any) -> None:
        super().__init__(f"HTTP {status}: {body}")
        self.status = status
        self.body = body

    @property
    def retryable(self) -> bool:
        return self.status in (0, 408, 425, 429) or self.status >= 500


def _encode(body: Any, gzip_body: bool) -> tuple[bytes | None, dict[str, str]]:
    if body is None:
        return None, {}
    data = json.dumps(body, separators=(",", ":"), default=str).encode()
    headers = {"Content-Type": "application/json"}
    if gzip_body:
        data = gzip.compress(data)
        headers["Content-Encoding"] = "gzip"
    return data, headers


# ------------------------------------------------------------ connection reuse
# A sensor talks to one API host every few seconds (events, heartbeats).
# urlopen() opened a new TCP + TLS connection for every call; across a fleet
# that is thousands of handshakes per second at the platform's edge. Idle
# connections are kept per host and reused. Anything unusual -- a proxy in
# the environment, a redirect -- takes the original urllib path unchanged.
_MAX_IDLE_PER_HOST = 4
_idle: dict[tuple[str, str, int], list[http.client.HTTPConnection]] = {}
_idle_lock = threading.Lock()
_STALE = (http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError, ConnectionAbortedError)


def _uses_proxy(u: Any) -> bool:
    proxies = urllib.request.getproxies()
    return u.scheme in proxies and not urllib.request.proxy_bypass(u.hostname or "")


def _checkout(key: tuple[str, str, int], timeout: float) -> tuple[http.client.HTTPConnection, bool]:
    with _idle_lock:
        pool = _idle.get(key)
        if pool:
            conn = pool.pop()
            conn.timeout = timeout
            if conn.sock is not None:
                conn.sock.settimeout(timeout)
            return conn, True
    scheme, host, port = key
    cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    return cls(host, port, timeout=timeout), False   # same default TLS context and verification as urlopen


def _checkin(key: tuple[str, str, int], conn: http.client.HTTPConnection) -> None:
    with _idle_lock:
        pool = _idle.setdefault(key, [])
        if len(pool) < _MAX_IDLE_PER_HOST:
            pool.append(conn)
            return
    conn.close()


def _keepalive_request(method: str, u: Any, data: bytes | None, headers: dict[str, str],
                       timeout: float) -> tuple[int, bytes, Any] | None:
    """(status, raw body, headers); None when urllib must handle it (redirect)."""
    key = (u.scheme, u.hostname or "", u.port or (443 if u.scheme == "https" else 80))
    target = (u.path or "/") + (f"?{u.query}" if u.query else "")
    for attempt in (0, 1):
        conn, reused = _checkout(key, timeout)
        try:
            conn.request(method, target, body=data, headers=headers)
            r = conn.getresponse()
            raw = r.read()
        except _STALE:
            conn.close()
            if reused and attempt == 0:
                continue   # the server closed an idle connection before reading the request: send it again
            raise
        except BaseException:
            conn.close()
            raise
        if r.will_close:
            conn.close()
        else:
            _checkin(key, conn)
        if 300 <= r.status < 400 and r.getheader("Location"):
            return None
        return r.status, raw, r.headers
    raise RuntimeError("unreachable")


def _gunzip(raw: bytes, encoding: str | None) -> bytes:
    """Undo Content-Encoding: gzip, capped so a hostile response cannot exhaust memory."""
    if (encoding or "").strip().lower() != "gzip":
        return raw
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = d.decompress(raw, MAX_RESPONSE_BYTES + 1)
    if len(out) > MAX_RESPONSE_BYTES or d.unconsumed_tail:
        raise ValueError("response exceeds the size limit")
    return out


def _request(method: str, url: str, token: str | None = None, body: Any = None, gzip_body: bool = False,
             timeout: float = 15.0, encoded: tuple[bytes | None, dict[str, str]] | None = None) -> tuple[int, Any, dict[str, str]]:
    data, body_headers = encoded if encoded is not None else _encode(body, gzip_body)
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json", "Accept-Encoding": "gzip", **body_headers}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    u = urlsplit(url)
    if u.scheme in ("http", "https") and u.hostname and not _uses_proxy(u):
        try:
            got = _keepalive_request(method, u, data, headers, timeout)
            if got is not None:
                got = (got[0], _gunzip(got[1], got[2].get("Content-Encoding") if got[2] else None), got[2])
        except (socket.timeout, ConnectionError, OSError, http.client.HTTPException, ValueError, zlib.error) as e:
            return 0, str(e), {}
        if got is not None:
            status, raw, resp_headers = got
            if 200 <= status < 300:
                return status, (json.loads(raw) if raw else None), dict(resp_headers)
            try:
                parsed = json.loads(raw)
            except ValueError:
                parsed = raw.decode(errors="replace")[:500]
            return status, parsed, dict(resp_headers or {})
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = _gunzip(r.read(), r.headers.get("Content-Encoding"))
            return r.status, (json.loads(raw) if raw else None), dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            raw = _gunzip(e.read(), (e.headers or {}).get("Content-Encoding"))
        except (ValueError, zlib.error):
            raw = b""
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = raw.decode(errors="replace")[:500]
        return e.code, parsed, dict(e.headers or {})
    except (urllib.error.URLError, socket.timeout, ConnectionError, OSError, ValueError, zlib.error) as e:
        return 0, str(e), {}


class Client:
    def __init__(self, api_base: str, token: str, spool_dir: str | os.PathLike | None = None,
                 max_spool_bytes: int = 256 * 1024 * 1024, max_retries: int = 5) -> None:
        if not api_base.startswith("https://") and not api_base.startswith("http://127.0.0.1") \
                and not api_base.startswith("http://localhost") and os.environ.get("PROSENTRIQ_ALLOW_HTTP") != "1":
            raise ValueError("api_base must be https:// (set PROSENTRIQ_ALLOW_HTTP=1 only for local testing)")
        self.api_base = api_base.rstrip("/")
        self.token = token
        self.spool = Path(spool_dir) if spool_dir else None
        self.max_spool_bytes = max_spool_bytes
        self.max_retries = max_retries
        if self.spool:
            self.spool.mkdir(parents=True, exist_ok=True, mode=0o700)

    # ------------------------------------------------------------ enrollment
    @classmethod
    def enroll(cls, api_base: str, enrollment_key: str, *, hostname: str, sensor_type: str, os: str,  # noqa: A002
               arch: str = "", version: str = "", can_enforce: bool = False, ip: str | None = None,
               gateway_ip: str | None = None, labels: dict[str, str] | None = None) -> dict[str, Any]:
        status, body, _ = _request("POST", api_base.rstrip("/") + "/v2/sensors/enroll", body={
            "enrollment_key": enrollment_key, "hostname": hostname, "sensor_type": sensor_type, "os": os, "arch": arch,
            "version": version, "can_enforce": can_enforce, "ip": ip, "gateway_ip": gateway_ip, "labels": labels or {}})
        if status != 201:
            raise ApiError(status, body)
        return body

    # ------------------------------------------------------------ core calls
    def _call(self, method: str, path: str, body: Any = None, gzip_body: bool = False) -> Any:
        delay = 1.0
        encoded = _encode(body, gzip_body)   # serialize and compress once, not once per retry
        for attempt in range(self.max_retries + 1):
            status, resp, headers = _request(method, self.api_base + path, self.token, encoded=encoded)
            if 200 <= status < 300:
                return resp
            err = ApiError(status, resp)
            if not err.retryable or attempt == self.max_retries:
                raise err
            retry_after = headers.get("Retry-After") or headers.get("retry-after")
            wait = float(retry_after) if retry_after and retry_after.isdigit() else delay * random.uniform(0.8, 1.2)
            time.sleep(min(wait, 60.0))
            delay = min(delay * 2, 60.0)
        raise RuntimeError("unreachable")

    def heartbeat(self, *, mode: str = "observe", can_enforce: bool = False, version: str = "", ip: str | None = None,
                  gateway_ip: str | None = None, stats: dict[str, Any] | None = None,
                  acks: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        return self._call("POST", "/v2/sensors/heartbeat", {
            "mode": mode, "can_enforce": can_enforce, "version": version, "ip": ip, "gateway_ip": gateway_ip,
            "stats": stats or {}, "acks": acks or []})

    def immunity_feed(self) -> dict[str, Any]:
        return self._call("GET", "/v2/sensors/immunity-feed")

    def signing_key(self) -> dict[str, Any]:
        """The plane's current signing key, key history and endorsement chain."""
        return self._call("GET", "/v2/public/signing-key")

    def send(self, events: Iterable[dict[str, Any]]) -> dict[str, int]:
        """Send events (any number); batches of 1,000, gzip. Undeliverable
        batches are spooled to disk when a spool directory is configured."""
        totals = {"accepted": 0, "duplicates": 0, "rejected": 0, "spooled": 0}
        self.flush_spool()
        batch: list[dict[str, Any]] = []
        for e in events:
            batch.append(e)
            if len(batch) >= MAX_BATCH:
                self._send_batch(batch, totals)
                batch = []
        if batch:
            self._send_batch(batch, totals)
        return totals

    def _send_batch(self, batch: list[dict[str, Any]], totals: dict[str, int]) -> None:
        try:
            r = self._call("POST", "/v2/events", {"events": batch}, gzip_body=True)
        except ApiError as e:
            if e.status == 400 and isinstance(e.body, dict) and e.body.get("error", {}).get("code") == "all_rejected":
                totals["rejected"] += len(batch)
                return
            if self.spool and e.retryable:
                self._spool(batch)
                totals["spooled"] += len(batch)
                return
            raise
        for k in ("accepted", "duplicates", "rejected"):
            totals[k] += int(r.get(k, 0))

    # ------------------------------------------------------------ spool
    def _spool_size(self) -> int:
        return sum(p.stat().st_size for p in self.spool.glob("*.json.gz")) if self.spool else 0

    def _spool(self, batch: list[dict[str, Any]]) -> None:
        assert self.spool is not None
        data = gzip.compress(json.dumps(batch, default=str).encode())
        while self._spool_size() + len(data) > self.max_spool_bytes:
            files = sorted(self.spool.glob("*.json.gz"))
            if not files:
                break
            files[0].unlink()  # drop the oldest: bounded memory/disk beats unbounded growth
        name = self.spool / f"{time.time_ns()}-{random.randint(0, 1 << 30)}.json.gz"
        tmp = name.with_suffix(".tmp")
        tmp.write_bytes(data)
        os.chmod(tmp, 0o600)
        tmp.rename(name)

    def flush_spool(self) -> int:
        if not self.spool:
            return 0
        sent = 0
        for f in sorted(self.spool.glob("*.json.gz")):
            batch = json.loads(gzip.decompress(f.read_bytes()))
            try:
                self._call("POST", "/v2/events", {"events": batch}, gzip_body=True)
            except ApiError as e:
                if e.retryable:
                    break  # still down: keep order, try later
                # permanently rejected batch: drop it rather than wedge the spool
            f.unlink()
            sent += len(batch)
        return sent


_ENVELOPE_PREFIX = b"prosentriq-signed-digest/1\nsha512:"
_ENDORSEMENT_TYPE = "prosentriq-key-endorsement/1"


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()


def key_id_for(public_raw: bytes) -> str:
    import hashlib

    return "ed25519:" + hashlib.sha256(public_raw).hexdigest()[:16]


def verify_signature(doc: Any, signature_b64: str, public_key_raw: bytes) -> bool:
    """Ed25519 over the canonical JSON of ``doc``, signed directly or through
    the platform's SHA-512 digest envelope (used by size-capped KMS signers)."""
    import hashlib

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        key = Ed25519PublicKey.from_public_bytes(public_key_raw)
        sig = base64.b64decode(signature_b64, validate=True)
    except (ValueError, TypeError):
        return False
    if len(sig) != 64:
        return False
    data = _canonical(doc)
    for message in (data, _ENVELOPE_PREFIX + hashlib.sha512(data).hexdigest().encode()):
        try:
            key.verify(sig, message)
            return True
        except InvalidSignature:
            continue
    return False


def resolve_chain(trusted: dict[str, bytes], chain: Any, target_key_id: str) -> bytes | None:
    """Follow the platform's key endorsements from a key already trusted to
    ``target_key_id``; every link must be signed by a key trusted before it."""
    known = dict(trusted)
    links = [x for x in (chain if isinstance(chain, list) else [])[:32] if isinstance(x, dict)]
    progress = True
    while target_key_id not in known and progress:
        progress = False
        for link in links:
            try:
                doc, sig = link["endorsement"], link["signature"]
                if (not isinstance(doc, dict) or doc.get("type") != _ENDORSEMENT_TYPE or doc.get("alg") != "Ed25519"
                        or doc.get("key_id") in known or doc.get("previous_key_id") not in known):
                    continue
                raw = base64.b64decode(doc["public_key"], validate=True)
                if len(raw) != 32 or key_id_for(raw) != doc["key_id"] or not verify_signature(doc, sig, known[doc["previous_key_id"]]):
                    continue
            except (KeyError, TypeError, ValueError):
                continue
            known[doc["key_id"]] = raw
            progress = True
    return known.get(target_key_id)


def verify_feed(feed: dict[str, Any], pinned_public_key_b64: str) -> bool:
    """Verify an immunity feed against the key pinned at enrollment. Never
    trust the public key the feed itself carries."""
    try:
        if not verify_signature(feed["payload"], feed["signature"], base64.b64decode(pinned_public_key_b64, validate=True)):
            return False
        valid_until = feed["payload"].get("valid_until")
    except (ValueError, KeyError, TypeError, AttributeError):
        return False
    if valid_until:
        from datetime import datetime, timezone

        try:
            if datetime.fromisoformat(valid_until) < datetime.now(timezone.utc):
                return False  # stale (possibly replayed) feed
        except (ValueError, TypeError):
            return False
    return True
