"""Append-only, hash-chained evidence ledger.

The ledger is a single NDJSON file. Every record carries a monotonic
sequence number and a hash chained to the previous record:

    hash = SHA-256( prev_hash || canonical_json(record without "hash") )

Periodically the writer seals a *checkpoint*: a record that carries the
Merkle root of all record hashes up to that point, signed with
HMAC-SHA-256 under an operator key that lives outside the ledger
directory. The checkpoint's Merkle root and signature are also appended
to an *anchor file* outside the ledger directory, so rewriting history
requires rewriting two places and re-forging a signature the operator
key protects.

The ledger never stores raw secrets: callers pass digests, not values.
The verifier additionally scans a finished bundle for known secret
values (see verify.py).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from datetime import datetime, timezone

GENESIS_HASH = "0" * 64


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def record_hash(prev_hash: str, payload: dict) -> str:
    return hashlib.sha256(prev_hash.encode("ascii") + canonical(payload)).hexdigest()


def merkle_root(hashes: list[str]) -> str:
    """Merkle root over hex hash strings; odd leaf is paired with itself."""
    if not hashes:
        return hashlib.sha256(b"").hexdigest()
    level = [bytes.fromhex(h) for h in hashes]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            nxt.append(hashlib.sha256(left + right).digest())
        level = nxt
    return level[0].hex()


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class Ledger:
    """Single-writer append-only ledger. One Ledger per run directory."""

    def __init__(self, ledger_path: str, anchor_path: str, signing_key: bytes,
                 run_id: str, agent: str, adapter: str, resume: bool = False):
        self.ledger_path = ledger_path
        self.anchor_path = anchor_path
        self._key = signing_key
        self.run_id = run_id
        self.agent = agent
        self.adapter = adapter
        self._lock = threading.Lock()
        self._seq = 0
        self._prev_hash = GENESIS_HASH
        self._hashes: list[str] = []
        os.makedirs(os.path.dirname(ledger_path), exist_ok=True)
        os.makedirs(os.path.dirname(anchor_path), exist_ok=True)
        if resume and os.path.exists(ledger_path) \
                and os.path.getsize(ledger_path) > 0:
            for rec in read_records(ledger_path):
                self._seq = rec["seq"]
                self._prev_hash = rec["hash"]
                self._hashes.append(rec["hash"])
                self.run_id = rec["run_id"]
        self._fh = open(ledger_path, "a", encoding="utf-8")

    def append(self, kind: str, action_class: str, subject: dict,
               decision: str | None = None, reason: str | None = None,
               action_id: str | None = None, source: str = "seatbelt",
               enforcement: str = "enforce",
               policy_hash: str | None = None,
               policy_version: str | None = None,
               extra: dict | None = None) -> dict:
        with self._lock:
            self._seq += 1
            payload = {
                "seq": self._seq,
                "ts": utcnow(),
                "run_id": self.run_id,
                "agent": self.agent,
                "adapter": self.adapter,
                "source": source,
                "class": action_class,
                "kind": kind,
                "action_id": action_id,
                "decision": decision,
                "enforcement": enforcement,
                "reason": reason,
                "policy_hash": policy_hash,
                "policy_version": policy_version,
                "subject": subject,
                "prev_hash": self._prev_hash,
            }
            if extra:
                payload["extra"] = extra
            h = record_hash(self._prev_hash, payload)
            record = dict(payload)
            record["hash"] = h
            self._fh.write(json.dumps(record, sort_keys=True) + "\n")
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._prev_hash = h
            self._hashes.append(h)
            return record

    def checkpoint(self) -> dict:
        """Seal the chain so far: Merkle root + HMAC signature + anchor."""
        with self._lock:
            root = merkle_root(self._hashes)
            sig = hmac.new(self._key, root.encode("ascii"),
                           hashlib.sha256).hexdigest()
            last_seq = self._seq
            head = self._prev_hash
        rec = self.append(
            "checkpoint", "integrity",
            {"covers_to_seq": last_seq, "merkle_root": root,
             "head_hash": head},
            extra={"signature": sig})
        with open(self.anchor_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "run_id": self.run_id, "covers_to_seq": last_seq,
                "merkle_root": root, "signature": sig,
                "checkpoint_seq": rec["seq"], "ts": rec["ts"],
            }, sort_keys=True) + "\n")
        return rec

    @property
    def head_hash(self) -> str:
        return self._prev_hash

    @property
    def seq(self) -> int:
        return self._seq

    def close(self):
        with self._lock:
            self._fh.close()


def load_signing_key(key_path: str) -> bytes:
    """Load (or create) the operator checkpoint-signing key.

    The key file must live outside the repository tree and outside the
    ledger directory; it is the operator's root of trust for checkpoint
    signatures in phase 1 (HMAC). KMS/HSM-backed signing is a phase-3
    roadmap item (blueprint risk R7).
    """
    if os.path.exists(key_path):
        with open(key_path, "rb") as fh:
            return fh.read().strip()
    key = os.urandom(32).hex().encode("ascii")
    os.makedirs(os.path.dirname(key_path) or ".", exist_ok=True)
    with open(key_path, "wb") as fh:
        fh.write(key)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    return key


def read_records(ledger_path: str) -> list[dict]:
    records = []
    with open(ledger_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records
