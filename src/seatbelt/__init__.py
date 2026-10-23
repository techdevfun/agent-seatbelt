"""Agent Seatbelt — a vendor-neutral policy + tamper-evident evidence layer
that sits above AI agent runtimes.

Every agent action (tool call, network egress, file access, credential use),
including actions that are denied, is decided by a deterministic policy
engine outside the agent process and recorded in an append-only,
hash-chained evidence ledger that can be verified with a single offline
command.
"""

__version__ = "0.1.0"
POLICY_PACK_VERSION = "1.0.0"
