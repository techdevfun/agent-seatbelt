"""Thin client for the Seatbelt daemon API, used by the hook CLI, the
MCP proxy, and agent harnesses that mediate their tools through
Seatbelt."""

from __future__ import annotations

import json
import urllib.request


class Client:
    def __init__(self, api_url: str):
        self.api_url = api_url.rstrip("/")

    def _post(self, path: str, payload: dict) -> dict:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.api_url + path, data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _get(self, path: str) -> dict:
        req = urllib.request.Request(self.api_url + path)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def decide(self, action: dict, action_id: str | None,
               subject: dict) -> dict:
        return self._post("/decide", {"action": action,
                                      "action_id": action_id,
                                      "subject": subject})

    def meter(self, action_id: str, add_cost: float,
              add_tokens: int) -> dict:
        return self._post("/meter", {"action_id": action_id,
                                     "add_cost": add_cost,
                                     "add_tokens": add_tokens})

    def broker_use(self, action_id: str, service: str, host: str,
                   method: str, path: str, port: int | None = None) -> dict:
        return self._post("/broker/use",
                          {"action_id": action_id, "service": service,
                           "host": host, "method": method, "path": path,
                           "port": port})

    def broker_read(self, action_id: str, service: str) -> dict:
        return self._post("/broker/read", {"action_id": action_id,
                                           "service": service})

    def run_start(self) -> dict:
        return self._post("/run/start", {})

    def run_end(self) -> dict:
        return self._post("/run/end", {})

    def checkpoint(self) -> dict:
        return self._post("/checkpoint", {})

    def stats(self) -> dict:
        return self._get("/stats")

    def healthy(self) -> bool:
        try:
            return bool(self._get("/health").get("ok"))
        except Exception:
            return False
