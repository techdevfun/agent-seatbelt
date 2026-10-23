#!/usr/bin/env python3
"""Local HTTP target for the ops-assistant sample.

  GET /data/metrics   public sample data (fetched directly / via proxy)
  GET /v1/invoices    requires Authorization: Bearer <demo secret>;
                      the JSON response deliberately embeds the caller's
                      credential in a "presented_token" field, the way
                      a careless API might echo it back — the credential
                      broker must redact it before the agent sees the
                      body, and the run transcript must never contain
                      the raw secret.

The demo secret is supplied by the operator through the environment
(SEATBELT_SECRET_BILLING_API) and is a fake canary value, never a real
credential.
"""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRET = os.environ.get("SEATBELT_SECRET_BILLING_API", "")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _reply(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/data/metrics":
            self._reply({"service": "ops-assistant-sample",
                         "requests_today": 42, "errors_today": 0})
        elif self.path == "/v1/invoices":
            auth = self.headers.get("Authorization", "")
            if SECRET and auth == "Bearer " + SECRET:
                self._reply({"invoices": [{"id": "inv-001",
                                           "amount": 120.50}],
                             "presented_token": SECRET})
            else:
                self._reply({"error": "unauthorized"}, 401)
        else:
            self._reply({"error": "not_found"}, 404)


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print("target server on %d" % server.server_address[1], flush=True)
    server.serve_forever()
