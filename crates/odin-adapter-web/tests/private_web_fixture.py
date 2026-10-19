"""Run-owned loopback upstreams for the real adapter transport fixture.

No adapter result is simulated here: this is a deliberately synthetic HTTP
upstream. --smoke checks only this helper's TLS/auth transport, not the adapter.
"""
from __future__ import annotations

import argparse
import http.server
import json
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
import threading
import urllib.parse
import urllib.request


class PrivateWebFixture:
    def __init__(self, root: Path):
        self.root = root
        self.token = "fixture-" + secrets.token_hex(24)
        self.nonce = secrets.token_hex(16)
        self.events = []
        self.lock = threading.Lock()
        self.servers = []
        self.threads = []
        self.mode = "fallback"

    def __enter__(self):
        try:
            self._start()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def _start(self):
        # Separate CA/leaf certificate; verification exercises IP SAN, chain,
        # serverAuth and validity, never CERT_NONE or a public fake endpoint.
        ca = self.root / "ca.pem"
        key = self.root / "ca.key"
        leaf = self.root / "server.pem"
        leaf_key = self.root / "server.key"
        csr = self.root / "server.csr"
        extension = self.root / "server.ext"
        extension.write_text("basicConstraints=critical,CA:FALSE\n"
                             "keyUsage=critical,digitalSignature,keyEncipherment\n"
                             "extendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n")
        commands = [
            ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=Odin private fixture CA", "-keyout", str(key), "-out", str(ca),
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
            ["req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=127.0.0.1",
             "-keyout", str(leaf_key), "-out", str(csr)],
            ["x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(key),
             "-CAcreateserial", "-days", "1", "-extfile", str(extension), "-out", str(leaf)],
        ]
        for command in commands:
            subprocess.run(["openssl", *command], check=True, capture_output=True, timeout=20)
        self.credential = self.root / "credential"
        self.credential.write_text(self.token)
        self.credential.chmod(0o600)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(leaf, leaf_key)
        owner = self

        def handler(backend):
            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *_args):
                    pass

                def do_GET(self):
                    parsed = urllib.parse.urlsplit(self.path)
                    query = urllib.parse.parse_qs(parsed.query)
                    auth = self.headers.get("X-Subscription-Token")
                    with owner.lock:
                        mode = owner.mode
                    if backend == "searxng" and mode != "healthy":
                        status, payload = 503, {"error": "controlled primary failure"}
                    elif backend == "brave" and mode == "both-down":
                        status, payload = 503, {"error": "controlled fallback failure"}
                    elif backend == "brave" and auth != owner.token:
                        status, payload = 401, {"error": "wrong fixture token"}
                    else:
                        result = {"title": "private-" + owner.nonce,
                                  "url": "https://fixture.invalid/" + owner.nonce,
                                  "description": "controlled-" + owner.nonce}
                        status = 200
                        payload = ({"type": "search", "web": {"results": [result]}} if backend == "brave"
                                   else {"results": [dict(result, content=result["description"])]})
                    with owner.lock:
                        # Record only equality, never the credential value.
                        owner.events.append({"backend": backend, "path": parsed.path,
                                             "query": query, "authenticated": auth == owner.token,
                                             "has_auth": auth is not None, "status": status})
                        owner.write_events()
                    body = json.dumps(payload).encode()
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
            return Handler

        for backend in ("searxng", "brave"):
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler(backend))
            self.servers.append(server)
            if backend == "brave":
                server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            self.threads.append(thread)
            thread.start()
        self.primary = f"http://127.0.0.1:{self.servers[0].server_port}/search"
        self.fallback = f"https://127.0.0.1:{self.servers[1].server_port}/search"
        self.write_events()
        (self.root / "ready.json").write_text(json.dumps({
            "primary": self.primary, "fallback": self.fallback, "nonce": self.nonce,
            "ca": str(ca), "credential": str(self.credential)}))

    def write_events(self):
        pending = self.root / "events.pending"
        pending.write_text(json.dumps(self.events))
        pending.replace(self.root / "events.json")

    def __exit__(self, *_args):
        for server, thread in zip(self.servers, self.threads):
            if thread.is_alive():
                server.shutdown()
        for server in self.servers:
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=5)


def smoke():
    with tempfile.TemporaryDirectory(prefix="odin-web-tls-") as directory:
        with PrivateWebFixture(Path(directory)) as fixture:
            context = ssl.create_default_context(cafile=str(fixture.root / "ca.pem"))
            request = urllib.request.Request(fixture.fallback + "?q=smoke&count=1",
                                             headers={"X-Subscription-Token": fixture.token})
            with urllib.request.urlopen(request, context=context, timeout=5) as reply:
                assert fixture.nonce in reply.read().decode()
            assert fixture.events == [{"backend": "brave", "path": "/search",
                                       "query": {"q": ["smoke"], "count": ["1"]},
                                       "authenticated": True, "has_auth": True, "status": 200}]
    print("TLS helper smoke passed (not adapter fallback acceptance)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--root", type=Path)
    args = parser.parse_args()
    if args.smoke:
        smoke()
        return
    if args.root is None or not args.root.is_dir():
        parser.error("--root must name the harness-owned private directory")
    with PrivateWebFixture(args.root) as fixture:
        # Harness keeps stdin open; EOF releases all owned listeners.
        for line in __import__("sys").stdin:
            command = json.loads(line)
            with fixture.lock:
                fixture.mode = command["mode"]
                fixture.events.clear()
                fixture.write_events()
            acknowledgement = fixture.root / "ack.pending"
            acknowledgement.write_text(command["mode"])
            acknowledgement.replace(fixture.root / "ack")


if __name__ == "__main__":
    main()
