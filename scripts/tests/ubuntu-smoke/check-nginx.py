#!/usr/bin/env python3
"""Exercise the rendered origin on real nginx with disposable mutual TLS."""

import http.client
import http.server
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import time

if not Path("/.dockerenv").exists() or not Path("/etc/zecwec-disposable-smoke").exists():
    raise SystemExit("Run only in the disposable smoke-test image")


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class Backend(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(self.path.encode())

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, *_args):
        pass


with tempfile.TemporaryDirectory(prefix="zecwec-nginx-") as directory:
    root = Path(directory)
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-keyout", str(root / "ca.key"), "-out", str(root / "ca.pem"),
        "-subj", "/CN=Disposable origin test CA")
    for name in ("server", "client"):
        run("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(root / f"{name}.key"), "-out", str(root / f"{name}.csr"),
            "-subj", f"/CN={name}")
        extension = root / f"{name}.ext"
        extension.write_text(
            "subjectAltName=IP:127.0.0.1,DNS:testnet.zecwec.test,DNS:zecwec.test\n"
            "extendedKeyUsage=serverAuth\n" if name == "server" else
            "extendedKeyUsage=clientAuth\n")
        run("openssl", "x509", "-req", "-in", str(root / f"{name}.csr"),
            "-CA", str(root / "ca.pem"), "-CAkey", str(root / "ca.key"),
            "-CAcreateserial", "-out", str(root / f"{name}.pem"), "-days", "1",
            "-extfile", str(extension))

    source = Path("/workspace/deploy/nginx/zecwec-testnet-portal.conf.in").read_text()
    values = {
        "PORTAL_LISTEN": "127.0.0.1:8080", "PORTAL_HOST": "testnet.zecwec.test",
        "PORTAL_TLS_CERT": str(root / "server.pem"),
        "PORTAL_TLS_KEY": str(root / "server.key"),
        "CLOUDFLARE_ORIGIN_PULL_CA": str(root / "ca.pem"),
    }
    for key, value in values.items():
        source = source.replace(f"@{key}@", value)
    assert "@" not in source
    config = root / "nginx.conf"
    config.write_text(
        f"pid {root}/nginx.pid;\nerror_log {root}/error.log;\n"
        "events {}\nhttp { access_log off;\n" + source + "\n}\n")
    run("nginx", "-t", "-c", str(config))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 8080), Backend)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    challenge_root = Path("/var/lib/letsencrypt/.well-known/acme-challenge")
    challenge_root.mkdir(parents=True, exist_ok=True)
    challenge = challenge_root / "disposable-smoke_token-0123456789"
    challenge.write_text("disposable ACME proof")
    run("nginx", "-c", str(config))
    try:
        trusted = ssl.create_default_context(cafile=str(root / "ca.pem"))
        trusted.load_cert_chain(str(root / "client.pem"), str(root / "client.key"))
        anonymous = ssl.create_default_context(cafile=str(root / "ca.pem"))

        def request(path, method="GET", context=trusted, client_header=True):
            connection = http.client.HTTPSConnection("127.0.0.1", 443, context=context, timeout=5)
            headers = {"Host": "testnet.zecwec.test"}
            if client_header:
                headers["CF-Connecting-IP"] = "192.0.2.20"
            connection.request(method, path, headers=headers)
            response = connection.getresponse()
            result = response.status, response.read()
            connection.close()
            return result

        def plain_request(host, path, method="GET"):
            connection = http.client.HTTPConnection("127.0.0.1", 80, timeout=5)
            try:
                connection.request(method, path, headers={
                    "Host": host, "CF-Connecting-IP": "192.0.2.20"})
                response = connection.getresponse()
                return response.status, response.read()
            except http.client.RemoteDisconnected:
                return None  # nginx 444 closes without an HTTP response.
            finally:
                connection.close()

        for _ in range(50):
            try:
                assert request("/")[0] == 200
                break
            except ConnectionRefusedError:
                time.sleep(0.1)
        else:
            raise AssertionError("nginx did not start")
        for path in ("/", "/assets/app.js", "/assets/app.css", "/assets/forms.css"):
            assert request(path) == (200, path.encode()), path
            assert request(path, "HEAD") == (200, b""), path
            assert request(path, "POST")[0] == 403, path
        for path in ("/other", "/assets/app.js.map", "/assets/appXjs", "/assets/other.css"):
            assert request(path)[0] == 404, path
        for path in ("/healthz", "/readyz", "/api/v1/overview"):
            assert request(path)[0] == 200, path
        assert request("/", context=anonymous)[0] in (400, 403)
        assert request("/", client_header=False)[0] == 403
        assert request("/api/v1/overview", context=anonymous)[0] in (400, 403)
        challenge_path = "/.well-known/acme-challenge/" + challenge.name
        for host in ("testnet.zecwec.test",):
            assert plain_request(host, challenge_path) == (200, b"disposable ACME proof"), host
            assert plain_request(host, "/.well-known/acme-challenge/missing-token")[0] == 404, host
            for method in ("HEAD", "POST", "PUT"):
                assert plain_request(host, challenge_path, method) is None, (host, method)
            for path in ("/", "/api/v1/overview", "/readyz", "/healthz", "/assets/app.js",
                         "/.well-known/acme-challenge/", challenge_path + "/nested",
                         "/.well-known/acme-challenge/invalid.token",
                         "/.well-known/acme-challenge/../../api/v1/overview"):
                assert plain_request(host, path) is None, (host, path)
        for host in ("zecwec.test", "unrelated.example"):
            assert plain_request(host, challenge_path) is None, host
            assert plain_request(host, "/api/v1/overview") is None, host
            connection = http.client.HTTPSConnection("127.0.0.1", 443, context=trusted, timeout=5)
            try:
                connection.request("GET", "/api/v1/overview", headers={
                    "Host": host, "CF-Connecting-IP": "192.0.2.20"})
                try:
                    connection.getresponse()
                except http.client.RemoteDisconnected:
                    pass
                else:
                    raise AssertionError("unrelated HTTPS Host was accepted")
            finally:
                connection.close()
        print("PASS real nginx: Testnet-only UI/API, origin mTLS, exact GET-only ACME and unrelated-host rejection")
    finally:
        run("nginx", "-s", "quit", "-c", str(config))
        server.shutdown()
        challenge.unlink()
