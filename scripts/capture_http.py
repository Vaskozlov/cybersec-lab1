"""Exercise the actual server through curl; save evidence without live credentials."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output" / "evidence"
OUT.mkdir(parents=True, exist_ok=True)
(ROOT / "tmp").mkdir(exist_ok=True)


def main():
    password = secrets.token_urlsafe(20)
    env = dict(os.environ, JWT_SECRET=secrets.token_urlsafe(32))
    # Server configuration deliberately expects canonical standard base64.
    import base64
    env["JWT_SECRET"] = base64.b64encode(secrets.token_bytes(32)).decode()
    env["LAB_PASSWORD"] = password
    env["PORT"] = "3001"
    with tempfile.TemporaryDirectory(prefix="http-evidence-", dir=ROOT / "tmp") as temporary:
        env["DB_PATH"] = str(Path(temporary) / "smoke.db")
        for username in ("vasily", "other-user"):
            subprocess.run(["node", "scripts/create-user.js", username], cwd=ROOT, env=env,
                           check=True, capture_output=True, text=True)
        env.pop("LAB_PASSWORD")
        with (Path(temporary) / "server.log").open("w") as log:
            server = subprocess.Popen(["node", "src/server.js"], cwd=ROOT, env=env,
                                      stdout=log, stderr=log)
            try:
                for _ in range(100):
                    if server.poll() is not None:
                        raise RuntimeError("Server startup failed: " + (Path(temporary) / "server.log").read_text())
                    if "Secure notes API" in (Path(temporary) / "server.log").read_text():
                        break
                    time.sleep(0.1)
                else:
                    raise RuntimeError("Server startup timed out")
                records = []

                def curl(label, method, path, expected, payload=None, token=None, content_type="application/json", extra_headers=None):
                    url = "http://127.0.0.1:3001" + path
                    args = ["curl", "--silent", "--show-error", "--max-time", "10", "-i", "-X", method]
                    display = ["curl -i", "-X " + method]
                    if token:
                        args += ["-H", "Authorization: Bearer " + token]
                        display += ["-H 'Authorization: Bearer <REDACTED>'"]
                    if payload is not None:
                        args += ["-H", "Content-Type: " + content_type, "--data-binary", "@-"]
                        display += ["-H 'Content-Type: " + content_type + "' --data-binary @-"]
                    for name, value in (extra_headers or {}).items():
                        args += ["-H", name + ": " + value]
                        display += ["-H '" + name + ": " + value + "'"]
                    args.append(url)
                    display.append(url)
                    raw = subprocess.run(args, input=None if payload is None else json.dumps(payload),
                                         capture_output=True, text=True, check=True).stdout
                    headers, body = raw.split("\n\n", 1)
                    status = int(headers.splitlines()[0].split()[1])
                    assert status == expected, (label, status, raw)
                    data = json.loads(body)
                    safe_data = dict(data)
                    if "access_token" in safe_data:
                        safe_data["access_token"] = "<REDACTED: ephemeral JWT>"
                    safe_payload = dict(payload) if payload is not None else None
                    if safe_payload is not None and "password" in safe_payload:
                        safe_payload["password"] = "<REDACTED>"
                    records.append(dict(label=label, command=" ".join(display), request=safe_payload,
                                        expected=expected, status=status, headers=headers,
                                        response=safe_data))
                    return data

                curl("Unauthenticated GET", "GET", "/api/data", 401)
                curl("Unauthenticated POST", "POST", "/api/data", 401, {"title": "Denied", "body": ""})
                login = curl("Successful login", "POST", "/auth/login", 200,
                             {"username": "vasily", "password": password})
                token = login["access_token"]
                curl("Incorrect password", "POST", "/auth/login", 401,
                     {"username": "vasily", "password": "incorrect"})
                curl("SQL injection in login", "POST", "/auth/login", 401,
                     {"username": "' OR 1=1 --", "password": "incorrect"})
                curl("Invalid JWT", "GET", "/api/data", 401, token="not.a.jwt")
                created = curl("Create note and encode XSS", "POST", "/api/data", 201,
                               {"title": "XSS check", "body": "<script>alert(1)</script>"}, token)
                assert created["data"]["body"] == "&lt;script&gt;alert(1)&lt;/script&gt;"
                notes = curl("Read own notes", "GET", "/api/data", 200, token=token)
                assert notes["data"][0] == created["data"]
                second = curl("Second user login", "POST", "/auth/login", 200,
                              {"username": "other-user", "password": password})
                other = curl("Second user cannot read first user note", "GET", "/api/data", 200,
                             token=second["access_token"])
                assert other["data"] == []
                curl("Unsupported JSON charset", "POST", "/auth/login", 415,
                     {}, content_type="application/json; charset=iso-8859-1")
                curl("Unsupported content encoding", "POST", "/auth/login", 415,
                     {}, extra_headers={"Content-Encoding": "unsupported"})
                result = dict(captured_at=datetime.now(timezone.utc).isoformat(),
                              node=subprocess.check_output(["node", "--version"], text=True).strip(),
                              passed=len(records), failed=0, records=records)
                (OUT / "http-results.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
                lines = ["Actual curl requests against the local lab1 server", result["captured_at"],
                         "Ephemeral passwords and JWTs are redacted. Temporary database was deleted."]
                for record in records:
                    lines += ["", "=== " + record["label"] + " ===", "$ " + record["command"]]
                    if record["request"] is not None:
                        lines += ["stdin: " + json.dumps(record["request"], ensure_ascii=False)]
                    lines += [record["headers"], json.dumps(record["response"], ensure_ascii=False)]
                (OUT / "http-transcript.txt").write_text("\n".join(lines) + "\n")
                print(f"curl checks: {len(records)} passed; credentials redacted")
            finally:
                server.terminate()
                try:
                    server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()


if __name__ == "__main__":
    main()
