#!/usr/bin/env python3
"""Bootstrap a fresh local Cortex for IRIS (stdlib only, idempotent).

1. Elasticsearch index migration.
2. Superadmin ``admin`` (organisation "cortex").
3. Organisation ``SOC`` with an org admin ``socadmin`` and the integration user ``iris``
   (roles read + analyze ONLY: org admins' keys expose analyzer configuration).
4. Enables free analyzers that need no API key, and the Mailer responder pointed at Mailpit.
5. Writes the ``iris`` API key to iris-web/.env as IRIS_CORTEX_API_KEY (never printed).

Generated passwords are stored in ./.credentials (mode 600). Re-running keeps existing users
and passwords and only fills what is missing.

    python3 bootstrap.py [--url http://localhost:9001] [--iris-env ../../../iris-web/.env]
"""
import argparse
import http.cookiejar
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
CREDENTIALS = HERE / ".credentials"
ORG = "SOC"

# Analyzers usable without third-party API keys (enabled when present in the catalog).
FREE_ANALYZERS = [
    "Abuse_Finder_3_0", "DShield_lookup_1_0", "TorProject_1_0", "CIRCLHashlookup_1_1", "FileInfo_8_0",
    "Crtsh_Transparency_Logs_1_0", "MalwareBazaar_1_0", "EmlParser_2_1", "GoogleDNS_resolve_1_0_0",
    "Urlscan_io_Search_0_1_1", "ThreatCrowd_1_0", "Robtex_IP_Query_1_0", "Robtex_Forward_PDNS_Query_1_0",
]
BASE_CONFIG = {"auto_extract_artifacts": True, "check_tlp": True, "max_tlp": 2, "check_pap": True, "max_pap": 2,
               "jobTimeout": 30}
RESPONDERS = {
    # Mailpit (iris-email-module test mailbox), published on the host loopback: responder jobs run
    # as sibling containers on the default bridge network, where "mailpit" does not resolve.
    "Mailer_1_0": {"from": "cortex@example.com", "smtp_host": "host.docker.internal", "smtp_port": 1025,
                   "smtp_user": "", "smtp_pwd": ""},
}


class Cortex:
    def __init__(self, url):
        self.url = url.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def _xsrf(self):
        return next((c.value for c in self.jar if c.name == "CORTEX-XSRF-TOKEN"), None)

    @staticmethod
    def _decode(raw):
        if not raw:
            return None
        try:
            return json.loads(raw)
        except ValueError:
            return raw.decode("utf-8", "replace").strip()     # e.g. key/renew returns the key as text

    def call(self, method, path, body=None, expect=(200, 201, 204)):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        token = self._xsrf()
        if token:
            req.add_header("X-CORTEX-XSRF-TOKEN", token)
        try:
            with self.opener.open(req, timeout=60) as r:
                raw = r.read()
                return r.status, self._decode(raw)
        except urllib.error.HTTPError as e:
            raw = e.read()
            if e.code in expect:
                return e.code, self._decode(raw)
            try:
                payload = json.loads(raw)
            except ValueError:
                payload = raw[:300].decode("utf-8", "replace")
            return e.code, payload

    def login(self, user, password):
        code, body = self.call("POST", "/api/login", {"user": user, "password": password})
        if code != 200:
            sys.exit(f"Login failed for {user}: HTTP {code} {body}")
        self.call("GET", "/api/user/current")      # obtains the XSRF cookie


def load_credentials():
    if CREDENTIALS.exists():
        return json.loads(CREDENTIALS.read_text())
    return {}


def save_credentials(creds):
    CREDENTIALS.write_text(json.dumps(creds, indent=2))
    os.chmod(CREDENTIALS, 0o600)


def password():
    return secrets.token_urlsafe(18)


def wait_ready(c):
    for _ in range(90):
        try:
            code, body = c.call("GET", "/api/status")
            if code == 200:
                return body
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(2)
    sys.exit("Cortex did not answer on /api/status")


def ensure_user(c, login, name, roles, org, creds):
    code, _ = c.call("GET", f"/api/user/{login}", expect=(200, 404))
    if code == 404:
        code, body = c.call("POST", "/api/user", {"login": login, "name": name, "roles": roles, "organization": org})
        if code not in (200, 201):
            sys.exit(f"Cannot create user {login}: {code} {body}")
        print(f"  user {login} created ({', '.join(roles)})")
    if login not in creds:
        creds[login] = password()
        code, body = c.call("POST", f"/api/user/{login}/password/set", {"password": creds[login]})
        if code not in (200, 204):
            sys.exit(f"Cannot set password for {login}: {code} {body}")


def current_key_works(url: str, env_path: Path) -> bool:
    if not env_path.exists():
        return False
    key = next((l.split("=", 1)[1].strip() for l in env_path.read_text().splitlines()
                if l.startswith("IRIS_CORTEX_API_KEY=")), "")
    if not key:
        return False
    req = urllib.request.Request(url.rstrip("/") + "/api/user/current", headers={"Authorization": f"Bearer {key}"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read()).get("id") == "iris"
    except (urllib.error.URLError, ValueError):
        return False


def write_iris_env(path: Path, key: str):
    lines = path.read_text().splitlines() if path.exists() else []
    lines = [l for l in lines if not l.startswith("IRIS_CORTEX_API_KEY=")]
    lines.append(f"IRIS_CORTEX_API_KEY={key}")
    path.write_text("\n".join(lines) + "\n")
    os.chmod(path, 0o600)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:9001")
    ap.add_argument("--iris-env", default=str(HERE.parents[2] / "iris-web" / ".env"))
    ap.add_argument("--renew-key", action="store_true", help="rotate the iris API key even if the current one works")
    args = ap.parse_args()

    c = Cortex(args.url)
    status = wait_ready(c)
    print(f"Cortex {status.get('versions', {}).get('Cortex')} reachable at {args.url}")
    creds = load_credentials()

    code, body = c.call("POST", "/api/maintenance/migrate", {})
    print(f"migration: HTTP {code}")

    # First superadmin: allowed without authentication only while Cortex has no user.
    if "admin" not in creds:
        creds["admin"] = password()
        code, body = c.call("POST", "/api/user", {"login": "admin", "name": "Administrator",
                                                  "roles": ["superadmin"], "password": creds["admin"]})
        if code not in (200, 201):
            sys.exit(f"Cannot create the superadmin (already initialised with another password?): {code} {body}")
        print("  superadmin admin created")
    save_credentials(creds)
    c.login("admin", creds["admin"])

    code, _ = c.call("GET", f"/api/organization/{ORG}", expect=(200, 404))
    if code == 404:
        code, body = c.call("POST", "/api/organization", {"name": ORG, "description": "SOC (IRIS)",
                                                           "status": "Active"})
        print(f"  organisation {ORG} created" if code in (200, 201) else f"  organisation: {code} {body}")
    ensure_user(c, "socadmin", "SOC org admin", ["read", "analyze", "orgadmin"], ORG, creds)
    ensure_user(c, "iris", "IRIS integration", ["read", "analyze"], ORG, creds)
    save_credentials(creds)

    if not args.renew_key and current_key_works(args.url, Path(args.iris_env)):
        print("  API key of user iris in IRIS env is valid: kept (use --renew-key to rotate)")
    else:
        code, key = c.call("POST", "/api/user/iris/key/renew")
        if code not in (200, 201) or not isinstance(key, str):
            sys.exit(f"Cannot create the iris API key: {code} {key}")
        write_iris_env(Path(args.iris_env), key)
        print(f"  API key of user iris written to {args.iris_env} (IRIS_CORTEX_API_KEY) -- "
              "recreate the IRIS app and worker containers to load it")

    # Analyzers and responders are enabled per organisation, by its org admin.
    org = Cortex(args.url)
    org.login("socadmin", creds["socadmin"])
    _, definitions = org.call("GET", "/api/analyzerdefinition?range=all")
    _, enabled = org.call("GET", "/api/organization/analyzer?range=all")
    enabled_names = {a.get("name") for a in (enabled or [])}
    by_id = {d["id"]: d for d in (definitions or [])}
    print(f"catalog: {len(by_id)} analyzer definitions")
    for name in FREE_ANALYZERS:
        d = by_id.get(name)
        if d is None or name in enabled_names:
            continue
        required = [i["name"] for i in d.get("configurationItems", []) if i.get("required") and
                    i.get("defaultValue") is None]
        if required:
            print(f"  skip {name}: needs {', '.join(required)}")
            continue
        config = dict(BASE_CONFIG)
        config.update({i["name"]: i["defaultValue"] for i in d.get("configurationItems", [])
                       if i.get("defaultValue") is not None})
        code, body = org.call("POST", f"/api/organization/analyzer/{name}",
                              {"name": name, "configuration": config, "jobCache": 10})
        print(f"  analyzer {name}: {'enabled' if code in (200, 201) else f'HTTP {code} {body}'}")

    _, rdefs = org.call("GET", "/api/responderdefinition?range=all")
    _, renabled = org.call("GET", "/api/organization/responder?range=all")
    renabled_names = {r.get("name") for r in (renabled or [])}
    rby_id = {d["id"]: d for d in (rdefs or [])}
    renabled_ids = {r.get("name"): r.get("id") for r in (renabled or [])}
    for name, extra in RESPONDERS.items():
        if name not in rby_id:
            continue
        # Responders only know the TLP/PAP checks, not the analyzer-only options.
        config = {k: BASE_CONFIG[k] for k in ("check_tlp", "max_tlp", "check_pap", "max_pap")}
        config.update({i["name"]: i["defaultValue"] for i in rby_id[name].get("configurationItems", [])
                       if i.get("defaultValue") is not None})
        config.update(extra)
        if name in renabled_names:
            code, body = org.call("PATCH", f"/api/responder/{renabled_ids[name]}", {"configuration": config})
            print(f"  responder {name}: {'configuration updated' if code in (200, 201) else f'HTTP {code} {body}'}")
        else:
            code, body = org.call("POST", f"/api/organization/responder/{name}", {"name": name, "configuration": config})
            print(f"  responder {name}: {'enabled' if code in (200, 201) else f'HTTP {code} {body}'}")

    print(f"\nDone. Cortex UI: {args.url} -- logins/passwords in {CREDENTIALS} (mode 600).")


if __name__ == "__main__":
    main()
