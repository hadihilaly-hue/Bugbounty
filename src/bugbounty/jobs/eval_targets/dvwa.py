"""DVWA adapter: graded against a local DVWA fixed at 'low' security.

Known planted bugs (DVWA security=low) with documented oracles. Authentication
goes through the shared SessionManager (CSRF form login + cookie session held
across the DB-init and security-level steps), demonstrating live session
handling against a CSRF-protected app. Reflected XSS is graded as HTTP
reflection (payload echoed unescaped) -- a weaker bar than the browser-execution
XSS harness, and flagged as such.

Local sandbox only; sends real payloads, so the dry-run gate is cleared for this
local target (global DRY_RUN stays on).
"""

from __future__ import annotations

from urllib.parse import urlencode

from ...config import Config
from ...net import AuthError, SessionManager
from ...net.session import Account, extract_csrf
from ...scope import LoginSpec, Platform, Target, TargetAuth
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
            "# the adapter then logs in admin/password (CSRF), runs setup.php create-db, "
            "and sets DVWA Security = Low automatically"
        )

    def _login_spec(self) -> LoginSpec:
        b = self.base_url
        return LoginSpec(
            mode="form",
            url=f"{b}/login.php",
            csrf_field="user_token",
            extra_fields={"Login": "Login"},
            user_field="username",
            pass_field="password",
            success_url=f"{b}/index.php",
            success_marker="Logout",
            expiry_marker="Login :: Damn Vulnerable Web Application",
        )

    def _authenticate(self, config: Config) -> str:
        """Hold a CSRF-protected cookie session; init the DB if needed; set low."""
        b = self.base_url
        sm = SessionManager(self._login_spec(), config=config, base_url=b)
        acct = Account("admin", "admin", "password")
        try:
            sm.authenticate(acct)
        except AuthError:
            # DB not initialised yet: create it on the held session, then retry.
            page = sm.request("GET", f"{b}/setup.php")
            tok = extract_csrf(page.text, "user_token")
            if tok:
                sm.request(
                    "POST",
                    f"{b}/setup.php",
                    data={"create_db": "Create / Reset Database", "user_token": tok},
                )
            sm.authenticate(acct)
        # Force DVWA Security = Low (page-specific CSRF token).
        page = sm.request("GET", f"{b}/security.php")
        tok = extract_csrf(page.text, "user_token")
        if tok:
            sm.request(
                "POST",
                f"{b}/security.php",
                data={"security": "low", "seclev_submit": "Submit", "user_token": tok},
            )
        sm.cookies["security"] = "low"
        return sm.cookie_header()

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
        config = config or Config(dry_run=False)
        try:
            cookie = self._authenticate(config)
        except Exception as exc:  # noqa: BLE001 - any auth failure -> unavailable, never fake
            return EvalResult(
                self.name, False, note=f"DVWA login/DB-setup failed: {exc}; see docker_setup"
            )
        target = Target(
            name="dvwa",
            platform=Platform.SELF,
            safe_harbor_url="https://github.com/digininja/DVWA",
            in_scope=["localhost", "127.0.0.1"],
            dry_run=False,
            auth=TargetAuth(login=self._login_spec()),
        )
        m, ms, rows = grade(self._cases(cookie), Validator(config), target)
        return EvalResult(self.name, True, m, ms, rows)
