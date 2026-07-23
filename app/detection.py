"""Signature-based intrusion detection for the honeypot.

Pure functions only — no I/O, no framework imports — so the engine is unit
testable in isolation and reusable from any surface (Flask, tests, a CLI).

The design goal is *defensive*: every request that reaches the honeypot is
inspected the instant it arrives, classified against a library of attack
signatures, and scored 0-100. Nothing here reaches out to any external
system; the engine only reads the request that was already sent to us.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple
from urllib.parse import unquote_plus


class Category:
    """Attack categories the engine can recognise."""

    SQLI = "sql-injection"
    XSS = "xss"
    TRAVERSAL = "path-traversal"
    RCE = "command-injection"
    LOG4SHELL = "log4shell"
    WEBSHELL = "webshell"
    SSTI = "template-injection"
    CREDENTIAL = "credential-access"
    SCANNER = "recon-scanner"


# Per-category weight added to the threat score when a signature matches.
_WEIGHTS: Dict[str, int] = {
    Category.RCE: 50,
    Category.LOG4SHELL: 50,
    Category.WEBSHELL: 45,
    Category.SQLI: 40,
    Category.TRAVERSAL: 35,
    Category.CREDENTIAL: 30,
    Category.SSTI: 30,
    Category.XSS: 25,
    Category.SCANNER: 20,
}

# (category, compiled-pattern) pairs. Patterns are intentionally broad — a
# honeypot has no legitimate traffic to protect, so false positives are cheap
# and completeness matters more than precision.
_SIGNATURES: List[Tuple[str, "re.Pattern[str]"]] = [
    (Category.SQLI, re.compile(
        r"(?i)(\bunion\b[\s\S]+\bselect\b|\bor\b\s+1\s*=\s*1|'\s*or\s*'|"
        r"';?\s*--|/\*.*\*/|\bsleep\s*\(|\bbenchmark\s*\(|waitfor\s+delay|"
        r"information_schema|\bxp_cmdshell\b|\bpg_sleep\s*\()")),
    (Category.XSS, re.compile(
        r"(?i)(<script\b|</script>|onerror\s*=|onload\s*=|javascript:|"
        r"<svg[^>]*onload|<img[^>]+onerror|document\.cookie|alert\s*\()")),
    (Category.TRAVERSAL, re.compile(
        r"(?i)(\.\./|\.\.\\|%2e%2e[%/\\]|/etc/passwd|/proc/self/environ|"
        r"\bboot\.ini\b|\bwin\.ini\b|file://)")),
    (Category.RCE, re.compile(
        r"(?i)([;|`]|\$\(|&&|\|\|)\s*(cat|ls|id|whoami|uname|wget|curl|nc\b|"
        r"ncat|bash|/bin/sh|powershell|certutil|ping\s+-c)\b")),
    (Category.LOG4SHELL, re.compile(
        r"(?i)\$\{\s*jndi\s*:\s*(ldap|ldaps|rmi|dns|iiop)\s*:")),
    (Category.WEBSHELL, re.compile(
        r"(?i)(eval\s*\(|base64_decode\s*\(|system\s*\(|passthru\s*\(|"
        r"shell_exec\s*\(|proc_open\s*\(|assert\s*\(\s*\$)")),
    (Category.SSTI, re.compile(
        r"(\{\{.*?\}\}|\$\{.*?\}|<%=.*?%>|#\{.*?\})")),
    (Category.CREDENTIAL, re.compile(
        r"(?i)(/\.env\b|/\.git/|/\.aws/|/\.ssh/|id_rsa\b|wp-config\.php|"
        r"config\.php\b|/\.htpasswd\b|credentials\b|/\.npmrc\b)")),
    (Category.SCANNER, re.compile(
        r"(?i)(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|acunetix|"
        r"nuclei|zgrab|nessus|whatweb|/wp-login\.php|/phpmyadmin|/xmlrpc\.php|"
        r"/vendor/phpunit|/actuator/|/solr/|/cgi-bin/)")),
]

# User-Agent fragments that only ever belong to automated tooling.
_SCANNER_AGENTS = re.compile(
    r"(?i)(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|acunetix|"
    r"nuclei|zgrab|nessus|whatweb|python-requests|go-http-client|libwww-perl|"
    r"curl/|wget/)")


@dataclass
class Detection:
    """Outcome of analysing a single request."""

    score: int = 0
    categories: List[str] = field(default_factory=list)
    matches: Dict[str, str] = field(default_factory=dict)

    @property
    def is_malicious(self) -> bool:
        return self.score > 0

    @property
    def severity(self) -> str:
        if self.score >= 80:
            return "critical"
        if self.score >= 50:
            return "high"
        if self.score >= 25:
            return "medium"
        if self.score > 0:
            return "low"
        return "none"


def expand(value: str, rounds: int = 2) -> str:
    """Return ``value`` plus its percent-decoded forms, joined by spaces.

    Attackers URL-encode (sometimes double-encode) payloads to slip past naive
    matchers, so the engine scans the raw string alongside up to ``rounds`` of
    decoding. Only distinct forms are appended.
    """
    if not value:
        return ""
    forms = [value]
    current = value
    for _ in range(rounds):
        decoded = unquote_plus(current)
        if decoded == current:
            break
        forms.append(decoded)
        current = decoded
    return " ".join(forms)


def analyze(
    method: str = "",
    path: str = "",
    query: str = "",
    body: str = "",
    user_agent: str = "",
) -> Detection:
    """Classify one request against the signature library.

    Returns a :class:`Detection` whose ``score`` is the sum of matched
    category weights, capped at 100. Order-independent and side-effect free.
    Path/query/body are decode-normalised so encoded payloads still match.
    """

    haystack = " ".join(
        expand(part) for part in (path, query, body) if part
    )
    detection = Detection()
    seen = set()

    for category, pattern in _SIGNATURES:
        match = pattern.search(haystack)
        if match and category not in seen:
            seen.add(category)
            detection.categories.append(category)
            detection.matches[category] = match.group(0)[:120]
            detection.score += _WEIGHTS[category]

    if user_agent:
        agent_match = _SCANNER_AGENTS.search(user_agent)
        if agent_match and Category.SCANNER not in seen:
            seen.add(Category.SCANNER)
            detection.categories.append(Category.SCANNER)
            detection.matches[Category.SCANNER] = agent_match.group(0)[:120]
            detection.score += _WEIGHTS[Category.SCANNER]

    detection.score = min(detection.score, 100)
    return detection
