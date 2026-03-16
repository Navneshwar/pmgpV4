"""
live_analyzer/signatures.py
All static threat-intelligence constants:
environment-variable watchlists, cmdline/map regex patterns,
offensive tool name sets, and suspicious port sets.
"""

import re

# ── Suspicious environment variable watchlist ─────────────────────────────────

SUSPICIOUS_ENV_VARS: dict[str, str] = {
    "LD_PRELOAD":            "Shared library injection – may hijack execution flow",
    "LD_LIBRARY_PATH":       "Custom library path – may redirect to malicious libraries",
    "LD_AUDIT":              "Library audit hook – used for stealthy function interception",
    "LD_DEBUG":              "Dynamic linker debug output – may indicate reconnaissance",
    "DYLD_INSERT_LIBRARIES": "macOS library injection equivalent (unusual on Linux)",
    "PYTHONPATH":            "Python module path override",
    "RUBYLIB":               "Ruby library path override",
    "PERL5LIB":              "Perl library path override",
}

# Environment variables that may carry an attacker's IP address
ATTACKER_IP_VARS: set[str] = {
    "SSH_CONNECTION",
    "SSH_CLIENT",
    "REMOTE_ADDR",
    "HTTP_X_FORWARDED_FOR",
}

# ── PATH component patterns ───────────────────────────────────────────────────

SUSPICIOUS_PATH_PATTERNS: list[re.Pattern] = [
    re.compile(r"/tmp/",     re.IGNORECASE),
    re.compile(r"/dev/shm/", re.IGNORECASE),
    re.compile(r"/var/tmp/", re.IGNORECASE),
    re.compile(r"\.\./",     re.IGNORECASE),
]

# ── Cmdline patterns → (regex, MITRE technique, category, human note) ─────────

SUSPICIOUS_CMDLINE_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (re.compile(r"\bnmap\b",             re.IGNORECASE), "T1046",     "Discovery",            "nmap detected in process cmdline"),
    (re.compile(r"\bmsfconsole\b",       re.IGNORECASE), "T1210",     "Exploitation",         "Metasploit console running"),
    (re.compile(r"\bmsfvenom\b",         re.IGNORECASE), "T1587.001", "Resource Development", "msfvenom payload generator running"),
    (re.compile(r"\bhydra\b",            re.IGNORECASE), "T1110.001", "Credential Access",    "Hydra brute-forcer running"),
    (re.compile(r"\bhashcat\b",          re.IGNORECASE), "T1110.002", "Credential Access",    "Hashcat password cracker running"),
    (re.compile(r"\bjohn\b",             re.IGNORECASE), "T1110.002", "Credential Access",    "John the Ripper running"),
    (re.compile(r"\baircrack",           re.IGNORECASE), "T1110",     "Credential Access",    "Aircrack-ng wireless cracker running"),
    (re.compile(r"\btcpdump\b",          re.IGNORECASE), "T1040",     "Collection",           "tcpdump packet capture running"),
    (re.compile(r"\bwireshark\b",        re.IGNORECASE), "T1040",     "Collection",           "Wireshark packet capture running"),
    (re.compile(r"\bnetcat\b|\bnc\b",    re.IGNORECASE), "T1059",     "Execution",            "Netcat running"),
    (re.compile(r"\bsqlmap\b",           re.IGNORECASE), "T1190",     "Exploitation",         "SQLmap injection tool running"),
    (re.compile(r"\btorsocks\b|\btor\b", re.IGNORECASE), "T1090.003", "Command and Control",  "Tor anonymizer running"),
    (re.compile(r"\bproxychains",        re.IGNORECASE), "T1090",     "Command and Control",  "Proxychains proxy chainer running"),
    (re.compile(r"\bburpsuite\b",        re.IGNORECASE), "T1190",     "Exploitation",         "Burp Suite proxy running"),
    (re.compile(r"\bgobuster\b",         re.IGNORECASE), "T1595.003", "Reconnaissance",       "Gobuster directory scanner running"),
    (re.compile(r"\bnikto\b",            re.IGNORECASE), "T1595",     "Reconnaissance",       "Nikto web scanner running"),
    (re.compile(r"\bresponder\b",        re.IGNORECASE), "T1557.001", "Collection",           "Responder LLMNR poisoner running"),
    (re.compile(r"\bettercap\b",         re.IGNORECASE), "T1557",     "Collection",           "Ettercap MitM tool running"),
    (re.compile(r"\bimpacket\b",         re.IGNORECASE), "T1550",     "Lateral Movement",     "Impacket toolkit running"),
]

# ── Memory-map path patterns ──────────────────────────────────────────────────

SUSPICIOUS_MAP_PATTERNS: list[re.Pattern] = [
    re.compile(r"/tmp/",         re.IGNORECASE),
    re.compile(r"/dev/shm/",     re.IGNORECASE),
    re.compile(r"\.so\b.*deleted", re.IGNORECASE),  # deleted shared libs – rootkit indicator
]

# ── Offensive tool comm-names (used for network cross-referencing) ────────────

OFFENSIVE_COMM_NAMES: set[str] = {
    "nmap", "msfconsole", "msfvenom", "hydra", "hashcat", "john", "aircrack-ng",
    "tcpdump", "tshark", "nc", "netcat", "ncat", "sqlmap", "tor", "proxychains",
    "proxychains4", "gobuster", "nikto", "dirb", "ffuf", "responder", "ettercap",
    "wifite", "reaver", "bettercap", "crackmapexec", "impacket",
}

# ── Suspicious ports (C2 / reverse-shell defaults) ────────────────────────────

SUSPICIOUS_PORTS: set[int] = {
    4444, 4445, 4446,           # default Metasploit reverse shells
    1234, 5555, 6666, 7777, 8888, 9999,  # common reverse shell ports
    31337,                      # classic "elite" port
    12345, 54321,
}

# ── TCP state decode table ────────────────────────────────────────────────────

TCP_STATES: dict[str, str] = {
    "01": "ESTABLISHED", "02": "SYN_SENT",  "03": "SYN_RECV",
    "04": "FIN_WAIT1",   "05": "FIN_WAIT2", "06": "TIME_WAIT",
    "07": "CLOSE",       "08": "CLOSE_WAIT","09": "LAST_ACK",
    "0A": "LISTEN",      "0B": "CLOSING",
}