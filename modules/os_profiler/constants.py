"""
modules/os_profiler/constants.py
Constants and structural indicator sets for OS detection.
"""

import re

# ── Structural indicator sets ─────────────────────────────────────────────────

KALI_METAPACKAGES = {
    "kali-linux-core", "kali-linux-default", "kali-linux-full",
    "kali-linux-everything", "kali-linux-headless", "kali-linux-nethunter",
    "kali-menu", "kali-desktop-xfce", "kali-themes",
}

BLACKARCH_GROUPS_RE = re.compile(
    r"^(blackarch|blackarch-exploitation|blackarch-recon|"
    r"blackarch-anti-forensic|blackarch-wireless|blackarch-crypto|"
    r"blackarch-scanner|blackarch-forensic)$",
    re.IGNORECASE,
)

KALI_REPO_RE    = re.compile(r"kali\.org",          re.IGNORECASE)
KALI_GPG_RE     = re.compile(r"ED444FF07D8D0BF6",   re.IGNORECASE)
TAILS_CMDLINE_MARKER = "module=Tails"


# Shell history files to scan
HISTORY_FILES = [
    "root/.bash_history",
    "root/.zsh_history",
    "root/.sh_history",
    "home/*/.bash_history",
    "home/*/.zsh_history",
]

# Offensive tool patterns to look for in shell history
OFFENSIVE_HISTORY_RE = re.compile(
    r"\b(nmap|msfconsole|msfvenom|hydra|hashcat|john|aircrack|sqlmap|"
    r"gobuster|nikto|dirb|ffuf|netcat|nc\s+-[lvp]|tcpdump|tshark|"
    r"responder|ettercap|proxychains|torsocks|setoolkit|beef|burpsuite|"
    r"crackmapexec|impacket|wifite|reaver|bettercap)\b",
    re.IGNORECASE,
)

# SSH-related paths indicating lateral movement preparation
SSH_ARTEFACT_PATHS = [
    "root/.ssh/known_hosts",
    "root/.ssh/authorized_keys",
    "root/.ssh/id_rsa",
    "root/.ssh/id_ed25519",
    "root/.ssh/config",
]

# Persistence mechanism paths
CRON_PATHS = [
    "etc/cron.d",
    "etc/cron.daily",
    "etc/cron.hourly",
    "etc/crontab",
    "var/spool/cron/crontabs",
    "var/spool/cron/root",
]

# /etc/hosts modification pattern (C2 infrastructure)
SUSPICIOUS_HOSTS_RE = re.compile(
    r"^\s*(?!127\.|0\.0\.0\.0|::1|#)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\S+",
    re.MULTILINE,
)
