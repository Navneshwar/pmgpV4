from pathlib import Path

_STATE_FILE = Path("remote_results/latest.json")
_POLL_INTERVAL = 2

RISK_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}
RISK_GRADIENTS = {
    "CRITICAL": "linear-gradient(135deg,#7f1d1d,#dc2626)",
    "HIGH":     "linear-gradient(135deg,#7c2d12,#ea580c)",
    "MEDIUM":   "linear-gradient(135deg,#713f12,#ca8a04)",
    "LOW":      "linear-gradient(135deg,#14532d,#16a34a)",
    "INFO":     "linear-gradient(135deg,#1e3a5f,#2563eb)",
}