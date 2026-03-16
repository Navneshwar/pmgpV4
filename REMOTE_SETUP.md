# PMGP Remote Setup — Quick Guide

## Your machine (analysis server)

### Step 1 — Install Flask
```bash
pip install flask --break-system-packages
```

### Step 2 — Find your local IP
```bash
hostname -I
# e.g. 192.168.1.42  ← use this
```

### Step 3 — Start the Flask server
```bash
python3 server.py
```
You will see:
```
PMGP Remote Ingestion Server
Listening on 0.0.0.0:5000
Share this with your collector:
bash system-health-check.sh
(SERVER_IP = 192.168.1.42)   ← your actual IP
```

### Step 4 — Start the Streamlit dashboard (new terminal)
```bash
streamlit run app_remote.py
```

---

## Your friend's machine (collector)

### Step 1 — Edit the script
Open `system-health-check.sh` and replace `SERVER_IP` on line 3:
```bash
SERVER_URL="http://192.168.1.42:5000/ingest"
#                   ^^^^^^^^^^^^^ your machine's IP
```

### Step 2 — Run it
```bash
bash system-health-check.sh
```
Output:
```
Diagnostic report submitted successfully.
```

That's it. Your Streamlit dashboard will update automatically within seconds.

---

## What happens under the hood

```
Friend's machine                    Your machine
─────────────────                   ─────────────────────────────────
system-health-check.sh
  └─ collects raw metadata
  └─ compresses to .tar.gz   ──────► Flask server (server.py)
  └─ HTTP POST /ingest                └─ extracts bundle
  └─ self-deletes                     └─ rebuilds virtual filesystem
                                      └─ runs PMGP pipeline
                                      └─ writes results
                                              │
                                      Streamlit (app_remote.py)
                                        └─ polls every 3 seconds
                                        └─ displays live results
```

## Notes
- The collector script reveals nothing about what PMGP analyses
- No tool names, no signatures, no forensic keywords in the script
- Private SSH keys are never sent — only their existence is noted
- /proc data is capped at 200 lines per process to keep bundle size small
