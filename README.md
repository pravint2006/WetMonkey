# wetmonkey V0

Network-anomaly attack simulator.

This toolkit bundles 17 discrete attack modules (port scanning, DDoS, SQLi, etc.) under one unified CLI similar to **ALHacking**.

> ⚠️  FOR LAB USE ONLY – running these scripts on networks you do not own or have explicit permission to test is illegal.

## Quick start (Debian / Ubuntu / Termux)
```bash
git clone <repo-url> wetmonkey
cd wetmonkey
bash install.sh      # installs OS + Python deps
./attack.sh list     # view available modules
./attack.sh run portscan -t 10.0.0.5 --ports 1-1024
```

## Directory layout
```
wetmonkey/
├─ attack.sh          # main dispatcher
├─ install.sh         # install dependencies
├─ core/              # shared helpers
│   ├─ utils.sh
│   └─ utils.py
├─ modules/           # one sub-folder per attack module
│   └─ portscan/      # sample module (nmap wrapper)
│       └─ run.sh
├─ requirements.txt   # Python libs (Scapy, etc.)
└─ LICENCE
```

## Roadmap
1. Implement and test remaining 16 modules.
2. Add Dockerfile for containerized use.
3. CI pipeline with integration self-tests.

---
© 2025 – released under MIT licence (see `LICENCE`).
