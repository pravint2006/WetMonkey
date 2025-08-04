# WetMonkey: Network Anomaly Attack Simulator

WetMonkey is a powerful and versatile network-anomaly attack simulator designed for penetration testing, security research, and educational purposes. It bundles 17 discrete attack modules under a unified, interactive command-line interface.

> ⚠️ **FOR LAB USE ONLY** – Running these scripts on networks you do not own or have explicit permission to test is illegal. The authors are not responsible for any misuse of this tool.

## Features

- **Unified CLI**: A central `attack.sh` script provides an easy-to-use, interactive menu to access all modules.
- **17 Attack Modules**: A comprehensive suite of tools for various network attack simulations.
- **Easy Installation**: A simple `install.sh` script to set up all necessary dependencies.
- **Modular Design**: Each attack module is self-contained, making it easy to extend and maintain.

## Usage

You can run WetMonkey in several ways:

### Interactive Mode

For a guided experience, run the main script without any arguments. This will launch an interactive menu where you can select and configure modules.

```bash
./attack.sh
```

### Direct Command

You can also run modules directly from the command line.

```bash
# List all available modules
./attack.sh list

# Run a specific module with its options
./attack.sh run portscan

# Get help for a specific module
./attack.sh run portscan -h
```

## Quick Start

Follow these steps to get WetMonkey up and running on a Debian-based system (like Kali, Ubuntu, or Termux).

```bash
# 1. Clone the repository
git clone https://github.com/pravint2006/WetMonkey.git
cd WetMonkey

# 2. Install dependencies
bash install.sh

# 3. Run the interactive toolkit
./attack.sh
```

## Available Modules

WetMonkey includes the following 17 attack modules:

1.  `bruteforce`: Perform brute-force attacks on various services (SSH, FTP, HTTP, etc.).
2.  `dataexfiltration`: Simulate data exfiltration using methods like HTTP POST and DNS tunneling.
3.  `ddos`: Simulate various DDoS attacks (HTTP flood, SYN flood, UDP flood, etc.).
4.  `dnstunnel`: Detect DNS tunneling activities.
5.  `dnszonetransfer`: Attempt DNS zone transfers to gather domain information.
6.  `exploitation`: Test for common web vulnerabilities like SQLi, XSS, and command injection.
7.  `geoipanomaly`: Detect geographic anomalies in IP addresses.
8.  `httpheaderabuse`: Test for vulnerabilities related to HTTP header manipulation.
9.  `malwarebeacon`: Simulate malware beaconing to a C2 server.
10. `malwaredrop`: Simulate malware dropper activities.
11. `osfingerprint`: Perform OS fingerprinting to identify the target's operating system.
12. `packetcraft`: Craft custom network packets for analysis and testing.
13. `portscan`: Scan for open ports on a target host.
14. `torproxy`: Test Tor connectivity and anonymity.
15. `unknownproto`: Analyze unknown protocols on open ports.
16. `urlobfuscation`: Test URL obfuscation and evasion techniques.
17. `webrecon`: Perform web reconnaissance and enumeration.

## Directory Layout

```
wetmonkey/
├─ attack.sh          # Main dispatcher script
├─ install.sh         # Dependency installer
├─ core/              # Shared helper utilities
├─ modules/           # Contains all 17 attack modules
├─ requirements.txt   # Python dependencies
└─ LICENSE            # GPL 3.0 License
```

---
© 2025 – Released under the GPL 3.0 license (see `LICENSE`).
