#!/usr/bin/env bash
# wetmonkey packetcraft – Interactive Packet Crafting & Analysis Suite v2.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$SCRIPT_DIR/../../"
source "$BASE_DIR/core/utils.sh"

# Configuration
VERSION="2.0"
MAX_PACKETS=1000

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║    📦 WetMonkey Packet Crafting Suite   ║"
    echo "║         Interactive Mode v2.0           ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Show usage information
show_help() {
    echo "WetMonkey Packet Crafting Module v${VERSION}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  --proto <tcp|udp|icmp>  Protocol type (legacy mode)"
    echo "  -t, --target <target>   Target IP or hostname (legacy mode)"
    echo "  --sport <port>          Source port (legacy mode)"
    echo "  --dport <port>          Destination port (legacy mode)"
    echo "  --flags <flags>         TCP flags (legacy mode)"
    echo "  --craft <type>          Quick packet crafting"
    echo ""
    echo "This module provides interactive packet crafting and analysis."
    echo "Supported features: Custom packets, protocol analysis, network testing"
    echo ""
    echo "Example:"
    echo "  $0                      # Run in interactive mode"
    echo "  $0 -h                   # Show this help"
    echo "  $0 --craft tcp          # Quick TCP packet crafting"
    echo "  $0 --proto tcp -t 192.168.1.1 --dport 80  # Legacy mode"
    echo ""
    echo "Note: This tool is for authorized security testing and research only!"
    echo "      Use responsibly and only on systems you own or have permission to test."
    echo "      Some features may require root privileges for raw socket access."
}

# Simple interactive input function
simple_input() {
    local prompt="$1"
    local default="${2:-}"
    local input

    if [ -n "$default" ]; then
        echo -ne "${BLUE}$prompt [${YELLOW}$default${BLUE}]: ${NC}" >&2
    else
        echo -ne "${BLUE}$prompt: ${NC}" >&2
    fi

    read -r input
    echo "${input:-$default}"
}

# Simple yes/no function
ask_yes_no() {
    local prompt="$1"
    local default="${2:-n}"
    local response

    while true; do
        if [ "$default" = "y" ]; then
            echo -ne "${BLUE}$prompt [Y/n]: ${NC}" >&2
        else
            echo -ne "${BLUE}$prompt [y/N]: ${NC}" >&2
        fi

        read -r response
        response="${response:-$default}"

        case "$response" in
            [Yy]|[Yy][Ee][Ss]) return 0 ;;
            [Nn]|[Nn][Oo]) return 1 ;;
            *) echo -e "${RED}Please answer yes or no.${NC}" >&2 ;;
        esac
    done
}

# Function to validate IP address
validate_ip() {
    local ip="$1"
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        local IFS='.'
        local -a octets=($ip)
        for octet in "${octets[@]}"; do
            if (( octet > 255 )); then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

# Function to validate hostname
validate_hostname() {
    local hostname="$1"
    if [[ $hostname =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        return 0
    fi
    return 1
}

# Function to validate target (IP or hostname)
validate_target() {
    local target="$1"
    if validate_ip "$target" || validate_hostname "$target"; then
        return 0
    fi
    return 1
}

# Function to validate port
validate_port() {
    local port="$1"
    if [[ $port =~ ^[0-9]+$ ]] && [ $port -ge 1 ] && [ $port -le 65535 ]; then
        return 0
    fi
    return 1
}

# Function to check if target is reachable
check_target_reachable() {
    local target="$1"
    echo -e "${YELLOW}Testing connectivity to $target...${NC}" >&2

    if ping -c 1 -W 3 "$target" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Target is reachable${NC}" >&2
        return 0
    else
        echo -e "${YELLOW}⚠ Target may not be reachable (continuing anyway)${NC}" >&2
        return 0  # Don't fail, just warn
    fi
}

# Function to craft TCP packets using multiple methods
craft_tcp_packet() {
    local target="$1"
    local sport="$2"
    local dport="$3"
    local flags="$4"
    local count="${5:-1}"

    echo -e "\n${GREEN}📦 Crafting TCP packets...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Target: $target${NC}"
    echo -e "${YELLOW}Source Port: $sport${NC}"
    echo -e "${YELLOW}Destination Port: $dport${NC}"
    echo -e "${YELLOW}TCP Flags: $flags${NC}"
    echo -e "${YELLOW}Packet Count: $count${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    local method_used=""
    local success=false

    # Method 1: Try scapy (most flexible)
    if command -v python3 >/dev/null 2>&1; then
        echo -e "${CYAN}Attempting to use scapy for packet crafting...${NC}"

        local scapy_script=$(cat << EOF
import sys
try:
    from scapy.all import *
    import socket

    target = "$target"
    sport = int("$sport")
    dport = int("$dport")
    flags = "$flags"
    count = int("$count")

    print(f"Creating TCP packet: {target}:{dport} <- :{sport} [{flags}]")

    # Convert flags string to scapy format
    flag_map = {
        'SYN': 'S', 'ACK': 'A', 'FIN': 'F', 'RST': 'R',
        'PSH': 'P', 'URG': 'U', 'ECE': 'E', 'CWR': 'C'
    }

    scapy_flags = ""
    for flag in flags.split(','):
        flag = flag.strip().upper()
        if flag in flag_map:
            scapy_flags += flag_map[flag]

    if not scapy_flags:
        scapy_flags = "S"  # Default to SYN

    # Create and send packets
    for i in range(count):
        pkt = IP(dst=target)/TCP(sport=sport, dport=dport, flags=scapy_flags)
        try:
            send(pkt, verbose=False)
            print(f"✓ Packet {i+1}/{count} sent successfully")
        except Exception as e:
            print(f"✗ Packet {i+1}/{count} failed: {e}")

    print("TCP packet crafting completed using scapy")
    sys.exit(0)

except ImportError:
    print("scapy not available")
    sys.exit(1)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
EOF
)

        if echo "$scapy_script" | python3 2>/dev/null; then
            method_used="scapy"
            success=true
            echo -e "${GREEN}✓ TCP packets sent successfully using scapy${NC}"
        else
            echo -e "${YELLOW}⚠ scapy method failed or not available${NC}"
        fi
    fi

    # Method 2: Try hping3 (if scapy failed)
    if [ "$success" = false ] && command -v hping3 >/dev/null 2>&1; then
        echo -e "${CYAN}Attempting to use hping3 for packet crafting...${NC}"

        # Convert flags to hping3 format
        local hping_flags=""
        if [[ $flags == *"SYN"* ]]; then hping_flags="$hping_flags -S"; fi
        if [[ $flags == *"ACK"* ]]; then hping_flags="$hping_flags -A"; fi
        if [[ $flags == *"FIN"* ]]; then hping_flags="$hping_flags -F"; fi
        if [[ $flags == *"RST"* ]]; then hping_flags="$hping_flags -R"; fi
        if [[ $flags == *"PSH"* ]]; then hping_flags="$hping_flags -P"; fi
        if [[ $flags == *"URG"* ]]; then hping_flags="$hping_flags -U"; fi

        # Default to SYN if no flags specified
        if [ -z "$hping_flags" ]; then
            hping_flags="-S"
        fi

        echo -e "${BLUE}hping3 command: hping3 $hping_flags -s $sport -p $dport -c $count $target${NC}"

        if hping3 $hping_flags -s "$sport" -p "$dport" -c "$count" "$target" 2>/dev/null; then
            method_used="hping3"
            success=true
            echo -e "${GREEN}✓ TCP packets sent successfully using hping3${NC}"
        else
            echo -e "${YELLOW}⚠ hping3 method failed${NC}"
        fi
    fi

    # Method 3: Try nmap (limited functionality)
    if [ "$success" = false ] && command -v nmap >/dev/null 2>&1; then
        echo -e "${CYAN}Attempting to use nmap for TCP packet simulation...${NC}"

        local nmap_flags=""
        if [[ $flags == *"SYN"* ]]; then
            nmap_flags="-sS"  # SYN scan
        elif [[ $flags == *"ACK"* ]]; then
            nmap_flags="-sA"  # ACK scan
        elif [[ $flags == *"FIN"* ]]; then
            nmap_flags="-sF"  # FIN scan
        else
            nmap_flags="-sS"  # Default to SYN
        fi

        echo -e "${BLUE}nmap command: nmap $nmap_flags -p $dport --source-port $sport $target${NC}"

        if nmap $nmap_flags -p "$dport" --source-port "$sport" "$target" >/dev/null 2>&1; then
            method_used="nmap"
            success=true
            echo -e "${GREEN}✓ TCP packets sent successfully using nmap${NC}"
        else
            echo -e "${YELLOW}⚠ nmap method failed${NC}"
        fi
    fi

    # Method 4: Manual netcat approach (very limited)
    if [ "$success" = false ] && command -v nc >/dev/null 2>&1; then
        echo -e "${CYAN}Attempting basic TCP connection using netcat...${NC}"

        if [[ $flags == *"SYN"* ]] || [ -z "$flags" ]; then
            echo -e "${BLUE}netcat command: timeout 3 nc -w 1 $target $dport${NC}"

            for ((i=1; i<=count; i++)); do
                if timeout 3 nc -w 1 "$target" "$dport" </dev/null >/dev/null 2>&1; then
                    echo -e "${GREEN}✓ Connection attempt $i/$count completed${NC}"
                else
                    echo -e "${YELLOW}⚠ Connection attempt $i/$count failed or filtered${NC}"
                fi
            done

            method_used="netcat"
            success=true
            echo -e "${GREEN}✓ TCP connection attempts completed using netcat${NC}"
        else
            echo -e "${YELLOW}⚠ netcat only supports basic SYN connections${NC}"
        fi
    fi

    # Summary
    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}📊 TCP Packet Crafting Summary${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Target: $target:$dport${NC}"
    echo -e "${CYAN}Source Port: $sport${NC}"
    echo -e "${CYAN}TCP Flags: $flags${NC}"
    echo -e "${CYAN}Packet Count: $count${NC}"
    echo -e "${CYAN}Method Used: $method_used${NC}"
    echo -e "${CYAN}Success: $([ "$success" = true ] && echo "Yes" || echo "No")${NC}"

    if [ "$success" = true ]; then
        echo -e "\n${YELLOW}Detection Indicators:${NC}"
        echo -e "• TCP connections to target port $dport"
        echo -e "• Source port $sport in network logs"
        echo -e "• TCP flags: $flags in packet analysis"
        echo -e "• Multiple packets if count > 1"

        echo -e "\n${YELLOW}Recommended Monitoring:${NC}"
        echo -e "• Monitor for unusual TCP flag combinations"
        echo -e "• Track connection attempts to sensitive ports"
        echo -e "• Analyze packet timing and patterns"
        echo -e "• Look for port scanning behavior"
    else
        echo -e "\n${RED}❌ ALL METHODS FAILED${NC}"
        echo -e "${YELLOW}Possible reasons:${NC}"
        echo -e "• No suitable packet crafting tools available"
        echo -e "• Insufficient privileges for raw socket access"
        echo -e "• Network filtering blocking packets"
        echo -e "• Target unreachable or protected"

        echo -e "\n${YELLOW}Required tools (install one or more):${NC}"
        echo -e "• python3 with scapy: pip3 install scapy"
        echo -e "• hping3: apt-get install hping3"
        echo -e "• nmap: apt-get install nmap"
        echo -e "• netcat: apt-get install netcat"
    fi

    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    return $([ "$success" = true ] && echo 0 || echo 1)
}

# Function to craft UDP packets
craft_udp_packet() {
    local target="$1"
    local sport="$2"
    local dport="$3"
    local payload="${4:-}"
    local count="${5:-1}"

    echo -e "\n${GREEN}📦 Crafting UDP packets...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Target: $target${NC}"
    echo -e "${YELLOW}Source Port: $sport${NC}"
    echo -e "${YELLOW}Destination Port: $dport${NC}"
    echo -e "${YELLOW}Payload: ${payload:-"(empty)"}${NC}"
    echo -e "${YELLOW}Packet Count: $count${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    local method_used=""
    local success=false

    # Method 1: Try scapy
    if command -v python3 >/dev/null 2>&1; then
        echo -e "${CYAN}Attempting to use scapy for UDP packet crafting...${NC}"

        local scapy_script=$(cat << EOF
import sys
try:
    from scapy.all import *

    target = "$target"
    sport = int("$sport")
    dport = int("$dport")
    payload = "$payload"
    count = int("$count")

    print(f"Creating UDP packet: {target}:{dport} <- :{sport}")
    if payload:
        print(f"Payload: {payload}")

    # Create and send packets
    for i in range(count):
        if payload:
            pkt = IP(dst=target)/UDP(sport=sport, dport=dport)/Raw(load=payload)
        else:
            pkt = IP(dst=target)/UDP(sport=sport, dport=dport)

        try:
            send(pkt, verbose=False)
            print(f"✓ UDP packet {i+1}/{count} sent successfully")
        except Exception as e:
            print(f"✗ UDP packet {i+1}/{count} failed: {e}")

    print("UDP packet crafting completed using scapy")
    sys.exit(0)

except ImportError:
    print("scapy not available")
    sys.exit(1)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
EOF
)

        if echo "$scapy_script" | python3 2>/dev/null; then
            method_used="scapy"
            success=true
            echo -e "${GREEN}✓ UDP packets sent successfully using scapy${NC}"
        else
            echo -e "${YELLOW}⚠ scapy method failed or not available${NC}"
        fi
    fi

    # Method 2: Try hping3
    if [ "$success" = false ] && command -v hping3 >/dev/null 2>&1; then
        echo -e "${CYAN}Attempting to use hping3 for UDP packet crafting...${NC}"

        local hping_cmd="hping3 --udp -s $sport -p $dport -c $count"
        if [ -n "$payload" ]; then
            hping_cmd="$hping_cmd -d ${#payload} -E $payload"
        fi
        hping_cmd="$hping_cmd $target"

        echo -e "${BLUE}hping3 command: $hping_cmd${NC}"

        if eval "$hping_cmd" 2>/dev/null; then
            method_used="hping3"
            success=true
            echo -e "${GREEN}✓ UDP packets sent successfully using hping3${NC}"
        else
            echo -e "${YELLOW}⚠ hping3 method failed${NC}"
        fi
    fi

    # Method 3: Try nmap UDP scan
    if [ "$success" = false ] && command -v nmap >/dev/null 2>&1; then
        echo -e "${CYAN}Attempting to use nmap for UDP packet simulation...${NC}"

        echo -e "${BLUE}nmap command: nmap -sU -p $dport --source-port $sport $target${NC}"

        if nmap -sU -p "$dport" --source-port "$sport" "$target" >/dev/null 2>&1; then
            method_used="nmap"
            success=true
            echo -e "${GREEN}✓ UDP packets sent successfully using nmap${NC}"
        else
            echo -e "${YELLOW}⚠ nmap method failed${NC}"
        fi
    fi

    # Method 4: Try netcat UDP
    if [ "$success" = false ] && command -v nc >/dev/null 2>&1; then
        echo -e "${CYAN}Attempting UDP packet sending using netcat...${NC}"

        for ((i=1; i<=count; i++)); do
            if [ -n "$payload" ]; then
                echo -e "${BLUE}Sending UDP packet $i/$count with payload${NC}"
                if echo "$payload" | timeout 3 nc -u -w 1 "$target" "$dport" 2>/dev/null; then
                    echo -e "${GREEN}✓ UDP packet $i/$count sent${NC}"
                else
                    echo -e "${YELLOW}⚠ UDP packet $i/$count may have been sent${NC}"
                fi
            else
                echo -e "${BLUE}Sending empty UDP packet $i/$count${NC}"
                if echo "" | timeout 3 nc -u -w 1 "$target" "$dport" 2>/dev/null; then
                    echo -e "${GREEN}✓ UDP packet $i/$count sent${NC}"
                else
                    echo -e "${YELLOW}⚠ UDP packet $i/$count may have been sent${NC}"
                fi
            fi
        done

        method_used="netcat"
        success=true
        echo -e "${GREEN}✓ UDP packets sent using netcat${NC}"
    fi

    # Summary
    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}📊 UDP Packet Crafting Summary${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Target: $target:$dport${NC}"
    echo -e "${CYAN}Source Port: $sport${NC}"
    echo -e "${CYAN}Payload: ${payload:-"(empty)"}${NC}"
    echo -e "${CYAN}Packet Count: $count${NC}"
    echo -e "${CYAN}Method Used: $method_used${NC}"
    echo -e "${CYAN}Success: $([ "$success" = true ] && echo "Yes" || echo "No")${NC}"

    if [ "$success" = true ]; then
        echo -e "\n${YELLOW}Detection Indicators:${NC}"
        echo -e "• UDP packets to target port $dport"
        echo -e "• Source port $sport in network logs"
        echo -e "• Custom payload if specified"
        echo -e "• Multiple packets if count > 1"

        echo -e "\n${YELLOW}Recommended Monitoring:${NC}"
        echo -e "• Monitor UDP traffic to sensitive ports"
        echo -e "• Analyze payload content for anomalies"
        echo -e "• Track unusual UDP communication patterns"
        echo -e "• Look for UDP flooding behavior"
    else
        echo -e "\n${RED}❌ ALL METHODS FAILED${NC}"
        echo -e "${YELLOW}Install packet crafting tools for better functionality${NC}"
    fi

    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    return $([ "$success" = true ] && echo 0 || echo 1)
}

# Function to craft ICMP packets
craft_icmp_packet() {
    local target="$1"
    local icmp_type="${2:-8}"  # Default to echo request
    local icmp_code="${3:-0}"
    local payload="${4:-}"
    local count="${5:-1}"

    echo -e "\n${GREEN}📦 Crafting ICMP packets...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Target: $target${NC}"
    echo -e "${YELLOW}ICMP Type: $icmp_type${NC}"
    echo -e "${YELLOW}ICMP Code: $icmp_code${NC}"
    echo -e "${YELLOW}Payload: ${payload:-"(default)"}${NC}"
    echo -e "${YELLOW}Packet Count: $count${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    local method_used=""
    local success=false

    # Method 1: Try scapy
    if command -v python3 >/dev/null 2>&1; then
        echo -e "${CYAN}Attempting to use scapy for ICMP packet crafting...${NC}"

        local scapy_script=$(cat << EOF
import sys
try:
    from scapy.all import *

    target = "$target"
    icmp_type = int("$icmp_type")
    icmp_code = int("$icmp_code")
    payload = "$payload"
    count = int("$count")

    print(f"Creating ICMP packet: {target} (type={icmp_type}, code={icmp_code})")
    if payload:
        print(f"Payload: {payload}")

    # Create and send packets
    for i in range(count):
        if payload:
            pkt = IP(dst=target)/ICMP(type=icmp_type, code=icmp_code)/Raw(load=payload)
        else:
            pkt = IP(dst=target)/ICMP(type=icmp_type, code=icmp_code)

        try:
            send(pkt, verbose=False)
            print(f"✓ ICMP packet {i+1}/{count} sent successfully")
        except Exception as e:
            print(f"✗ ICMP packet {i+1}/{count} failed: {e}")

    print("ICMP packet crafting completed using scapy")
    sys.exit(0)

except ImportError:
    print("scapy not available")
    sys.exit(1)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
EOF
)

        if echo "$scapy_script" | python3 2>/dev/null; then
            method_used="scapy"
            success=true
            echo -e "${GREEN}✓ ICMP packets sent successfully using scapy${NC}"
        else
            echo -e "${YELLOW}⚠ scapy method failed or not available${NC}"
        fi
    fi

    # Method 2: Try hping3
    if [ "$success" = false ] && command -v hping3 >/dev/null 2>&1; then
        echo -e "${CYAN}Attempting to use hping3 for ICMP packet crafting...${NC}"

        local hping_cmd="hping3 --icmp -C $icmp_type -K $icmp_code -c $count"
        if [ -n "$payload" ]; then
            hping_cmd="$hping_cmd -d ${#payload} -E $payload"
        fi
        hping_cmd="$hping_cmd $target"

        echo -e "${BLUE}hping3 command: $hping_cmd${NC}"

        if eval "$hping_cmd" 2>/dev/null; then
            method_used="hping3"
            success=true
            echo -e "${GREEN}✓ ICMP packets sent successfully using hping3${NC}"
        else
            echo -e "${YELLOW}⚠ hping3 method failed${NC}"
        fi
    fi

    # Method 3: Try ping (limited to echo requests)
    if [ "$success" = false ] && [ "$icmp_type" = "8" ] && command -v ping >/dev/null 2>&1; then
        echo -e "${CYAN}Attempting to use ping for ICMP echo requests...${NC}"

        local ping_cmd="ping -c $count"
        if [ -n "$payload" ] && [ ${#payload} -le 65507 ]; then
            ping_cmd="$ping_cmd -s ${#payload}"
        fi
        ping_cmd="$ping_cmd $target"

        echo -e "${BLUE}ping command: $ping_cmd${NC}"

        if eval "$ping_cmd" >/dev/null 2>&1; then
            method_used="ping"
            success=true
            echo -e "${GREEN}✓ ICMP echo requests sent successfully using ping${NC}"
        else
            echo -e "${YELLOW}⚠ ping method failed${NC}"
        fi
    fi

    # Summary
    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}📊 ICMP Packet Crafting Summary${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Target: $target${NC}"
    echo -e "${CYAN}ICMP Type: $icmp_type${NC}"
    echo -e "${CYAN}ICMP Code: $icmp_code${NC}"
    echo -e "${CYAN}Payload: ${payload:-"(default)"}${NC}"
    echo -e "${CYAN}Packet Count: $count${NC}"
    echo -e "${CYAN}Method Used: $method_used${NC}"
    echo -e "${CYAN}Success: $([ "$success" = true ] && echo "Yes" || echo "No")${NC}"

    if [ "$success" = true ]; then
        echo -e "\n${YELLOW}Detection Indicators:${NC}"
        echo -e "• ICMP packets with type $icmp_type, code $icmp_code"
        echo -e "• Custom payload if specified"
        echo -e "• Multiple packets if count > 1"
        echo -e "• Unusual ICMP types/codes if not standard ping"

        echo -e "\n${YELLOW}Recommended Monitoring:${NC}"
        echo -e "• Monitor for unusual ICMP types and codes"
        echo -e "• Track ICMP packet frequency and patterns"
        echo -e "• Analyze ICMP payload content"
        echo -e "• Look for ICMP tunneling attempts"
    else
        echo -e "\n${RED}❌ ALL METHODS FAILED${NC}"
        echo -e "${YELLOW}Install packet crafting tools for better functionality${NC}"
    fi

    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    return $([ "$success" = true ] && echo 0 || echo 1)
}

# Educational information function
show_educational_info() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║         📚 Packet Crafting Guide        ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}\n"

    echo -e "${GREEN}What is Packet Crafting?${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "Packet crafting is the process of creating custom network packets with"
    echo -e "specific headers, flags, and payloads. It's used for network testing,"
    echo -e "security research, penetration testing, and protocol analysis."
    echo -e "Crafted packets can test network defenses and application responses.\n"

    echo -e "${GREEN}Common Packet Types${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}1. TCP Packets${NC}"
    echo -e "   • Connection-oriented, reliable protocol"
    echo -e "   • Flags: SYN, ACK, FIN, RST, PSH, URG"
    echo -e "   • Used for: Port scanning, connection testing, flag manipulation"
    echo -e "${YELLOW}2. UDP Packets${NC}"
    echo -e "   • Connectionless, unreliable protocol"
    echo -e "   • No connection state or acknowledgments"
    echo -e "   • Used for: Service discovery, payload delivery, flooding"
    echo -e "${YELLOW}3. ICMP Packets${NC}"
    echo -e "   • Internet Control Message Protocol"
    echo -e "   • Types: Echo (ping), Destination Unreachable, Time Exceeded"
    echo -e "   • Used for: Network diagnostics, covert channels, reconnaissance\n"

    echo -e "${GREEN}TCP Flag Combinations${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Common TCP Flags:${NC}"
    echo -e "• SYN: Synchronize, initiate connection"
    echo -e "• ACK: Acknowledge received data"
    echo -e "• FIN: Finish, close connection gracefully"
    echo -e "• RST: Reset, abort connection immediately"
    echo -e "• PSH: Push, send data immediately"
    echo -e "• URG: Urgent, prioritize data"
    echo -e "${CYAN}Special Combinations:${NC}"
    echo -e "• SYN: Connection initiation (port scanning)"
    echo -e "• SYN+ACK: Connection acknowledgment"
    echo -e "• FIN: Stealth scanning technique"
    echo -e "• RST: Connection reset/rejection"
    echo -e "• NULL (no flags): Stealth scanning"
    echo -e "• XMAS (FIN+PSH+URG): Christmas tree scan\n"

    echo -e "${GREEN}ICMP Types and Codes${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Common ICMP Types:${NC}"
    echo -e "• Type 0: Echo Reply (ping response)"
    echo -e "• Type 3: Destination Unreachable"
    echo -e "• Type 5: Redirect Message"
    echo -e "• Type 8: Echo Request (ping)"
    echo -e "• Type 11: Time Exceeded"
    echo -e "• Type 12: Parameter Problem"
    echo -e "${CYAN}Destination Unreachable Codes:${NC}"
    echo -e "• Code 0: Network Unreachable"
    echo -e "• Code 1: Host Unreachable"
    echo -e "• Code 2: Protocol Unreachable"
    echo -e "• Code 3: Port Unreachable\n"

    echo -e "${GREEN}Packet Crafting Tools${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}1. Scapy (Python):${NC}"
    echo -e "   • Most flexible and powerful"
    echo -e "   • Supports all protocols and custom fields"
    echo -e "   • Interactive and scriptable"
    echo -e "${CYAN}2. hping3:${NC}"
    echo -e "   • Command-line packet generator"
    echo -e "   • TCP, UDP, ICMP support"
    echo -e "   • Good for scripting and automation"
    echo -e "${CYAN}3. nmap:${NC}"
    echo -e "   • Limited packet crafting via scan types"
    echo -e "   • Good for standard reconnaissance"
    echo -e "   • Built-in timing and stealth options"
    echo -e "${CYAN}4. netcat:${NC}"
    echo -e "   • Basic TCP/UDP packet sending"
    echo -e "   • Simple payload delivery"
    echo -e "   • Limited customization options\n"

    echo -e "${GREEN}Security Applications${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Penetration Testing:${NC}"
    echo -e "• Port scanning with custom flags"
    echo -e "• Firewall and IDS evasion testing"
    echo -e "• Service fingerprinting and enumeration"
    echo -e "${CYAN}Network Security Testing:${NC}"
    echo -e "• DoS/DDoS simulation and testing"
    echo -e "• Protocol fuzzing and stress testing"
    echo -e "• Network device response analysis"
    echo -e "${CYAN}Research and Analysis:${NC}"
    echo -e "• Protocol behavior investigation"
    echo -e "• Network troubleshooting and diagnostics"
    echo -e "• Covert channel development and detection\n"

    echo -e "${GREEN}Detection and Defense${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}✓ Network Monitoring:${NC}"
    echo -e "  • Monitor for unusual packet patterns"
    echo -e "  • Track abnormal flag combinations"
    echo -e "  • Analyze packet timing and frequency"
    echo -e "${GREEN}✓ Intrusion Detection:${NC}"
    echo -e "  • Signature-based detection of crafted packets"
    echo -e "  • Anomaly detection for unusual traffic"
    echo -e "  • Rate limiting and connection throttling"
    echo -e "${GREEN}✓ Firewall Rules:${NC}"
    echo -e "  • Block suspicious flag combinations"
    echo -e "  • Filter unusual ICMP types and codes"
    echo -e "  • Implement stateful connection tracking"
    echo -e "${GREEN}✓ Network Segmentation:${NC}"
    echo -e "  • Isolate critical network segments"
    echo -e "  • Limit broadcast and multicast traffic"
    echo -e "  • Implement micro-segmentation\n"

    echo -e "${GREEN}Legal and Ethical Considerations${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${RED}⚠ IMPORTANT:${NC} Only craft packets against systems you own or have permission"
    echo -e "${RED}⚠ LEGAL:${NC} Unauthorized packet crafting may violate computer crime laws"
    echo -e "${RED}⚠ ETHICAL:${NC} Use packet crafting for legitimate security testing only"
    echo -e "${RED}⚠ PROFESSIONAL:${NC} Document findings and follow responsible disclosure"
    echo -e "${RED}⚠ PRIVILEGES:${NC} Raw socket access typically requires root/administrator privileges\n"
}

# Main interactive function
interactive_mode() {
    while true; do
        show_banner

        echo -e "${GREEN}Welcome to WetMonkey Packet Crafting Suite!${NC}"
        echo -e "${YELLOW}This tool helps create and send custom network packets for security testing.${NC}\n"
        echo -e "${RED}⚠ WARNING: Only test against systems you own or have permission to test!${NC}\n"

        # Step 1: Packet type selection
        echo -e "${GREEN}Step 1: Packet Type${NC}"
        echo -e "Choose the type of packet to craft:"
        echo -e "  ${YELLOW}1)${NC} TCP Packet - Transmission Control Protocol"
        echo -e "  ${YELLOW}2)${NC} UDP Packet - User Datagram Protocol"
        echo -e "  ${YELLOW}3)${NC} ICMP Packet - Internet Control Message Protocol"
        echo -e "  ${YELLOW}4)${NC} Educational Information - Learn about packet crafting"

        local packet_type
        while true; do
            choice=$(simple_input "Select packet type (1-4)")
            case "$choice" in
                "1") packet_type="tcp"; break ;;
                "2") packet_type="udp"; break ;;
                "3") packet_type="icmp"; break ;;
                "4") packet_type="educational"; break ;;
                *) echo -e "${RED}Please select a number between 1-4${NC}" ;;
            esac
        done

        case "$packet_type" in
            "educational")
                # Show educational information
                show_educational_info
                echo -e "\n${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;

            *)
                # Packet crafting
                echo -e "\n${GREEN}Step 2: Target Configuration${NC}"

                local target
                while true; do
                    target=$(simple_input "Target IP address or hostname")
                    if [ -z "$target" ]; then
                        echo -e "${RED}Target is required!${NC}"
                        continue
                    fi

                    if validate_target "$target"; then
                        break
                    else
                        echo -e "${RED}Please enter a valid IP address or hostname${NC}"
                    fi
                done

                # Check connectivity
                check_target_reachable "$target"

                # Step 3: Protocol-specific configuration
                case "$packet_type" in
                    "tcp")
                        echo -e "\n${GREEN}Step 3: TCP Configuration${NC}"

                        local sport
                        while true; do
                            sport=$(simple_input "Source port" "12345")
                            if validate_port "$sport"; then
                                break
                            else
                                echo -e "${RED}Please enter a valid port (1-65535)${NC}"
                            fi
                        done

                        local dport
                        while true; do
                            dport=$(simple_input "Destination port" "80")
                            if validate_port "$dport"; then
                                break
                            else
                                echo -e "${RED}Please enter a valid port (1-65535)${NC}"
                            fi
                        done

                        echo -e "\nTCP Flag options:"
                        echo -e "  ${YELLOW}1)${NC} SYN - Connection initiation"
                        echo -e "  ${YELLOW}2)${NC} ACK - Acknowledgment"
                        echo -e "  ${YELLOW}3)${NC} FIN - Connection termination"
                        echo -e "  ${YELLOW}4)${NC} RST - Connection reset"
                        echo -e "  ${YELLOW}5)${NC} SYN,ACK - Connection response"
                        echo -e "  ${YELLOW}6)${NC} FIN,PSH,URG - Christmas tree scan"
                        echo -e "  ${YELLOW}7)${NC} Custom - Enter custom flags"

                        local flags
                        while true; do
                            flag_choice=$(simple_input "Select TCP flags (1-7)" "1")
                            case "$flag_choice" in
                                "1") flags="SYN"; break ;;
                                "2") flags="ACK"; break ;;
                                "3") flags="FIN"; break ;;
                                "4") flags="RST"; break ;;
                                "5") flags="SYN,ACK"; break ;;
                                "6") flags="FIN,PSH,URG"; break ;;
                                "7")
                                    flags=$(simple_input "Enter custom flags (comma-separated)" "SYN")
                                    break ;;
                                *) echo -e "${RED}Please select a number between 1-7${NC}" ;;
                            esac
                        done

                        local count
                        while true; do
                            count=$(simple_input "Number of packets to send" "1")
                            if [[ $count =~ ^[0-9]+$ ]] && [ $count -ge 1 ] && [ $count -le $MAX_PACKETS ]; then
                                break
                            else
                                echo -e "${RED}Please enter a valid count (1-$MAX_PACKETS)${NC}"
                            fi
                        done

                        # Execution summary
                        echo -e "\n${GREEN}Step 4: TCP Packet Summary${NC}"
                        echo -e "${BLUE}═══════════════════════════════════════${NC}"
                        echo -e "${CYAN}Target: $target:$dport${NC}"
                        echo -e "${CYAN}Source Port: $sport${NC}"
                        echo -e "${CYAN}TCP Flags: $flags${NC}"
                        echo -e "${CYAN}Packet Count: $count${NC}"
                        echo -e "${BLUE}═══════════════════════════════════════${NC}"

                        echo -e "\n${RED}⚠ WARNING: This will send TCP packets to the target!${NC}"
                        echo -e "${RED}⚠ Only proceed if you have authorization to test this target!${NC}"

                        if ask_yes_no "Send TCP packets?" "n"; then
                            echo -e "\n${CYAN}Starting TCP packet crafting...${NC}"

                            # Log start
                            log_json "packetcraft_start" "type=tcp target=$target sport=$sport dport=$dport flags=$flags count=$count" 2>/dev/null || true

                            # Craft TCP packets
                            craft_tcp_packet "$target" "$sport" "$dport" "$flags" "$count"

                            # Log end
                            log_json "packetcraft_end" "type=tcp target=$target" 2>/dev/null || true
                        else
                            echo -e "${YELLOW}TCP packet crafting cancelled.${NC}"
                        fi
                        ;;

                    "udp")
                        echo -e "\n${GREEN}Step 3: UDP Configuration${NC}"

                        local sport
                        while true; do
                            sport=$(simple_input "Source port" "12345")
                            if validate_port "$sport"; then
                                break
                            else
                                echo -e "${RED}Please enter a valid port (1-65535)${NC}"
                            fi
                        done

                        local dport
                        while true; do
                            dport=$(simple_input "Destination port" "53")
                            if validate_port "$dport"; then
                                break
                            else
                                echo -e "${RED}Please enter a valid port (1-65535)${NC}"
                            fi
                        done

                        local payload
                        payload=$(simple_input "Payload (optional)")

                        local count
                        while true; do
                            count=$(simple_input "Number of packets to send" "1")
                            if [[ $count =~ ^[0-9]+$ ]] && [ $count -ge 1 ] && [ $count -le $MAX_PACKETS ]; then
                                break
                            else
                                echo -e "${RED}Please enter a valid count (1-$MAX_PACKETS)${NC}"
                            fi
                        done

                        # Execution summary
                        echo -e "\n${GREEN}Step 4: UDP Packet Summary${NC}"
                        echo -e "${BLUE}═══════════════════════════════════════${NC}"
                        echo -e "${CYAN}Target: $target:$dport${NC}"
                        echo -e "${CYAN}Source Port: $sport${NC}"
                        echo -e "${CYAN}Payload: ${payload:-"(empty)"}${NC}"
                        echo -e "${CYAN}Packet Count: $count${NC}"
                        echo -e "${BLUE}═══════════════════════════════════════${NC}"

                        echo -e "\n${RED}⚠ WARNING: This will send UDP packets to the target!${NC}"
                        echo -e "${RED}⚠ Only proceed if you have authorization to test this target!${NC}"

                        if ask_yes_no "Send UDP packets?" "n"; then
                            echo -e "\n${CYAN}Starting UDP packet crafting...${NC}"

                            # Log start
                            log_json "packetcraft_start" "type=udp target=$target sport=$sport dport=$dport payload=$payload count=$count" 2>/dev/null || true

                            # Craft UDP packets
                            craft_udp_packet "$target" "$sport" "$dport" "$payload" "$count"

                            # Log end
                            log_json "packetcraft_end" "type=udp target=$target" 2>/dev/null || true
                        else
                            echo -e "${YELLOW}UDP packet crafting cancelled.${NC}"
                        fi
                        ;;

                    "icmp")
                        echo -e "\n${GREEN}Step 3: ICMP Configuration${NC}"

                        echo -e "\nICMP Type options:"
                        echo -e "  ${YELLOW}1)${NC} Echo Request (ping) - Type 8"
                        echo -e "  ${YELLOW}2)${NC} Echo Reply - Type 0"
                        echo -e "  ${YELLOW}3)${NC} Destination Unreachable - Type 3"
                        echo -e "  ${YELLOW}4)${NC} Time Exceeded - Type 11"
                        echo -e "  ${YELLOW}5)${NC} Custom - Enter custom type/code"

                        local icmp_type icmp_code
                        while true; do
                            type_choice=$(simple_input "Select ICMP type (1-5)" "1")
                            case "$type_choice" in
                                "1") icmp_type="8"; icmp_code="0"; break ;;
                                "2") icmp_type="0"; icmp_code="0"; break ;;
                                "3") icmp_type="3"; icmp_code="1"; break ;;
                                "4") icmp_type="11"; icmp_code="0"; break ;;
                                "5")
                                    icmp_type=$(simple_input "ICMP Type (0-255)" "8")
                                    icmp_code=$(simple_input "ICMP Code (0-255)" "0")
                                    break ;;
                                *) echo -e "${RED}Please select a number between 1-5${NC}" ;;
                            esac
                        done

                        local payload
                        payload=$(simple_input "Payload (optional)")

                        local count
                        while true; do
                            count=$(simple_input "Number of packets to send" "1")
                            if [[ $count =~ ^[0-9]+$ ]] && [ $count -ge 1 ] && [ $count -le $MAX_PACKETS ]; then
                                break
                            else
                                echo -e "${RED}Please enter a valid count (1-$MAX_PACKETS)${NC}"
                            fi
                        done

                        # Execution summary
                        echo -e "\n${GREEN}Step 4: ICMP Packet Summary${NC}"
                        echo -e "${BLUE}═══════════════════════════════════════${NC}"
                        echo -e "${CYAN}Target: $target${NC}"
                        echo -e "${CYAN}ICMP Type: $icmp_type${NC}"
                        echo -e "${CYAN}ICMP Code: $icmp_code${NC}"
                        echo -e "${CYAN}Payload: ${payload:-"(default)"}${NC}"
                        echo -e "${CYAN}Packet Count: $count${NC}"
                        echo -e "${BLUE}═══════════════════════════════════════${NC}"

                        echo -e "\n${RED}⚠ WARNING: This will send ICMP packets to the target!${NC}"
                        echo -e "${RED}⚠ Only proceed if you have authorization to test this target!${NC}"

                        if ask_yes_no "Send ICMP packets?" "n"; then
                            echo -e "\n${CYAN}Starting ICMP packet crafting...${NC}"

                            # Log start
                            log_json "packetcraft_start" "type=icmp target=$target icmp_type=$icmp_type icmp_code=$icmp_code payload=$payload count=$count" 2>/dev/null || true

                            # Craft ICMP packets
                            craft_icmp_packet "$target" "$icmp_type" "$icmp_code" "$payload" "$count"

                            # Log end
                            log_json "packetcraft_end" "type=icmp target=$target" 2>/dev/null || true
                        else
                            echo -e "${YELLOW}ICMP packet crafting cancelled.${NC}"
                        fi
                        ;;
                esac
                ;;
        esac

        echo -e "\n${YELLOW}Press Enter to continue...${NC}"
        read -r

        if ! ask_yes_no "Craft another packet?" "y"; then
            break
        fi
    done
}

# Legacy mode function
legacy_mode() {
    local proto="$1"
    local target="$2"
    local sport="$3"
    local dport="$4"
    local flags="$5"

    echo -e "${YELLOW}Running in legacy mode...${NC}"
    echo -e "${RED}⚠ WARNING: Only test targets you own or have permission to test!${NC}\n"

    # Validate parameters
    if ! validate_target "$target"; then
        echo -e "${RED}Error: Invalid target format${NC}" >&2
        exit 1
    fi

    if ! validate_port "$sport"; then
        echo -e "${RED}Error: Invalid source port${NC}" >&2
        exit 1
    fi

    if ! validate_port "$dport"; then
        echo -e "${RED}Error: Invalid destination port${NC}" >&2
        exit 1
    fi

    # Log start
    log_json "packetcraft_start" "proto=$proto target=$target sport=$sport dport=$dport flags=$flags mode=legacy" 2>/dev/null || true

    # Perform packet crafting based on protocol
    case "$proto" in
        "tcp")
            echo -e "${CYAN}Crafting TCP packet in legacy mode...${NC}"
            craft_tcp_packet "$target" "$sport" "$dport" "$flags" "1"
            ;;
        "udp")
            echo -e "${CYAN}Crafting UDP packet in legacy mode...${NC}"
            craft_udp_packet "$target" "$sport" "$dport" "" "1"
            ;;
        "icmp")
            echo -e "${CYAN}Crafting ICMP packet in legacy mode...${NC}"
            craft_icmp_packet "$target" "8" "0" "" "1"
            ;;
        *)
            echo -e "${RED}Error: Invalid protocol (tcp|udp|icmp)${NC}" >&2
            exit 1
            ;;
    esac

    # Log end
    log_json "packetcraft_end" "proto=$proto target=$target" 2>/dev/null || true
}

# Main function
main() {
    local proto="tcp"
    local target=""
    local sport="1234"
    local dport="80"
    local flags="SYN"
    local craft_type=""

    # Parse command line arguments
    if [[ $# -gt 0 ]]; then
        while [[ $# -gt 0 ]]; do
            case "$1" in
                -h|--help)
                    show_help
                    exit 0
                    ;;
                --proto)
                    if [ -z "${2:-}" ]; then
                        echo -e "${RED}Error: --proto requires a value (tcp|udp|icmp)${NC}" >&2
                        exit 1
                    fi
                    proto="$2"
                    shift 2
                    ;;
                -t|--target)
                    if [ -z "${2:-}" ]; then
                        echo -e "${RED}Error: -t requires a target${NC}" >&2
                        exit 1
                    fi
                    target="$2"
                    shift 2
                    ;;
                --sport)
                    if [ -z "${2:-}" ]; then
                        echo -e "${RED}Error: --sport requires a port number${NC}" >&2
                        exit 1
                    fi
                    sport="$2"
                    shift 2
                    ;;
                --dport)
                    if [ -z "${2:-}" ]; then
                        echo -e "${RED}Error: --dport requires a port number${NC}" >&2
                        exit 1
                    fi
                    dport="$2"
                    shift 2
                    ;;
                --flags)
                    if [ -z "${2:-}" ]; then
                        echo -e "${RED}Error: --flags requires flag values${NC}" >&2
                        exit 1
                    fi
                    flags="$2"
                    shift 2
                    ;;
                --craft)
                    if [ -z "${2:-}" ]; then
                        echo -e "${RED}Error: --craft requires a type (tcp|udp|icmp)${NC}" >&2
                        exit 1
                    fi
                    craft_type="$2"
                    shift 2
                    ;;
                *)
                    echo -e "${RED}Unknown option: $1${NC}" >&2
                    echo "Use -h for help." >&2
                    exit 1
                    ;;
            esac
        done

        # Handle quick craft mode
        if [ -n "$craft_type" ]; then
            echo -e "${GREEN}Quick Packet Crafting: $craft_type${NC}"

            case "$craft_type" in
                "tcp")
                    echo -e "${YELLOW}Quick TCP packet crafting to localhost:80${NC}"

                    # Log start
                    log_json "packetcraft_start" "type=tcp mode=quick" 2>/dev/null || true

                    # Craft quick TCP packet
                    craft_tcp_packet "127.0.0.1" "12345" "80" "SYN" "1"

                    # Log end
                    log_json "packetcraft_end" "type=tcp" 2>/dev/null || true
                    ;;
                "udp")
                    echo -e "${YELLOW}Quick UDP packet crafting to localhost:53${NC}"

                    # Log start
                    log_json "packetcraft_start" "type=udp mode=quick" 2>/dev/null || true

                    # Craft quick UDP packet
                    craft_udp_packet "127.0.0.1" "12345" "53" "test" "1"

                    # Log end
                    log_json "packetcraft_end" "type=udp" 2>/dev/null || true
                    ;;
                "icmp")
                    echo -e "${YELLOW}Quick ICMP packet crafting to localhost${NC}"

                    # Log start
                    log_json "packetcraft_start" "type=icmp mode=quick" 2>/dev/null || true

                    # Craft quick ICMP packet
                    craft_icmp_packet "127.0.0.1" "8" "0" "" "1"

                    # Log end
                    log_json "packetcraft_end" "type=icmp" 2>/dev/null || true
                    ;;
                *)
                    echo -e "${RED}Error: Invalid craft type (tcp|udp|icmp)${NC}" >&2
                    exit 1
                    ;;
            esac
            exit 0
        fi

        # Handle legacy mode
        if [ -n "$target" ]; then
            legacy_mode "$proto" "$target" "$sport" "$dport" "$flags"
            exit $?
        fi

        # If we get here, invalid combination of arguments
        echo -e "${RED}Error: Invalid argument combination${NC}" >&2
        echo "Use -h for help or run without arguments for interactive mode." >&2
        exit 1
    fi

    # Check dependencies for interactive mode
    missing_deps=()
    if ! command -v ping >/dev/null 2>&1; then
        missing_deps+=("ping")
    fi
    if ! command -v nc >/dev/null 2>&1; then
        missing_deps+=("nc (netcat)")
    fi

    if [ ${#missing_deps[@]} -gt 0 ]; then
        echo -e "${YELLOW}Warning: Some basic tools are missing: ${missing_deps[*]}${NC}"
        echo -e "${YELLOW}For advanced packet crafting, consider installing:${NC}"
        echo -e "${YELLOW}• python3 with scapy: pip3 install scapy${NC}"
        echo -e "${YELLOW}• hping3: apt-get install hping3${NC}"
        echo -e "${YELLOW}• nmap: apt-get install nmap${NC}\n"
    fi

    # Check for advanced tools
    advanced_tools=()
    if command -v python3 >/dev/null 2>&1; then
        if python3 -c "import scapy" 2>/dev/null; then
            advanced_tools+=("scapy")
        fi
    fi
    if command -v hping3 >/dev/null 2>&1; then
        advanced_tools+=("hping3")
    fi
    if command -v nmap >/dev/null 2>&1; then
        advanced_tools+=("nmap")
    fi

    if [ ${#advanced_tools[@]} -gt 0 ]; then
        echo -e "${GREEN}Advanced packet crafting tools available: ${advanced_tools[*]}${NC}\n"
    fi

    # Start interactive mode
    interactive_mode
}

# Run the main function with all arguments
main "$@"
