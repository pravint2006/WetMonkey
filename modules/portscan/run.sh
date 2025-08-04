#!/usr/bin/env bash
# wetmonkey portscan – Interactive Port Scanning & Analysis Suite v2.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$SCRIPT_DIR/../../"
source "$BASE_DIR/core/utils.sh"

# Configuration
VERSION="2.0"
MAX_PORTS=65535

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
    echo "║    🔍 WetMonkey Port Scanning Suite     ║"
    echo "║         Interactive Mode v2.0           ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Show usage information
show_help() {
    echo "WetMonkey Port Scanning Module v${VERSION}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  -t, --target <target>   Target IP or hostname (legacy mode)"
    echo "  --ports <range>         Port range to scan (legacy mode)"
    echo "  --flags <flags>         nmap flags (legacy mode)"
    echo "  --scan <target>         Quick port scan"
    echo ""
    echo "This module provides interactive port scanning and analysis."
    echo "Supported features: Multiple scanning methods, stealth scanning, service detection"
    echo ""
    echo "Example:"
    echo "  $0                      # Run in interactive mode"
    echo "  $0 -h                   # Show this help"
    echo "  $0 --scan 192.168.1.1   # Quick port scan"
    echo "  $0 -t 192.168.1.1 --ports 1-1000  # Legacy mode"
    echo ""
    echo "Note: This tool is for authorized security testing and research only!"
    echo "      Use responsibly and only on systems you own or have permission to test."
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

# Function to validate port range
validate_port_range() {
    local range="$1"

    # Single port
    if [[ $range =~ ^[0-9]+$ ]]; then
        if [ $range -ge 1 ] && [ $range -le 65535 ]; then
            return 0
        fi
        return 1
    fi

    # Port range (e.g., 1-1000)
    if [[ $range =~ ^[0-9]+-[0-9]+$ ]]; then
        local start_port=$(echo "$range" | cut -d'-' -f1)
        local end_port=$(echo "$range" | cut -d'-' -f2)

        if [ $start_port -ge 1 ] && [ $start_port -le 65535 ] && \
           [ $end_port -ge 1 ] && [ $end_port -le 65535 ] && \
           [ $start_port -le $end_port ]; then
            return 0
        fi
        return 1
    fi

    # Comma-separated ports (e.g., 80,443,8080)
    if [[ $range =~ ^[0-9]+(,[0-9]+)*$ ]]; then
        local IFS=','
        local -a ports=($range)
        for port in "${ports[@]}"; do
            if [ $port -lt 1 ] || [ $port -gt 65535 ]; then
                return 1
            fi
        done
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

# Function to perform nmap port scanning
nmap_port_scan() {
    local target="$1"
    local ports="$2"
    local scan_type="$3"
    local timing="${4:-T3}"

    echo -e "\n${GREEN}🔍 Performing nmap port scan...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Target: $target${NC}"
    echo -e "${YELLOW}Ports: $ports${NC}"
    echo -e "${YELLOW}Scan Type: $scan_type${NC}"
    echo -e "${YELLOW}Timing: $timing${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    if ! command -v nmap >/dev/null 2>&1; then
        echo -e "${RED}❌ nmap is not installed${NC}"
        echo -e "${YELLOW}Please install nmap: sudo apt-get install nmap${NC}"
        return 1
    fi

    # Build nmap command
    local nmap_cmd="nmap"
    local nmap_args=()

    # Add scan type
    case "$scan_type" in
        "syn")
            nmap_args+=("-sS")  # SYN stealth scan
            echo -e "${CYAN}Using SYN stealth scan${NC}"
            ;;
        "connect")
            nmap_args+=("-sT")  # TCP connect scan
            echo -e "${CYAN}Using TCP connect scan${NC}"
            ;;
        "udp")
            nmap_args+=("-sU")  # UDP scan
            echo -e "${CYAN}Using UDP scan${NC}"
            ;;
        "fin")
            nmap_args+=("-sF")  # FIN scan
            echo -e "${CYAN}Using FIN stealth scan${NC}"
            ;;
        "xmas")
            nmap_args+=("-sX")  # XMAS scan
            echo -e "${CYAN}Using XMAS scan${NC}"
            ;;
        "null")
            nmap_args+=("-sN")  # NULL scan
            echo -e "${CYAN}Using NULL scan${NC}"
            ;;
        "ack")
            nmap_args+=("-sA")  # ACK scan
            echo -e "${CYAN}Using ACK scan${NC}"
            ;;
        "comprehensive")
            nmap_args+=("-sS" "-sU")  # Both TCP and UDP
            echo -e "${CYAN}Using comprehensive TCP+UDP scan${NC}"
            ;;
        *)
            nmap_args+=("-sS")  # Default to SYN
            echo -e "${CYAN}Using default SYN scan${NC}"
            ;;
    esac

    # Add timing
    nmap_args+=("-$timing")

    # Add port specification
    nmap_args+=("-p" "$ports")

    # Add additional useful flags
    nmap_args+=("-v")       # Verbose output
    nmap_args+=("--open")   # Show only open ports
    nmap_args+=("$target")

    echo -e "${BLUE}Command: $nmap_cmd ${nmap_args[*]}${NC}\n"

    # Execute nmap scan
    local nmap_output
    local nmap_exit_code

    echo -e "${CYAN}Starting nmap port scan...${NC}"
    if nmap_output=$("$nmap_cmd" "${nmap_args[@]}" 2>&1); then
        nmap_exit_code=0
        echo -e "${GREEN}✓ nmap scan completed successfully${NC}"
    else
        nmap_exit_code=$?
        echo -e "${YELLOW}⚠ nmap scan completed with warnings (exit code: $nmap_exit_code)${NC}"
    fi

    # Parse and display results
    echo -e "\n${GREEN}📊 nmap Port Scan Results${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    # Extract open ports
    local open_ports
    open_ports=$(echo "$nmap_output" | grep "^[0-9].*open" | head -20)

    if [ -n "$open_ports" ]; then
        echo -e "${CYAN}Open Ports:${NC}"
        echo "$open_ports" | sed 's/^/  /'

        # Count open ports
        local port_count
        port_count=$(echo "$open_ports" | wc -l)
        echo -e "\n${CYAN}Total Open Ports: $port_count${NC}"
    else
        echo -e "${YELLOW}No open ports detected${NC}"
    fi

    # Extract filtered ports info
    local filtered_info
    filtered_info=$(echo "$nmap_output" | grep -i "filtered" | head -5)
    if [ -n "$filtered_info" ]; then
        echo -e "\n${CYAN}Filtered Ports Information:${NC}"
        echo "$filtered_info" | sed 's/^/  /'
    fi

    # Extract timing information
    local timing_info
    timing_info=$(echo "$nmap_output" | grep -i "scan completed\|elapsed" | head -3)
    if [ -n "$timing_info" ]; then
        echo -e "\n${CYAN}Scan Timing:${NC}"
        echo "$timing_info" | sed 's/^/  /'
    fi

    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    return $nmap_exit_code
}

# Function to perform manual port scanning techniques
manual_port_scan() {
    local target="$1"
    local ports="$2"

    echo -e "\n${GREEN}🔍 Performing manual port scanning...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Target: $target${NC}"
    echo -e "${YELLOW}Ports: $ports${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    local open_ports=()
    local closed_ports=()
    local filtered_ports=()

    # Parse port range
    local port_list=()
    if [[ $ports =~ ^[0-9]+-[0-9]+$ ]]; then
        # Range format (e.g., 1-1000)
        local start_port=$(echo "$ports" | cut -d'-' -f1)
        local end_port=$(echo "$ports" | cut -d'-' -f2)

        # Limit range for manual scanning
        if [ $((end_port - start_port)) -gt 100 ]; then
            echo -e "${YELLOW}⚠ Large port range detected, limiting to first 100 ports${NC}"
            end_port=$((start_port + 99))
        fi

        for ((port=start_port; port<=end_port; port++)); do
            port_list+=("$port")
        done
    elif [[ $ports =~ ^[0-9]+(,[0-9]+)*$ ]]; then
        # Comma-separated format
        IFS=',' read -ra port_list <<< "$ports"
    else
        # Single port
        port_list=("$ports")
    fi

    echo -e "${CYAN}Testing ${#port_list[@]} ports manually...${NC}\n"

    # Test each port
    local count=0
    for port in "${port_list[@]}"; do
        ((count++))
        echo -ne "${BLUE}Testing port $port ($count/${#port_list[@]})... ${NC}"

        # Method 1: Try netcat
        if command -v nc >/dev/null 2>&1; then
            if timeout 3 nc -z -w 1 "$target" "$port" 2>/dev/null; then
                echo -e "${GREEN}Open${NC}"
                open_ports+=("$port")
                continue
            fi
        fi

        # Method 2: Try telnet
        if command -v telnet >/dev/null 2>&1; then
            if timeout 3 bash -c "echo '' | telnet $target $port" 2>/dev/null | grep -q "Connected"; then
                echo -e "${GREEN}Open${NC}"
                open_ports+=("$port")
                continue
            fi
        fi

        # Method 3: Try /dev/tcp (bash built-in)
        if timeout 3 bash -c "exec 3<>/dev/tcp/$target/$port" 2>/dev/null; then
            echo -e "${GREEN}Open${NC}"
            open_ports+=("$port")
            exec 3>&-  # Close the connection
            continue
        fi

        # If all methods fail, consider it closed/filtered
        echo -e "${RED}Closed/Filtered${NC}"
        closed_ports+=("$port")
    done

    # Summary
    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}📊 Manual Port Scan Summary${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Target: $target${NC}"
    echo -e "${CYAN}Ports Tested: ${#port_list[@]}${NC}"
    echo -e "${CYAN}Open Ports: ${#open_ports[@]}${NC}"
    echo -e "${CYAN}Closed/Filtered: ${#closed_ports[@]}${NC}"

    if [ ${#open_ports[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}Open Ports Found:${NC}"
        for port in "${open_ports[@]}"; do
            echo -e "  • Port $port/tcp"
        done

        echo -e "\n${GREEN}🎯 SUCCESS: Found ${#open_ports[@]} open port(s)${NC}"
    else
        echo -e "\n${RED}❌ NO OPEN PORTS FOUND${NC}"
        echo -e "${YELLOW}Possible reasons:${NC}"
        echo -e "• Target is heavily firewalled"
        echo -e "• Ports are actually closed"
        echo -e "• Network filtering is in place"
        echo -e "• Target is unreachable"
    fi

    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    return 0
}

# Function to perform service detection
service_detection_scan() {
    local target="$1"
    local ports="$2"

    echo -e "\n${GREEN}🔍 Performing service detection...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Target: $target${NC}"
    echo -e "${YELLOW}Ports: $ports${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    local services_found=()
    local banners_found=()

    # First, do a quick port scan to find open ports
    echo -e "${CYAN}Step 1: Finding open ports...${NC}"
    local open_ports=()

    # Parse port range for service detection
    local port_list=()
    if [[ $ports =~ ^[0-9]+-[0-9]+$ ]]; then
        # For service detection, limit to common ports if range is too large
        local start_port=$(echo "$ports" | cut -d'-' -f1)
        local end_port=$(echo "$ports" | cut -d'-' -f2)

        if [ $((end_port - start_port)) -gt 50 ]; then
            echo -e "${YELLOW}⚠ Large port range, focusing on common service ports${NC}"
            port_list=(21 22 23 25 53 80 110 143 443 993 995 1433 3389 5432 8080 8443)
        else
            for ((port=start_port; port<=end_port; port++)); do
                port_list+=("$port")
            done
        fi
    elif [[ $ports =~ ^[0-9]+(,[0-9]+)*$ ]]; then
        IFS=',' read -ra port_list <<< "$ports"
    else
        port_list=("$ports")
    fi

    # Quick connectivity test for each port
    for port in "${port_list[@]}"; do
        echo -ne "${BLUE}Testing port $port... ${NC}"
        if timeout 3 nc -z -w 1 "$target" "$port" 2>/dev/null; then
            echo -e "${GREEN}Open${NC}"
            open_ports+=("$port")
        else
            echo -e "${RED}Closed${NC}"
        fi
    done

    if [ ${#open_ports[@]} -eq 0 ]; then
        echo -e "\n${RED}❌ No open ports found for service detection${NC}"
        return 1
    fi

    echo -e "\n${CYAN}Step 2: Detecting services on ${#open_ports[@]} open port(s)...${NC}\n"

    # Service detection for each open port
    for port in "${open_ports[@]}"; do
        echo -e "${MAGENTA}═══ Port $port Service Detection ═══${NC}"

        local service_name=""
        local banner=""

        # Try to identify service by port number
        case "$port" in
            21) service_name="FTP" ;;
            22) service_name="SSH" ;;
            23) service_name="Telnet" ;;
            25) service_name="SMTP" ;;
            53) service_name="DNS" ;;
            80) service_name="HTTP" ;;
            110) service_name="POP3" ;;
            143) service_name="IMAP" ;;
            443) service_name="HTTPS" ;;
            993) service_name="IMAPS" ;;
            995) service_name="POP3S" ;;
            1433) service_name="SQL Server" ;;
            3389) service_name="RDP" ;;
            5432) service_name="PostgreSQL" ;;
            8080) service_name="HTTP-Alt" ;;
            8443) service_name="HTTPS-Alt" ;;
            *) service_name="Unknown" ;;
        esac

        echo -e "${CYAN}  Expected Service: $service_name${NC}"

        # Try to grab banner
        echo -e "${CYAN}  Banner Detection:${NC}"

        # Method 1: Try netcat for banner grabbing
        if command -v nc >/dev/null 2>&1; then
            banner=$(timeout 5 nc "$target" "$port" < /dev/null 2>/dev/null | head -3 | tr -d '\r\n' | head -c 200)
            if [ -n "$banner" ]; then
                echo -e "${GREEN}    ✓ Banner: $banner${NC}"
                banners_found+=("Port $port: $banner")
            else
                echo -e "${YELLOW}    ⚠ No banner received${NC}"
            fi
        fi

        # Method 2: HTTP-specific detection
        if [[ "$port" == "80" ]] || [[ "$port" == "8080" ]] || [[ "$port" == "443" ]] || [[ "$port" == "8443" ]]; then
            echo -e "${CYAN}  HTTP Service Detection:${NC}"

            local protocol="http"
            if [[ "$port" == "443" ]] || [[ "$port" == "8443" ]]; then
                protocol="https"
            fi

            if command -v curl >/dev/null 2>&1; then
                local http_response
                http_response=$(curl -I --connect-timeout 5 --max-time 10 "$protocol://$target:$port" 2>/dev/null | head -5)
                if [ -n "$http_response" ]; then
                    echo -e "${GREEN}    ✓ HTTP Response:${NC}"
                    echo "$http_response" | sed 's/^/      /'

                    # Extract server information
                    local server_info
                    server_info=$(echo "$http_response" | grep -i "server:" | head -1)
                    if [ -n "$server_info" ]; then
                        services_found+=("Port $port: $server_info")
                    fi
                else
                    echo -e "${YELLOW}    ⚠ No HTTP response${NC}"
                fi
            fi
        fi

        # Method 3: SSH-specific detection
        if [[ "$port" == "22" ]]; then
            echo -e "${CYAN}  SSH Service Detection:${NC}"
            local ssh_banner
            ssh_banner=$(timeout 5 nc "$target" "$port" < /dev/null 2>/dev/null | head -1)
            if [ -n "$ssh_banner" ]; then
                echo -e "${GREEN}    ✓ SSH Banner: $ssh_banner${NC}"
                services_found+=("Port $port: $ssh_banner")
            else
                echo -e "${YELLOW}    ⚠ No SSH banner${NC}"
            fi
        fi

        echo ""
    done

    # Summary
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}📊 Service Detection Summary${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Target: $target${NC}"
    echo -e "${CYAN}Open Ports: ${#open_ports[@]}${NC}"
    echo -e "${CYAN}Services Detected: ${#services_found[@]}${NC}"
    echo -e "${CYAN}Banners Collected: ${#banners_found[@]}${NC}"

    if [ ${#open_ports[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}Open Ports:${NC}"
        for port in "${open_ports[@]}"; do
            echo -e "  • Port $port/tcp"
        done
    fi

    if [ ${#services_found[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}Services Identified:${NC}"
        for service in "${services_found[@]}"; do
            echo -e "  • $service"
        done
    fi

    if [ ${#banners_found[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}Banners Collected:${NC}"
        for banner in "${banners_found[@]}"; do
            echo -e "  • $banner"
        done
    fi

    echo -e "\n${YELLOW}Security Recommendations:${NC}"
    echo -e "• Review all open ports for necessity"
    echo -e "• Update services to latest versions"
    echo -e "• Consider banner obfuscation"
    echo -e "• Implement proper access controls"
    echo -e "• Monitor for unauthorized services"

    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    return 0
}

# Function to perform comprehensive port scanning
comprehensive_port_scan() {
    local target="$1"
    local ports="$2"

    echo -e "\n${GREEN}🔍 Starting comprehensive port scanning...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Target: $target${NC}"
    echo -e "${YELLOW}Ports: $ports${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    local total_tests=0
    local successful_tests=0
    local scan_results=()

    # Test 1: nmap SYN scan
    ((total_tests++))
    echo -e "${MAGENTA}═══ Test 1: nmap SYN Scan ═══${NC}"
    if nmap_port_scan "$target" "$ports" "syn" "T3"; then
        ((successful_tests++))
        scan_results+=("nmap SYN scan completed")
    else
        scan_results+=("nmap SYN scan failed or limited")
    fi

    # Test 2: Manual port scanning
    ((total_tests++))
    echo -e "\n${MAGENTA}═══ Test 2: Manual Port Scanning ═══${NC}"
    if manual_port_scan "$target" "$ports"; then
        ((successful_tests++))
        scan_results+=("Manual port scanning completed")
    else
        scan_results+=("Manual port scanning failed")
    fi

    # Test 3: Service detection
    ((total_tests++))
    echo -e "\n${MAGENTA}═══ Test 3: Service Detection ═══${NC}"
    if service_detection_scan "$target" "$ports"; then
        ((successful_tests++))
        scan_results+=("Service detection completed")
    else
        scan_results+=("Service detection failed")
    fi

    # Test 4: Stealth scanning (if nmap available)
    if command -v nmap >/dev/null 2>&1; then
        ((total_tests++))
        echo -e "\n${MAGENTA}═══ Test 4: Stealth Scanning ═══${NC}"
        if nmap_port_scan "$target" "$ports" "fin" "T2"; then
            ((successful_tests++))
            scan_results+=("Stealth FIN scan completed")
        else
            scan_results+=("Stealth FIN scan failed")
        fi
    fi

    # Final comprehensive summary
    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}🎯 Comprehensive Port Scanning Summary${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Target: $target${NC}"
    echo -e "${CYAN}Port Range: $ports${NC}"
    echo -e "${CYAN}Total Tests: $total_tests${NC}"
    echo -e "${CYAN}Successful Tests: $successful_tests${NC}"
    echo -e "${CYAN}Success Rate: $(( (successful_tests * 100) / total_tests ))%${NC}"

    if [ ${#scan_results[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}Scan Results:${NC}"
        for result in "${scan_results[@]}"; do
            echo -e "  • $result"
        done
    fi

    echo -e "\n${YELLOW}Scanning Recommendations:${NC}"
    echo -e "• Combine multiple scanning techniques for accuracy"
    echo -e "• Use stealth scans to avoid detection"
    echo -e "• Perform service detection on open ports"
    echo -e "• Consider network filtering and firewalls"
    echo -e "• Document findings for security assessment"

    echo -e "\n${YELLOW}Detection Indicators:${NC}"
    echo -e "• Multiple connection attempts to various ports"
    echo -e "• Unusual TCP flag combinations (stealth scans)"
    echo -e "• Rapid sequential port probing"
    echo -e "• Service banner grabbing attempts"
    echo -e "• Pattern-based scanning behavior"

    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    return 0
}

# Educational information function
show_educational_info() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║         📚 Port Scanning Guide          ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}\n"

    echo -e "${GREEN}What is Port Scanning?${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "Port scanning is the process of probing a target system to discover"
    echo -e "open network ports and running services. It's a fundamental technique"
    echo -e "in network reconnaissance, security assessment, and penetration testing."
    echo -e "Port scans help identify potential attack vectors and security gaps.\n"

    echo -e "${GREEN}Common Port Scanning Techniques${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}1. TCP Connect Scan${NC}"
    echo -e "   • Completes full TCP three-way handshake"
    echo -e "   • Most reliable but easily detected"
    echo -e "   • Works without special privileges"
    echo -e "${YELLOW}2. SYN Stealth Scan${NC}"
    echo -e "   • Sends SYN packets, doesn't complete handshake"
    echo -e "   • Harder to detect, requires root privileges"
    echo -e "   • Most popular scanning technique"
    echo -e "${YELLOW}3. FIN Scan${NC}"
    echo -e "   • Sends FIN packets to closed ports"
    echo -e "   • Bypasses some firewalls and filters"
    echo -e "   • Stealthy but less reliable"
    echo -e "${YELLOW}4. XMAS Scan${NC}"
    echo -e "   • Sets FIN, PSH, and URG flags"
    echo -e "   • Named after Christmas tree lights"
    echo -e "   • Good for firewall evasion"
    echo -e "${YELLOW}5. NULL Scan${NC}"
    echo -e "   • Sends packets with no flags set"
    echo -e "   • Stealthy scanning technique"
    echo -e "   • May bypass simple filters"
    echo -e "${YELLOW}6. UDP Scan${NC}"
    echo -e "   • Probes UDP services"
    echo -e "   • Slower and less reliable than TCP"
    echo -e "   • Important for complete assessment\n"

    echo -e "${GREEN}Port States and Responses${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Open Ports:${NC}"
    echo -e "• Service is listening and accepting connections"
    echo -e "• TCP: SYN/ACK response to SYN packet"
    echo -e "• UDP: Service-specific response or silence"
    echo -e "${CYAN}Closed Ports:${NC}"
    echo -e "• No service listening on the port"
    echo -e "• TCP: RST response to SYN packet"
    echo -e "• UDP: ICMP port unreachable message"
    echo -e "${CYAN}Filtered Ports:${NC}"
    echo -e "• Firewall or filter blocking access"
    echo -e "• No response to probe packets"
    echo -e "• Cannot determine if port is open or closed\n"

    echo -e "${GREEN}Common Service Ports${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Well-Known Ports (1-1023):${NC}"
    echo -e "• 21: FTP (File Transfer Protocol)"
    echo -e "• 22: SSH (Secure Shell)"
    echo -e "• 23: Telnet"
    echo -e "• 25: SMTP (Simple Mail Transfer Protocol)"
    echo -e "• 53: DNS (Domain Name System)"
    echo -e "• 80: HTTP (Hypertext Transfer Protocol)"
    echo -e "• 110: POP3 (Post Office Protocol)"
    echo -e "• 143: IMAP (Internet Message Access Protocol)"
    echo -e "• 443: HTTPS (HTTP Secure)"
    echo -e "${CYAN}Registered Ports (1024-49151):${NC}"
    echo -e "• 1433: Microsoft SQL Server"
    echo -e "• 3389: RDP (Remote Desktop Protocol)"
    echo -e "• 5432: PostgreSQL"
    echo -e "• 8080: HTTP Alternative"
    echo -e "• 8443: HTTPS Alternative\n"

    echo -e "${GREEN}Scanning Tools and Methods${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}1. nmap:${NC}"
    echo -e "   • Most comprehensive port scanner"
    echo -e "   • Multiple scan types and timing options"
    echo -e "   • Service detection and OS fingerprinting"
    echo -e "${CYAN}2. netcat (nc):${NC}"
    echo -e "   • Simple TCP/UDP connectivity testing"
    echo -e "   • Banner grabbing capabilities"
    echo -e "   • Lightweight and widely available"
    echo -e "${CYAN}3. telnet:${NC}"
    echo -e "   • Basic TCP port connectivity testing"
    echo -e "   • Manual service interaction"
    echo -e "   • Limited but universally available"
    echo -e "${CYAN}4. Custom Scripts:${NC}"
    echo -e "   • /dev/tcp bash built-in for TCP testing"
    echo -e "   • Python socket programming"
    echo -e "   • Custom protocol implementations\n"

    echo -e "${GREEN}Evasion and Stealth Techniques${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Timing Control:${NC}"
    echo -e "• Slow scans to avoid detection (T0, T1)"
    echo -e "• Normal timing for balanced approach (T3)"
    echo -e "• Aggressive timing for fast scans (T4, T5)"
    echo -e "${CYAN}Source Port Manipulation:${NC}"
    echo -e "• Use common source ports (53, 80, 443)"
    echo -e "• Randomize source ports"
    echo -e "• Spoof source addresses (advanced)"
    echo -e "${CYAN}Fragmentation:${NC}"
    echo -e "• Fragment packets to evade filters"
    echo -e "• Use decoy hosts to mask origin"
    echo -e "• Idle scan using zombie hosts"
    echo -e "${CYAN}Protocol Manipulation:${NC}"
    echo -e "• Use unusual flag combinations"
    echo -e "• Mix TCP and UDP scanning"
    echo -e "• Vary packet sizes and timing\n"

    echo -e "${GREEN}Detection and Defense${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}✓ Network Monitoring:${NC}"
    echo -e "  • Monitor for connection attempts to multiple ports"
    echo -e "  • Track unusual TCP flag combinations"
    echo -e "  • Analyze connection patterns and timing"
    echo -e "${GREEN}✓ Intrusion Detection:${NC}"
    echo -e "  • Signature-based detection of scan patterns"
    echo -e "  • Threshold-based alerting on port probes"
    echo -e "  • Behavioral analysis of network traffic"
    echo -e "${GREEN}✓ Firewall Configuration:${NC}"
    echo -e "  • Block unnecessary ports and services"
    echo -e "  • Implement rate limiting and connection throttling"
    echo -e "  • Use stateful inspection and deep packet analysis"
    echo -e "${GREEN}✓ Service Hardening:${NC}"
    echo -e "  • Disable unnecessary services"
    echo -e "  • Change default ports for critical services"
    echo -e "  • Implement service banners obfuscation"
    echo -e "${GREEN}✓ Network Segmentation:${NC}"
    echo -e "  • Isolate critical systems and services"
    echo -e "  • Implement micro-segmentation"
    echo -e "  • Use VLANs and network access control\n"

    echo -e "${GREEN}Legal and Ethical Considerations${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${RED}⚠ IMPORTANT:${NC} Only scan systems you own or have explicit permission to test"
    echo -e "${RED}⚠ LEGAL:${NC} Unauthorized port scanning may violate computer crime laws"
    echo -e "${RED}⚠ ETHICAL:${NC} Use port scanning for legitimate security assessment only"
    echo -e "${RED}⚠ PROFESSIONAL:${NC} Document findings and follow responsible disclosure"
    echo -e "${RED}⚠ DETECTION:${NC} Be aware that scanning activities are often logged and monitored\n"
}

# Main interactive function
interactive_mode() {
    while true; do
        show_banner

        echo -e "${GREEN}Welcome to WetMonkey Port Scanning Suite!${NC}"
        echo -e "${YELLOW}This tool helps discover open ports and services on target systems.${NC}\n"
        echo -e "${RED}⚠ WARNING: Only scan systems you own or have permission to test!${NC}\n"

        # Step 1: Scanning method selection
        echo -e "${GREEN}Step 1: Scanning Method${NC}"
        echo -e "Choose the port scanning method:"
        echo -e "  ${YELLOW}1)${NC} nmap Scan - Advanced nmap-based port scanning"
        echo -e "  ${YELLOW}2)${NC} Manual Scan - Custom techniques (netcat, telnet, etc.)"
        echo -e "  ${YELLOW}3)${NC} Service Detection - Identify services on open ports"
        echo -e "  ${YELLOW}4)${NC} Comprehensive Scan - All methods combined"
        echo -e "  ${YELLOW}5)${NC} Educational Information - Learn about port scanning"

        local scan_type
        while true; do
            choice=$(simple_input "Select scanning method (1-5)")
            case "$choice" in
                "1") scan_type="nmap"; break ;;
                "2") scan_type="manual"; break ;;
                "3") scan_type="service"; break ;;
                "4") scan_type="comprehensive"; break ;;
                "5") scan_type="educational"; break ;;
                *) echo -e "${RED}Please select a number between 1-5${NC}" ;;
            esac
        done

        case "$scan_type" in
            "educational")
                # Show educational information
                show_educational_info
                echo -e "\n${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;

            *)
                # Port scanning
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

                # Step 3: Port configuration
                echo -e "\n${GREEN}Step 3: Port Configuration${NC}"
                echo -e "Port range options:"
                echo -e "  ${YELLOW}1)${NC} Common Ports - Top 100 most common ports"
                echo -e "  ${YELLOW}2)${NC} Well-Known Ports - Ports 1-1023"
                echo -e "  ${YELLOW}3)${NC} All Ports - Full range 1-65535 (slow)"
                echo -e "  ${YELLOW}4)${NC} Custom Range - Specify your own range"
                echo -e "  ${YELLOW}5)${NC} Specific Ports - Comma-separated list"

                local ports
                while true; do
                    port_choice=$(simple_input "Select port range (1-5)" "1")
                    case "$port_choice" in
                        "1")
                            ports="21,22,23,25,53,80,110,143,443,993,995,1433,3389,5432,8080,8443"
                            break ;;
                        "2")
                            ports="1-1023"
                            break ;;
                        "3")
                            ports="1-65535"
                            echo -e "${YELLOW}⚠ Warning: Full port scan will take a long time${NC}"
                            break ;;
                        "4")
                            while true; do
                                ports=$(simple_input "Enter port range (e.g., 1-1000)")
                                if validate_port_range "$ports"; then
                                    break
                                else
                                    echo -e "${RED}Please enter a valid port range${NC}"
                                fi
                            done
                            break ;;
                        "5")
                            while true; do
                                ports=$(simple_input "Enter comma-separated ports (e.g., 80,443,8080)")
                                if validate_port_range "$ports"; then
                                    break
                                else
                                    echo -e "${RED}Please enter valid port numbers${NC}"
                                fi
                            done
                            break ;;
                        *) echo -e "${RED}Please select a number between 1-5${NC}" ;;
                    esac
                done

                # Step 4: Advanced options (for nmap scans)
                local nmap_scan_type="syn"
                local timing="T3"

                if [[ "$scan_type" == "nmap" ]] || [[ "$scan_type" == "comprehensive" ]]; then
                    echo -e "\n${GREEN}Step 4: Advanced Options${NC}"

                    echo -e "nmap scan type options:"
                    echo -e "  ${YELLOW}1)${NC} SYN Scan - Fast and stealthy (default)"
                    echo -e "  ${YELLOW}2)${NC} Connect Scan - Full TCP connection"
                    echo -e "  ${YELLOW}3)${NC} FIN Scan - Stealth scan using FIN packets"
                    echo -e "  ${YELLOW}4)${NC} XMAS Scan - Christmas tree scan"
                    echo -e "  ${YELLOW}5)${NC} UDP Scan - Scan UDP ports"

                    while true; do
                        nmap_choice=$(simple_input "Select nmap scan type (1-5)" "1")
                        case "$nmap_choice" in
                            "1") nmap_scan_type="syn"; break ;;
                            "2") nmap_scan_type="connect"; break ;;
                            "3") nmap_scan_type="fin"; break ;;
                            "4") nmap_scan_type="xmas"; break ;;
                            "5") nmap_scan_type="udp"; break ;;
                            *) echo -e "${RED}Please select a number between 1-5${NC}" ;;
                        esac
                    done

                    echo -e "\nTiming options:"
                    echo -e "  ${YELLOW}1)${NC} Paranoid (T0) - Very slow, avoid detection"
                    echo -e "  ${YELLOW}2)${NC} Sneaky (T1) - Slow, avoid detection"
                    echo -e "  ${YELLOW}3)${NC} Polite (T2) - Slow, less bandwidth"
                    echo -e "  ${YELLOW}4)${NC} Normal (T3) - Default timing (recommended)"
                    echo -e "  ${YELLOW}5)${NC} Aggressive (T4) - Fast, assume good network"
                    echo -e "  ${YELLOW}6)${NC} Insane (T5) - Very fast, may miss results"

                    while true; do
                        timing_choice=$(simple_input "Select timing (1-6)" "4")
                        case "$timing_choice" in
                            "1") timing="T0"; break ;;
                            "2") timing="T1"; break ;;
                            "3") timing="T2"; break ;;
                            "4") timing="T3"; break ;;
                            "5") timing="T4"; break ;;
                            "6") timing="T5"; break ;;
                            *) echo -e "${RED}Please select a number between 1-6${NC}" ;;
                        esac
                    done
                fi

                # Step 5: Execution summary
                echo -e "\n${GREEN}Step 5: Scanning Summary${NC}"
                echo -e "${BLUE}═══════════════════════════════════════${NC}"
                echo -e "${CYAN}Target: $target${NC}"
                echo -e "${CYAN}Ports: $ports${NC}"
                echo -e "${CYAN}Method: $scan_type${NC}"
                if [[ "$scan_type" == "nmap" ]] || [[ "$scan_type" == "comprehensive" ]]; then
                    echo -e "${CYAN}nmap Scan Type: $nmap_scan_type${NC}"
                    echo -e "${CYAN}Timing: $timing${NC}"
                fi
                echo -e "${BLUE}═══════════════════════════════════════${NC}"

                echo -e "\n${RED}⚠ WARNING: This will perform port scanning against the target!${NC}"
                echo -e "${RED}⚠ Only proceed if you have authorization to test this target!${NC}"

                if ask_yes_no "Start port scanning?" "n"; then
                    echo -e "\n${CYAN}Starting port scanning...${NC}"

                    # Log start
                    log_json "portscan_start" "target=$target ports=$ports method=$scan_type" 2>/dev/null || true

                    # Perform scanning based on method
                    case "$scan_type" in
                        "nmap")
                            nmap_port_scan "$target" "$ports" "$nmap_scan_type" "$timing"
                            ;;
                        "manual")
                            manual_port_scan "$target" "$ports"
                            ;;
                        "service")
                            service_detection_scan "$target" "$ports"
                            ;;
                        "comprehensive")
                            comprehensive_port_scan "$target" "$ports"
                            ;;
                    esac

                    # Log end
                    log_json "portscan_end" "target=$target method=$scan_type" 2>/dev/null || true
                else
                    echo -e "${YELLOW}Port scanning cancelled.${NC}"
                fi
                ;;
        esac

        echo -e "\n${YELLOW}Press Enter to continue...${NC}"
        read -r

        if ! ask_yes_no "Perform another port scan?" "y"; then
            break
        fi
    done
}

# Legacy mode function
legacy_mode() {
    local target="$1"
    local ports="$2"
    local flags="$3"

    echo -e "${YELLOW}Running in legacy mode...${NC}"
    echo -e "${RED}⚠ WARNING: Only scan targets you own or have permission to test!${NC}\n"

    # Validate parameters
    if ! validate_target "$target"; then
        echo -e "${RED}Error: Invalid target format${NC}" >&2
        exit 1
    fi

    if ! validate_port_range "$ports"; then
        echo -e "${RED}Error: Invalid port range${NC}" >&2
        exit 1
    fi

    # Log start
    log_json "portscan_start" "target=$target ports=$ports flags=$flags mode=legacy" 2>/dev/null || true

    # Perform nmap scan (legacy behavior)
    echo -e "${CYAN}Performing legacy nmap scan...${NC}"

    if command -v nmap >/dev/null 2>&1; then
        echo -e "${BLUE}nmap command: nmap $flags -p $ports $target${NC}\n"

        if nmap $flags -p "$ports" "$target"; then
            echo -e "\n${GREEN}✓ Legacy nmap scan completed${NC}"
        else
            echo -e "\n${YELLOW}⚠ nmap scan completed with warnings${NC}"
        fi
    else
        echo -e "${RED}❌ nmap is not installed${NC}"
        echo -e "${YELLOW}Falling back to manual port scanning...${NC}"
        manual_port_scan "$target" "$ports"
    fi

    # Log end
    log_json "portscan_end" "target=$target" 2>/dev/null || true
}

# Main function
main() {
    local target=""
    local ports="1-65535"
    local flags="-sS -sX"
    local scan_target=""

    # Parse command line arguments
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
                --ports)
                    if [ -z "${2:-}" ]; then
                        echo -e "${RED}Error: --ports requires a port range${NC}" >&2
                        exit 1
                    fi
                    ports="$2"
                    shift 2
                    ;;
                --flags)
                    if [ -z "${2:-}" ]; then
                        echo -e "${RED}Error: --flags requires nmap flags${NC}" >&2
                        exit 1
                    fi
                    flags="$2"
                    shift 2
                    ;;
                --scan)
                    if [ -z "${2:-}" ]; then
                        echo -e "${RED}Error: --scan requires a target${NC}" >&2
                        exit 1
                    fi
                    scan_target="$2"
                    shift 2
                    ;;
                *)
                    echo -e "${RED}Unknown option: $1${NC}" >&2
                    echo "Use -h for help." >&2
                    exit 1
                    ;;
            esac
        done

        # Handle quick scan mode
        if [ -n "$scan_target" ]; then
            echo -e "${GREEN}Quick Port Scan: $scan_target${NC}"

            if ! validate_target "$scan_target"; then
                echo -e "${RED}Error: Invalid target format${NC}" >&2
                exit 1
            fi

            # Log start
            log_json "portscan_start" "target=$scan_target mode=quick" 2>/dev/null || true

            # Perform quick comprehensive scan
            comprehensive_port_scan "$scan_target" "21,22,23,25,53,80,110,143,443,993,995,1433,3389,5432,8080,8443"

            # Log end
            log_json "portscan_end" "target=$scan_target" 2>/dev/null || true

            exit 0
        fi

        # Handle legacy mode
        if [ -n "$target" ]; then
            legacy_mode "$target" "$ports" "$flags"
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
        echo -e "${YELLOW}Some features may have reduced functionality.${NC}\n"
    fi

    # Check for advanced tools
    advanced_tools=()
    if command -v nmap >/dev/null 2>&1; then
        advanced_tools+=("nmap")
    fi
    if command -v telnet >/dev/null 2>&1; then
        advanced_tools+=("telnet")
    fi
    if command -v curl >/dev/null 2>&1; then
        advanced_tools+=("curl")
    fi

    if [ ${#advanced_tools[@]} -gt 0 ]; then
        echo -e "${GREEN}Advanced scanning tools available: ${advanced_tools[*]}${NC}\n"
    fi

    # Start interactive mode
    interactive_mode
}

# Run the main function with all arguments
main "$@"
