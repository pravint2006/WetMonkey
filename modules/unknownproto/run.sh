#!/usr/bin/env bash
# wetmonkey unknownproto – Interactive Unknown Protocol Analysis & Fingerprinting Suite v2.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$SCRIPT_DIR/../../"
source "$BASE_DIR/core/utils.sh"

# Configuration
VERSION="2.0"

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
    echo "║    🔍 WetMonkey Protocol Analysis Suite ║"
    echo "║         Interactive Mode v2.0           ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Show usage information
show_help() {
    echo "WetMonkey Unknown Protocol Analysis Module v${VERSION}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  -t, --target <target>   Target IP or hostname (legacy mode)"
    echo "  -p, --port <port>       Target port (legacy mode)"
    echo "  --tool <tool>           Tool to use: telnet|nc (legacy mode)"
    echo "  --analyze <target:port> Quick protocol analysis"
    echo ""
    echo "This module provides interactive unknown protocol analysis and fingerprinting."
    echo "Supported features: Protocol detection, banner grabbing, service fingerprinting"
    echo ""
    echo "Example:"
    echo "  $0                      # Run in interactive mode"
    echo "  $0 -h                   # Show this help"
    echo "  $0 --analyze 192.168.1.1:8080  # Quick protocol analysis"
    echo "  $0 -t 192.168.1.1 -p 8080  # Legacy mode"
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

# Function to validate port
validate_port() {
    local port="$1"
    if [[ $port =~ ^[0-9]+$ ]] && [ $port -ge 1 ] && [ $port -le 65535 ]; then
        return 0
    fi
    return 1
}

# Function to check if target:port is reachable
check_target_port_reachable() {
    local target="$1"
    local port="$2"
    echo -e "${YELLOW}Testing connectivity to $target:$port...${NC}" >&2

    if command -v nc >/dev/null 2>&1; then
        if timeout 5 nc -z -w 3 "$target" "$port" 2>/dev/null; then
            echo -e "${GREEN}✓ Target port is reachable${NC}" >&2
            return 0
        else
            echo -e "${YELLOW}⚠ Target port may not be reachable (continuing anyway)${NC}" >&2
            return 0  # Don't fail, just warn
        fi
    else
        echo -e "${YELLOW}⚠ Cannot test connectivity (nc not available)${NC}" >&2
        return 0
    fi
}

# Function to perform comprehensive protocol analysis
analyze_unknown_protocol() {
    local target="$1"
    local port="$2"

    echo -e "\n${GREEN}🔍 Analyzing unknown protocol...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Target: $target:$port${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    local protocol_indicators=()
    local banners_found=()
    local analysis_results=()

    # Step 1: Basic connectivity test
    echo -e "${CYAN}Step 1: Basic Connectivity Test${NC}"
    if ! check_target_port_reachable "$target" "$port"; then
        echo -e "${RED}❌ Cannot reach target, continuing with analysis anyway${NC}"
    fi

    # Step 2: Banner grabbing
    echo -e "\n${CYAN}Step 2: Banner Grabbing${NC}"
    local banner=""

    # Method 1: Try netcat banner grab
    if command -v nc >/dev/null 2>&1; then
        echo -e "${BLUE}  Using netcat for banner grabbing...${NC}"

        # Try different approaches for banner grabbing
        local nc_banner

        # Approach 1: Simple connection
        if nc_banner=$(timeout 10 bash -c "echo '' | nc $target $port" 2>/dev/null | head -5 | tr -d '\r' | head -c 500); then
            if [ -n "$nc_banner" ]; then
                echo -e "${GREEN}  ✓ Banner received (simple connection):${NC}"
                echo "$nc_banner" | sed 's/^/    /'
                banner="$nc_banner"
                banners_found+=("Simple connection: $nc_banner")
            fi
        fi

        # Approach 2: HTTP-style request
        if [ -z "$banner" ]; then
            if nc_banner=$(timeout 10 bash -c "echo -e 'GET / HTTP/1.0\r\n\r\n' | nc $target $port" 2>/dev/null | head -10 | tr -d '\r' | head -c 500); then
                if [ -n "$nc_banner" ]; then
                    echo -e "${GREEN}  ✓ Banner received (HTTP request):${NC}"
                    echo "$nc_banner" | sed 's/^/    /'
                    banner="$nc_banner"
                    banners_found+=("HTTP request: $nc_banner")
                fi
            fi
        fi

        # Approach 3: Generic probe
        if [ -z "$banner" ]; then
            if nc_banner=$(timeout 10 bash -c "echo -e 'HELLO\r\n' | nc $target $port" 2>/dev/null | head -5 | tr -d '\r' | head -c 500); then
                if [ -n "$nc_banner" ]; then
                    echo -e "${GREEN}  ✓ Banner received (generic probe):${NC}"
                    echo "$nc_banner" | sed 's/^/    /'
                    banner="$nc_banner"
                    banners_found+=("Generic probe: $nc_banner")
                fi
            fi
        fi
    fi

    # Method 2: Try telnet banner grab
    if [ -z "$banner" ] && command -v telnet >/dev/null 2>&1; then
        echo -e "${BLUE}  Using telnet for banner grabbing...${NC}"

        local telnet_banner
        if telnet_banner=$(timeout 10 bash -c "echo '' | telnet $target $port" 2>/dev/null | head -10 | grep -v "Trying\|Connected\|Escape" | tr -d '\r' | head -c 500); then
            if [ -n "$telnet_banner" ]; then
                echo -e "${GREEN}  ✓ Banner received (telnet):${NC}"
                echo "$telnet_banner" | sed 's/^/    /'
                banner="$telnet_banner"
                banners_found+=("Telnet: $telnet_banner")
            fi
        fi
    fi

    if [ -z "$banner" ]; then
        echo -e "${YELLOW}  ⚠ No banner received from target${NC}"
    fi

    # Step 3: Protocol identification
    echo -e "\n${CYAN}Step 3: Protocol Identification${NC}"

    if [ -n "$banner" ]; then
        echo -e "${BLUE}  Analyzing banner for protocol indicators...${NC}"

        # HTTP detection
        if [[ $banner == *"HTTP/"* ]] || [[ $banner == *"Server:"* ]] || [[ $banner == *"Content-Type:"* ]]; then
            protocol_indicators+=("HTTP - Web server protocol")
            analysis_results+=("Likely HTTP web server")
        fi

        # FTP detection
        if [[ $banner == *"220"* ]] && [[ $banner == *"FTP"* ]]; then
            protocol_indicators+=("FTP - File Transfer Protocol")
            analysis_results+=("Likely FTP server")
        fi

        # SMTP detection
        if [[ $banner == *"220"* ]] && [[ $banner == *"SMTP"* ]]; then
            protocol_indicators+=("SMTP - Simple Mail Transfer Protocol")
            analysis_results+=("Likely SMTP mail server")
        fi

        # SSH detection
        if [[ $banner == *"SSH-"* ]]; then
            protocol_indicators+=("SSH - Secure Shell Protocol")
            analysis_results+=("Likely SSH server")
        fi

        # Telnet detection
        if [[ $banner == *"login:"* ]] || [[ $banner == *"Username:"* ]]; then
            protocol_indicators+=("Telnet - Terminal protocol")
            analysis_results+=("Likely Telnet server")
        fi

        # POP3 detection
        if [[ $banner == *"+OK"* ]] && [[ $banner == *"POP"* ]]; then
            protocol_indicators+=("POP3 - Post Office Protocol")
            analysis_results+=("Likely POP3 mail server")
        fi

        # IMAP detection
        if [[ $banner == *"* OK"* ]] && [[ $banner == *"IMAP"* ]]; then
            protocol_indicators+=("IMAP - Internet Message Access Protocol")
            analysis_results+=("Likely IMAP mail server")
        fi

        # Generic database detection
        if [[ $banner == *"mysql"* ]] || [[ $banner == *"MySQL"* ]]; then
            protocol_indicators+=("MySQL - Database server")
            analysis_results+=("Likely MySQL database")
        fi

        if [[ $banner == *"PostgreSQL"* ]]; then
            protocol_indicators+=("PostgreSQL - Database server")
            analysis_results+=("Likely PostgreSQL database")
        fi

        # Custom/Unknown protocol
        if [ ${#protocol_indicators[@]} -eq 0 ]; then
            protocol_indicators+=("Unknown - Custom or proprietary protocol")
            analysis_results+=("Unknown or custom protocol detected")
        fi
    else
        echo -e "${YELLOW}  ⚠ No banner available for protocol identification${NC}"
        protocol_indicators+=("Silent service - No banner response")
        analysis_results+=("Silent service or filtered port")
    fi

    # Step 4: Port-based analysis
    echo -e "\n${CYAN}Step 4: Port-based Analysis${NC}"
    echo -e "${BLUE}  Analyzing port $port for common services...${NC}"

    case "$port" in
        21) analysis_results+=("Port 21 typically used for FTP") ;;
        22) analysis_results+=("Port 22 typically used for SSH") ;;
        23) analysis_results+=("Port 23 typically used for Telnet") ;;
        25) analysis_results+=("Port 25 typically used for SMTP") ;;
        53) analysis_results+=("Port 53 typically used for DNS") ;;
        80) analysis_results+=("Port 80 typically used for HTTP") ;;
        110) analysis_results+=("Port 110 typically used for POP3") ;;
        143) analysis_results+=("Port 143 typically used for IMAP") ;;
        443) analysis_results+=("Port 443 typically used for HTTPS") ;;
        993) analysis_results+=("Port 993 typically used for IMAPS") ;;
        995) analysis_results+=("Port 995 typically used for POP3S") ;;
        1433) analysis_results+=("Port 1433 typically used for SQL Server") ;;
        3306) analysis_results+=("Port 3306 typically used for MySQL") ;;
        3389) analysis_results+=("Port 3389 typically used for RDP") ;;
        5432) analysis_results+=("Port 5432 typically used for PostgreSQL") ;;
        8080) analysis_results+=("Port 8080 typically used for HTTP-Alt") ;;
        8443) analysis_results+=("Port 8443 typically used for HTTPS-Alt") ;;
        *)
            if [ $port -lt 1024 ]; then
                analysis_results+=("Port $port is in well-known range (1-1023)")
            elif [ $port -lt 49152 ]; then
                analysis_results+=("Port $port is in registered range (1024-49151)")
            else
                analysis_results+=("Port $port is in dynamic/private range (49152-65535)")
            fi
            ;;
    esac

    # Summary
    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}📊 Protocol Analysis Summary${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Target: $target:$port${NC}"
    echo -e "${CYAN}Banners Collected: ${#banners_found[@]}${NC}"
    echo -e "${CYAN}Protocol Indicators: ${#protocol_indicators[@]}${NC}"
    echo -e "${CYAN}Analysis Results: ${#analysis_results[@]}${NC}"

    if [ ${#banners_found[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}Banners Found:${NC}"
        for banner_info in "${banners_found[@]}"; do
            echo -e "  • $banner_info" | head -c 100
            echo ""
        done
    fi

    if [ ${#protocol_indicators[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}Protocol Indicators:${NC}"
        for indicator in "${protocol_indicators[@]}"; do
            echo -e "  • $indicator"
        done
    fi

    if [ ${#analysis_results[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}Analysis Results:${NC}"
        for result in "${analysis_results[@]}"; do
            echo -e "  • $result"
        done
    fi

    echo -e "\n${YELLOW}Security Recommendations:${NC}"
    echo -e "• Verify if this service should be exposed"
    echo -e "• Check for default credentials if applicable"
    echo -e "• Ensure service is updated to latest version"
    echo -e "• Consider implementing access controls"
    echo -e "• Monitor for unusual connection patterns"

    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    return 0
}

# Function to perform advanced protocol fingerprinting
advanced_protocol_fingerprinting() {
    local target="$1"
    local port="$2"

    echo -e "\n${GREEN}🔬 Advanced protocol fingerprinting...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Target: $target:$port${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    local fingerprint_results=()
    local probe_responses=()

    # Check connectivity first
    if ! check_target_port_reachable "$target" "$port"; then
        echo -e "${RED}❌ Target not reachable for fingerprinting${NC}"
        return 1
    fi

    # Probe 1: HTTP methods
    echo -e "${CYAN}Probe 1: HTTP Methods Testing${NC}"
    if command -v nc >/dev/null 2>&1; then
        local http_methods=("GET" "POST" "HEAD" "OPTIONS" "PUT" "DELETE")

        for method in "${http_methods[@]}"; do
            echo -ne "${BLUE}  Testing $method... ${NC}"

            local response
            if response=$(timeout 8 bash -c "echo -e '$method / HTTP/1.0\r\n\r\n' | nc $target $port" 2>/dev/null | head -3 | tr -d '\r'); then
                if [ -n "$response" ]; then
                    echo -e "${GREEN}Response received${NC}"
                    probe_responses+=("$method: $response")

                    # Analyze response
                    if [[ $response == *"HTTP/"* ]]; then
                        fingerprint_results+=("HTTP server responds to $method")
                    fi
                else
                    echo -e "${YELLOW}No response${NC}"
                fi
            else
                echo -e "${RED}Failed${NC}"
            fi
        done
    fi

    # Probe 2: Protocol-specific commands
    echo -e "\n${CYAN}Probe 2: Protocol-specific Commands${NC}"

    # FTP commands
    echo -ne "${BLUE}  Testing FTP commands... ${NC}"
    if command -v nc >/dev/null 2>&1; then
        local ftp_response
        if ftp_response=$(timeout 8 bash -c "echo -e 'USER anonymous\r\n' | nc $target $port" 2>/dev/null | head -3 | tr -d '\r'); then
            if [[ $ftp_response == *"220"* ]] || [[ $ftp_response == *"331"* ]]; then
                echo -e "${GREEN}FTP-like response${NC}"
                fingerprint_results+=("Responds to FTP USER command")
                probe_responses+=("FTP USER: $ftp_response")
            else
                echo -e "${YELLOW}Non-FTP response${NC}"
            fi
        else
            echo -e "${RED}No response${NC}"
        fi
    fi

    # SMTP commands
    echo -ne "${BLUE}  Testing SMTP commands... ${NC}"
    if command -v nc >/dev/null 2>&1; then
        local smtp_response
        if smtp_response=$(timeout 8 bash -c "echo -e 'HELO test\r\n' | nc $target $port" 2>/dev/null | head -3 | tr -d '\r'); then
            if [[ $smtp_response == *"250"* ]] || [[ $smtp_response == *"220"* ]]; then
                echo -e "${GREEN}SMTP-like response${NC}"
                fingerprint_results+=("Responds to SMTP HELO command")
                probe_responses+=("SMTP HELO: $smtp_response")
            else
                echo -e "${YELLOW}Non-SMTP response${NC}"
            fi
        else
            echo -e "${RED}No response${NC}"
        fi
    fi

    # POP3 commands
    echo -ne "${BLUE}  Testing POP3 commands... ${NC}"
    if command -v nc >/dev/null 2>&1; then
        local pop3_response
        if pop3_response=$(timeout 8 bash -c "echo -e 'USER test\r\n' | nc $target $port" 2>/dev/null | head -3 | tr -d '\r'); then
            if [[ $pop3_response == *"+OK"* ]] || [[ $pop3_response == *"-ERR"* ]]; then
                echo -e "${GREEN}POP3-like response${NC}"
                fingerprint_results+=("Responds to POP3 USER command")
                probe_responses+=("POP3 USER: $pop3_response")
            else
                echo -e "${YELLOW}Non-POP3 response${NC}"
            fi
        else
            echo -e "${RED}No response${NC}"
        fi
    fi

    # Probe 3: Binary protocol detection
    echo -e "\n${CYAN}Probe 3: Binary Protocol Detection${NC}"
    echo -ne "${BLUE}  Testing binary data response... ${NC}"

    if command -v nc >/dev/null 2>&1; then
        local binary_response
        if binary_response=$(timeout 8 bash -c "echo -ne '\x00\x01\x02\x03' | nc $target $port" 2>/dev/null | head -c 100 | xxd -p 2>/dev/null); then
            if [ -n "$binary_response" ]; then
                echo -e "${GREEN}Binary response received${NC}"
                fingerprint_results+=("Responds to binary data")
                probe_responses+=("Binary: $binary_response")
            else
                echo -e "${YELLOW}No binary response${NC}"
            fi
        else
            echo -e "${RED}Binary test failed${NC}"
        fi
    fi

    # Probe 4: Timing analysis
    echo -e "\n${CYAN}Probe 4: Timing Analysis${NC}"
    echo -ne "${BLUE}  Measuring response times... ${NC}"

    local response_times=()
    for i in {1..3}; do
        local start_time=$(date +%s%N)
        if timeout 5 nc -z "$target" "$port" 2>/dev/null; then
            local end_time=$(date +%s%N)
            local response_time=$(( (end_time - start_time) / 1000000 ))  # Convert to milliseconds
            response_times+=("$response_time")
        fi
    done

    if [ ${#response_times[@]} -gt 0 ]; then
        local avg_time=0
        for time in "${response_times[@]}"; do
            avg_time=$((avg_time + time))
        done
        avg_time=$((avg_time / ${#response_times[@]}))

        echo -e "${GREEN}Average: ${avg_time}ms${NC}"
        fingerprint_results+=("Average response time: ${avg_time}ms")

        if [ $avg_time -lt 10 ]; then
            fingerprint_results+=("Very fast response (likely local or high-performance)")
        elif [ $avg_time -lt 100 ]; then
            fingerprint_results+=("Fast response (likely network service)")
        else
            fingerprint_results+=("Slow response (may indicate processing or filtering)")
        fi
    else
        echo -e "${RED}No timing data${NC}"
    fi

    # Summary
    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}📊 Advanced Fingerprinting Summary${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Target: $target:$port${NC}"
    echo -e "${CYAN}Probes Performed: 4${NC}"
    echo -e "${CYAN}Responses Collected: ${#probe_responses[@]}${NC}"
    echo -e "${CYAN}Fingerprint Results: ${#fingerprint_results[@]}${NC}"

    if [ ${#probe_responses[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}Probe Responses:${NC}"
        for response in "${probe_responses[@]}"; do
            echo -e "  • $response" | head -c 150
            echo ""
        done
    fi

    if [ ${#fingerprint_results[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}Fingerprint Analysis:${NC}"
        for result in "${fingerprint_results[@]}"; do
            echo -e "  • $result"
        done
    else
        echo -e "\n${RED}❌ NO FINGERPRINT DATA COLLECTED${NC}"
        echo -e "${YELLOW}Possible reasons:${NC}"
        echo -e "• Service is heavily filtered or firewalled"
        echo -e "• Custom protocol with no standard responses"
        echo -e "• Service requires specific authentication"
        echo -e "• Port is closed or service is down"
    fi

    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    return 0
}

# Educational information function
show_educational_info() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║      📚 Protocol Analysis Guide         ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}\n"

    echo -e "${GREEN}What is Protocol Analysis?${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "Protocol analysis is the process of examining network communications"
    echo -e "to identify, understand, and fingerprint unknown or custom protocols."
    echo -e "It's essential for security assessment, network troubleshooting,"
    echo -e "and reverse engineering of proprietary systems.\n"

    echo -e "${GREEN}Common Protocol Analysis Techniques${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}1. Banner Grabbing${NC}"
    echo -e "   • Connect to service and capture initial response"
    echo -e "   • Reveals service type, version, and configuration"
    echo -e "   • Most effective for text-based protocols"
    echo -e "${YELLOW}2. Protocol Probing${NC}"
    echo -e "   • Send specific commands or data patterns"
    echo -e "   • Analyze responses to identify protocol type"
    echo -e "   • Test various protocol-specific commands"
    echo -e "${YELLOW}3. Traffic Analysis${NC}"
    echo -e "   • Monitor network traffic patterns"
    echo -e "   • Analyze packet timing and sizes"
    echo -e "   • Identify communication patterns"
    echo -e "${YELLOW}4. Fingerprinting${NC}"
    echo -e "   • Compare responses against known signatures"
    echo -e "   • Identify specific implementations or versions"
    echo -e "   • Build behavioral profiles of services\n"

    echo -e "${GREEN}Protocol Categories${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Text-based Protocols:${NC}"
    echo -e "• HTTP, SMTP, FTP, POP3, IMAP"
    echo -e "• Human-readable commands and responses"
    echo -e "• Easier to analyze and understand"
    echo -e "• Often use ASCII or UTF-8 encoding"
    echo -e "${CYAN}Binary Protocols:${NC}"
    echo -e "• Custom applications, databases, games"
    echo -e "• Efficient but harder to analyze"
    echo -e "• Require reverse engineering techniques"
    echo -e "• May use compression or encryption"
    echo -e "${CYAN}Hybrid Protocols:${NC}"
    echo -e "• Combination of text and binary elements"
    echo -e "• Examples: HTTP with binary payloads"
    echo -e "• Require multiple analysis approaches\n"

    echo -e "${GREEN}Analysis Tools and Methods${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}1. netcat (nc):${NC}"
    echo -e "   • Swiss army knife for network connections"
    echo -e "   • Banner grabbing and manual protocol testing"
    echo -e "   • Simple and widely available"
    echo -e "${CYAN}2. telnet:${NC}"
    echo -e "   • Interactive terminal connections"
    echo -e "   • Good for text-based protocol exploration"
    echo -e "   • Manual command testing"
    echo -e "${CYAN}3. nmap:${NC}"
    echo -e "   • Service detection and version scanning"
    echo -e "   • Built-in protocol fingerprints"
    echo -e "   • Automated service identification"
    echo -e "${CYAN}4. Wireshark:${NC}"
    echo -e "   • Comprehensive packet analysis"
    echo -e "   • Protocol dissectors and decoders"
    echo -e "   • Deep traffic inspection capabilities"
    echo -e "${CYAN}5. Custom Scripts:${NC}"
    echo -e "   • Automated probing and analysis"
    echo -e "   • Protocol-specific testing tools"
    echo -e "   • Behavioral analysis scripts\n"

    echo -e "${GREEN}Security Applications${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Penetration Testing:${NC}"
    echo -e "• Identify unknown services and applications"
    echo -e "• Discover custom or proprietary protocols"
    echo -e "• Find potential attack vectors"
    echo -e "${CYAN}Network Security Assessment:${NC}"
    echo -e "• Inventory network services and protocols"
    echo -e "• Identify unauthorized or rogue services"
    echo -e "• Assess protocol security implementations"
    echo -e "${CYAN}Incident Response:${NC}"
    echo -e "• Analyze suspicious network communications"
    echo -e "• Identify malware command and control"
    echo -e "• Understand attack methodologies"
    echo -e "${CYAN}Reverse Engineering:${NC}"
    echo -e "• Understand proprietary protocol formats"
    echo -e "• Develop custom analysis tools"
    echo -e "• Create protocol documentation\n"

    echo -e "${GREEN}Common Protocol Indicators${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}HTTP Indicators:${NC}"
    echo -e "• 'HTTP/' in response headers"
    echo -e "• 'Server:' header fields"
    echo -e "• Status codes (200, 404, 500, etc.)"
    echo -e "${CYAN}Mail Protocol Indicators:${NC}"
    echo -e "• SMTP: '220' greeting, 'HELO' command"
    echo -e "• POP3: '+OK' responses, 'USER' command"
    echo -e "• IMAP: '* OK' responses, folder operations"
    echo -e "${CYAN}Database Indicators:${NC}"
    echo -e "• MySQL: Version strings, authentication"
    echo -e "• PostgreSQL: Protocol version, SSL support"
    echo -e "• Custom: Proprietary authentication methods"
    echo -e "${CYAN}Binary Protocol Indicators:${NC}"
    echo -e "• Fixed-length headers or magic bytes"
    echo -e "• Structured data formats"
    echo -e "• Compression or encryption signatures\n"

    echo -e "${GREEN}Analysis Best Practices${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}✓ Systematic Approach:${NC}"
    echo -e "  • Start with basic connectivity testing"
    echo -e "  • Progress from simple to complex probes"
    echo -e "  • Document all findings and responses"
    echo -e "${GREEN}✓ Multiple Techniques:${NC}"
    echo -e "  • Use various tools and methods"
    echo -e "  • Cross-validate findings"
    echo -e "  • Consider different protocol layers"
    echo -e "${GREEN}✓ Safety Considerations:${NC}"
    echo -e "  • Avoid sending potentially harmful data"
    echo -e "  • Respect rate limits and timeouts"
    echo -e "  • Monitor for defensive responses"
    echo -e "${GREEN}✓ Documentation:${NC}"
    echo -e "  • Record all commands and responses"
    echo -e "  • Create protocol behavior profiles"
    echo -e "  • Build reusable analysis scripts\n"

    echo -e "${GREEN}Legal and Ethical Considerations${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${RED}⚠ IMPORTANT:${NC} Only analyze protocols on systems you own or have permission"
    echo -e "${RED}⚠ LEGAL:${NC} Unauthorized protocol analysis may violate computer crime laws"
    echo -e "${RED}⚠ ETHICAL:${NC} Use protocol analysis for legitimate security purposes only"
    echo -e "${RED}⚠ PROFESSIONAL:${NC} Document findings and follow responsible disclosure"
    echo -e "${RED}⚠ PRIVACY:${NC} Respect data privacy and confidentiality requirements\n"
}

# Main interactive function
interactive_mode() {
    while true; do
        show_banner

        echo -e "${GREEN}Welcome to WetMonkey Protocol Analysis Suite!${NC}"
        echo -e "${YELLOW}This tool helps analyze and fingerprint unknown network protocols.${NC}\n"
        echo -e "${RED}⚠ WARNING: Only analyze systems you own or have permission to test!${NC}\n"

        # Step 1: Analysis type selection
        echo -e "${GREEN}Step 1: Analysis Type${NC}"
        echo -e "Choose the type of protocol analysis:"
        echo -e "  ${YELLOW}1)${NC} Basic Analysis - Protocol identification and banner grabbing"
        echo -e "  ${YELLOW}2)${NC} Advanced Fingerprinting - Comprehensive protocol probing"
        echo -e "  ${YELLOW}3)${NC} Educational Information - Learn about protocol analysis"

        local analysis_type
        while true; do
            choice=$(simple_input "Select analysis type (1-3)")
            case "$choice" in
                "1") analysis_type="basic"; break ;;
                "2") analysis_type="advanced"; break ;;
                "3") analysis_type="educational"; break ;;
                *) echo -e "${RED}Please select a number between 1-3${NC}" ;;
            esac
        done

        case "$analysis_type" in
            "educational")
                # Show educational information
                show_educational_info
                echo -e "\n${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;

            *)
                # Protocol analysis
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

                local port
                while true; do
                    port=$(simple_input "Target port")
                    if [ -z "$port" ]; then
                        echo -e "${RED}Port is required!${NC}"
                        continue
                    fi

                    if validate_port "$port"; then
                        break
                    else
                        echo -e "${RED}Please enter a valid port (1-65535)${NC}"
                    fi
                done

                # Check connectivity
                check_target_port_reachable "$target" "$port"

                # Step 3: Execution summary
                echo -e "\n${GREEN}Step 3: Analysis Summary${NC}"
                echo -e "${BLUE}═══════════════════════════════════════${NC}"
                echo -e "${CYAN}Target: $target:$port${NC}"
                echo -e "${CYAN}Analysis Type: $analysis_type${NC}"
                echo -e "${BLUE}═══════════════════════════════════════${NC}"

                echo -e "\n${RED}⚠ WARNING: This will perform protocol analysis against the target!${NC}"
                echo -e "${RED}⚠ Only proceed if you have authorization to test this target!${NC}"

                if ask_yes_no "Start protocol analysis?" "n"; then
                    echo -e "\n${CYAN}Starting protocol analysis...${NC}"

                    # Log start
                    log_json "unknownproto_start" "target=$target port=$port type=$analysis_type" 2>/dev/null || true

                    # Perform analysis based on type
                    case "$analysis_type" in
                        "basic")
                            analyze_unknown_protocol "$target" "$port"
                            ;;
                        "advanced")
                            analyze_unknown_protocol "$target" "$port"
                            echo -e "\n${MAGENTA}═══ Advanced Fingerprinting ═══${NC}"
                            advanced_protocol_fingerprinting "$target" "$port"
                            ;;
                    esac

                    # Log end
                    log_json "unknownproto_end" "target=$target port=$port type=$analysis_type" 2>/dev/null || true
                else
                    echo -e "${YELLOW}Protocol analysis cancelled.${NC}"
                fi
                ;;
        esac

        echo -e "\n${YELLOW}Press Enter to continue...${NC}"
        read -r

        if ! ask_yes_no "Perform another protocol analysis?" "y"; then
            break
        fi
    done
}

# Legacy mode function
legacy_mode() {
    local target="$1"
    local port="$2"
    local tool="$3"

    echo -e "${YELLOW}Running in legacy mode...${NC}"
    echo -e "${RED}⚠ WARNING: Only test targets you own or have permission to test!${NC}\n"

    # Validate parameters
    if ! validate_target "$target"; then
        echo -e "${RED}Error: Invalid target format${NC}" >&2
        exit 1
    fi

    if ! validate_port "$port"; then
        echo -e "${RED}Error: Invalid port${NC}" >&2
        exit 1
    fi

    # Log start
    log_json "unknownproto_start" "target=$target port=$port tool=$tool mode=legacy" 2>/dev/null || true

    # Perform legacy protocol test
    echo -e "${CYAN}Performing legacy protocol test...${NC}"
    echo -e "${BLUE}Target: $target:$port${NC}"
    echo -e "${BLUE}Tool: $tool${NC}\n"

    case "$tool" in
        "telnet")
            if command -v telnet >/dev/null 2>&1; then
                echo -e "${BLUE}Using telnet to connect...${NC}"
                printf "\n" | timeout 10 telnet "$target" "$port" || true
            else
                echo -e "${RED}❌ telnet is not available${NC}"
                exit 1
            fi
            ;;
        "nc")
            if command -v nc >/dev/null 2>&1; then
                echo -e "${BLUE}Using netcat to connect...${NC}"
                timeout 10 nc -vz "$target" "$port" || true
            else
                echo -e "${RED}❌ netcat is not available${NC}"
                exit 1
            fi
            ;;
        *)
            echo -e "${RED}Error: Unknown tool '$tool' (use telnet or nc)${NC}" >&2
            exit 1
            ;;
    esac

    # Log end
    log_json "unknownproto_end" "target=$target port=$port tool=$tool" 2>/dev/null || true
}

# Main function
main() {
    local target=""
    local port=""
    local tool="telnet"
    local analyze_target=""

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
                -p|--port)
                    if [ -z "${2:-}" ]; then
                        echo -e "${RED}Error: -p requires a port${NC}" >&2
                        exit 1
                    fi
                    port="$2"
                    shift 2
                    ;;
                --tool)
                    if [ -z "${2:-}" ]; then
                        echo -e "${RED}Error: --tool requires a tool name${NC}" >&2
                        exit 1
                    fi
                    tool="$2"
                    shift 2
                    ;;
                --analyze)
                    if [ -z "${2:-}" ]; then
                        echo -e "${RED}Error: --analyze requires target:port${NC}" >&2
                        exit 1
                    fi
                    analyze_target="$2"
                    shift 2
                    ;;
                *)
                    echo -e "${RED}Unknown option: $1${NC}" >&2
                    echo "Use -h for help." >&2
                    exit 1
                    ;;
            esac
        done

        # Handle quick analyze mode
        if [ -n "$analyze_target" ]; then
            echo -e "${GREEN}Quick Protocol Analysis: $analyze_target${NC}"

            # Parse target:port
            if [[ $analyze_target == *":"* ]]; then
                local quick_target=$(echo "$analyze_target" | cut -d':' -f1)
                local quick_port=$(echo "$analyze_target" | cut -d':' -f2)

                if ! validate_target "$quick_target"; then
                    echo -e "${RED}Error: Invalid target format${NC}" >&2
                    exit 1
                fi

                if ! validate_port "$quick_port"; then
                    echo -e "${RED}Error: Invalid port${NC}" >&2
                    exit 1
                fi

                # Log start
                log_json "unknownproto_start" "target=$quick_target port=$quick_port mode=quick" 2>/dev/null || true

                # Perform quick analysis
                analyze_unknown_protocol "$quick_target" "$quick_port"

                # Log end
                log_json "unknownproto_end" "target=$quick_target port=$quick_port" 2>/dev/null || true

                exit 0
            else
                echo -e "${RED}Error: --analyze requires target:port format${NC}" >&2
                exit 1
            fi
        fi

        # Handle legacy mode
        if [ -n "$target" ] && [ -n "$port" ]; then
            legacy_mode "$target" "$port" "$tool"
            exit $?
        fi

        # If we get here, invalid combination of arguments
        echo -e "${RED}Error: Invalid argument combination${NC}" >&2
        echo "Use -h for help or run without arguments for interactive mode." >&2
        exit 1
    fi

    # Check dependencies for interactive mode
    missing_deps=()
    if ! command -v nc >/dev/null 2>&1; then
        missing_deps+=("nc (netcat)")
    fi
    if ! command -v telnet >/dev/null 2>&1; then
        missing_deps+=("telnet")
    fi

    if [ ${#missing_deps[@]} -gt 0 ]; then
        echo -e "${YELLOW}Warning: Some tools are missing: ${missing_deps[*]}${NC}"
        echo -e "${YELLOW}Some features may have reduced functionality.${NC}\n"
    fi

    # Check for advanced tools
    advanced_tools=()
    if command -v nc >/dev/null 2>&1; then
        advanced_tools+=("netcat")
    fi
    if command -v telnet >/dev/null 2>&1; then
        advanced_tools+=("telnet")
    fi
    if command -v xxd >/dev/null 2>&1; then
        advanced_tools+=("xxd")
    fi

    if [ ${#advanced_tools[@]} -gt 0 ]; then
        echo -e "${GREEN}Protocol analysis tools available: ${advanced_tools[*]}${NC}\n"
    fi

    # Start interactive mode
    interactive_mode
}

# Run the main function with all arguments
main "$@"
