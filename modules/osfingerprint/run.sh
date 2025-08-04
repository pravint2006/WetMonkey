#!/usr/bin/env bash
# wetmonkey osfingerprint – Interactive OS Fingerprinting & Detection Suite v2.0
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
    echo "║    🔍 WetMonkey OS Fingerprinting Suite  ║"
    echo "║         Interactive Mode v2.0            ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Show usage information
show_help() {
    echo -e "${GREEN}WetMonkey OS Fingerprinting Module v${VERSION}${NC}"
    echo ""
    echo -e "${CYAN}Usage:${NC} $0 [OPTIONS]"
    echo ""
    echo -e "${CYAN}Options:${NC}"
    echo "  -h, --help              Show this help message"
    echo "  -t, --target <target>   Target IP or hostname (legacy mode)"
    echo "  --scan <target>         Quick OS fingerprint scan"
    echo ""
    echo "This module provides interactive OS fingerprinting and detection."
    echo "Supported features: Multiple fingerprinting methods, stealth scanning, analysis"
    echo ""
    echo -e "${YELLOW}Example:${NC}"
    echo "  $0                      # Run in interactive mode"
    echo "  $0 -h                   # Show this help"
    echo "  $0 --scan 192.168.1.1   # Quick OS scan"
    echo "  $0 -t 192.168.1.1       # Legacy mode"
    echo ""
    echo -e "${RED}Note:${NC} This tool is for authorized security testing and research only!"
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

# Function to perform nmap OS fingerprinting
nmap_os_fingerprint() {
    local target="$1"
    local stealth="${2:-false}"

    echo -e "\n${GREEN}🔍 Performing nmap OS fingerprinting...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Target: $target${NC}"
    echo -e "${YELLOW}Stealth mode: $([ "$stealth" = "true" ] && echo "Enabled" || echo "Disabled")${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    if ! command -v nmap >/dev/null 2>&1; then
        echo -e "${RED}❌ nmap is not installed${NC}"
        echo -e "${YELLOW}Please install nmap: sudo apt-get install nmap${NC}"
        return 1
    fi

    # Build nmap command
    local nmap_cmd="nmap"
    local nmap_args=()

    if [ "$stealth" = "true" ]; then
        nmap_args+=("-sS")  # SYN stealth scan
        nmap_args+=("-T2")  # Polite timing
        echo -e "${CYAN}Using stealth SYN scan with polite timing${NC}"
    else
        nmap_args+=("-T4")  # Aggressive timing
        echo -e "${CYAN}Using standard scan with aggressive timing${NC}"
    fi

    nmap_args+=("-O")       # OS detection
    nmap_args+=("--osscan-guess")  # Guess OS more aggressively
    nmap_args+=("-v")       # Verbose output
    nmap_args+=("$target")

    echo -e "${BLUE}Command: $nmap_cmd ${nmap_args[*]}${NC}\n"

    # Execute nmap scan
    local nmap_output
    local nmap_exit_code

    echo -e "${CYAN}Starting nmap OS detection...${NC}"
    if nmap_output=$("$nmap_cmd" "${nmap_args[@]}" 2>&1); then
        nmap_exit_code=0
        echo -e "${GREEN}✓ nmap scan completed successfully${NC}"
    else
        nmap_exit_code=$?
        echo -e "${YELLOW}⚠ nmap scan completed with warnings (exit code: $nmap_exit_code)${NC}"
    fi

    # Parse and display results
    echo -e "\n${GREEN}📊 nmap OS Detection Results${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    # Extract OS information
    local os_matches
    os_matches=$(echo "$nmap_output" | grep -A 10 "OS details:" | head -10)

    if [ -n "$os_matches" ]; then
        echo -e "${CYAN}OS Detection Results:${NC}"
        echo "$os_matches" | sed 's/^/  /'
    else
        # Try alternative parsing
        local running_info
        running_info=$(echo "$nmap_output" | grep "Running:" | head -5)
        if [ -n "$running_info" ]; then
            echo -e "${CYAN}Running OS Information:${NC}"
            echo "$running_info" | sed 's/^/  /'
        fi

        local os_cpe
        os_cpe=$(echo "$nmap_output" | grep "OS CPE:" | head -5)
        if [ -n "$os_cpe" ]; then
            echo -e "${CYAN}OS CPE Information:${NC}"
            echo "$os_cpe" | sed 's/^/  /'
        fi
    fi

    # Extract port information
    local open_ports
    open_ports=$(echo "$nmap_output" | grep "^[0-9].*open" | head -10)
    if [ -n "$open_ports" ]; then
        echo -e "\n${CYAN}Open Ports Detected:${NC}"
        echo "$open_ports" | sed 's/^/  /'
    fi

    # Extract MAC address information
    local mac_info
    mac_info=$(echo "$nmap_output" | grep "MAC Address:" | head -3)
    if [ -n "$mac_info" ]; then
        echo -e "\n${CYAN}MAC Address Information:${NC}"
        echo "$mac_info" | sed 's/^/  /'
    fi

    # Show confidence information
    local confidence_info
    confidence_info=$(echo "$nmap_output" | grep -i "confidence\|accuracy" | head -5)
    if [ -n "$confidence_info" ]; then
        echo -e "\n${CYAN}Confidence Information:${NC}"
        echo "$confidence_info" | sed 's/^/  /'
    fi

    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    return $nmap_exit_code
}

# Function to perform manual OS fingerprinting techniques
manual_os_fingerprint() {
    local target="$1"

    echo -e "\n${GREEN}🔍 Performing manual OS fingerprinting...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Target: $target${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    local os_indicators=()
    local confidence_score=0

    # Test 1: TTL Analysis
    echo -e "${CYAN}Test 1: TTL (Time To Live) Analysis${NC}"
    local ttl_output
    if ttl_output=$(ping -c 3 -W 3 "$target" 2>/dev/null | grep "ttl=" | head -1); then
        local ttl_value
        ttl_value=$(echo "$ttl_output" | grep -o "ttl=[0-9]*" | cut -d'=' -f2)

        if [ -n "$ttl_value" ]; then
            echo -e "${BLUE}  TTL Value: $ttl_value${NC}"

            # Analyze TTL value
            if [ "$ttl_value" -ge 240 ] && [ "$ttl_value" -le 255 ]; then
                os_indicators+=("Windows (TTL ~255)")
                ((confidence_score += 3))
            elif [ "$ttl_value" -ge 60 ] && [ "$ttl_value" -le 64 ]; then
                os_indicators+=("Linux/Unix (TTL ~64)")
                ((confidence_score += 3))
            elif [ "$ttl_value" -ge 120 ] && [ "$ttl_value" -le 128 ]; then
                os_indicators+=("Windows (TTL ~128)")
                ((confidence_score += 3))
            elif [ "$ttl_value" -ge 250 ] && [ "$ttl_value" -le 255 ]; then
                os_indicators+=("Cisco/Network Device (TTL ~255)")
                ((confidence_score += 2))
            else
                os_indicators+=("Unknown OS (TTL $ttl_value)")
                ((confidence_score += 1))
            fi
        else
            echo -e "${YELLOW}  ⚠ Could not extract TTL value${NC}"
        fi
    else
        echo -e "${YELLOW}  ⚠ Ping failed or filtered${NC}"
    fi

    # Test 2: TCP Window Size Analysis (if nmap is available)
    echo -e "\n${CYAN}Test 2: TCP Window Size Analysis${NC}"
    if command -v nmap >/dev/null 2>&1; then
        local window_output
        if window_output=$(nmap -sS -p 80,443,22,21 --packet-trace "$target" 2>/dev/null | grep "window" | head -3); then
            if [ -n "$window_output" ]; then
                echo -e "${BLUE}  TCP Window Information:${NC}"
                echo "$window_output" | sed 's/^/    /'
                os_indicators+=("TCP window analysis available")
                ((confidence_score += 1))
            else
                echo -e "${YELLOW}  ⚠ No TCP window information available${NC}"
            fi
        else
            echo -e "${YELLOW}  ⚠ TCP window analysis failed${NC}"
        fi
    else
        echo -e "${YELLOW}  ⚠ nmap not available for TCP window analysis${NC}"
    fi

    # Test 3: HTTP Server Banner Detection
    echo -e "\n${CYAN}Test 3: HTTP Server Banner Detection${NC}"
    local http_ports=(80 443 8080 8443)
    local banner_found=false

    for port in "${http_ports[@]}"; do
        echo -e "${BLUE}  Testing port $port...${NC}"
        local banner_output
        if banner_output=$(curl -I --connect-timeout 5 --max-time 10 "http://$target:$port" 2>/dev/null | grep -i "server:" | head -1); then
            if [ -n "$banner_output" ]; then
                echo -e "${GREEN}    ✓ $banner_output${NC}"
                banner_found=true

                # Analyze server banner
                if [[ $banner_output == *"IIS"* ]]; then
                    os_indicators+=("Windows (IIS Server)")
                    ((confidence_score += 4))
                elif [[ $banner_output == *"Apache"* ]]; then
                    if [[ $banner_output == *"Ubuntu"* ]]; then
                        os_indicators+=("Ubuntu Linux (Apache)")
                        ((confidence_score += 4))
                    elif [[ $banner_output == *"CentOS"* ]]; then
                        os_indicators+=("CentOS Linux (Apache)")
                        ((confidence_score += 4))
                    else
                        os_indicators+=("Linux/Unix (Apache)")
                        ((confidence_score += 3))
                    fi
                elif [[ $banner_output == *"nginx"* ]]; then
                    os_indicators+=("Linux/Unix (nginx)")
                    ((confidence_score += 3))
                elif [[ $banner_output == *"lighttpd"* ]]; then
                    os_indicators+=("Linux/Unix (lighttpd)")
                    ((confidence_score += 3))
                fi
                break
            fi
        fi
    done

    if [ "$banner_found" = false ]; then
        echo -e "${YELLOW}  ⚠ No HTTP server banners detected${NC}"
    fi

    # Test 4: SSH Banner Detection
    echo -e "\n${CYAN}Test 4: SSH Banner Detection${NC}"
    local ssh_output
    if ssh_output=$(timeout 10 nc "$target" 22 2>/dev/null | head -1); then
        if [ -n "$ssh_output" ]; then
            echo -e "${GREEN}  ✓ SSH Banner: $ssh_output${NC}"

            # Analyze SSH banner
            if [[ $ssh_output == *"OpenSSH"* ]]; then
                if [[ $ssh_output == *"Ubuntu"* ]]; then
                    os_indicators+=("Ubuntu Linux (OpenSSH)")
                    ((confidence_score += 4))
                elif [[ $ssh_output == *"Debian"* ]]; then
                    os_indicators+=("Debian Linux (OpenSSH)")
                    ((confidence_score += 4))
                else
                    os_indicators+=("Linux/Unix (OpenSSH)")
                    ((confidence_score += 3))
                fi
            fi
        else
            echo -e "${YELLOW}  ⚠ SSH port open but no banner received${NC}"
        fi
    else
        echo -e "${YELLOW}  ⚠ SSH port closed or filtered${NC}"
    fi

    # Summary
    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}📊 Manual OS Fingerprinting Summary${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Target: $target${NC}"
    echo -e "${CYAN}Tests performed: 4${NC}"
    echo -e "${CYAN}Confidence score: $confidence_score/15${NC}"

    if [ ${#os_indicators[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}OS Indicators Found:${NC}"
        for indicator in "${os_indicators[@]}"; do
            echo -e "  • $indicator"
        done

        # Provide confidence assessment
        if [ $confidence_score -ge 10 ]; then
            echo -e "\n${GREEN}🎯 HIGH CONFIDENCE: Strong OS identification${NC}"
        elif [ $confidence_score -ge 6 ]; then
            echo -e "\n${YELLOW}🎯 MEDIUM CONFIDENCE: Probable OS identification${NC}"
        elif [ $confidence_score -ge 3 ]; then
            echo -e "\n${BLUE}🎯 LOW CONFIDENCE: Possible OS identification${NC}"
        else
            echo -e "\n${RED}🎯 VERY LOW CONFIDENCE: Insufficient data for OS identification${NC}"
        fi
    else
        echo -e "\n${RED}❌ NO OS INDICATORS FOUND${NC}"
        echo -e "${YELLOW}The target may be heavily filtered or unreachable${NC}"
    fi

    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    return 0
}

# Function to perform comprehensive OS fingerprinting
comprehensive_os_fingerprint() {
    local target="$1"
    local stealth="${2:-false}"

    echo -e "\n${GREEN}🔍 Starting comprehensive OS fingerprinting...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Target: $target${NC}"
    echo -e "${YELLOW}Stealth mode: $([ "$stealth" = "true" ] && echo "Enabled" || echo "Disabled")${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    local total_tests=0
    local successful_tests=0
    local os_results=()

    # Test 1: nmap OS fingerprinting
    ((total_tests++))
    echo -e "${MAGENTA}═══ Test 1: nmap OS Detection ═══${NC}"
    if nmap_os_fingerprint "$target" "$stealth"; then
        ((successful_tests++))
        os_results+=("nmap OS detection completed")
    else
        os_results+=("nmap OS detection failed or limited")
    fi

    # Test 2: Manual fingerprinting techniques
    ((total_tests++))
    echo -e "\n${MAGENTA}═══ Test 2: Manual OS Fingerprinting ═══${NC}"
    if manual_os_fingerprint "$target"; then
        ((successful_tests++))
        os_results+=("Manual fingerprinting completed")
    else
        os_results+=("Manual fingerprinting failed")
    fi

    # Test 3: Additional service detection
    ((total_tests++))
    echo -e "\n${MAGENTA}═══ Test 3: Service-based OS Detection ═══${NC}"
    if service_based_detection "$target"; then
        ((successful_tests++))
        os_results+=("Service-based detection completed")
    else
        os_results+=("Service-based detection failed")
    fi

    # Final comprehensive summary
    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}🎯 Comprehensive OS Fingerprinting Summary${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Target: $target${NC}"
    echo -e "${CYAN}Total tests: $total_tests${NC}"
    echo -e "${CYAN}Successful tests: $successful_tests${NC}"
    echo -e "${CYAN}Success rate: $(( (successful_tests * 100) / total_tests ))%${NC}"

    if [ ${#os_results[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}Test Results:${NC}"
        for result in "${os_results[@]}"; do
            echo -e "  • $result"
        done
    fi

    echo -e "\n${YELLOW}Fingerprinting Recommendations:${NC}"
    echo -e "• Combine multiple techniques for better accuracy"
    echo -e "• Use stealth mode to avoid detection"
    echo -e "• Cross-reference results from different methods"
    echo -e "• Consider network filtering and firewalls"
    echo -e "• Verify results with additional reconnaissance"

    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    return 0
}

# Function to perform service-based OS detection
service_based_detection() {
    local target="$1"

    echo -e "${CYAN}Performing service-based OS detection...${NC}"
    echo -e "${YELLOW}Target: $target${NC}\n"

    local services_found=()
    local os_hints=()

    # Check common services and their OS implications
    local common_ports=(21 22 23 25 53 80 110 143 443 993 995)

    echo -e "${BLUE}Scanning common service ports...${NC}"

    for port in "${common_ports[@]}"; do
        echo -ne "${CYAN}  Testing port $port... ${NC}"

        if timeout 5 nc -z "$target" "$port" 2>/dev/null; then
            echo -e "${GREEN}Open${NC}"
            services_found+=("$port")

            # Analyze service implications
            case "$port" in
                21)  # FTP
                    os_hints+=("FTP service (common on all OS)")
                    ;;
                22)  # SSH
                    os_hints+=("SSH service (likely Linux/Unix)")
                    ;;
                23)  # Telnet
                    os_hints+=("Telnet service (legacy systems)")
                    ;;
                25)  # SMTP
                    os_hints+=("SMTP service (mail server)")
                    ;;
                53)  # DNS
                    os_hints+=("DNS service (server role)")
                    ;;
                80)  # HTTP
                    os_hints+=("HTTP service (web server)")
                    ;;
                110) # POP3
                    os_hints+=("POP3 service (mail server)")
                    ;;
                143) # IMAP
                    os_hints+=("IMAP service (mail server)")
                    ;;
                443) # HTTPS
                    os_hints+=("HTTPS service (web server)")
                    ;;
                993) # IMAPS
                    os_hints+=("IMAPS service (secure mail)")
                    ;;
                995) # POP3S
                    os_hints+=("POP3S service (secure mail)")
                    ;;
            esac
        else
            echo -e "${RED}Closed/Filtered${NC}"
        fi
    done

    # Check for Windows-specific services
    echo -e "\n${BLUE}Checking Windows-specific services...${NC}"
    local windows_ports=(135 139 445 1433 3389)
    local windows_services=0

    for port in "${windows_ports[@]}"; do
        echo -ne "${CYAN}  Testing port $port... ${NC}"

        if timeout 5 nc -z "$target" "$port" 2>/dev/null; then
            echo -e "${GREEN}Open${NC}"
            ((windows_services++))
            services_found+=("$port")

            case "$port" in
                135) os_hints+=("RPC service (Windows)") ;;
                139) os_hints+=("NetBIOS service (Windows)") ;;
                445) os_hints+=("SMB service (Windows/Samba)") ;;
                1433) os_hints+=("SQL Server (Windows)") ;;
                3389) os_hints+=("RDP service (Windows)") ;;
            esac
        else
            echo -e "${RED}Closed/Filtered${NC}"
        fi
    done

    # Analyze results
    echo -e "\n${GREEN}📊 Service-based Detection Results${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Total open ports: ${#services_found[@]}${NC}"
    echo -e "${CYAN}Windows-specific services: $windows_services${NC}"

    if [ ${#os_hints[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}Service-based OS Hints:${NC}"
        for hint in "${os_hints[@]}"; do
            echo -e "  • $hint"
        done

        # Provide OS assessment based on services
        if [ $windows_services -ge 2 ]; then
            echo -e "\n${GREEN}🎯 LIKELY WINDOWS: Multiple Windows-specific services detected${NC}"
        elif [ $windows_services -eq 1 ]; then
            echo -e "\n${YELLOW}🎯 POSSIBLY WINDOWS: One Windows-specific service detected${NC}"
        else
            # Check for Linux/Unix indicators
            local unix_indicators=0
            for hint in "${os_hints[@]}"; do
                if [[ $hint == *"SSH"* ]] || [[ $hint == *"Linux"* ]] || [[ $hint == *"Unix"* ]]; then
                    ((unix_indicators++))
                fi
            done

            if [ $unix_indicators -gt 0 ]; then
                echo -e "\n${GREEN}🎯 LIKELY LINUX/UNIX: Unix-style services detected${NC}"
            else
                echo -e "\n${BLUE}🎯 UNKNOWN: Insufficient service information for OS determination${NC}"
            fi
        fi
    else
        echo -e "\n${RED}❌ NO SERVICE-BASED OS HINTS AVAILABLE${NC}"
    fi

    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    return 0
}

# Educational information function
show_educational_info() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║         📚 OS Fingerprinting Guide      ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}\n"

    echo -e "${GREEN}What is OS Fingerprinting?${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "OS fingerprinting is the process of determining the operating system"
    echo -e "running on a remote target by analyzing network responses and behavior."
    echo -e "It's a crucial reconnaissance technique used in penetration testing"
    echo -e "and network security assessments to understand target environments.\n"

    echo -e "${GREEN}Common Fingerprinting Techniques${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}1. Active Fingerprinting${NC}"
    echo -e "   • Send crafted packets and analyze responses"
    echo -e "   • TCP/IP stack analysis (TTL, window size, flags)"
    echo -e "   • ICMP response analysis"
    echo -e "   • More accurate but detectable"
    echo -e "${YELLOW}2. Passive Fingerprinting${NC}"
    echo -e "   • Analyze existing network traffic"
    echo -e "   • Monitor packet characteristics passively"
    echo -e "   • Less accurate but stealthy"
    echo -e "${YELLOW}3. Banner Grabbing${NC}"
    echo -e "   • Collect service banners and headers"
    echo -e "   • HTTP, SSH, FTP, SMTP server identification"
    echo -e "   • Application-level OS detection"
    echo -e "${YELLOW}4. Behavioral Analysis${NC}"
    echo -e "   • Analyze timing and response patterns"
    echo -e "   • Protocol implementation differences"
    echo -e "   • Service availability patterns\n"

    echo -e "${GREEN}Technical Indicators${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}TTL (Time To Live) Values:${NC}"
    echo -e "• Windows: 128 (older) or 255 (newer)"
    echo -e "• Linux/Unix: 64"
    echo -e "• Cisco/Network devices: 255"
    echo -e "• Note: Values may be modified by routers"
    echo -e "${CYAN}TCP Window Sizes:${NC}"
    echo -e "• Windows: Often 65535 or 8192"
    echo -e "• Linux: Varies (32768, 5840, etc.)"
    echo -e "• Different OS versions have distinct patterns"
    echo -e "${CYAN}TCP Options:${NC}"
    echo -e "• MSS (Maximum Segment Size) values"
    echo -e "• Window scaling options"
    echo -e "• SACK (Selective Acknowledgment) support"
    echo -e "${CYAN}ICMP Responses:${NC}"
    echo -e "• Error message formats and codes"
    echo -e "• Response timing characteristics"
    echo -e "• Payload echoing behavior\n"

    echo -e "${GREEN}Service-based Detection${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Windows Indicators:${NC}"
    echo -e "• Port 135 (RPC), 139 (NetBIOS), 445 (SMB)"
    echo -e "• Port 3389 (RDP), 1433 (SQL Server)"
    echo -e "• IIS web server banners"
    echo -e "${CYAN}Linux/Unix Indicators:${NC}"
    echo -e "• Port 22 (SSH) with OpenSSH banners"
    echo -e "• Apache/nginx web servers"
    echo -e "• Distribution-specific SSH banners"
    echo -e "${CYAN}Network Device Indicators:${NC}"
    echo -e "• SNMP (161), Telnet (23)"
    echo -e "• Vendor-specific management ports"
    echo -e "• Specialized service banners\n"

    echo -e "${GREEN}Detection Tools and Methods${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}1. nmap:${NC}"
    echo -e "   • -O flag for OS detection"
    echo -e "   • --osscan-guess for aggressive guessing"
    echo -e "   • Comprehensive fingerprint database"
    echo -e "${CYAN}2. p0f:${NC}"
    echo -e "   • Passive OS fingerprinting"
    echo -e "   • Real-time traffic analysis"
    echo -e "   • Minimal network footprint"
    echo -e "${CYAN}3. Xprobe2:${NC}"
    echo -e "   • Active OS fingerprinting"
    echo -e "   • ICMP-based detection"
    echo -e "   • Alternative to nmap"
    echo -e "${CYAN}4. Manual Techniques:${NC}"
    echo -e "   • Custom packet crafting"
    echo -e "   • Banner analysis scripts"
    echo -e "   • Protocol-specific probes\n"

    echo -e "${GREEN}Evasion and Countermeasures${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}✓ Defensive Measures:${NC}"
    echo -e "  • Firewall filtering of fingerprinting attempts"
    echo -e "  • IDS/IPS detection of OS scanning"
    echo -e "  • TTL normalization and scrubbing"
    echo -e "  • Service banner modification"
    echo -e "${GREEN}✓ OS Obfuscation:${NC}"
    echo -e "  • Modify TCP/IP stack parameters"
    echo -e "  • Use proxy or NAT devices"
    echo -e "  • Implement decoy responses"
    echo -e "  • Rate limiting and connection throttling"
    echo -e "${GREEN}✓ Network Segmentation:${NC}"
    echo -e "  • Isolate critical systems"
    echo -e "  • Limit external reconnaissance"
    echo -e "  • Use jump hosts and bastion servers\n"

    echo -e "${GREEN}Legal and Ethical Considerations${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${RED}⚠ IMPORTANT:${NC} Only fingerprint systems you own or have explicit permission"
    echo -e "${RED}⚠ LEGAL:${NC} Unauthorized OS fingerprinting may violate computer crime laws"
    echo -e "${RED}⚠ ETHICAL:${NC} Use fingerprinting for legitimate security assessment only"
    echo -e "${RED}⚠ PROFESSIONAL:${NC} Document findings and follow responsible disclosure\n"
}

# Main interactive function
interactive_mode() {
    while true; do
        show_banner

        echo -e "${GREEN}Welcome to WetMonkey OS Fingerprinting Suite!${NC}"
        echo -e "${YELLOW}This tool helps identify operating systems through various fingerprinting techniques.${NC}\n"
        echo -e "${RED}⚠ WARNING: Only test against systems you own or have permission to test!${NC}\n"

        # Step 1: Fingerprinting method selection
        echo -e "${GREEN}Step 1: Fingerprinting Method${NC}"
        echo -e "Choose the OS fingerprinting method:"
        echo -e "  ${YELLOW}1)${NC} nmap OS Detection - Advanced nmap-based fingerprinting"
        echo -e "  ${YELLOW}2)${NC} Manual Fingerprinting - Custom techniques (TTL, banners, etc.)"
        echo -e "  ${YELLOW}3)${NC} Service-based Detection - OS detection via service analysis"
        echo -e "  ${YELLOW}4)${NC} Comprehensive Scan - All methods combined"
        echo -e "  ${YELLOW}5)${NC} Educational Information - Learn about OS fingerprinting"

        local method_type
        while true; do
            choice=$(simple_input "Select fingerprinting method (1-5)")
            case "$choice" in
                "1") method_type="nmap"; break ;;
                "2") method_type="manual"; break ;;
                "3") method_type="service"; break ;;
                "4") method_type="comprehensive"; break ;;
                "5") method_type="educational"; break ;;
                *) echo -e "${RED}Please select a number between 1-5${NC}" ;;
            esac
        done

        case "$method_type" in
            "educational")
                # Show educational information
                show_educational_info
                echo -e "\n${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;

            *)
                # OS fingerprinting
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

                # Step 3: Stealth options (for applicable methods)
                local stealth=false
                if [[ "$method_type" == "nmap" ]] || [[ "$method_type" == "comprehensive" ]]; then
                    echo -e "\n${GREEN}Step 3: Stealth Configuration${NC}"
                    if ask_yes_no "Enable stealth mode (slower but less detectable)?" "n"; then
                        stealth=true
                    fi
                fi

                # Step 4: Execution
                echo -e "\n${GREEN}Step 4: Fingerprinting Summary${NC}"
                echo -e "${BLUE}═══════════════════════════════════════${NC}"
                echo -e "${CYAN}Target: $target${NC}"
                echo -e "${CYAN}Method: $method_type${NC}"
                if [[ "$method_type" == "nmap" ]] || [[ "$method_type" == "comprehensive" ]]; then
                    echo -e "${CYAN}Stealth mode: $([ "$stealth" = true ] && echo "Enabled" || echo "Disabled")${NC}"
                fi
                echo -e "${BLUE}═══════════════════════════════════════${NC}"

                echo -e "\n${RED}⚠ WARNING: This will perform OS fingerprinting against the target!${NC}"
                echo -e "${RED}⚠ Only proceed if you have authorization to test this target!${NC}"

                if ask_yes_no "Start OS fingerprinting?" "n"; then
                    echo -e "\n${CYAN}Starting OS fingerprinting...${NC}"

                    # Log start
                    log_json "osfingerprint_start" "target=$target method=$method_type stealth=$stealth" 2>/dev/null || true

                    # Perform fingerprinting based on method
                    case "$method_type" in
                        "nmap")
                            nmap_os_fingerprint "$target" "$stealth"
                            ;;
                        "manual")
                            manual_os_fingerprint "$target"
                            ;;
                        "service")
                            service_based_detection "$target"
                            ;;
                        "comprehensive")
                            comprehensive_os_fingerprint "$target" "$stealth"
                            ;;
                    esac

                    # Log end
                    log_json "osfingerprint_end" "target=$target method=$method_type" 2>/dev/null || true
                else
                    echo -e "${YELLOW}OS fingerprinting cancelled.${NC}"
                fi
                ;;
        esac

        echo -e "\n${YELLOW}Press Enter to continue...${NC}"
        read -r

        if ! ask_yes_no "Perform another fingerprinting scan?" "y"; then
            break
        fi
    done
}

# Legacy mode function
legacy_mode() {
    local target="$1"

    echo -e "${YELLOW}Running in legacy mode...${NC}"
    echo -e "${RED}⚠ WARNING: Only test targets you own or have permission to test!${NC}\n"

    # Validate target
    if ! validate_target "$target"; then
        echo -e "${RED}Error: Invalid target format${NC}" >&2
        exit 1
    fi

    # Log start
    log_json "osfingerprint_start" "target=$target mode=legacy" 2>/dev/null || true

    # Perform nmap OS fingerprinting (legacy behavior)
    echo -e "${CYAN}Performing legacy nmap OS detection...${NC}"
    nmap_os_fingerprint "$target" "false"

    # Log end
    log_json "osfingerprint_end" "target=$target" 2>/dev/null || true
}

# Main function
main() {
    local target=""
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
            echo -e "${GREEN}Quick OS Fingerprint Scan: $scan_target${NC}"

            if ! validate_target "$scan_target"; then
                echo -e "${RED}Error: Invalid target format${NC}" >&2
                exit 1
            fi

            # Log start
            log_json "osfingerprint_start" "target=$scan_target mode=quick" 2>/dev/null || true

            # Perform quick comprehensive scan
            comprehensive_os_fingerprint "$scan_target" "false"

            # Log end
            log_json "osfingerprint_end" "target=$scan_target" 2>/dev/null || true

            exit 0
        fi

        # Handle legacy mode
        if [ -n "$target" ]; then
            legacy_mode "$target"
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
    if ! command -v curl >/dev/null 2>&1; then
        missing_deps+=("curl")
    fi

    if [ ${#missing_deps[@]} -gt 0 ]; then
        echo -e "${YELLOW}Warning: Some tools are missing: ${missing_deps[*]}${NC}"
        echo -e "${YELLOW}Some features may have reduced functionality.${NC}\n"
    fi

    # Start interactive mode
    interactive_mode
}

# Run the main function with all arguments
main "$@"
