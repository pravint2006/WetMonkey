#!/usr/bin/env bash
# wetmonkey torproxy – Interactive Tor Proxy & Anonymity Testing Suite v2.0
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
    echo "║    🧅 WetMonkey Tor Proxy Suite         ║"
    echo "║         Interactive Mode v2.0           ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Show usage information
show_help() {
    echo "WetMonkey Tor Proxy Module v${VERSION}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  -u, --url <url>         Target URL (legacy mode)"
    echo "  --test <url>            Quick Tor proxy test"
    echo "  --check-tor             Check Tor connection status"
    echo ""
    echo "This module provides interactive Tor proxy testing and anonymity analysis."
    echo "Supported features: Tor connectivity, IP anonymity, proxy chains, analysis"
    echo ""
    echo "Example:"
    echo "  $0                      # Run in interactive mode"
    echo "  $0 -h                   # Show this help"
    echo "  $0 --test http://httpbin.org/ip  # Quick Tor test"
    echo "  $0 --check-tor          # Check Tor status"
    echo "  $0 -u http://example.com  # Legacy mode"
    echo ""
    echo "Note: This tool is for authorized security testing and research only!"
    echo "      Use responsibly and only on systems you own or have permission to test."
    echo "      Requires Tor service and torsocks to be installed."
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

# Function to validate URL
validate_url() {
    local url="$1"
    if [[ $url =~ ^https?://[a-zA-Z0-9.-]+([:/][^[:space:]]*)?$ ]]; then
        return 0
    fi
    return 1
}

# Function to check if Tor is running
check_tor_status() {
    echo -e "${YELLOW}Checking Tor service status...${NC}" >&2

    # Method 1: Check if Tor process is running
    if pgrep -x "tor" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Tor process is running${NC}" >&2
        return 0
    fi

    # Method 2: Check if Tor service is active (systemd)
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active tor >/dev/null 2>&1; then
            echo -e "${GREEN}✓ Tor service is active${NC}" >&2
            return 0
        fi
    fi

    # Method 3: Try to connect to Tor SOCKS port
    if command -v nc >/dev/null 2>&1; then
        if timeout 3 nc -z 127.0.0.1 9050 2>/dev/null; then
            echo -e "${GREEN}✓ Tor SOCKS port (9050) is accessible${NC}" >&2
            return 0
        fi
    fi

    echo -e "${RED}❌ Tor service does not appear to be running${NC}" >&2
    return 1
}

# Function to check torsocks availability
check_torsocks() {
    if command -v torsocks >/dev/null 2>&1; then
        echo -e "${GREEN}✓ torsocks is available${NC}" >&2
        return 0
    else
        echo -e "${RED}❌ torsocks is not installed${NC}" >&2
        echo -e "${YELLOW}Please install torsocks: sudo apt-get install torsocks${NC}" >&2
        return 1
    fi
}

# Function to test Tor connectivity and anonymity
test_tor_connectivity() {
    local test_url="${1:-http://httpbin.org/ip}"

    echo -e "\n${GREEN}🧅 Testing Tor connectivity and anonymity...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Test URL: $test_url${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    local tor_working=false
    local direct_ip=""
    local tor_ip=""

    # Step 1: Test direct connection (without Tor)
    echo -e "${CYAN}Step 1: Testing direct connection (without Tor)...${NC}"

    if command -v curl >/dev/null 2>&1; then
        echo -e "${BLUE}Using curl for direct connection test${NC}"

        local direct_response
        if direct_response=$(timeout 15 curl -s --connect-timeout 10 "$test_url" 2>/dev/null); then
            echo -e "${GREEN}✓ Direct connection successful${NC}"

            # Try to extract IP from response
            if [[ $test_url == *"httpbin.org/ip"* ]]; then
                direct_ip=$(echo "$direct_response" | grep -o '"origin": "[^"]*"' | cut -d'"' -f4 | head -1)
                if [ -n "$direct_ip" ]; then
                    echo -e "${CYAN}  Your direct IP: $direct_ip${NC}"
                fi
            else
                echo -e "${CYAN}  Response received (first 100 chars):${NC}"
                echo "$direct_response" | head -c 100 | sed 's/^/    /'
            fi
        else
            echo -e "${YELLOW}⚠ Direct connection failed or timed out${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ curl not available for direct connection test${NC}"
    fi

    # Step 2: Test Tor connection
    echo -e "\n${CYAN}Step 2: Testing Tor connection...${NC}"

    if ! check_torsocks; then
        echo -e "${RED}❌ Cannot test Tor connection without torsocks${NC}"
        return 1
    fi

    if ! check_tor_status; then
        echo -e "${RED}❌ Tor service is not running${NC}"
        echo -e "${YELLOW}Please start Tor service: sudo systemctl start tor${NC}"
        return 1
    fi

    echo -e "${BLUE}Using torsocks curl for Tor connection test${NC}"

    local tor_response
    if tor_response=$(timeout 30 torsocks curl -s --connect-timeout 15 "$test_url" 2>/dev/null); then
        echo -e "${GREEN}✓ Tor connection successful${NC}"
        tor_working=true

        # Try to extract IP from response
        if [[ $test_url == *"httpbin.org/ip"* ]]; then
            tor_ip=$(echo "$tor_response" | grep -o '"origin": "[^"]*"' | cut -d'"' -f4 | head -1)
            if [ -n "$tor_ip" ]; then
                echo -e "${CYAN}  Your Tor IP: $tor_ip${NC}"
            fi
        else
            echo -e "${CYAN}  Response received (first 100 chars):${NC}"
            echo "$tor_response" | head -c 100 | sed 's/^/    /'
        fi
    else
        echo -e "${RED}❌ Tor connection failed or timed out${NC}"
        echo -e "${YELLOW}This could indicate:${NC}"
        echo -e "${YELLOW}  • Tor service is not properly configured${NC}"
        echo -e "${YELLOW}  • Target website blocks Tor exit nodes${NC}"
        echo -e "${YELLOW}  • Network connectivity issues${NC}"
    fi

    # Step 3: Anonymity analysis
    echo -e "\n${CYAN}Step 3: Anonymity analysis...${NC}"

    if [ -n "$direct_ip" ] && [ -n "$tor_ip" ]; then
        if [ "$direct_ip" != "$tor_ip" ]; then
            echo -e "${GREEN}✓ ANONYMITY CONFIRMED: IP addresses are different${NC}"
            echo -e "${CYAN}  Direct IP: $direct_ip${NC}"
            echo -e "${CYAN}  Tor IP: $tor_ip${NC}"

            # Try to get geolocation info
            echo -e "\n${CYAN}Geolocation Analysis:${NC}"
            get_ip_geolocation "$direct_ip" "Direct"
            get_ip_geolocation "$tor_ip" "Tor"
        else
            echo -e "${RED}❌ ANONYMITY FAILED: IP addresses are the same${NC}"
            echo -e "${YELLOW}This indicates Tor is not working properly${NC}"
        fi
    elif [ -n "$tor_ip" ]; then
        echo -e "${GREEN}✓ Tor connection working (IP: $tor_ip)${NC}"
        if [ -z "$direct_ip" ]; then
            echo -e "${YELLOW}⚠ Could not determine direct IP for comparison${NC}"
        fi
    else
        echo -e "${RED}❌ Could not determine Tor IP address${NC}"
    fi

    # Summary
    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}📊 Tor Connectivity Test Summary${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Test URL: $test_url${NC}"
    echo -e "${CYAN}Direct IP: ${direct_ip:-"Unknown"}${NC}"
    echo -e "${CYAN}Tor IP: ${tor_ip:-"Unknown"}${NC}"
    echo -e "${CYAN}Tor Working: $([ "$tor_working" = true ] && echo "Yes" || echo "No")${NC}"

    if [ "$tor_working" = true ]; then
        echo -e "\n${YELLOW}Security Recommendations:${NC}"
        echo -e "• Always verify Tor is working before sensitive activities"
        echo -e "• Use HTTPS websites when possible for additional security"
        echo -e "• Be aware that some websites block Tor exit nodes"
        echo -e "• Consider using Tor Browser for complete anonymity"
        echo -e "• Regularly test your anonymity setup"
    else
        echo -e "\n${YELLOW}Troubleshooting Steps:${NC}"
        echo -e "• Check if Tor service is running: sudo systemctl status tor"
        echo -e "• Start Tor service: sudo systemctl start tor"
        echo -e "• Check Tor configuration: /etc/tor/torrc"
        echo -e "• Test SOCKS proxy: nc -z 127.0.0.1 9050"
        echo -e "• Check firewall settings and network connectivity"
    fi

    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    return $([ "$tor_working" = true ] && echo 0 || echo 1)
}

# Function to get IP geolocation (basic)
get_ip_geolocation() {
    local ip="$1"
    local label="$2"

    if [ -z "$ip" ]; then
        return 1
    fi

    echo -e "${BLUE}  $label IP Geolocation:${NC}"

    # Try to get basic geolocation info using a simple API
    if command -v curl >/dev/null 2>&1; then
        local geo_info
        if geo_info=$(timeout 10 curl -s "http://ip-api.com/line/$ip?fields=country,regionName,city,isp" 2>/dev/null); then
            local country=$(echo "$geo_info" | sed -n '1p')
            local region=$(echo "$geo_info" | sed -n '2p')
            local city=$(echo "$geo_info" | sed -n '3p')
            local isp=$(echo "$geo_info" | sed -n '4p')

            if [ -n "$country" ] && [ "$country" != "fail" ]; then
                echo -e "${CYAN}    Country: $country${NC}"
                echo -e "${CYAN}    Region: $region${NC}"
                echo -e "${CYAN}    City: $city${NC}"
                echo -e "${CYAN}    ISP: $isp${NC}"
            else
                echo -e "${YELLOW}    Geolocation lookup failed${NC}"
            fi
        else
            echo -e "${YELLOW}    Geolocation service unavailable${NC}"
        fi
    fi
}

# Function to test multiple Tor circuits
test_tor_circuits() {
    local test_url="${1:-http://httpbin.org/ip}"
    local circuit_count="${2:-3}"

    echo -e "\n${GREEN}🔄 Testing multiple Tor circuits...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Test URL: $test_url${NC}"
    echo -e "${YELLOW}Circuit Tests: $circuit_count${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    if ! check_torsocks || ! check_tor_status; then
        echo -e "${RED}❌ Tor is not properly configured${NC}"
        return 1
    fi

    local ips_found=()
    local unique_ips=0

    for ((i=1; i<=circuit_count; i++)); do
        echo -e "${CYAN}Circuit Test $i/$circuit_count:${NC}"

        # Request new Tor circuit (if tor control port is available)
        if command -v nc >/dev/null 2>&1 && timeout 2 nc -z 127.0.0.1 9051 2>/dev/null; then
            echo -e "${BLUE}  Requesting new Tor circuit...${NC}"
            echo -e "AUTHENTICATE\nSIGNAL NEWNYM\nQUIT" | timeout 5 nc 127.0.0.1 9051 >/dev/null 2>&1 || true
            sleep 2  # Wait for new circuit
        fi

        # Test the circuit
        local circuit_ip
        if circuit_ip=$(timeout 20 torsocks curl -s --connect-timeout 10 "$test_url" 2>/dev/null | grep -o '"origin": "[^"]*"' | cut -d'"' -f4 | head -1); then
            if [ -n "$circuit_ip" ]; then
                echo -e "${GREEN}  ✓ Circuit $i IP: $circuit_ip${NC}"

                # Check if this IP is new
                local is_new=true
                for existing_ip in "${ips_found[@]}"; do
                    if [ "$existing_ip" = "$circuit_ip" ]; then
                        is_new=false
                        break
                    fi
                done

                if [ "$is_new" = true ]; then
                    ips_found+=("$circuit_ip")
                    ((unique_ips++))
                    echo -e "${CYAN}    → New unique IP found${NC}"
                else
                    echo -e "${YELLOW}    → Duplicate IP (circuit reuse)${NC}"
                fi
            else
                echo -e "${RED}  ❌ Circuit $i: Could not extract IP${NC}"
            fi
        else
            echo -e "${RED}  ❌ Circuit $i: Connection failed${NC}"
        fi

        # Small delay between tests
        if [ $i -lt $circuit_count ]; then
            sleep 3
        fi
    done

    # Summary
    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}📊 Tor Circuit Test Summary${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Total Tests: $circuit_count${NC}"
    echo -e "${CYAN}Unique IPs: $unique_ips${NC}"
    echo -e "${CYAN}Circuit Diversity: $(( (unique_ips * 100) / circuit_count ))%${NC}"

    if [ ${#ips_found[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}Unique IP Addresses Found:${NC}"
        for ip in "${ips_found[@]}"; do
            echo -e "  • $ip"
        done

        if [ $unique_ips -ge 2 ]; then
            echo -e "\n${GREEN}✓ GOOD: Multiple unique exit nodes detected${NC}"
            echo -e "${CYAN}This indicates healthy Tor circuit diversity${NC}"
        else
            echo -e "\n${YELLOW}⚠ LIMITED: Only one unique exit node detected${NC}"
            echo -e "${CYAN}This could indicate circuit reuse or limited exit nodes${NC}"
        fi
    else
        echo -e "\n${RED}❌ NO SUCCESSFUL CONNECTIONS${NC}"
    fi

    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    return 0
}

# Function to test Tor performance
test_tor_performance() {
    local test_url="${1:-http://httpbin.org/get}"

    echo -e "\n${GREEN}⚡ Testing Tor performance...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Test URL: $test_url${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    if ! check_torsocks || ! check_tor_status; then
        echo -e "${RED}❌ Tor is not properly configured${NC}"
        return 1
    fi

    local direct_time=""
    local tor_time=""

    # Test direct connection speed
    echo -e "${CYAN}Testing direct connection speed...${NC}"
    if command -v curl >/dev/null 2>&1; then
        local direct_result
        if direct_result=$(timeout 30 curl -s -w "Time: %{time_total}s\nSpeed: %{speed_download} bytes/s\nSize: %{size_download} bytes\n" -o /dev/null "$test_url" 2>/dev/null); then
            echo -e "${GREEN}✓ Direct connection completed${NC}"
            echo "$direct_result" | sed 's/^/  /'
            direct_time=$(echo "$direct_result" | grep "Time:" | cut -d' ' -f2)
        else
            echo -e "${YELLOW}⚠ Direct connection test failed${NC}"
        fi
    fi

    # Test Tor connection speed
    echo -e "\n${CYAN}Testing Tor connection speed...${NC}"
    local tor_result
    if tor_result=$(timeout 60 torsocks curl -s -w "Time: %{time_total}s\nSpeed: %{speed_download} bytes/s\nSize: %{size_download} bytes\n" -o /dev/null "$test_url" 2>/dev/null); then
        echo -e "${GREEN}✓ Tor connection completed${NC}"
        echo "$tor_result" | sed 's/^/  /'
        tor_time=$(echo "$tor_result" | grep "Time:" | cut -d' ' -f2)
    else
        echo -e "${RED}❌ Tor connection test failed${NC}"
    fi

    # Performance comparison
    if [ -n "$direct_time" ] && [ -n "$tor_time" ]; then
        echo -e "\n${CYAN}Performance Comparison:${NC}"
        echo -e "${BLUE}  Direct Time: ${direct_time}${NC}"
        echo -e "${BLUE}  Tor Time: ${tor_time}${NC}"

        # Calculate slowdown factor (basic)
        local direct_ms=$(echo "$direct_time" | sed 's/s$//' | awk '{print $1 * 1000}')
        local tor_ms=$(echo "$tor_time" | sed 's/s$//' | awk '{print $1 * 1000}')

        if command -v bc >/dev/null 2>&1; then
            local slowdown=$(echo "scale=1; $tor_ms / $direct_ms" | bc 2>/dev/null || echo "N/A")
            if [ "$slowdown" != "N/A" ]; then
                echo -e "${YELLOW}  Tor Slowdown Factor: ${slowdown}x${NC}"

                if (( $(echo "$slowdown < 3" | bc -l 2>/dev/null || echo 0) )); then
                    echo -e "${GREEN}  ✓ Good performance (less than 3x slower)${NC}"
                elif (( $(echo "$slowdown < 10" | bc -l 2>/dev/null || echo 0) )); then
                    echo -e "${YELLOW}  ⚠ Moderate performance (3-10x slower)${NC}"
                else
                    echo -e "${RED}  ❌ Poor performance (more than 10x slower)${NC}"
                fi
            fi
        fi
    fi

    echo -e "\n${YELLOW}Performance Notes:${NC}"
    echo -e "• Tor adds latency due to multi-hop routing"
    echo -e "• Performance varies based on exit node location"
    echo -e "• Network congestion affects Tor more than direct connections"
    echo -e "• Some websites may throttle Tor connections"

    return 0
}

# Educational information function
show_educational_info() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║         📚 Tor Proxy Guide              ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}\n"

    echo -e "${GREEN}What is Tor?${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "Tor (The Onion Router) is a free, open-source software that enables"
    echo -e "anonymous communication by directing internet traffic through a worldwide"
    echo -e "volunteer network of servers. It protects users' privacy and enables"
    echo -e "circumvention of internet censorship and surveillance.\n"

    echo -e "${GREEN}How Tor Works${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}1. Onion Routing${NC}"
    echo -e "   • Traffic is encrypted in multiple layers (like an onion)"
    echo -e "   • Each relay only knows the previous and next hop"
    echo -e "   • No single relay knows the complete path"
    echo -e "${YELLOW}2. Three-Hop Circuit${NC}"
    echo -e "   • Entry/Guard Node: First hop, knows your IP"
    echo -e "   • Middle Node: Relay node, doesn't know source or destination"
    echo -e "   • Exit Node: Final hop, connects to destination"
    echo -e "${YELLOW}3. Circuit Rotation${NC}"
    echo -e "   • Circuits change every 10 minutes by default"
    echo -e "   • New circuits can be requested manually"
    echo -e "   • Provides additional anonymity and load distribution\n"

    echo -e "${GREEN}Tor Network Components${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Tor Client:${NC}"
    echo -e "• SOCKS proxy running on port 9050"
    echo -e "• Control port on 9051 (if enabled)"
    echo -e "• Handles circuit creation and management"
    echo -e "${CYAN}Directory Authorities:${NC}"
    echo -e "• Maintain list of active Tor relays"
    echo -e "• Provide network consensus information"
    echo -e "• Ensure network integrity and security"
    echo -e "${CYAN}Relay Types:${NC}"
    echo -e "• Guard Relays: Entry points to Tor network"
    echo -e "• Middle Relays: Forward traffic within network"
    echo -e "• Exit Relays: Connect to final destinations"
    echo -e "• Bridge Relays: Help circumvent Tor blocking\n"

    echo -e "${GREEN}Using Tor for Security Testing${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Anonymity Testing:${NC}"
    echo -e "• Verify IP address changes through Tor"
    echo -e "• Test geolocation obfuscation"
    echo -e "• Validate anonymity tools and configurations"
    echo -e "${CYAN}Circumvention Testing:${NC}"
    echo -e "• Test access to blocked or censored content"
    echo -e "• Evaluate firewall and filtering bypass"
    echo -e "• Assess network monitoring evasion"
    echo -e "${CYAN}Privacy Assessment:${NC}"
    echo -e "• Analyze traffic patterns and metadata"
    echo -e "• Test application-level privacy leaks"
    echo -e "• Evaluate browser fingerprinting resistance\n"

    echo -e "${GREEN}Tor Configuration and Tools${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}1. Tor Service:${NC}"
    echo -e "   • Main Tor daemon (tor)"
    echo -e "   • Configuration file: /etc/tor/torrc"
    echo -e "   • Service management: systemctl start/stop tor"
    echo -e "${CYAN}2. torsocks:${NC}"
    echo -e "   • Wrapper to route applications through Tor"
    echo -e "   • Usage: torsocks <application>"
    echo -e "   • Transparent SOCKS proxy integration"
    echo -e "${CYAN}3. Tor Browser:${NC}"
    echo -e "   • Pre-configured Firefox with Tor integration"
    echo -e "   • Built-in privacy and security features"
    echo -e "   • Recommended for web browsing anonymity"
    echo -e "${CYAN}4. Control Tools:${NC}"
    echo -e "   • tor-arm: Terminal-based Tor monitor"
    echo -e "   • Nyx: Modern replacement for tor-arm"
    echo -e "   • Custom scripts using control protocol\n"

    echo -e "${GREEN}Security Considerations${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}✓ Tor Strengths:${NC}"
    echo -e "  • Strong anonymity against network surveillance"
    echo -e "  • Resistance to traffic analysis"
    echo -e "  • Circumvention of internet censorship"
    echo -e "  • Protection against location tracking"
    echo -e "${RED}⚠ Tor Limitations:${NC}"
    echo -e "  • Exit node can see unencrypted traffic"
    echo -e "  • Vulnerable to timing correlation attacks"
    echo -e "  • Some websites block Tor exit nodes"
    echo -e "  • Performance impact due to multi-hop routing"
    echo -e "${YELLOW}🛡 Best Practices:${NC}"
    echo -e "  • Always use HTTPS when possible"
    echo -e "  • Disable JavaScript and plugins"
    echo -e "  • Use Tor Browser for web browsing"
    echo -e "  • Avoid downloading files through Tor"
    echo -e "  • Don't log into personal accounts\n"

    echo -e "${GREEN}Detection and Countermeasures${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Tor Detection Methods:${NC}"
    echo -e "• Exit node IP address blacklists"
    echo -e "• Traffic pattern analysis"
    echo -e "• Timing correlation attacks"
    echo -e "• Deep packet inspection (DPI)"
    echo -e "${CYAN}Blocking Techniques:${NC}"
    echo -e "• IP-based blocking of known exit nodes"
    echo -e "• Protocol-based detection and blocking"
    echo -e "• Captcha challenges for Tor users"
    echo -e "• Service degradation or rate limiting"
    echo -e "${CYAN}Countermeasures:${NC}"
    echo -e "• Use bridges to hide Tor usage"
    echo -e "• Employ pluggable transports (obfs4, meek)"
    echo -e "• Combine with VPN for additional layers"
    echo -e "• Use domain fronting techniques\n"

    echo -e "${GREEN}Legal and Ethical Considerations${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${RED}⚠ IMPORTANT:${NC} Only use Tor for legitimate and legal purposes"
    echo -e "${RED}⚠ LEGAL:${NC} Tor usage is legal in most countries but may be restricted"
    echo -e "${RED}⚠ ETHICAL:${NC} Respect website terms of service and rate limits"
    echo -e "${RED}⚠ PROFESSIONAL:${NC} Use for authorized security testing and research only"
    echo -e "${RED}⚠ RESPONSIBILITY:${NC} Be aware of local laws and regulations\n"
}

# Main interactive function
interactive_mode() {
    while true; do
        show_banner

        echo -e "${GREEN}Welcome to WetMonkey Tor Proxy Suite!${NC}"
        echo -e "${YELLOW}This tool helps test Tor connectivity, anonymity, and performance.${NC}\n"
        echo -e "${RED}⚠ WARNING: Only use Tor for legitimate and legal purposes!${NC}\n"

        # Step 1: Test type selection
        echo -e "${GREEN}Step 1: Test Type${NC}"
        echo -e "Choose the type of Tor test:"
        echo -e "  ${YELLOW}1)${NC} Connectivity Test - Basic Tor connection and anonymity test"
        echo -e "  ${YELLOW}2)${NC} Circuit Test - Test multiple Tor circuits and IP diversity"
        echo -e "  ${YELLOW}3)${NC} Performance Test - Compare Tor vs direct connection speed"
        echo -e "  ${YELLOW}4)${NC} Tor Status Check - Check if Tor service is running"
        echo -e "  ${YELLOW}5)${NC} Educational Information - Learn about Tor and anonymity"

        local test_type
        while true; do
            choice=$(simple_input "Select test type (1-5)")
            case "$choice" in
                "1") test_type="connectivity"; break ;;
                "2") test_type="circuits"; break ;;
                "3") test_type="performance"; break ;;
                "4") test_type="status"; break ;;
                "5") test_type="educational"; break ;;
                *) echo -e "${RED}Please select a number between 1-5${NC}" ;;
            esac
        done

        case "$test_type" in
            "educational")
                # Show educational information
                show_educational_info
                echo -e "\n${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;

            "status")
                # Tor status check
                echo -e "\n${GREEN}Step 2: Tor Status Check${NC}"
                echo -e "${BLUE}═══════════════════════════════════════${NC}"

                echo -e "${CYAN}Checking Tor service status...${NC}"
                if check_tor_status; then
                    echo -e "${GREEN}✓ Tor service is running${NC}"
                else
                    echo -e "${RED}❌ Tor service is not running${NC}"
                    echo -e "${YELLOW}To start Tor: sudo systemctl start tor${NC}"
                fi

                echo -e "\n${CYAN}Checking torsocks availability...${NC}"
                if check_torsocks; then
                    echo -e "${GREEN}✓ torsocks is available${NC}"
                else
                    echo -e "${RED}❌ torsocks is not available${NC}"
                    echo -e "${YELLOW}To install: sudo apt-get install torsocks${NC}"
                fi

                echo -e "${BLUE}═══════════════════════════════════════${NC}"
                ;;

            *)
                # Tor testing
                echo -e "\n${GREEN}Step 2: Test Configuration${NC}"

                local test_url
                if [[ "$test_type" == "connectivity" ]] || [[ "$test_type" == "circuits" ]]; then
                    echo -e "Test URL options:"
                    echo -e "  ${YELLOW}1)${NC} httpbin.org/ip - IP address detection (recommended)"
                    echo -e "  ${YELLOW}2)${NC} httpbin.org/get - HTTP GET test"
                    echo -e "  ${YELLOW}3)${NC} httpbin.org/headers - HTTP headers analysis"
                    echo -e "  ${YELLOW}4)${NC} Custom URL - Enter your own URL"

                    while true; do
                        url_choice=$(simple_input "Select test URL (1-4)" "1")
                        case "$url_choice" in
                            "1") test_url="http://httpbin.org/ip"; break ;;
                            "2") test_url="http://httpbin.org/get"; break ;;
                            "3") test_url="http://httpbin.org/headers"; break ;;
                            "4")
                                while true; do
                                    test_url=$(simple_input "Enter custom URL")
                                    if [ -z "$test_url" ]; then
                                        echo -e "${RED}URL is required!${NC}"
                                        continue
                                    fi

                                    if validate_url "$test_url"; then
                                        break
                                    else
                                        echo -e "${RED}Please enter a valid URL (http:// or https://)${NC}"
                                    fi
                                done
                                break ;;
                            *) echo -e "${RED}Please select a number between 1-4${NC}" ;;
                        esac
                    done
                elif [[ "$test_type" == "performance" ]]; then
                    test_url="http://httpbin.org/get"  # Good for performance testing
                fi

                # Additional configuration for circuit test
                local circuit_count=3
                if [[ "$test_type" == "circuits" ]]; then
                    while true; do
                        circuit_count=$(simple_input "Number of circuits to test" "3")
                        if [[ $circuit_count =~ ^[0-9]+$ ]] && [ $circuit_count -ge 1 ] && [ $circuit_count -le 10 ]; then
                            break
                        else
                            echo -e "${RED}Please enter a valid count (1-10)${NC}"
                        fi
                    done
                fi

                # Step 3: Execution summary
                echo -e "\n${GREEN}Step 3: Test Summary${NC}"
                echo -e "${BLUE}═══════════════════════════════════════${NC}"
                echo -e "${CYAN}Test Type: $test_type${NC}"
                echo -e "${CYAN}Test URL: $test_url${NC}"
                if [[ "$test_type" == "circuits" ]]; then
                    echo -e "${CYAN}Circuit Count: $circuit_count${NC}"
                fi
                echo -e "${BLUE}═══════════════════════════════════════${NC}"

                echo -e "\n${RED}⚠ WARNING: This will test Tor connectivity and may reveal your usage!${NC}"
                echo -e "${RED}⚠ Only proceed if you have authorization and understand the implications!${NC}"

                if ask_yes_no "Start Tor testing?" "n"; then
                    echo -e "\n${CYAN}Starting Tor testing...${NC}"

                    # Log start
                    log_json "torproxy_start" "type=$test_type url=$test_url" 2>/dev/null || true

                    # Perform testing based on type
                    case "$test_type" in
                        "connectivity")
                            test_tor_connectivity "$test_url"
                            ;;
                        "circuits")
                            test_tor_circuits "$test_url" "$circuit_count"
                            ;;
                        "performance")
                            test_tor_performance "$test_url"
                            ;;
                    esac

                    # Log end
                    log_json "torproxy_end" "type=$test_type url=$test_url" 2>/dev/null || true
                else
                    echo -e "${YELLOW}Tor testing cancelled.${NC}"
                fi
                ;;
        esac

        echo -e "\n${YELLOW}Press Enter to continue...${NC}"
        read -r

        if ! ask_yes_no "Perform another Tor test?" "y"; then
            break
        fi
    done
}

# Legacy mode function
legacy_mode() {
    local url="$1"

    echo -e "${YELLOW}Running in legacy mode...${NC}"
    echo -e "${RED}⚠ WARNING: Only test URLs you own or have permission to test!${NC}\n"

    # Validate URL
    if ! validate_url "$url"; then
        echo -e "${RED}Error: Invalid URL format${NC}" >&2
        exit 1
    fi

    # Log start
    log_json "torproxy_start" "url=$url mode=legacy" 2>/dev/null || true

    # Perform legacy Tor test
    echo -e "${CYAN}Performing legacy Tor proxy test...${NC}"

    if ! check_torsocks; then
        echo -e "${RED}❌ torsocks is not available${NC}"
        exit 1
    fi

    if ! check_tor_status; then
        echo -e "${RED}❌ Tor service is not running${NC}"
        echo -e "${YELLOW}Please start Tor service: sudo systemctl start tor${NC}"
        exit 1
    fi

    echo -e "${BLUE}Using torsocks curl to access: $url${NC}"

    # Perform the legacy test (similar to original)
    local http_code
    if http_code=$(timeout 30 torsocks curl -s -o /dev/null -w "%{http_code}\n" "$url" 2>/dev/null); then
        echo -e "${GREEN}✓ HTTP Response Code: $http_code${NC}"

        if [[ $http_code =~ ^2[0-9][0-9]$ ]]; then
            echo -e "${GREEN}✓ Success: Received successful HTTP response${NC}"
        elif [[ $http_code =~ ^3[0-9][0-9]$ ]]; then
            echo -e "${YELLOW}⚠ Redirect: Received redirect response${NC}"
        elif [[ $http_code =~ ^4[0-9][0-9]$ ]]; then
            echo -e "${YELLOW}⚠ Client Error: Received client error response${NC}"
        elif [[ $http_code =~ ^5[0-9][0-9]$ ]]; then
            echo -e "${RED}❌ Server Error: Received server error response${NC}"
        else
            echo -e "${YELLOW}⚠ Unknown response code${NC}"
        fi
    else
        echo -e "${RED}❌ Connection failed or timed out${NC}"
        exit 1
    fi

    # Log end
    log_json "torproxy_end" "url=$url http_code=$http_code" 2>/dev/null || true
}

# Main function
main() {
    local url=""
    local test_url=""
    local check_tor=false

    # Parse command line arguments
    if [[ $# -gt 0 ]]; then
        while [[ $# -gt 0 ]]; do
            case "$1" in
                -h|--help)
                    show_help
                    exit 0
                    ;;
                -u|--url)
                    if [ -z "${2:-}" ]; then
                        echo -e "${RED}Error: -u requires a URL${NC}" >&2
                        exit 1
                    fi
                    url="$2"
                    shift 2
                    ;;
                --test)
                    if [ -z "${2:-}" ]; then
                        echo -e "${RED}Error: --test requires a URL${NC}" >&2
                        exit 1
                    fi
                    test_url="$2"
                    shift 2
                    ;;
                --check-tor)
                    check_tor=true
                    shift
                    ;;
                *)
                    echo -e "${RED}Unknown option: $1${NC}" >&2
                    echo "Use -h for help." >&2
                    exit 1
                    ;;
            esac
        done

        # Handle quick test mode
        if [ -n "$test_url" ]; then
            echo -e "${GREEN}Quick Tor Connectivity Test: $test_url${NC}"

            if ! validate_url "$test_url"; then
                echo -e "${RED}Error: Invalid URL format${NC}" >&2
                exit 1
            fi

            # Log start
            log_json "torproxy_start" "url=$test_url mode=quick" 2>/dev/null || true

            # Perform quick connectivity test
            test_tor_connectivity "$test_url"

            # Log end
            log_json "torproxy_end" "url=$test_url" 2>/dev/null || true

            exit 0
        fi

        # Handle Tor status check
        if [ "$check_tor" = true ]; then
            echo -e "${GREEN}Tor Status Check${NC}"

            echo -e "\n${CYAN}Checking Tor service...${NC}"
            if check_tor_status; then
                echo -e "${GREEN}✓ Tor service is running${NC}"
            else
                echo -e "${RED}❌ Tor service is not running${NC}"
                exit 1
            fi

            echo -e "\n${CYAN}Checking torsocks...${NC}"
            if check_torsocks; then
                echo -e "${GREEN}✓ torsocks is available${NC}"
            else
                echo -e "${RED}❌ torsocks is not available${NC}"
                exit 1
            fi

            echo -e "\n${GREEN}✓ Tor setup appears to be working${NC}"
            exit 0
        fi

        # Handle legacy mode
        if [ -n "$url" ]; then
            legacy_mode "$url"
            exit $?
        fi

        # If we get here, invalid combination of arguments
        echo -e "${RED}Error: Invalid argument combination${NC}" >&2
        echo "Use -h for help or run without arguments for interactive mode." >&2
        exit 1
    fi

    # Check dependencies for interactive mode
    missing_deps=()
    if ! command -v curl >/dev/null 2>&1; then
        missing_deps+=("curl")
    fi

    if [ ${#missing_deps[@]} -gt 0 ]; then
        echo -e "${YELLOW}Warning: Some tools are missing: ${missing_deps[*]}${NC}"
        echo -e "${YELLOW}Some features may have reduced functionality.${NC}\n"
    fi

    # Check Tor-specific dependencies
    tor_deps=()
    if ! command -v torsocks >/dev/null 2>&1; then
        tor_deps+=("torsocks")
    fi

    if [ ${#tor_deps[@]} -gt 0 ]; then
        echo -e "${YELLOW}Warning: Tor tools are missing: ${tor_deps[*]}${NC}"
        echo -e "${YELLOW}Install with: sudo apt-get install ${tor_deps[*]}${NC}\n"
    fi

    # Start interactive mode
    interactive_mode
}

# Run the main function with all arguments
main "$@"
