#!/usr/bin/env bash
# wetmonkey geoipanomaly – Interactive GeoIP Anomaly Detection Suite v2.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$SCRIPT_DIR/../../"
source "$BASE_DIR/core/utils.sh"

# Configuration
VERSION="2.0"
MAX_IPS=20

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
    echo "║    🌍 WetMonkey GeoIP Anomaly Detector   ║"
    echo "║         Interactive Mode v2.0           ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Show usage information
show_help() {
    echo "WetMonkey GeoIP Anomaly Detection Module v${VERSION}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  --lookup <ip>           Quick GeoIP lookup for an IP address"
    echo "  --analyze <ip1,ip2,...> Analyze multiple IPs for anomalies"
    echo "  -u, --url <url>         Target URL (legacy mode)"
    echo "  --ip <ip>               IP address to spoof (legacy mode)"
    echo ""
    echo "This module provides interactive GeoIP anomaly detection and analysis."
    echo "Supported features: IP geolocation, anomaly detection, spoofing simulation"
    echo ""
    echo "Example:"
    echo "  $0                      # Run in interactive mode"
    echo "  $0 -h                   # Show this help"
    echo "  $0 --lookup 8.8.8.8     # Quick IP lookup"
    echo "  $0 --analyze \"1.1.1.1,8.8.8.8,9.9.9.9\"  # Analyze multiple IPs"
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

# Function to validate URL
validate_url() {
    local url="$1"
    if [[ $url =~ ^https?://[a-zA-Z0-9.-]+([:/][^[:space:]]*)?$ ]]; then
        return 0
    fi
    return 1
}

# Function to perform GeoIP lookup using free online APIs
geoip_lookup() {
    local ip="$1"
    local api_used=""
    local location_data=""

    echo -e "${YELLOW}Performing GeoIP lookup for $ip...${NC}" >&2

    # Try multiple free GeoIP APIs
    local apis=(
        "http://ip-api.com/json/$ip"
        "https://ipapi.co/$ip/json/"
        "https://freegeoip.app/json/$ip"
    )

    for api in "${apis[@]}"; do
        echo -e "${CYAN}Trying API: ${api%%/*}//${api#*//}${NC}" >&2

        local response
        if response=$(curl -s --connect-timeout 5 --max-time 10 "$api" 2>/dev/null); then
            if [[ $response == *"country"* ]] || [[ $response == *"Country"* ]]; then
                location_data="$response"
                api_used="$api"
                echo -e "${GREEN}✓ Successfully retrieved location data${NC}" >&2
                break
            fi
        fi

        echo -e "${YELLOW}⚠ API failed or rate limited, trying next...${NC}" >&2
        sleep 1
    done

    if [ -z "$location_data" ]; then
        echo -e "${RED}❌ All GeoIP APIs failed or are rate limited${NC}" >&2
        return 1
    fi

    # Parse and display the location data
    echo -e "\n${GREEN}🌍 GeoIP Information for $ip${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    # Extract common fields from different API responses
    local country city region isp org timezone lat lon

    # Parse JSON response (basic parsing without jq dependency)
    if [[ $location_data == *'"country"'* ]]; then
        country=$(echo "$location_data" | sed -n 's/.*"country"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
        city=$(echo "$location_data" | sed -n 's/.*"city"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
        region=$(echo "$location_data" | sed -n 's/.*"region"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
        isp=$(echo "$location_data" | sed -n 's/.*"isp"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
        org=$(echo "$location_data" | sed -n 's/.*"org"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
        timezone=$(echo "$location_data" | sed -n 's/.*"timezone"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
        lat=$(echo "$location_data" | sed -n 's/.*"lat"[[:space:]]*:[[:space:]]*\([0-9.-]*\).*/\1/p' | head -1)
        lon=$(echo "$location_data" | sed -n 's/.*"lon"[[:space:]]*:[[:space:]]*\([0-9.-]*\).*/\1/p' | head -1)
    fi

    # Display parsed information
    echo -e "${CYAN}IP Address:${NC} $ip"
    [ -n "$country" ] && echo -e "${CYAN}Country:${NC} $country"
    [ -n "$city" ] && echo -e "${CYAN}City:${NC} $city"
    [ -n "$region" ] && echo -e "${CYAN}Region:${NC} $region"
    [ -n "$isp" ] && echo -e "${CYAN}ISP:${NC} $isp"
    [ -n "$org" ] && echo -e "${CYAN}Organization:${NC} $org"
    [ -n "$timezone" ] && echo -e "${CYAN}Timezone:${NC} $timezone"
    [ -n "$lat" ] && [ -n "$lon" ] && echo -e "${CYAN}Coordinates:${NC} $lat, $lon"

    echo -e "${BLUE}Data Source:${NC} ${api_used%%/*}//${api_used#*//}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    # Store data for anomaly analysis
    echo "$ip|$country|$city|$region|$isp|$org|$lat|$lon"

    return 0
}

# Function to detect anomalies in IP geolocation data
detect_geoip_anomalies() {
    local ip_data=("$@")
    local anomalies=()
    local suspicious_score=0

    echo -e "\n${GREEN}🔍 Analyzing GeoIP data for anomalies...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    # Check for common anomaly patterns
    for data in "${ip_data[@]}"; do
        IFS='|' read -r ip country city region isp org lat lon <<< "$data"

        local ip_anomalies=()
        local ip_score=0

        # Check for VPN/Proxy indicators
        if [[ $isp == *"VPN"* ]] || [[ $isp == *"Proxy"* ]] || [[ $org == *"VPN"* ]] || [[ $org == *"Proxy"* ]]; then
            ip_anomalies+=("VPN/Proxy service detected")
            ((ip_score += 3))
        fi

        # Check for hosting providers (potential VPS/servers)
        if [[ $isp == *"Amazon"* ]] || [[ $isp == *"Google"* ]] || [[ $isp == *"Microsoft"* ]] || [[ $isp == *"DigitalOcean"* ]]; then
            ip_anomalies+=("Cloud/hosting provider")
            ((ip_score += 2))
        fi

        # Check for Tor exit nodes (basic patterns)
        if [[ $org == *"Tor"* ]] || [[ $isp == *"Tor"* ]]; then
            ip_anomalies+=("Potential Tor exit node")
            ((ip_score += 4))
        fi

        # Check for unusual geographic locations for common services
        if [[ $country == "North Korea" ]] || [[ $country == "Iran" ]] || [[ $country == "Syria" ]]; then
            ip_anomalies+=("High-risk geographic location")
            ((ip_score += 3))
        fi

        # Check for missing location data (suspicious)
        if [[ -z "$country" ]] || [[ -z "$city" ]]; then
            ip_anomalies+=("Incomplete geolocation data")
            ((ip_score += 2))
        fi

        # Report findings for this IP
        echo -e "${CYAN}IP: $ip${NC}"
        if [ ${#ip_anomalies[@]} -gt 0 ]; then
            echo -e "${YELLOW}Anomalies detected:${NC}"
            for anomaly in "${ip_anomalies[@]}"; do
                echo -e "  • $anomaly"
            done
            echo -e "${YELLOW}Risk Score: $ip_score/10${NC}"
            anomalies+=("$ip: ${ip_anomalies[*]}")
            ((suspicious_score += ip_score))
        else
            echo -e "${GREEN}✓ No anomalies detected${NC}"
        fi
        echo ""
    done

    # Overall assessment
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}📊 Anomaly Analysis Summary${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Total IPs analyzed: ${#ip_data[@]}${NC}"
    echo -e "${CYAN}Anomalies found: ${#anomalies[@]}${NC}"
    echo -e "${CYAN}Overall risk score: $suspicious_score${NC}"

    if [ ${#anomalies[@]} -gt 0 ]; then
        echo -e "${RED}🚨 ANOMALIES DETECTED:${NC}"
        for anomaly in "${anomalies[@]}"; do
            echo -e "${RED}  • $anomaly${NC}"
        done

        if (( suspicious_score >= 8 )); then
            echo -e "\n${RED}⚠ HIGH RISK: Multiple suspicious indicators detected${NC}"
            echo -e "${YELLOW}Recommendations:${NC}"
            echo -e "• Investigate traffic sources and patterns"
            echo -e "• Consider implementing geo-blocking for high-risk regions"
            echo -e "• Monitor for VPN/proxy usage patterns"
            echo -e "• Review access logs for unusual activity"
        elif (( suspicious_score >= 4 )); then
            echo -e "\n${YELLOW}⚠ MEDIUM RISK: Some suspicious indicators detected${NC}"
            echo -e "${YELLOW}Recommendations:${NC}"
            echo -e "• Monitor these IPs for unusual activity"
            echo -e "• Consider additional authentication for suspicious sources"
        fi
    else
        echo -e "${GREEN}✅ NO ANOMALIES DETECTED${NC}"
        echo -e "${GREEN}All analyzed IPs appear to be from legitimate sources.${NC}"
    fi

    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    return ${#anomalies[@]}
}

# Function to simulate IP spoofing
simulate_ip_spoofing() {
    local url="$1"
    local spoof_ip="$2"

    echo -e "\n${GREEN}🎭 Simulating IP spoofing...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Target URL: $url${NC}"
    echo -e "${YELLOW}Spoofed IP: $spoof_ip${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    # Get GeoIP info for the spoofed IP
    echo -e "${CYAN}Getting GeoIP information for spoofed IP...${NC}"
    local spoof_data
    if spoof_data=$(geoip_lookup "$spoof_ip"); then
        echo -e "${GREEN}✓ Spoofed IP geolocation retrieved${NC}"
    else
        echo -e "${YELLOW}⚠ Could not retrieve geolocation for spoofed IP${NC}"
    fi

    # Simulate HTTP request with spoofed headers
    echo -e "\n${CYAN}Simulating HTTP request with spoofed headers...${NC}"

    local headers=(
        "X-Forwarded-For: $spoof_ip"
        "X-Real-IP: $spoof_ip"
        "X-Originating-IP: $spoof_ip"
        "X-Remote-IP: $spoof_ip"
        "X-Client-IP: $spoof_ip"
    )

    local curl_args=()
    for header in "${headers[@]}"; do
        curl_args+=("-H" "$header")
    done

    echo -e "${YELLOW}Headers being sent:${NC}"
    for header in "${headers[@]}"; do
        echo -e "  • $header"
    done

    echo -e "\n${CYAN}Making request...${NC}"
    local response
    if response=$(curl -s --connect-timeout 10 --max-time 15 "${curl_args[@]}" -I "$url" 2>&1); then
        echo -e "${GREEN}✓ Request completed successfully${NC}"

        # Analyze response
        local status_code
        status_code=$(echo "$response" | head -1 | grep -o '[0-9]\{3\}' | head -1)

        echo -e "\n${BLUE}Response Analysis:${NC}"
        echo -e "${CYAN}Status Code:${NC} ${status_code:-Unknown}"

        # Check for common spoofing detection headers
        if [[ $response == *"X-Forwarded-For"* ]]; then
            echo -e "${GREEN}✓ Server appears to process X-Forwarded-For header${NC}"
        else
            echo -e "${YELLOW}⚠ No evidence of X-Forwarded-For processing${NC}"
        fi

        # Check for rate limiting or blocking
        if [[ $status_code == "429" ]]; then
            echo -e "${RED}⚠ Rate limiting detected (429)${NC}"
        elif [[ $status_code == "403" ]]; then
            echo -e "${RED}⚠ Access forbidden (403) - possible IP blocking${NC}"
        elif [[ $status_code == "200" ]]; then
            echo -e "${GREEN}✓ Request accepted (200)${NC}"
        fi

    else
        echo -e "${RED}❌ Request failed: $response${NC}"
    fi

    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}📊 IP Spoofing Simulation Summary${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Target: $url${NC}"
    echo -e "${CYAN}Spoofed IP: $spoof_ip${NC}"
    echo -e "${CYAN}Headers sent: ${#headers[@]}${NC}"

    echo -e "\n${YELLOW}Important Notes:${NC}"
    echo -e "• This is a simulation using HTTP headers only"
    echo -e "• True IP spoofing requires raw socket manipulation"
    echo -e "• Many servers ignore or validate forwarded headers"
    echo -e "• Effectiveness depends on server configuration"
    echo -e "• Use only for authorized testing and research"

    echo -e "${BLUE}═══════════════════════════════════════${NC}"
}

# Main interactive function
interactive_mode() {
    while true; do
        show_banner

        echo -e "${GREEN}Welcome to WetMonkey GeoIP Anomaly Detector!${NC}"
        echo -e "${YELLOW}This tool helps analyze IP addresses for geographic anomalies and suspicious patterns.${NC}\n"
        echo -e "${RED}⚠ WARNING: Only test systems you own or have permission to test!${NC}\n"

        # Step 1: Analysis type selection
        echo -e "${GREEN}Step 1: Analysis Type${NC}"
        echo -e "Choose the type of GeoIP analysis:"
        echo -e "  ${YELLOW}1)${NC} Single IP Lookup - Get geolocation for one IP address"
        echo -e "  ${YELLOW}2)${NC} Multiple IP Analysis - Analyze multiple IPs for anomalies"
        echo -e "  ${YELLOW}3)${NC} IP Spoofing Simulation - Test IP spoofing against a target"
        echo -e "  ${YELLOW}4)${NC} Educational Information - Learn about GeoIP anomalies"

        local analysis_type
        while true; do
            choice=$(simple_input "Select analysis type (1-4)")
            case "$choice" in
                "1") analysis_type="single"; break ;;
                "2") analysis_type="multiple"; break ;;
                "3") analysis_type="spoofing"; break ;;
                "4") analysis_type="educational"; break ;;
                *) echo -e "${RED}Please select a number between 1-4${NC}" ;;
            esac
        done

        case "$analysis_type" in
            "single")
                # Single IP lookup
                echo -e "\n${GREEN}Step 2: IP Address Input${NC}"
                echo -e "Enter the IP address you want to analyze"

                local ip
                while true; do
                    ip=$(simple_input "IP Address")
                    if [ -z "$ip" ]; then
                        echo -e "${RED}IP address is required!${NC}"
                        continue
                    fi

                    if validate_ip "$ip"; then
                        break
                    else
                        echo -e "${RED}Please enter a valid IP address${NC}"
                    fi
                done

                # Step 3: Perform lookup
                echo -e "\n${GREEN}Step 3: GeoIP Lookup${NC}"

                # Log start
                log_json "geoip_start" "ip=$ip mode=single" 2>/dev/null || true

                # Perform lookup
                local lookup_data
                if lookup_data=$(geoip_lookup "$ip"); then
                    # Analyze for anomalies
                    detect_geoip_anomalies "$lookup_data"
                else
                    echo -e "${RED}Failed to retrieve GeoIP information${NC}"
                fi

                # Log end
                log_json "geoip_end" "ip=$ip" 2>/dev/null || true
                ;;

            "multiple")
                # Multiple IP analysis
                echo -e "\n${GREEN}Step 2: IP Address List${NC}"
                echo -e "Enter IP addresses one by one (press Enter with empty input to finish)"
                echo -e "${YELLOW}Maximum $MAX_IPS IP addresses${NC}"

                local ips=()
                local ip_count=0

                while true; do
                    ip=$(simple_input "IP Address $((ip_count + 1)) (or press Enter to finish)")
                    if [ -z "$ip" ]; then
                        if [ ${#ips[@]} -eq 0 ]; then
                            echo -e "${RED}Please enter at least one IP address${NC}"
                            continue
                        else
                            break
                        fi
                    fi

                    if validate_ip "$ip"; then
                        ips+=("$ip")
                        ((ip_count++))
                        echo -e "${GREEN}✓ Added: $ip${NC}"
                    else
                        echo -e "${RED}Invalid IP format, skipping: $ip${NC}"
                    fi

                    if [ ${#ips[@]} -ge $MAX_IPS ]; then
                        echo -e "${YELLOW}Maximum $MAX_IPS IP addresses reached${NC}"
                        break
                    fi
                done

                # Step 3: Perform analysis
                echo -e "\n${GREEN}Step 3: GeoIP Analysis${NC}"
                echo -e "${CYAN}Analyzing ${#ips[@]} IP addresses...${NC}"

                # Log start
                log_json "geoip_start" "ips=${#ips[@]} mode=multiple" 2>/dev/null || true

                # Collect data for all IPs
                local ip_data=()
                for ip in "${ips[@]}"; do
                    echo -e "\n${MAGENTA}Analyzing: $ip${NC}"
                    local lookup_data
                    if lookup_data=$(geoip_lookup "$ip"); then
                        ip_data+=("$lookup_data")
                    else
                        echo -e "${RED}Failed to get data for $ip${NC}"
                    fi
                done

                # Perform anomaly analysis
                if [ ${#ip_data[@]} -gt 0 ]; then
                    detect_geoip_anomalies "${ip_data[@]}"
                else
                    echo -e "${RED}No valid IP data collected for analysis${NC}"
                fi

                # Log end
                log_json "geoip_end" "ips=${#ips[@]} analyzed=${#ip_data[@]}" 2>/dev/null || true
                ;;

            "spoofing")
                # IP spoofing simulation
                echo -e "\n${GREEN}Step 2: Target and Spoofed IP${NC}"

                local target_url
                while true; do
                    target_url=$(simple_input "Target URL")
                    if [ -z "$target_url" ]; then
                        echo -e "${RED}Target URL is required!${NC}"
                        continue
                    fi

                    if validate_url "$target_url"; then
                        break
                    else
                        echo -e "${RED}Please enter a valid URL (http:// or https://)${NC}"
                    fi
                done

                local spoof_ip
                while true; do
                    spoof_ip=$(simple_input "IP to spoof")
                    if [ -z "$spoof_ip" ]; then
                        echo -e "${RED}IP address is required!${NC}"
                        continue
                    fi

                    if validate_ip "$spoof_ip"; then
                        break
                    else
                        echo -e "${RED}Please enter a valid IP address${NC}"
                    fi
                done

                # Step 3: Authorization warning
                echo -e "\n${RED}⚠ AUTHORIZATION WARNING ⚠${NC}"
                echo -e "${YELLOW}You are about to simulate IP spoofing against: $target_url${NC}"
                echo -e "${RED}Only proceed if you have explicit permission to test this target!${NC}"

                if ask_yes_no "Do you have authorization to test this target?" "n"; then
                    # Log start
                    log_json "geoip_spoof_start" "url=$target_url spoof_ip=$spoof_ip" 2>/dev/null || true

                    # Perform spoofing simulation
                    simulate_ip_spoofing "$target_url" "$spoof_ip"

                    # Log end
                    log_json "geoip_spoof_end" "url=$target_url spoof_ip=$spoof_ip" 2>/dev/null || true
                else
                    echo -e "${YELLOW}Spoofing simulation cancelled.${NC}"
                fi
                ;;

            "educational")
                # Show educational information
                show_educational_info
                ;;
        esac

        echo -e "\n${YELLOW}Press Enter to continue...${NC}"
        read -r

        if ! ask_yes_no "Perform another analysis?" "y"; then
            break
        fi
    done
}

# Educational information function
show_educational_info() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║         📚 GeoIP Anomaly Guide          ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}\n"

    echo -e "${GREEN}What is GeoIP Analysis?${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "GeoIP analysis maps IP addresses to geographic locations using databases"
    echo -e "that correlate IP ranges with countries, cities, ISPs, and organizations."
    echo -e "This helps identify the physical location of network traffic sources.\n"

    echo -e "${GREEN}Common GeoIP Anomalies${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}1. VPN/Proxy Usage${NC}"
    echo -e "   • Traffic appears from VPN or proxy services"
    echo -e "   • May indicate attempts to hide true location"
    echo -e "${YELLOW}2. Tor Network Activity${NC}"
    echo -e "   • Traffic from known Tor exit nodes"
    echo -e "   • High anonymity, potential security concern"
    echo -e "${YELLOW}3. Cloud/Hosting Providers${NC}"
    echo -e "   • Traffic from data centers instead of residential IPs"
    echo -e "   • May indicate automated/bot activity"
    echo -e "${YELLOW}4. High-Risk Locations${NC}"
    echo -e "   • Traffic from countries with high cybercrime rates"
    echo -e "   • May require additional security measures\n"

    echo -e "${GREEN}Detection Techniques${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}1. ISP Analysis:${NC} Check if ISP is known VPN/proxy provider"
    echo -e "${CYAN}2. ASN Lookup:${NC} Identify the Autonomous System Number"
    echo -e "${CYAN}3. Geolocation Consistency:${NC} Verify location data across sources"
    echo -e "${CYAN}4. Behavioral Analysis:${NC} Compare with expected user patterns"
    echo -e "${CYAN}5. Blacklist Checking:${NC} Cross-reference with threat intelligence\n"

    echo -e "${GREEN}IP Spoofing Techniques${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}1. HTTP Header Spoofing${NC}"
    echo -e "   • X-Forwarded-For: Indicates original client IP"
    echo -e "   • X-Real-IP: Alternative header for client IP"
    echo -e "   • X-Originating-IP: Microsoft-specific header"
    echo -e "${YELLOW}2. Raw Socket Spoofing${NC}"
    echo -e "   • Requires root privileges and raw socket access"
    echo -e "   • Can forge source IP in packet headers"
    echo -e "   • Limited by network infrastructure filtering\n"

    echo -e "${GREEN}Defensive Measures${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}✓ Multi-Source Validation:${NC}"
    echo -e "  • Use multiple GeoIP databases for verification"
    echo -e "  • Cross-reference with other data sources"
    echo -e "${GREEN}✓ Behavioral Analysis:${NC}"
    echo -e "  • Monitor for unusual access patterns"
    echo -e "  • Implement rate limiting and anomaly detection"
    echo -e "${GREEN}✓ Header Validation:${NC}"
    echo -e "  • Validate X-Forwarded-For headers carefully"
    echo -e "  • Implement proper proxy chain validation"
    echo -e "${GREEN}✓ Geographic Restrictions:${NC}"
    echo -e "  • Block traffic from high-risk countries"
    echo -e "  • Implement country-based access controls\n"

    echo -e "${GREEN}Legal and Ethical Considerations${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${RED}⚠ IMPORTANT:${NC} Only analyze IPs and test systems you own or have permission"
    echo -e "${RED}⚠ PRIVACY:${NC} GeoIP data may be subject to privacy regulations"
    echo -e "${RED}⚠ ACCURACY:${NC} GeoIP data is not 100% accurate and should not be solely relied upon"
    echo -e "${RED}⚠ LEGAL:${NC} IP spoofing may violate terms of service and local laws\n"
}

# Main function
main() {
    local lookup_ip=""
    local analyze_ips=""
    local url=""
    local spoof_ip=""

    # Parse command line arguments
    if [[ $# -gt 0 ]]; then
        while [[ $# -gt 0 ]]; do
            case "$1" in
                -h|--help)
                    show_help
                    exit 0
                    ;;
                --lookup)
                    if [ -z "${2:-}" ]; then
                        echo -e "${RED}Error: --lookup requires an IP address${NC}" >&2
                        exit 1
                    fi
                    lookup_ip="$2"
                    shift 2
                    ;;
                --analyze)
                    if [ -z "${2:-}" ]; then
                        echo -e "${RED}Error: --analyze requires IP addresses${NC}" >&2
                        exit 1
                    fi
                    analyze_ips="$2"
                    shift 2
                    ;;
                -u|--url)
                    if [ -z "${2:-}" ]; then
                        echo -e "${RED}Error: -u requires a URL${NC}" >&2
                        exit 1
                    fi
                    url="$2"
                    shift 2
                    ;;
                --ip)
                    if [ -z "${2:-}" ]; then
                        echo -e "${RED}Error: --ip requires an IP address${NC}" >&2
                        exit 1
                    fi
                    spoof_ip="$2"
                    shift 2
                    ;;
                *)
                    echo -e "${RED}Unknown option: $1${NC}" >&2
                    echo "Use -h for help." >&2
                    exit 1
                    ;;
            esac
        done

        # Handle lookup mode
        if [ -n "$lookup_ip" ]; then
            echo -e "${GREEN}Quick GeoIP Lookup: $lookup_ip${NC}"

            if ! validate_ip "$lookup_ip"; then
                echo -e "${RED}Error: Invalid IP address format${NC}" >&2
                exit 1
            fi

            # Log start
            log_json "geoip_start" "ip=$lookup_ip mode=quick" 2>/dev/null || true

            # Perform lookup
            local lookup_data
            if lookup_data=$(geoip_lookup "$lookup_ip"); then
                detect_geoip_anomalies "$lookup_data"
            else
                echo -e "${RED}Failed to retrieve GeoIP information${NC}"
                exit 1
            fi

            # Log end
            log_json "geoip_end" "ip=$lookup_ip" 2>/dev/null || true
            exit 0
        fi

        # Handle analyze mode
        if [ -n "$analyze_ips" ]; then
            echo -e "${GREEN}GeoIP Analysis: $analyze_ips${NC}"

            # Parse comma-separated IPs
            IFS=',' read -ra ip_array <<< "$analyze_ips"
            local valid_ips=()

            for ip in "${ip_array[@]}"; do
                ip=$(echo "$ip" | xargs)  # Trim whitespace
                if validate_ip "$ip"; then
                    valid_ips+=("$ip")
                else
                    echo -e "${RED}Warning: Invalid IP format, skipping: $ip${NC}" >&2
                fi
            done

            if [ ${#valid_ips[@]} -eq 0 ]; then
                echo -e "${RED}Error: No valid IP addresses provided${NC}" >&2
                exit 1
            fi

            # Log start
            log_json "geoip_start" "ips=${#valid_ips[@]} mode=analyze" 2>/dev/null || true

            # Collect data for all IPs
            local ip_data=()
            for ip in "${valid_ips[@]}"; do
                echo -e "\n${MAGENTA}Analyzing: $ip${NC}"
                local lookup_data
                if lookup_data=$(geoip_lookup "$ip"); then
                    ip_data+=("$lookup_data")
                fi
            done

            # Perform anomaly analysis
            if [ ${#ip_data[@]} -gt 0 ]; then
                detect_geoip_anomalies "${ip_data[@]}"
            else
                echo -e "${RED}No valid IP data collected for analysis${NC}"
                exit 1
            fi

            # Log end
            log_json "geoip_end" "ips=${#valid_ips[@]} analyzed=${#ip_data[@]}" 2>/dev/null || true
            exit 0
        fi

        # Handle legacy spoofing mode
        if [ -n "$url" ] && [ -n "$spoof_ip" ]; then
            echo -e "${YELLOW}Legacy spoofing mode...${NC}"

            if ! validate_url "$url"; then
                echo -e "${RED}Error: Invalid URL format${NC}" >&2
                exit 1
            fi

            if ! validate_ip "$spoof_ip"; then
                echo -e "${RED}Error: Invalid IP address format${NC}" >&2
                exit 1
            fi

            # Log start
            log_json "geoip_spoof_start" "url=$url spoof_ip=$spoof_ip mode=legacy" 2>/dev/null || true

            # Perform spoofing simulation
            simulate_ip_spoofing "$url" "$spoof_ip"

            # Log end
            log_json "geoip_spoof_end" "url=$url spoof_ip=$spoof_ip" 2>/dev/null || true
            exit 0
        fi

        # If we get here, invalid combination of arguments
        echo -e "${RED}Error: Invalid argument combination${NC}" >&2
        echo "Use -h for help or run without arguments for interactive mode." >&2
        exit 1
    fi

    # Check dependencies for interactive mode
    missing_deps=()
    if ! command -v curl &> /dev/null; then
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
