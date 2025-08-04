#!/usr/bin/env bash
# wetmonkey dnszonetransfer – Interactive DNS Zone Transfer Testing Suite v2.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$SCRIPT_DIR/../../"
source "$BASE_DIR/core/utils.sh"

# Configuration
VERSION="2.0"
MAX_NAMESERVERS=10

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
    echo "║    🌐 WetMonkey DNS Zone Transfer Tester ║"
    echo "║         Interactive Mode v2.0           ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Show usage information
show_help() {
    echo "WetMonkey DNS Zone Transfer Testing Module v${VERSION}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  -d, --domain <domain>   Domain to test (legacy mode)"
    echo "  -n, --ns <nameserver>   Nameserver to test (legacy mode)"
    echo "  --quick <domain>        Quick zone transfer test"
    echo ""
    echo "This module provides interactive DNS zone transfer testing."
    echo "Supported features: AXFR testing, nameserver discovery, comprehensive analysis"
    echo ""
    echo "Example:"
    echo "  $0                      # Run in interactive mode"
    echo "  $0 -h                   # Show this help"
    echo "  $0 --quick example.com  # Quick zone transfer test"
    echo "  $0 -d example.com -n ns1.example.com  # Legacy mode"
    echo ""
    echo "Note: This tool is for authorized security testing only!"
    echo "      Use responsibly and only on domains you own or have permission to test."
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

# Function to validate domain name
validate_domain() {
    local domain="$1"
    if [[ ${#domain} -gt 255 ]]; then
        return 1
    fi
    if [[ $domain =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        return 0
    fi
    return 1
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

# Function to discover nameservers for a domain
discover_nameservers() {
    local domain="$1"
    local nameservers=()

    echo -e "${YELLOW}Discovering nameservers for $domain...${NC}" >&2

    # Use dig to get NS records
    local ns_records
    ns_records=$(dig +short NS "$domain" 2>/dev/null | head -10)

    if [ -n "$ns_records" ]; then
        while IFS= read -r ns; do
            if [ -n "$ns" ]; then
                # Remove trailing dot if present
                ns="${ns%.}"
                nameservers+=("$ns")
                echo -e "${GREEN}✓ Found nameserver: $ns${NC}" >&2
            fi
        done <<< "$ns_records"
    fi

    # If no NS records found, try common nameserver patterns
    if [ ${#nameservers[@]} -eq 0 ]; then
        echo -e "${YELLOW}No NS records found, trying common patterns...${NC}" >&2
        local common_ns=("ns1.$domain" "ns2.$domain" "ns.$domain" "dns1.$domain" "dns2.$domain")

        for ns in "${common_ns[@]}"; do
            if nslookup "$ns" >/dev/null 2>&1; then
                nameservers+=("$ns")
                echo -e "${GREEN}✓ Found nameserver: $ns${NC}" >&2
            fi
        done
    fi

    # Return nameservers as array
    printf '%s\n' "${nameservers[@]}"
}

# Function to test AXFR zone transfer
test_axfr_transfer() {
    local domain="$1"
    local nameserver="$2"
    local success=false

    echo -e "${CYAN}Testing AXFR zone transfer...${NC}" >&2
    echo -e "${BLUE}Domain: $domain${NC}" >&2
    echo -e "${BLUE}Nameserver: $nameserver${NC}" >&2
    echo -e "${BLUE}═══════════════════════════════════════${NC}" >&2

    # Test AXFR transfer
    local axfr_output
    axfr_output=$(dig "@$nameserver" AXFR "$domain" 2>&1)
    local axfr_exit_code=$?

    if [ $axfr_exit_code -eq 0 ] && [[ $axfr_output != *"Transfer failed"* ]] && [[ $axfr_output != *"connection timed out"* ]] && [[ $axfr_output == *"$domain"* ]]; then
        echo -e "${RED}🚨 VULNERABILITY: Zone transfer successful!${NC}" >&2
        echo -e "${YELLOW}Zone transfer data:${NC}" >&2
        echo "$axfr_output" | head -20
        if [ $(echo "$axfr_output" | wc -l) -gt 20 ]; then
            echo -e "${YELLOW}... (output truncated, showing first 20 lines)${NC}" >&2
        fi
        success=true
    else
        echo -e "${GREEN}✓ Zone transfer denied (secure)${NC}" >&2
        if [[ $axfr_output == *"Transfer failed"* ]]; then
            echo -e "${BLUE}  Reason: Transfer explicitly denied${NC}" >&2
        elif [[ $axfr_output == *"connection timed out"* ]]; then
            echo -e "${BLUE}  Reason: Connection timeout${NC}" >&2
        elif [[ $axfr_output == *"REFUSED"* ]]; then
            echo -e "${BLUE}  Reason: Query refused${NC}" >&2
        else
            echo -e "${BLUE}  Reason: No zone data returned${NC}" >&2
        fi
    fi

    echo -e "${BLUE}═══════════════════════════════════════${NC}" >&2

    if [ "$success" = true ]; then
        return 0
    else
        return 1
    fi
}

# Function to test with dnsrecon
test_dnsrecon() {
    local domain="$1"
    local nameserver="$2"

    echo -e "${CYAN}Testing with dnsrecon...${NC}" >&2
    echo -e "${BLUE}═══════════════════════════════════════${NC}" >&2

    if command -v dnsrecon &> /dev/null; then
        local dnsrecon_output
        dnsrecon_output=$(timeout 30 dnsrecon -d "$domain" -n "$nameserver" -t axfr 2>&1 || true)

        if [[ $dnsrecon_output == *"Zone Transfer was successful"* ]] || [[ $dnsrecon_output == *"AXFR"* ]]; then
            echo -e "${RED}🚨 VULNERABILITY: dnsrecon detected successful zone transfer!${NC}" >&2
            echo -e "${YELLOW}dnsrecon output:${NC}" >&2
            echo "$dnsrecon_output" | head -15
            return 0
        else
            echo -e "${GREEN}✓ dnsrecon: No zone transfer vulnerability${NC}" >&2
            if [[ $dnsrecon_output == *"REFUSED"* ]]; then
                echo -e "${BLUE}  Reason: Query refused${NC}" >&2
            elif [[ $dnsrecon_output == *"timeout"* ]]; then
                echo -e "${BLUE}  Reason: Connection timeout${NC}" >&2
            fi
            return 1
        fi
    else
        echo -e "${YELLOW}⚠ dnsrecon not available, skipping${NC}" >&2
        return 1
    fi

    echo -e "${BLUE}═══════════════════════════════════════${NC}" >&2
}

# Function to perform comprehensive zone transfer testing
comprehensive_zone_test() {
    local domain="$1"
    local nameservers=("${@:2}")
    local vulnerable_servers=()
    local total_tests=0
    local successful_transfers=0

    echo -e "\n${GREEN}🔍 Starting comprehensive zone transfer testing...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Target Domain: $domain${NC}"
    echo -e "${YELLOW}Nameservers to test: ${#nameservers[@]}${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    for nameserver in "${nameservers[@]}"; do
        echo -e "${MAGENTA}Testing nameserver: $nameserver${NC}"
        ((total_tests++))

        # Test AXFR
        if test_axfr_transfer "$domain" "$nameserver"; then
            vulnerable_servers+=("$nameserver (AXFR)")
            ((successful_transfers++))
        fi

        # Test with dnsrecon
        if test_dnsrecon "$domain" "$nameserver"; then
            if [[ ! " ${vulnerable_servers[@]} " =~ " $nameserver (AXFR) " ]]; then
                vulnerable_servers+=("$nameserver (dnsrecon)")
                ((successful_transfers++))
            fi
        fi

        echo ""
    done

    # Summary
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}📊 Zone Transfer Test Summary${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Domain tested: $domain${NC}"
    echo -e "${CYAN}Nameservers tested: $total_tests${NC}"
    echo -e "${CYAN}Successful transfers: $successful_transfers${NC}"

    if [ ${#vulnerable_servers[@]} -gt 0 ]; then
        echo -e "${RED}🚨 VULNERABLE NAMESERVERS FOUND:${NC}"
        for server in "${vulnerable_servers[@]}"; do
            echo -e "${RED}  • $server${NC}"
        done
        echo -e "\n${RED}⚠ SECURITY RISK: Zone transfer is enabled!${NC}"
        echo -e "${YELLOW}Recommendation: Disable zone transfers or restrict to authorized servers only.${NC}"
    else
        echo -e "${GREEN}✅ SECURE: No zone transfer vulnerabilities found${NC}"
        echo -e "${GREEN}All nameservers properly deny zone transfer requests.${NC}"
    fi

    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    return $successful_transfers
}

# Main interactive function
interactive_mode() {
    while true; do
        show_banner

        echo -e "${GREEN}Welcome to WetMonkey DNS Zone Transfer Tester!${NC}"
        echo -e "${YELLOW}Let's test domains for DNS zone transfer vulnerabilities step by step.${NC}\n"
        echo -e "${RED}⚠ WARNING: Only test domains you own or have permission to test!${NC}\n"

        # Educational information
        echo -e "${CYAN}📚 About DNS Zone Transfers:${NC}"
        echo -e "${BLUE}DNS zone transfers (AXFR) allow replication of DNS zone data between servers.${NC}"
        echo -e "${BLUE}If misconfigured, they can expose all DNS records to unauthorized users.${NC}"
        echo -e "${BLUE}This includes subdomains, internal IPs, and network infrastructure details.${NC}\n"

        # Step 1: Test type selection
        echo -e "${GREEN}Step 1: Test Type${NC}"
        echo -e "Choose the type of zone transfer test:"
        echo -e "  ${YELLOW}1)${NC} Single Domain Test - Test one domain comprehensively"
        echo -e "  ${YELLOW}2)${NC} Custom Nameserver Test - Test specific domain/nameserver combination"
        echo -e "  ${YELLOW}3)${NC} Educational Information - Learn about zone transfer security"

        local test_type
        while true; do
            choice=$(simple_input "Select test type (1-3)")
            case "$choice" in
                "1") test_type="single"; break ;;
                "2") test_type="custom"; break ;;
                "3") test_type="educational"; break ;;
                *) echo -e "${RED}Please select a number between 1-3${NC}" ;;
            esac
        done

        case "$test_type" in
            "single")
                # Single domain comprehensive test
                echo -e "\n${GREEN}Step 2: Domain Input${NC}"
                echo -e "Enter the domain you want to test for zone transfer vulnerabilities"

                local domain
                while true; do
                    domain=$(simple_input "Domain name")
                    if [ -z "$domain" ]; then
                        echo -e "${RED}Domain name is required!${NC}"
                        continue
                    fi

                    if validate_domain "$domain"; then
                        break
                    else
                        echo -e "${RED}Please enter a valid domain name${NC}"
                    fi
                done

                # Step 3: Nameserver discovery
                echo -e "\n${GREEN}Step 3: Nameserver Discovery${NC}"
                echo -e "${CYAN}Discovering nameservers for $domain...${NC}"

                local nameservers_array=()
                while IFS= read -r ns; do
                    if [ -n "$ns" ]; then
                        nameservers_array+=("$ns")
                    fi
                done < <(discover_nameservers "$domain")

                if [ ${#nameservers_array[@]} -eq 0 ]; then
                    echo -e "${RED}❌ No nameservers found for $domain${NC}"
                    echo -e "${YELLOW}You can try the custom nameserver test if you know specific nameservers.${NC}"
                else
                    echo -e "${GREEN}✓ Found ${#nameservers_array[@]} nameserver(s)${NC}"

                    # Step 4: Execute comprehensive test
                    echo -e "\n${GREEN}Step 4: Zone Transfer Testing${NC}"

                    if ask_yes_no "Start comprehensive zone transfer testing?" "y"; then
                        echo -e "\n${CYAN}Starting zone transfer tests...${NC}"

                        # Log start
                        log_json "dnszonetransfer_start" "domain=$domain nameservers=${#nameservers_array[@]} mode=comprehensive" 2>/dev/null || true

                        # Perform comprehensive test
                        comprehensive_zone_test "$domain" "${nameservers_array[@]}"
                        local test_result=$?

                        # Log end
                        log_json "dnszonetransfer_end" "domain=$domain vulnerabilities=$test_result" 2>/dev/null || true
                    else
                        echo -e "${YELLOW}Test cancelled.${NC}"
                    fi
                fi
                ;;

            "custom")
                # Custom domain/nameserver test
                echo -e "\n${GREEN}Step 2: Domain and Nameserver Input${NC}"

                local domain
                while true; do
                    domain=$(simple_input "Domain name")
                    if [ -z "$domain" ]; then
                        echo -e "${RED}Domain name is required!${NC}"
                        continue
                    fi

                    if validate_domain "$domain"; then
                        break
                    else
                        echo -e "${RED}Please enter a valid domain name${NC}"
                    fi
                done

                local nameserver
                while true; do
                    nameserver=$(simple_input "Nameserver (IP or hostname)")
                    if [ -z "$nameserver" ]; then
                        echo -e "${RED}Nameserver is required!${NC}"
                        continue
                    fi

                    if validate_domain "$nameserver" || validate_ip "$nameserver"; then
                        break
                    else
                        echo -e "${RED}Please enter a valid nameserver IP or hostname${NC}"
                    fi
                done

                # Step 3: Execute custom test
                echo -e "\n${GREEN}Step 3: Zone Transfer Testing${NC}"
                echo -e "${CYAN}Testing specific domain/nameserver combination...${NC}"

                if ask_yes_no "Start zone transfer test?" "y"; then
                    echo -e "\n${CYAN}Starting zone transfer test...${NC}"

                    # Log start
                    log_json "dnszonetransfer_start" "domain=$domain nameserver=$nameserver mode=custom" 2>/dev/null || true

                    # Perform single test
                    local vulnerable=0
                    if test_axfr_transfer "$domain" "$nameserver"; then
                        ((vulnerable++))
                    fi
                    if test_dnsrecon "$domain" "$nameserver"; then
                        ((vulnerable++))
                    fi

                    # Summary for single test
                    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
                    echo -e "${GREEN}📊 Single Test Summary${NC}"
                    echo -e "${BLUE}═══════════════════════════════════════${NC}"
                    echo -e "${CYAN}Domain: $domain${NC}"
                    echo -e "${CYAN}Nameserver: $nameserver${NC}"

                    if [ $vulnerable -gt 0 ]; then
                        echo -e "${RED}🚨 VULNERABILITY FOUND: Zone transfer is possible!${NC}"
                        echo -e "${YELLOW}Recommendation: Disable zone transfers or restrict access.${NC}"
                    else
                        echo -e "${GREEN}✅ SECURE: Zone transfer properly denied${NC}"
                    fi
                    echo -e "${BLUE}═══════════════════════════════════════${NC}"

                    # Log end
                    log_json "dnszonetransfer_end" "domain=$domain nameserver=$nameserver vulnerable=$vulnerable" 2>/dev/null || true
                else
                    echo -e "${YELLOW}Test cancelled.${NC}"
                fi
                ;;

            "educational")
                # Educational information
                show_educational_info
                ;;
        esac

        echo -e "\n${YELLOW}Press Enter to continue...${NC}"
        read -r

        if ! ask_yes_no "Perform another test?" "y"; then
            break
        fi
    done
}

# Educational information function
show_educational_info() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║         📚 DNS Zone Transfer Guide       ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}\n"

    echo -e "${GREEN}What is DNS Zone Transfer?${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "DNS zone transfer (AXFR) is a mechanism that allows DNS servers"
    echo -e "to replicate zone data between primary and secondary nameservers."
    echo -e "It's essential for DNS redundancy and load distribution.\n"

    echo -e "${GREEN}Security Implications${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${RED}• Information Disclosure:${NC} Exposes all DNS records"
    echo -e "${RED}• Subdomain Enumeration:${NC} Reveals hidden subdomains"
    echo -e "${RED}• Network Mapping:${NC} Shows internal IP addresses"
    echo -e "${RED}• Infrastructure Discovery:${NC} Reveals server locations\n"

    echo -e "${GREEN}Common Vulnerabilities${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}1. Unrestricted Zone Transfers${NC}"
    echo -e "   - Any client can request full zone data"
    echo -e "   - No IP address restrictions configured"
    echo -e "${YELLOW}2. Misconfigured Secondary Servers${NC}"
    echo -e "   - Secondary servers allow public transfers"
    echo -e "   - Backup servers with weak security"
    echo -e "${YELLOW}3. Legacy DNS Configurations${NC}"
    echo -e "   - Old DNS software with default settings"
    echo -e "   - Unpatched DNS servers\n"

    echo -e "${GREEN}Testing Methods${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}1. AXFR Query (dig):${NC}"
    echo -e "   dig @nameserver AXFR domain.com"
    echo -e "${CYAN}2. DNS Reconnaissance (dnsrecon):${NC}"
    echo -e "   dnsrecon -d domain.com -t axfr"
    echo -e "${CYAN}3. Automated Testing:${NC}"
    echo -e "   Test multiple nameservers automatically\n"

    echo -e "${GREEN}Mitigation Strategies${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}✓ Restrict Zone Transfers:${NC}"
    echo -e "  - Configure 'allow-transfer' with specific IPs"
    echo -e "  - Use TSIG (Transaction Signatures) for authentication"
    echo -e "${GREEN}✓ Network Segmentation:${NC}"
    echo -e "  - Place DNS servers in protected network segments"
    echo -e "  - Use firewalls to restrict DNS traffic"
    echo -e "${GREEN}✓ Regular Auditing:${NC}"
    echo -e "  - Regularly test zone transfer configurations"
    echo -e "  - Monitor DNS query logs for suspicious activity"
    echo -e "${GREEN}✓ DNS Security Extensions:${NC}"
    echo -e "  - Implement DNSSEC for data integrity"
    echo -e "  - Use DNS over HTTPS (DoH) or DNS over TLS (DoT)\n"

    echo -e "${GREEN}Example Secure Configuration (BIND)${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}zone \"example.com\" {${NC}"
    echo -e "${YELLOW}    type master;${NC}"
    echo -e "${YELLOW}    file \"/etc/bind/db.example.com\";${NC}"
    echo -e "${YELLOW}    allow-transfer { 192.168.1.10; 192.168.1.11; };${NC}"
    echo -e "${YELLOW}    also-notify { 192.168.1.10; 192.168.1.11; };${NC}"
    echo -e "${YELLOW}};${NC}\n"

    echo -e "${GREEN}Legal and Ethical Considerations${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${RED}⚠ IMPORTANT:${NC} Only test domains you own or have explicit permission to test"
    echo -e "${RED}⚠ LEGAL:${NC} Unauthorized DNS testing may violate computer crime laws"
    echo -e "${RED}⚠ ETHICAL:${NC} Always follow responsible disclosure practices"
    echo -e "${RED}⚠ PROFESSIONAL:${NC} Document findings and provide remediation guidance\n"
}

# Legacy mode function
legacy_mode() {
    local domain="$1"
    local nameserver="$2"

    echo -e "${YELLOW}Running in legacy mode...${NC}"
    echo -e "${RED}⚠ WARNING: Only test domains you own or have permission to test!${NC}\n"

    # Validate inputs
    if ! validate_domain "$domain"; then
        echo -e "${RED}Error: Invalid domain format${NC}" >&2
        exit 1
    fi

    if ! validate_domain "$nameserver" && ! validate_ip "$nameserver"; then
        echo -e "${RED}Error: Invalid nameserver format${NC}" >&2
        exit 1
    fi

    # Log start
    log_json "dnszonetransfer_start" "domain=$domain nameserver=$nameserver mode=legacy" 2>/dev/null || true

    # Perform tests
    echo -e "${CYAN}Testing zone transfer for $domain using nameserver $nameserver${NC}"

    local vulnerable=0
    if test_axfr_transfer "$domain" "$nameserver"; then
        ((vulnerable++))
    fi
    if test_dnsrecon "$domain" "$nameserver"; then
        ((vulnerable++))
    fi

    # Log end
    log_json "dnszonetransfer_end" "domain=$domain nameserver=$nameserver vulnerable=$vulnerable" 2>/dev/null || true

    if [ $vulnerable -gt 0 ]; then
        exit 1  # Indicate vulnerability found
    else
        exit 0  # Secure
    fi
}

# Main function
main() {
    local domain=""
    local nameserver=""
    local quick_domain=""

    # Parse command line arguments
    if [[ $# -gt 0 ]]; then
        while [[ $# -gt 0 ]]; do
            case "$1" in
                -h|--help)
                    show_help
                    exit 0
                    ;;
                -d|--domain)
                    if [ -z "${2:-}" ]; then
                        echo -e "${RED}Error: -d requires a domain${NC}" >&2
                        exit 1
                    fi
                    domain="$2"
                    shift 2
                    ;;
                -n|--ns)
                    if [ -z "${2:-}" ]; then
                        echo -e "${RED}Error: -n requires a nameserver${NC}" >&2
                        exit 1
                    fi
                    nameserver="$2"
                    shift 2
                    ;;
                --quick)
                    if [ -z "${2:-}" ]; then
                        echo -e "${RED}Error: --quick requires a domain${NC}" >&2
                        exit 1
                    fi
                    quick_domain="$2"
                    shift 2
                    ;;
                *)
                    echo -e "${RED}Unknown option: $1${NC}" >&2
                    echo "Use -h for help." >&2
                    exit 1
                    ;;
            esac
        done

        # Handle quick domain test
        if [ -n "$quick_domain" ]; then
            echo -e "${GREEN}Quick Zone Transfer Test: $quick_domain${NC}"

            if ! validate_domain "$quick_domain"; then
                echo -e "${RED}Error: Invalid domain format${NC}" >&2
                exit 1
            fi

            # Discover nameservers and test
            local nameservers_array=()
            while IFS= read -r ns; do
                if [ -n "$ns" ]; then
                    nameservers_array+=("$ns")
                fi
            done < <(discover_nameservers "$quick_domain")

            if [ ${#nameservers_array[@]} -eq 0 ]; then
                echo -e "${RED}❌ No nameservers found for $quick_domain${NC}"
                exit 1
            fi

            # Log start
            log_json "dnszonetransfer_start" "domain=$quick_domain nameservers=${#nameservers_array[@]} mode=quick" 2>/dev/null || true

            # Perform test
            comprehensive_zone_test "$quick_domain" "${nameservers_array[@]}"
            local test_result=$?

            # Log end
            log_json "dnszonetransfer_end" "domain=$quick_domain vulnerabilities=$test_result" 2>/dev/null || true

            exit $test_result
        fi

        # Handle legacy mode
        if [ -n "$domain" ] && [ -n "$nameserver" ]; then
            legacy_mode "$domain" "$nameserver"
            exit $?
        elif [ -n "$domain" ] || [ -n "$nameserver" ]; then
            echo -e "${RED}Error: Both -d and -n are required for legacy mode${NC}" >&2
            echo "Use -h for help or run without arguments for interactive mode." >&2
            exit 1
        fi
    fi

    # Check dependencies for interactive mode
    missing_deps=()
    if ! command -v dig &> /dev/null; then
        missing_deps+=("dig (dnsutils)")
    fi
    if ! command -v nslookup &> /dev/null; then
        missing_deps+=("nslookup")
    fi

    if [ ${#missing_deps[@]} -gt 0 ]; then
        echo -e "${YELLOW}Warning: Some DNS tools are missing: ${missing_deps[*]}${NC}"
        echo -e "${YELLOW}Some features may have reduced functionality.${NC}\n"
    fi

    # Start interactive mode
    interactive_mode
}

# Run the main function with all arguments
main "$@"
