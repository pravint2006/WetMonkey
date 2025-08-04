#!/usr/bin/env bash
# wetmonkey dnstunnel – Interactive DNS Tunneling Detection and Analysis v2.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$SCRIPT_DIR/../../"
source "$BASE_DIR/core/utils.sh"

# Configuration
VERSION="2.0"
MAX_TIMEOUT=3600  # 1 hour max

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'
RESET='\033[0m'  # For backward compatibility

show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║      🕳️  WetMonkey DNS Tunnel Detector   ║"
    echo "║         Interactive Mode v2.0           ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
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

# Function to check if domain is reachable
check_domain_reachable() {
    local domain="$1"
    echo -e "${YELLOW}Testing domain resolution for $domain...${NC}" >&2

    if nslookup "$domain" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Domain resolves successfully${NC}" >&2
        return 0
    else
        echo -e "${YELLOW}⚠ Domain may not resolve (continuing anyway)${NC}" >&2
        return 0  # Don't fail, just warn
    fi
}

# Function to analyze domain for tunneling indicators
analyze_domain() {
    local domain="$1"
    local suspicious_score=0
    local indicators=()

    echo -e "\n${GREEN}🔍 Analyzing domain: $domain${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    # Check domain length
    local domain_length=${#domain}
    echo -e "${CYAN}Domain length: $domain_length characters${NC}"
    if (( domain_length > 50 )); then
        ((suspicious_score += 2))
        indicators+=("Long domain name (>50 chars)")
        echo -e "${YELLOW}⚠ Suspicious: Domain is unusually long${NC}"
    fi

    # Check for excessive subdomains
    local subdomain_count=$(echo "$domain" | tr '.' '\n' | wc -l)
    echo -e "${CYAN}Subdomain levels: $subdomain_count${NC}"
    if (( subdomain_count > 5 )); then
        ((suspicious_score += 2))
        indicators+=("Excessive subdomain levels (>5)")
        echo -e "${YELLOW}⚠ Suspicious: Too many subdomain levels${NC}"
    fi

    # Check for high entropy (random-looking strings)
    local first_part=$(echo "$domain" | cut -d'.' -f1)
    local entropy_score=0

    # Simple entropy check - count unique characters vs length
    local unique_chars=$(echo "$first_part" | fold -w1 | sort -u | wc -l)
    local total_chars=${#first_part}
    if (( total_chars > 0 )); then
        entropy_score=$(( (unique_chars * 100) / total_chars ))
        echo -e "${CYAN}Character entropy: ${entropy_score}%${NC}"
        if (( entropy_score > 70 && total_chars > 10 )); then
            ((suspicious_score += 3))
            indicators+=("High entropy subdomain (${entropy_score}%)")
            echo -e "${YELLOW}⚠ Suspicious: High entropy in subdomain${NC}"
        fi
    fi

    # Check for known tunneling patterns
    echo -e "${CYAN}Checking known tunneling patterns...${NC}"

    # Iodine patterns
    if [[ $domain =~ \.t\. ]]; then
        ((suspicious_score += 4))
        indicators+=("Matches Iodine pattern (.t.)")
        echo -e "${RED}🚨 Alert: Matches Iodine DNS tunnel pattern${NC}"
    fi

    # Long hex-like strings
    if [[ $first_part =~ ^[a-f0-9]{16,}$ ]]; then
        ((suspicious_score += 4))
        indicators+=("Long hexadecimal string pattern")
        echo -e "${RED}🚨 Alert: Matches hex encoding pattern${NC}"
    fi

    # Base32/Base64-like patterns
    if [[ $first_part =~ ^[a-z0-9]{32,}$ ]]; then
        ((suspicious_score += 3))
        indicators+=("Long alphanumeric string (Base32/64-like)")
        echo -e "${YELLOW}⚠ Suspicious: Matches Base32/64 encoding pattern${NC}"
    fi

    # Check against known tunneling domains
    local known_tunneling_domains=(
        "dnslog.cn" "dnslog.link" "dnslog.pw" "ceye.io"
        "burpcollaborator.net" "interact.sh" "dnslog.site"
        "dnslog.pro" "dnslog.co" "dnslog.me" "dnslog.xyz"
    )

    for tunnel_domain in "${known_tunneling_domains[@]}"; do
        if [[ $domain == *"$tunnel_domain"* ]]; then
            ((suspicious_score += 5))
            indicators+=("Known tunneling service domain")
            echo -e "${RED}🚨 ALERT: Known DNS tunneling service domain!${NC}"
            break
        fi
    done

    # Final assessment
    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Analysis Results:${NC}"
    echo -e "${CYAN}Suspicious Score: $suspicious_score/20${NC}"

    if (( suspicious_score >= 8 )); then
        echo -e "${RED}🚨 HIGH RISK: Very likely DNS tunneling${NC}"
    elif (( suspicious_score >= 5 )); then
        echo -e "${YELLOW}⚠ MEDIUM RISK: Possible DNS tunneling${NC}"
    elif (( suspicious_score >= 2 )); then
        echo -e "${BLUE}ℹ LOW RISK: Some suspicious indicators${NC}"
    else
        echo -e "${GREEN}✓ LOW RISK: No significant tunneling indicators${NC}"
    fi

    if [ ${#indicators[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}Detected Indicators:${NC}"
        for indicator in "${indicators[@]}"; do
            echo -e "  • $indicator"
        done
    fi

    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    return 0
}

# Function to perform DNS queries and analyze responses
perform_dns_analysis() {
    local domain="$1"
    local query_types=("A" "AAAA" "TXT" "MX" "NS" "CNAME")

    echo -e "\n${GREEN}🔍 Performing DNS queries for: $domain${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    local suspicious_responses=0

    for qtype in "${query_types[@]}"; do
        echo -e "${CYAN}Querying $qtype records...${NC}"

        local response
        response=$(dig +short "$domain" "$qtype" 2>/dev/null || echo "")

        if [ -n "$response" ]; then
            local response_length=${#response}
            echo -e "${GREEN}✓ $qtype: $response_length chars${NC}"

            # Check for unusually long responses
            if (( response_length > 200 )); then
                ((suspicious_responses++))
                echo -e "${YELLOW}  ⚠ Unusually long response${NC}"
            fi

            # Check TXT records for encoded data
            if [ "$qtype" = "TXT" ] && (( response_length > 50 )); then
                ((suspicious_responses++))
                echo -e "${YELLOW}  ⚠ Large TXT record (possible data exfiltration)${NC}"
            fi
        else
            echo -e "${BLUE}  - No $qtype records${NC}"
        fi
    done

    echo -e "\n${CYAN}Suspicious DNS responses: $suspicious_responses${NC}"
    if (( suspicious_responses > 2 )); then
        echo -e "${RED}🚨 Multiple suspicious DNS responses detected${NC}"
    fi

    echo -e "${BLUE}═══════════════════════════════════════${NC}"
}



# Show usage information
show_help() {
    echo "WetMonkey DNS Tunnel Detection Module v${VERSION}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  --check <domain>        Check a specific domain for tunneling indicators"
    echo "  -l, --list-patterns     List known DNS tunneling patterns"
    echo "  -d, --domain <domain>   Domain to analyze (legacy mode)"
    echo "  -i, --interface <iface> Network interface to monitor (legacy mode)"
    echo "  -r, --pcap <file.pcap>  PCAP file to analyze (legacy mode)"
    echo ""
    echo "This module provides interactive DNS tunneling detection and analysis."
    echo "Supported features: Domain analysis, pattern matching, DNS query analysis"
    echo ""
    echo "Example:"
    echo "  $0                      # Run in interactive mode"
    echo "  $0 -h                   # Show this help"
    echo "  $0 --check example.com  # Quick domain check"
    echo "  $0 --list-patterns      # Show known patterns"
    echo ""
    echo "Note: This tool is for authorized security testing only!"
    echo "      Use responsibly and only on domains you own or have permission to test."
}

# Legacy usage function for backward compatibility
usage() {
    show_help
    exit 1
}

# Main interactive function
interactive_mode() {
    while true; do
        show_banner

        echo -e "${GREEN}Welcome to WetMonkey DNS Tunnel Detector!${NC}"
        echo -e "${YELLOW}Let's analyze domains for DNS tunneling indicators step by step.${NC}\n"
        echo -e "${RED}⚠ WARNING: Only analyze domains you own or have permission to test!${NC}\n"

        # Step 1: Analysis type selection
        echo -e "${GREEN}Step 1: Analysis Type${NC}"
        echo -e "Choose the type of analysis you want to perform:"
        echo -e "  ${YELLOW}1)${NC} Single Domain Analysis - Analyze one domain for tunneling indicators"
        echo -e "  ${YELLOW}2)${NC} Multiple Domain Analysis - Analyze multiple domains from a list"
        echo -e "  ${YELLOW}3)${NC} Pattern Information - View known DNS tunneling patterns"

        local analysis_type
        while true; do
            choice=$(simple_input "Select analysis type (1-3)")
            case "$choice" in
                "1") analysis_type="single"; break ;;
                "2") analysis_type="multiple"; break ;;
                "3") analysis_type="patterns"; break ;;
                *) echo -e "${RED}Please select a number between 1-3${NC}" ;;
            esac
        done

        case "$analysis_type" in
            "single")
                # Single domain analysis
                echo -e "\n${GREEN}Step 2: Domain Input${NC}"
                echo -e "Enter the domain you want to analyze for DNS tunneling indicators"

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

                # Step 3: Analysis options
                echo -e "\n${GREEN}Step 3: Analysis Options${NC}"
                local perform_dns_queries=false
                if ask_yes_no "Perform DNS queries for additional analysis?" "y"; then
                    perform_dns_queries=true
                    check_domain_reachable "$domain"
                fi

                # Step 4: Execute analysis
                echo -e "\n${CYAN}Starting analysis...${NC}"

                # Log start
                log_json "dnstunnel_start" "domain=$domain mode=single" 2>/dev/null || true

                # Perform domain analysis
                analyze_domain "$domain"

                # Perform DNS queries if requested
                if [ "$perform_dns_queries" = true ]; then
                    perform_dns_analysis "$domain"
                fi

                # Log end
                log_json "dnstunnel_end" "domain=$domain" 2>/dev/null || true

                echo -e "\n${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;

            "multiple")
                # Multiple domain analysis
                echo -e "\n${GREEN}Step 2: Domain List Input${NC}"
                echo -e "Enter domains one by one (press Enter with empty input to finish)"

                local domains=()
                local domain_count=0

                while true; do
                    domain=$(simple_input "Domain $((domain_count + 1)) (or press Enter to finish)")
                    if [ -z "$domain" ]; then
                        if [ ${#domains[@]} -eq 0 ]; then
                            echo -e "${RED}Please enter at least one domain${NC}"
                            continue
                        else
                            break
                        fi
                    fi

                    if validate_domain "$domain"; then
                        domains+=("$domain")
                        ((domain_count++))
                        echo -e "${GREEN}✓ Added: $domain${NC}"
                    else
                        echo -e "${RED}Invalid domain format, skipping: $domain${NC}"
                    fi

                    if [ ${#domains[@]} -ge 10 ]; then
                        echo -e "${YELLOW}Maximum 10 domains reached${NC}"
                        break
                    fi
                done

                # Step 3: Analysis options
                echo -e "\n${GREEN}Step 3: Analysis Options${NC}"
                local perform_dns_queries=false
                if ask_yes_no "Perform DNS queries for additional analysis?" "n"; then
                    perform_dns_queries=true
                fi

                # Step 4: Execute analysis
                echo -e "\n${CYAN}Starting analysis of ${#domains[@]} domains...${NC}"

                # Log start
                log_json "dnstunnel_start" "domains=${#domains[@]} mode=multiple" 2>/dev/null || true

                local high_risk_count=0
                local medium_risk_count=0

                for domain in "${domains[@]}"; do
                    echo -e "\n${MAGENTA}Analyzing: $domain${NC}"

                    # Perform domain analysis
                    analyze_domain "$domain"

                    # Perform DNS queries if requested
                    if [ "$perform_dns_queries" = true ]; then
                        perform_dns_analysis "$domain"
                    fi

                    echo -e "${BLUE}─────────────────────────────────────────${NC}"
                done

                # Log end
                log_json "dnstunnel_end" "domains=${#domains[@]}" 2>/dev/null || true

                echo -e "\n${GREEN}✓ Analysis completed for ${#domains[@]} domains${NC}"
                echo -e "\n${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;

            "patterns")
                # Show patterns
                list_patterns
                echo -e "\n${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;
        esac

        if ! ask_yes_no "Perform another analysis?" "y"; then
            break
        fi
    done
}

# List known DNS tunneling patterns
list_patterns() {
    echo "${YELLOW}Known DNS Tunneling Patterns:${RESET}"
    echo "--------------------------------"
    
    echo "${CYAN}1. Iodine:${RESET}"
    echo "   - Pattern: .+\\.t\\. (e.g., abc123.t.example.com)"
    echo "   - Pattern: ^[a-z0-9]{16,}\\..+ (e.g., abc123def456abc12.example.com)"
    echo
    
    echo "${CYAN}2. DNSCat2:${RESET}"
    echo "   - Pattern: ^[a-f0-9]{16,}\\..+ (e.g., abc123def4567890.example.com)"
    echo "   - Pattern: ^[a-z0-9]{32,}\\..+ (e.g., abc123def456ghi789jkl012mno345p)"
    echo
    
    echo "${CYAN}3. DNS2TCP:${RESET}"
    echo "   - Pattern: ^[a-f0-9]{16,}\\..+"
    echo "   - Pattern: ^[a-z0-9]{20,}\\..+"
    echo
    
    echo "${CYAN}4. Known Tunneling Domains:${RESET}"
    echo "   - t1.dnslog.cn, dnslog.link, dnslog.pw, ceye.io"
    echo "   - burpcollaborator.net, interact.sh, dnslog.site"
    echo "   - dnslog.pro, dnslog.co, dnslog.me, dnslog.xyz"
    echo
    
    echo "${YELLOW}Detection Methods:${RESET}"
    echo "1. Domain length (suspicious if > 50 chars)"
    echo "2. Entropy analysis (high entropy indicates possible encryption/encoding)"
    echo "3. Pattern matching against known tunneling tools"
    echo "4. Unusual query types (TXT, NULL, CNAME, etc.)"
    echo "5. High volume of DNS queries from a single source"
    echo "6. Unusually large DNS responses"
}

# Main function
main() {
    local check_domain=""
    local list_patterns_flag=0

    # Parse command line arguments
    if [[ $# -gt 0 ]]; then
        while [[ $# -gt 0 ]]; do
            case "$1" in
                -h|--help)
                    show_help
                    exit 0
                    ;;
                --check)
                    if [ -z "${2:-}" ]; then
                        echo -e "${RED}Error: --check requires a domain${NC}" >&2
                        exit 1
                    fi
                    check_domain="$2"
                    shift 2
                    ;;
                -l|--list-patterns)
                    list_patterns_flag=1
                    shift
                    ;;
                -d|--domain|-i|--interface|-r|--pcap|-t|--timeout|-o|--output)
                    echo -e "${YELLOW}Legacy mode options are deprecated. Use interactive mode instead.${NC}" >&2
                    echo -e "${YELLOW}Run without arguments for interactive mode, or use --check for quick domain analysis.${NC}" >&2
                    exit 1
                    ;;
                *)
                    echo -e "${RED}Unknown option: $1${NC}" >&2
                    echo "Use -h for help." >&2
                    exit 1
                    ;;
            esac
        done

        # Handle list patterns request
        if [ $list_patterns_flag -eq 1 ]; then
            list_patterns
            exit 0
        fi

        # Handle quick domain check
        if [ -n "$check_domain" ]; then
            echo -e "${GREEN}Quick Domain Analysis: $check_domain${NC}"

            if ! validate_domain "$check_domain"; then
                echo -e "${RED}Error: Invalid domain format${NC}" >&2
                exit 1
            fi

            # Log start
            log_json "dnstunnel_start" "domain=$check_domain mode=quick" 2>/dev/null || true

            # Perform analysis
            analyze_domain "$check_domain"
            perform_dns_analysis "$check_domain"

            # Log end
            log_json "dnstunnel_end" "domain=$check_domain" 2>/dev/null || true

            exit 0
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
        echo -e "${YELLOW}Some analysis features may have reduced functionality.${NC}\n"
    fi

    # Start interactive mode
    interactive_mode
}

# Run the main function with all arguments
main "$@"
