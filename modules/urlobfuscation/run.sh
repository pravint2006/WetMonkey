#!/usr/bin/env bash
# wetmonkey urlobfuscation – Interactive URL Obfuscation & Evasion Testing Suite v2.0
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
    echo "║    🔗 WetMonkey URL Obfuscation Suite   ║"
    echo "║         Interactive Mode v2.0           ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Show usage information
show_help() {
    echo "WetMonkey URL Obfuscation Module v${VERSION}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  -u, --url <url>         Target URL (legacy mode)"
    echo "  --mode <mode>           Obfuscation mode: hex|unicode|double|mixed (legacy mode)"
    echo "  --test <url>            Quick obfuscation test"
    echo ""
    echo "This module provides interactive URL obfuscation and evasion testing."
    echo "Supported features: Multiple encoding methods, bypass testing, analysis"
    echo ""
    echo "Example:"
    echo "  $0                      # Run in interactive mode"
    echo "  $0 -h                   # Show this help"
    echo "  $0 --test http://example.com/path  # Quick obfuscation test"
    echo "  $0 -u http://example.com --mode hex  # Legacy mode"
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

# Function to validate URL
validate_url() {
    local url="$1"
    if [[ $url =~ ^https?://[a-zA-Z0-9.-]+([:/][^[:space:]]*)?$ ]]; then
        return 0
    fi
    return 1
}

# Function to URL encode using bash (no Python dependency)
url_encode_bash() {
    local string="$1"
    local encoded=""
    local char

    for (( i=0; i<${#string}; i++ )); do
        char="${string:$i:1}"
        case "$char" in
            [a-zA-Z0-9.~_-])
                encoded+="$char"
                ;;
            *)
                printf -v hex '%02X' "'$char"
                encoded+="%$hex"
                ;;
        esac
    done

    echo "$encoded"
}

# Function to double URL encode
double_url_encode() {
    local string="$1"
    local first_encode=$(url_encode_bash "$string")
    url_encode_bash "$first_encode"
}

# Function to hex encode all characters
hex_encode_all() {
    local string="$1"
    local encoded=""
    local char

    for (( i=0; i<${#string}; i++ )); do
        char="${string:$i:1}"
        printf -v hex '%02x' "'$char"
        encoded+="%$hex"
    done

    echo "$encoded"
}

# Function to unicode encode (UTF-16)
unicode_encode() {
    local string="$1"
    local encoded=""
    local char

    for (( i=0; i<${#string}; i++ )); do
        char="${string:$i:1}"
        printf -v unicode '%04x' "'$char"
        encoded+="%u$unicode"
    done

    echo "$encoded"
}

# Function to mixed case encoding
mixed_case_encode() {
    local string="$1"
    local encoded=""
    local char

    for (( i=0; i<${#string}; i++ )); do
        char="${string:$i:1}"
        case "$char" in
            [a-zA-Z0-9.~_-])
                # Randomly mix case for letters
                if [[ "$char" =~ [a-zA-Z] ]]; then
                    if (( RANDOM % 2 )); then
                        encoded+="${char^^}"  # uppercase
                    else
                        encoded+="${char,,}"  # lowercase
                    fi
                else
                    encoded+="$char"
                fi
                ;;
            *)
                # Mix hex encoding styles
                if (( RANDOM % 2 )); then
                    printf -v hex '%02X' "'$char"  # uppercase hex
                else
                    printf -v hex '%02x' "'$char"  # lowercase hex
                fi
                encoded+="%$hex"
                ;;
        esac
    done

    echo "$encoded"
}

# Function to perform comprehensive URL obfuscation testing
test_url_obfuscation() {
    local original_url="$1"

    echo -e "\n${GREEN}🔗 Testing URL obfuscation techniques...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Original URL: $original_url${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    local obfuscation_results=()
    local test_results=()

    # Test 1: Standard URL encoding
    echo -e "${CYAN}Test 1: Standard URL Encoding${NC}"
    local standard_encoded=$(url_encode_bash "$original_url")
    echo -e "${BLUE}  Encoded: $standard_encoded${NC}"
    obfuscation_results+=("Standard: $standard_encoded")

    # Test the encoded URL
    if command -v curl >/dev/null 2>&1; then
        echo -ne "${BLUE}  Testing encoded URL... ${NC}"
        local http_code
        if http_code=$(timeout 15 curl -s -o /dev/null -w "%{http_code}" "$standard_encoded" 2>/dev/null); then
            if [[ $http_code =~ ^[2-3][0-9][0-9]$ ]]; then
                echo -e "${GREEN}Success ($http_code)${NC}"
                test_results+=("Standard encoding: SUCCESS ($http_code)")
            else
                echo -e "${YELLOW}Response ($http_code)${NC}"
                test_results+=("Standard encoding: RESPONSE ($http_code)")
            fi
        else
            echo -e "${RED}Failed${NC}"
            test_results+=("Standard encoding: FAILED")
        fi
    fi

    # Test 2: Double URL encoding
    echo -e "\n${CYAN}Test 2: Double URL Encoding${NC}"
    local double_encoded=$(double_url_encode "$original_url")
    echo -e "${BLUE}  Encoded: $double_encoded${NC}"
    obfuscation_results+=("Double: $double_encoded")

    if command -v curl >/dev/null 2>&1; then
        echo -ne "${BLUE}  Testing double encoded URL... ${NC}"
        if http_code=$(timeout 15 curl -s -o /dev/null -w "%{http_code}" "$double_encoded" 2>/dev/null); then
            if [[ $http_code =~ ^[2-3][0-9][0-9]$ ]]; then
                echo -e "${GREEN}Success ($http_code)${NC}"
                test_results+=("Double encoding: SUCCESS ($http_code)")
            else
                echo -e "${YELLOW}Response ($http_code)${NC}"
                test_results+=("Double encoding: RESPONSE ($http_code)")
            fi
        else
            echo -e "${RED}Failed${NC}"
            test_results+=("Double encoding: FAILED")
        fi
    fi

    # Test 3: Hex encoding (all characters)
    echo -e "\n${CYAN}Test 3: Full Hex Encoding${NC}"
    local hex_encoded=$(hex_encode_all "$original_url")
    echo -e "${BLUE}  Encoded: $hex_encoded${NC}"
    obfuscation_results+=("Hex: $hex_encoded")

    if command -v curl >/dev/null 2>&1; then
        echo -ne "${BLUE}  Testing hex encoded URL... ${NC}"
        if http_code=$(timeout 15 curl -s -o /dev/null -w "%{http_code}" "$hex_encoded" 2>/dev/null); then
            if [[ $http_code =~ ^[2-3][0-9][0-9]$ ]]; then
                echo -e "${GREEN}Success ($http_code)${NC}"
                test_results+=("Hex encoding: SUCCESS ($http_code)")
            else
                echo -e "${YELLOW}Response ($http_code)${NC}"
                test_results+=("Hex encoding: RESPONSE ($http_code)")
            fi
        else
            echo -e "${RED}Failed${NC}"
            test_results+=("Hex encoding: FAILED")
        fi
    fi

    # Test 4: Unicode encoding
    echo -e "\n${CYAN}Test 4: Unicode Encoding${NC}"
    local unicode_encoded=$(unicode_encode "$original_url")
    echo -e "${BLUE}  Encoded: $unicode_encoded${NC}"
    obfuscation_results+=("Unicode: $unicode_encoded")

    if command -v curl >/dev/null 2>&1; then
        echo -ne "${BLUE}  Testing unicode encoded URL... ${NC}"
        if http_code=$(timeout 15 curl -s -o /dev/null -w "%{http_code}" "$unicode_encoded" 2>/dev/null); then
            if [[ $http_code =~ ^[2-3][0-9][0-9]$ ]]; then
                echo -e "${GREEN}Success ($http_code)${NC}"
                test_results+=("Unicode encoding: SUCCESS ($http_code)")
            else
                echo -e "${YELLOW}Response ($http_code)${NC}"
                test_results+=("Unicode encoding: RESPONSE ($http_code)")
            fi
        else
            echo -e "${RED}Failed${NC}"
            test_results+=("Unicode encoding: FAILED")
        fi
    fi

    # Test 5: Mixed case encoding
    echo -e "\n${CYAN}Test 5: Mixed Case Encoding${NC}"
    local mixed_encoded=$(mixed_case_encode "$original_url")
    echo -e "${BLUE}  Encoded: $mixed_encoded${NC}"
    obfuscation_results+=("Mixed: $mixed_encoded")

    if command -v curl >/dev/null 2>&1; then
        echo -ne "${BLUE}  Testing mixed case encoded URL... ${NC}"
        if http_code=$(timeout 15 curl -s -o /dev/null -w "%{http_code}" "$mixed_encoded" 2>/dev/null); then
            if [[ $http_code =~ ^[2-3][0-9][0-9]$ ]]; then
                echo -e "${GREEN}Success ($http_code)${NC}"
                test_results+=("Mixed encoding: SUCCESS ($http_code)")
            else
                echo -e "${YELLOW}Response ($http_code)${NC}"
                test_results+=("Mixed encoding: RESPONSE ($http_code)")
            fi
        else
            echo -e "${RED}Failed${NC}"
            test_results+=("Mixed encoding: FAILED")
        fi
    fi

    # Summary
    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}📊 URL Obfuscation Test Summary${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Original URL: $original_url${NC}"
    echo -e "${CYAN}Obfuscation Methods Tested: ${#obfuscation_results[@]}${NC}"
    echo -e "${CYAN}Response Tests Performed: ${#test_results[@]}${NC}"

    if [ ${#obfuscation_results[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}Obfuscated URLs Generated:${NC}"
        for result in "${obfuscation_results[@]}"; do
            echo -e "  • $result" | head -c 120
            echo ""
        done
    fi

    if [ ${#test_results[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}Test Results:${NC}"
        for result in "${test_results[@]}"; do
            echo -e "  • $result"
        done

        # Count successful tests
        local success_count=0
        for result in "${test_results[@]}"; do
            if [[ $result == *"SUCCESS"* ]]; then
                ((success_count++))
            fi
        done

        echo -e "\n${CYAN}Success Rate: $success_count/${#test_results[@]} ($(( (success_count * 100) / ${#test_results[@]} ))%)${NC}"

        if [ $success_count -gt 0 ]; then
            echo -e "${GREEN}✓ Some obfuscation methods were successful${NC}"
            echo -e "${CYAN}This indicates potential filter bypass capabilities${NC}"
        else
            echo -e "${YELLOW}⚠ No obfuscation methods were successful${NC}"
            echo -e "${CYAN}Target may have robust URL filtering or be unreachable${NC}"
        fi
    else
        echo -e "\n${RED}❌ NO RESPONSE TESTS PERFORMED${NC}"
        echo -e "${YELLOW}curl is not available for testing obfuscated URLs${NC}"
    fi

    echo -e "\n${YELLOW}Security Implications:${NC}"
    echo -e "• URL obfuscation can bypass basic content filters"
    echo -e "• Double encoding may evade some security controls"
    echo -e "• Mixed case encoding can confuse pattern matching"
    echo -e "• Unicode encoding may bypass character restrictions"
    echo -e "• Always test obfuscation in authorized environments only"

    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    return 0
}

# Function to perform advanced evasion testing
advanced_evasion_testing() {
    local original_url="$1"

    echo -e "\n${GREEN}🛡️ Advanced evasion testing...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Target URL: $original_url${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    local evasion_techniques=()
    local evasion_results=()

    # Check if curl is available
    if ! command -v curl >/dev/null 2>&1; then
        echo -e "${RED}❌ curl is not available for evasion testing${NC}"
        return 1
    fi

    # Technique 1: User-Agent rotation
    echo -e "${CYAN}Technique 1: User-Agent Rotation${NC}"
    local user_agents=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        "curl/7.68.0"
        "Wget/1.20.3"
    )

    for ua in "${user_agents[@]}"; do
        echo -ne "${BLUE}  Testing User-Agent: ${ua:0:30}... ${NC}"
        local http_code
        if http_code=$(timeout 10 curl -s -o /dev/null -w "%{http_code}" -H "User-Agent: $ua" "$original_url" 2>/dev/null); then
            if [[ $http_code =~ ^[2-3][0-9][0-9]$ ]]; then
                echo -e "${GREEN}Success ($http_code)${NC}"
                evasion_results+=("User-Agent '$ua': SUCCESS ($http_code)")
            else
                echo -e "${YELLOW}Response ($http_code)${NC}"
                evasion_results+=("User-Agent '$ua': RESPONSE ($http_code)")
            fi
        else
            echo -e "${RED}Failed${NC}"
            evasion_results+=("User-Agent '$ua': FAILED")
        fi
    done

    # Technique 2: HTTP method variation
    echo -e "\n${CYAN}Technique 2: HTTP Method Variation${NC}"
    local methods=("GET" "POST" "HEAD" "OPTIONS" "PUT")

    for method in "${methods[@]}"; do
        echo -ne "${BLUE}  Testing HTTP $method... ${NC}"
        local http_code
        if http_code=$(timeout 10 curl -s -o /dev/null -w "%{http_code}" -X "$method" "$original_url" 2>/dev/null); then
            if [[ $http_code =~ ^[2-3][0-9][0-9]$ ]]; then
                echo -e "${GREEN}Success ($http_code)${NC}"
                evasion_results+=("HTTP $method: SUCCESS ($http_code)")
            else
                echo -e "${YELLOW}Response ($http_code)${NC}"
                evasion_results+=("HTTP $method: RESPONSE ($http_code)")
            fi
        else
            echo -e "${RED}Failed${NC}"
            evasion_results+=("HTTP $method: FAILED")
        fi
    done

    # Technique 3: Header manipulation
    echo -e "\n${CYAN}Technique 3: Header Manipulation${NC}"
    local headers=(
        "X-Forwarded-For: 127.0.0.1"
        "X-Real-IP: 192.168.1.1"
        "X-Originating-IP: 10.0.0.1"
        "Referer: https://www.google.com/"
        "Accept-Language: en-US,en;q=0.9"
    )

    for header in "${headers[@]}"; do
        echo -ne "${BLUE}  Testing header: ${header:0:25}... ${NC}"
        local http_code
        if http_code=$(timeout 10 curl -s -o /dev/null -w "%{http_code}" -H "$header" "$original_url" 2>/dev/null); then
            if [[ $http_code =~ ^[2-3][0-9][0-9]$ ]]; then
                echo -e "${GREEN}Success ($http_code)${NC}"
                evasion_results+=("Header '$header': SUCCESS ($http_code)")
            else
                echo -e "${YELLOW}Response ($http_code)${NC}"
                evasion_results+=("Header '$header': RESPONSE ($http_code)")
            fi
        else
            echo -e "${RED}Failed${NC}"
            evasion_results+=("Header '$header': FAILED")
        fi
    done

    # Technique 4: Protocol variation
    echo -e "\n${CYAN}Technique 4: Protocol Variation${NC}"

    # Test HTTP/1.0 vs HTTP/1.1
    echo -ne "${BLUE}  Testing HTTP/1.0... ${NC}"
    local http_code
    if http_code=$(timeout 10 curl -s -o /dev/null -w "%{http_code}" --http1.0 "$original_url" 2>/dev/null); then
        if [[ $http_code =~ ^[2-3][0-9][0-9]$ ]]; then
            echo -e "${GREEN}Success ($http_code)${NC}"
            evasion_results+=("HTTP/1.0: SUCCESS ($http_code)")
        else
            echo -e "${YELLOW}Response ($http_code)${NC}"
            evasion_results+=("HTTP/1.0: RESPONSE ($http_code)")
        fi
    else
        echo -e "${RED}Failed${NC}"
        evasion_results+=("HTTP/1.0: FAILED")
    fi

    # Test with different connection handling
    echo -ne "${BLUE}  Testing Connection: close... ${NC}"
    if http_code=$(timeout 10 curl -s -o /dev/null -w "%{http_code}" -H "Connection: close" "$original_url" 2>/dev/null); then
        if [[ $http_code =~ ^[2-3][0-9][0-9]$ ]]; then
            echo -e "${GREEN}Success ($http_code)${NC}"
            evasion_results+=("Connection close: SUCCESS ($http_code)")
        else
            echo -e "${YELLOW}Response ($http_code)${NC}"
            evasion_results+=("Connection close: RESPONSE ($http_code)")
        fi
    else
        echo -e "${RED}Failed${NC}"
        evasion_results+=("Connection close: FAILED")
    fi

    # Technique 5: Timing variation
    echo -e "\n${CYAN}Technique 5: Timing Variation${NC}"
    local delays=(1 3 5)

    for delay in "${delays[@]}"; do
        echo -ne "${BLUE}  Testing with ${delay}s delay... ${NC}"
        sleep "$delay"
        if http_code=$(timeout 10 curl -s -o /dev/null -w "%{http_code}" "$original_url" 2>/dev/null); then
            if [[ $http_code =~ ^[2-3][0-9][0-9]$ ]]; then
                echo -e "${GREEN}Success ($http_code)${NC}"
                evasion_results+=("${delay}s delay: SUCCESS ($http_code)")
            else
                echo -e "${YELLOW}Response ($http_code)${NC}"
                evasion_results+=("${delay}s delay: RESPONSE ($http_code)")
            fi
        else
            echo -e "${RED}Failed${NC}"
            evasion_results+=("${delay}s delay: FAILED")
        fi
    done

    # Summary
    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}📊 Advanced Evasion Test Summary${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Target URL: $original_url${NC}"
    echo -e "${CYAN}Evasion Techniques Tested: 5${NC}"
    echo -e "${CYAN}Total Tests Performed: ${#evasion_results[@]}${NC}"

    if [ ${#evasion_results[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}Evasion Test Results:${NC}"
        for result in "${evasion_results[@]}"; do
            echo -e "  • $result" | head -c 100
            echo ""
        done

        # Count successful tests
        local success_count=0
        for result in "${evasion_results[@]}"; do
            if [[ $result == *"SUCCESS"* ]]; then
                ((success_count++))
            fi
        done

        echo -e "\n${CYAN}Success Rate: $success_count/${#evasion_results[@]} ($(( (success_count * 100) / ${#evasion_results[@]} ))%)${NC}"

        if [ $success_count -gt 0 ]; then
            echo -e "${GREEN}✓ Some evasion techniques were successful${NC}"
            echo -e "${CYAN}This indicates potential security control bypass capabilities${NC}"
        else
            echo -e "${YELLOW}⚠ No evasion techniques were successful${NC}"
            echo -e "${CYAN}Target may have robust security controls or be unreachable${NC}"
        fi
    else
        echo -e "\n${RED}❌ NO EVASION TESTS PERFORMED${NC}"
    fi

    echo -e "\n${YELLOW}Evasion Analysis:${NC}"
    echo -e "• User-Agent rotation can bypass basic bot detection"
    echo -e "• HTTP method variation may evade method-specific filters"
    echo -e "• Header manipulation can confuse security controls"
    echo -e "• Protocol variation may bypass version-specific rules"
    echo -e "• Timing variation can evade rate limiting and detection"

    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    return 0
}

# Educational information function
show_educational_info() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║      📚 URL Obfuscation Guide           ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}\n"

    echo -e "${GREEN}What is URL Obfuscation?${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "URL obfuscation is the practice of encoding or modifying URLs to"
    echo -e "disguise their true destination or bypass security controls. It's"
    echo -e "commonly used in security testing to evaluate filter effectiveness"
    echo -e "and in malicious attacks to evade detection systems.\n"

    echo -e "${GREEN}Common Obfuscation Techniques${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}1. URL Encoding (Percent Encoding)${NC}"
    echo -e "   • Converts characters to %XX format"
    echo -e "   • Example: 'hello' → '%68%65%6c%6c%6f'"
    echo -e "   • Standard method defined in RFC 3986"
    echo -e "${YELLOW}2. Double URL Encoding${NC}"
    echo -e "   • Applies URL encoding twice"
    echo -e "   • Example: 'hello' → '%2568%2565%256c%256c%256f'"
    echo -e "   • Can bypass single-decode filters"
    echo -e "${YELLOW}3. Unicode Encoding${NC}"
    echo -e "   • Uses Unicode escape sequences"
    echo -e "   • Example: 'hello' → '%u0068%u0065%u006c%u006c%u006f'"
    echo -e "   • May bypass character-based filters"
    echo -e "${YELLOW}4. Mixed Case Encoding${NC}"
    echo -e "   • Combines uppercase and lowercase hex"
    echo -e "   • Example: 'hello' → '%68%65%6C%6C%6F'"
    echo -e "   • Can evade case-sensitive pattern matching"
    echo -e "${YELLOW}5. Hex Encoding Variations${NC}"
    echo -e "   • Different hex representation styles"
    echo -e "   • Mixing encoded and unencoded characters"
    echo -e "   • Selective character encoding\n"

    echo -e "${GREEN}Security Applications${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Penetration Testing:${NC}"
    echo -e "• Test web application filter bypass"
    echo -e "• Evaluate URL filtering effectiveness"
    echo -e "• Assess input validation mechanisms"
    echo -e "${CYAN}Security Assessment:${NC}"
    echo -e "• Identify weak content filtering"
    echo -e "• Test WAF (Web Application Firewall) rules"
    echo -e "• Evaluate proxy and gateway controls"
    echo -e "${CYAN}Red Team Operations:${NC}"
    echo -e "• Bypass network security controls"
    echo -e "• Evade detection systems"
    echo -e "• Test incident response capabilities"
    echo -e "${CYAN}Blue Team Training:${NC}"
    echo -e "• Understand attack techniques"
    echo -e "• Improve detection capabilities"
    echo -e "• Develop better filtering rules\n"

    echo -e "${GREEN}Evasion Techniques${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}1. User-Agent Manipulation:${NC}"
    echo -e "   • Rotate between different browser signatures"
    echo -e "   • Mimic legitimate traffic patterns"
    echo -e "   • Bypass user-agent based filtering"
    echo -e "${CYAN}2. HTTP Method Variation:${NC}"
    echo -e "   • Use different HTTP verbs (GET, POST, PUT)"
    echo -e "   • Test method-specific security rules"
    echo -e "   • Exploit method-based access controls"
    echo -e "${CYAN}3. Header Manipulation:${NC}"
    echo -e "   • Add spoofed headers (X-Forwarded-For)"
    echo -e "   • Modify standard headers (Referer, Accept)"
    echo -e "   • Inject custom headers for bypass"
    echo -e "${CYAN}4. Protocol Variation:${NC}"
    echo -e "   • Switch between HTTP versions"
    echo -e "   • Modify connection handling"
    echo -e "   • Test protocol-specific rules"
    echo -e "${CYAN}5. Timing Attacks:${NC}"
    echo -e "   • Vary request timing patterns"
    echo -e "   • Bypass rate limiting controls"
    echo -e "   • Evade behavioral detection\n"

    echo -e "${GREEN}Common Bypass Scenarios${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Web Application Firewalls (WAF):${NC}"
    echo -e "• URL encoding to bypass signature matching"
    echo -e "• Case variation to evade pattern detection"
    echo -e "• Double encoding for multi-layer bypass"
    echo -e "${CYAN}Content Filters:${NC}"
    echo -e "• Unicode encoding for character restrictions"
    echo -e "• Mixed encoding to confuse parsers"
    echo -e "• Selective encoding of filtered terms"
    echo -e "${CYAN}Proxy Servers:${NC}"
    echo -e "• Header manipulation for access control bypass"
    echo -e "• Method variation for rule evasion"
    echo -e "• Protocol downgrade attacks"
    echo -e "${CYAN}Network Security Devices:${NC}"
    echo -e "• Timing variation for detection evasion"
    echo -e "• User-agent rotation for bot detection bypass"
    echo -e "• Traffic pattern modification\n"

    echo -e "${GREEN}Detection and Countermeasures${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Detection Methods:${NC}"
    echo -e "• Multi-layer URL decoding and analysis"
    echo -e "• Behavioral pattern recognition"
    echo -e "• Anomaly detection in request patterns"
    echo -e "• Content inspection after decoding"
    echo -e "${CYAN}Prevention Strategies:${NC}"
    echo -e "• Implement recursive URL decoding"
    echo -e "• Use whitelist-based filtering"
    echo -e "• Deploy behavioral analysis systems"
    echo -e "• Regular security rule updates"
    echo -e "${CYAN}Monitoring Approaches:${NC}"
    echo -e "• Log all URL variations and encodings"
    echo -e "• Monitor for suspicious encoding patterns"
    echo -e "• Track request timing anomalies"
    echo -e "• Analyze user-agent and header patterns\n"

    echo -e "${GREEN}Tools and Techniques${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}1. Manual Encoding:${NC}"
    echo -e "   • Bash/shell scripting for custom encoding"
    echo -e "   • Online URL encoding tools"
    echo -e "   • Browser developer tools"
    echo -e "${CYAN}2. Automated Tools:${NC}"
    echo -e "   • Burp Suite for web application testing"
    echo -e "   • OWASP ZAP for security scanning"
    echo -e "   • Custom scripts for bulk testing"
    echo -e "${CYAN}3. Programming Libraries:${NC}"
    echo -e "   • Python urllib for URL manipulation"
    echo -e "   • JavaScript encodeURIComponent()"
    echo -e "   • Various language-specific libraries"
    echo -e "${CYAN}4. Testing Frameworks:${NC}"
    echo -e "   • Automated bypass testing suites"
    echo -e "   • WAF testing frameworks"
    echo -e "   • Custom penetration testing tools\n"

    echo -e "${GREEN}Legal and Ethical Considerations${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${RED}⚠ IMPORTANT:${NC} Only test URL obfuscation on systems you own or have permission"
    echo -e "${RED}⚠ LEGAL:${NC} Unauthorized bypass attempts may violate computer crime laws"
    echo -e "${RED}⚠ ETHICAL:${NC} Use obfuscation techniques for legitimate security testing only"
    echo -e "${RED}⚠ PROFESSIONAL:${NC} Document findings and follow responsible disclosure"
    echo -e "${RED}⚠ EDUCATIONAL:${NC} Understand techniques to improve defensive capabilities\n"
}

# Main interactive function
interactive_mode() {
    while true; do
        show_banner

        echo -e "${GREEN}Welcome to WetMonkey URL Obfuscation Suite!${NC}"
        echo -e "${YELLOW}This tool helps test URL obfuscation and evasion techniques.${NC}\n"
        echo -e "${RED}⚠ WARNING: Only test URLs you own or have permission to test!${NC}\n"

        # Step 1: Test type selection
        echo -e "${GREEN}Step 1: Test Type${NC}"
        echo -e "Choose the type of URL obfuscation test:"
        echo -e "  ${YELLOW}1)${NC} Basic Obfuscation - Test multiple URL encoding methods"
        echo -e "  ${YELLOW}2)${NC} Advanced Evasion - Comprehensive bypass technique testing"
        echo -e "  ${YELLOW}3)${NC} Educational Information - Learn about URL obfuscation"

        local test_type
        while true; do
            choice=$(simple_input "Select test type (1-3)")
            case "$choice" in
                "1") test_type="basic"; break ;;
                "2") test_type="advanced"; break ;;
                "3") test_type="educational"; break ;;
                *) echo -e "${RED}Please select a number between 1-3${NC}" ;;
            esac
        done

        case "$test_type" in
            "educational")
                # Show educational information
                show_educational_info
                echo -e "\n${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;

            *)
                # URL obfuscation testing
                echo -e "\n${GREEN}Step 2: Target Configuration${NC}"

                local target_url
                while true; do
                    target_url=$(simple_input "Target URL")
                    if [ -z "$target_url" ]; then
                        echo -e "${RED}URL is required!${NC}"
                        continue
                    fi

                    if validate_url "$target_url"; then
                        break
                    else
                        echo -e "${RED}Please enter a valid URL (http:// or https://)${NC}"
                    fi
                done

                # Step 3: Execution summary
                echo -e "\n${GREEN}Step 3: Test Summary${NC}"
                echo -e "${BLUE}═══════════════════════════════════════${NC}"
                echo -e "${CYAN}Target URL: $target_url${NC}"
                echo -e "${CYAN}Test Type: $test_type${NC}"
                echo -e "${BLUE}═══════════════════════════════════════${NC}"

                echo -e "\n${RED}⚠ WARNING: This will perform URL obfuscation testing against the target!${NC}"
                echo -e "${RED}⚠ Only proceed if you have authorization to test this URL!${NC}"

                if ask_yes_no "Start URL obfuscation testing?" "n"; then
                    echo -e "\n${CYAN}Starting URL obfuscation testing...${NC}"

                    # Log start
                    log_json "urlobfuscation_start" "url=$target_url type=$test_type" 2>/dev/null || true

                    # Perform testing based on type
                    case "$test_type" in
                        "basic")
                            test_url_obfuscation "$target_url"
                            ;;
                        "advanced")
                            test_url_obfuscation "$target_url"
                            echo -e "\n${MAGENTA}═══ Advanced Evasion Testing ═══${NC}"
                            advanced_evasion_testing "$target_url"
                            ;;
                    esac

                    # Log end
                    log_json "urlobfuscation_end" "url=$target_url type=$test_type" 2>/dev/null || true
                else
                    echo -e "${YELLOW}URL obfuscation testing cancelled.${NC}"
                fi
                ;;
        esac

        echo -e "\n${YELLOW}Press Enter to continue...${NC}"
        read -r

        if ! ask_yes_no "Perform another URL obfuscation test?" "y"; then
            break
        fi
    done
}

# Legacy mode function
legacy_mode() {
    local url="$1"
    local mode="$2"

    echo -e "${YELLOW}Running in legacy mode...${NC}"
    echo -e "${RED}⚠ WARNING: Only test URLs you own or have permission to test!${NC}\n"

    # Validate URL
    if ! validate_url "$url"; then
        echo -e "${RED}Error: Invalid URL format${NC}" >&2
        exit 1
    fi

    # Log start
    log_json "urlobfuscation_start" "url=$url mode=$mode legacy=true" 2>/dev/null || true

    # Perform legacy obfuscation
    echo -e "${CYAN}Performing legacy URL obfuscation...${NC}"
    echo -e "${BLUE}Original URL: $url${NC}"
    echo -e "${BLUE}Mode: $mode${NC}\n"

    local obfuscated=""
    case "$mode" in
        "hex")
            obfuscated=$(hex_encode_all "$url")
            echo -e "${GREEN}Hex encoded URL:${NC}"
            echo "$obfuscated"
            ;;
        "unicode")
            obfuscated=$(unicode_encode "$url")
            echo -e "${GREEN}Unicode encoded URL:${NC}"
            echo "$obfuscated"
            ;;
        "double")
            obfuscated=$(double_url_encode "$url")
            echo -e "${GREEN}Double encoded URL:${NC}"
            echo "$obfuscated"
            ;;
        "mixed")
            obfuscated=$(mixed_case_encode "$url")
            echo -e "${GREEN}Mixed case encoded URL:${NC}"
            echo "$obfuscated"
            ;;
        *)
            echo -e "${RED}Error: Unknown mode '$mode' (use hex, unicode, double, or mixed)${NC}" >&2
            exit 1
            ;;
    esac

    # Test the obfuscated URL if curl is available
    if command -v curl >/dev/null 2>&1; then
        echo -e "\n${CYAN}Testing obfuscated URL...${NC}"
        local http_code
        if http_code=$(timeout 15 curl -s -o /dev/null -w "%{http_code}" "$obfuscated" 2>/dev/null); then
            echo -e "${GREEN}HTTP Response Code: $http_code${NC}"

            if [[ $http_code =~ ^2[0-9][0-9]$ ]]; then
                echo -e "${GREEN}✓ Success: Obfuscated URL works${NC}"
            elif [[ $http_code =~ ^3[0-9][0-9]$ ]]; then
                echo -e "${YELLOW}⚠ Redirect: Obfuscated URL redirected${NC}"
            else
                echo -e "${YELLOW}⚠ Response: Obfuscated URL responded with $http_code${NC}"
            fi
        else
            echo -e "${RED}❌ Failed: Could not access obfuscated URL${NC}"
        fi
    else
        echo -e "\n${YELLOW}⚠ curl not available - cannot test obfuscated URL${NC}"
    fi

    # Log end
    log_json "urlobfuscation_end" "obfuscated=$obfuscated" 2>/dev/null || true
}

# Main function
main() {
    local url=""
    local mode="hex"
    local test_url=""

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
                --mode)
                    if [ -z "${2:-}" ]; then
                        echo -e "${RED}Error: --mode requires a mode${NC}" >&2
                        exit 1
                    fi
                    mode="$2"
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
                *)
                    echo -e "${RED}Unknown option: $1${NC}" >&2
                    echo "Use -h for help." >&2
                    exit 1
                    ;;
            esac
        done

        # Handle quick test mode
        if [ -n "$test_url" ]; then
            echo -e "${GREEN}Quick URL Obfuscation Test: $test_url${NC}"

            if ! validate_url "$test_url"; then
                echo -e "${RED}Error: Invalid URL format${NC}" >&2
                exit 1
            fi

            # Log start
            log_json "urlobfuscation_start" "url=$test_url mode=quick" 2>/dev/null || true

            # Perform quick obfuscation test
            test_url_obfuscation "$test_url"

            # Log end
            log_json "urlobfuscation_end" "url=$test_url" 2>/dev/null || true

            exit 0
        fi

        # Handle legacy mode
        if [ -n "$url" ]; then
            legacy_mode "$url" "$mode"
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
        echo -e "${YELLOW}URL testing features will have reduced functionality.${NC}\n"
    fi

    # Check for advanced tools
    advanced_tools=()
    if command -v curl >/dev/null 2>&1; then
        advanced_tools+=("curl")
    fi

    if [ ${#advanced_tools[@]} -gt 0 ]; then
        echo -e "${GREEN}URL testing tools available: ${advanced_tools[*]}${NC}\n"
    fi

    # Start interactive mode
    interactive_mode
}

# Run the main function with all arguments
main "$@"
