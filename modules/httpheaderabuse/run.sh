#!/usr/bin/env bash
# wetmonkey httpheaderabuse – Interactive HTTP Header Abuse Testing Suite v2.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$SCRIPT_DIR/../../"
source "$BASE_DIR/core/utils.sh"

# Configuration
VERSION="2.0"
MAX_HEADERS=20

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
    echo "║    📡 WetMonkey HTTP Header Abuse Tester ║"
    echo "║         Interactive Mode v2.0           ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Show usage information
show_help() {
    echo "WetMonkey HTTP Header Abuse Testing Module v${VERSION}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  -u, --url <url>         Target URL (legacy mode)"
    echo "  -H, --header <header>   Custom header (legacy mode)"
    echo "  --test <url>            Quick header injection test"
    echo ""
    echo "This module provides interactive HTTP header abuse testing."
    echo "Supported tests: Header injection, bypass techniques, security analysis"
    echo ""
    echo "Example:"
    echo "  $0                      # Run in interactive mode"
    echo "  $0 -h                   # Show this help"
    echo "  $0 --test http://target.com  # Quick header test"
    echo "  $0 -u http://target.com -H 'X-Test: value'  # Legacy mode"
    echo ""
    echo "Note: This tool is for authorized security testing only!"
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

# Function to check if URL is reachable
check_url_reachable() {
    local url="$1"
    echo -e "${YELLOW}Testing connectivity to $url...${NC}" >&2

    if curl -s --connect-timeout 10 --max-time 15 -I "$url" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Target is reachable${NC}" >&2
        return 0
    else
        echo -e "${YELLOW}⚠ Target may not be reachable (continuing anyway)${NC}" >&2
        return 0  # Don't fail, just warn
    fi
}

# Function to test for header injection vulnerabilities
test_header_injection() {
    local url="$1"
    local vulnerable=false
    local findings=()

    echo -e "\n${GREEN}🔍 Testing for HTTP Header Injection vulnerabilities...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Target: $url${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    # Test various header injection payloads
    local injection_payloads=(
        "X-Injected-Header: test\r\nX-Evil-Header: injected"
        "X-Test: value\nSet-Cookie: evil=true"
        "X-Forwarded-For: 127.0.0.1\r\nX-Injected: true"
        "User-Agent: Mozilla/5.0\r\nX-XSS: <script>alert(1)</script>"
        "Referer: http://evil.com\nLocation: http://malicious.com"
    )

    for payload in "${injection_payloads[@]}"; do
        echo -e "${CYAN}Testing injection payload...${NC}"

        local response
        if response=$(curl -s -I -H "$payload" "$url" 2>&1); then
            # Check if injected headers appear in response
            if [[ $response == *"X-Evil-Header"* ]] || [[ $response == *"X-Injected"* ]] || [[ $response == *"Set-Cookie: evil"* ]]; then
                echo -e "${RED}🚨 Header injection vulnerability detected!${NC}"
                findings+=("Header injection possible with payload: ${payload:0:50}...")
                vulnerable=true
            fi

            # Check for CRLF injection indicators
            if [[ $response == *$'\r\n'* ]] && [[ $payload == *$'\r\n'* ]]; then
                echo -e "${RED}🚨 CRLF injection vulnerability detected!${NC}"
                findings+=("CRLF injection possible")
                vulnerable=true
            fi
        fi
    done

    if [ "$vulnerable" = true ]; then
        echo -e "${RED}🚨 HEADER INJECTION VULNERABILITIES FOUND!${NC}"
        for finding in "${findings[@]}"; do
            echo -e "${RED}  • $finding${NC}"
        done
        return 0
    else
        echo -e "${GREEN}✓ No header injection vulnerabilities detected${NC}"
        return 1
    fi
}

# Function to test security bypass techniques
test_security_bypasses() {
    local url="$1"
    local bypasses_found=()

    echo -e "\n${GREEN}🔍 Testing security bypass techniques...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Target: $url${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    # Test various bypass headers
    local bypass_headers=(
        "X-Forwarded-For: 127.0.0.1"
        "X-Real-IP: 127.0.0.1"
        "X-Originating-IP: 127.0.0.1"
        "X-Remote-IP: 127.0.0.1"
        "X-Client-IP: 127.0.0.1"
        "X-Forwarded-Host: localhost"
        "X-Forwarded-Proto: https"
        "X-Forwarded-Scheme: https"
        "X-Scheme: https"
        "X-Original-URL: /admin"
        "X-Rewrite-URL: /admin"
        "X-Override-URL: /admin"
        "X-HTTP-Method-Override: GET"
        "X-HTTP-Method: GET"
        "X-Method-Override: GET"
    )

    # Get baseline response
    echo -e "${CYAN}Getting baseline response...${NC}"
    local baseline_response
    baseline_response=$(curl -s -I "$url" 2>/dev/null || echo "")
    local baseline_code
    baseline_code=$(echo "$baseline_response" | head -1 | grep -o '[0-9]\{3\}' | head -1)

    echo -e "${BLUE}Baseline status: ${baseline_code:-Unknown}${NC}"

    # Test each bypass header
    for header in "${bypass_headers[@]}"; do
        echo -e "${CYAN}Testing: $header${NC}"

        local response
        response=$(curl -s -I -H "$header" "$url" 2>/dev/null || echo "")
        local status_code
        status_code=$(echo "$response" | head -1 | grep -o '[0-9]\{3\}' | head -1)

        if [ -n "$status_code" ] && [ "$status_code" != "$baseline_code" ]; then
            echo -e "${YELLOW}⚠ Status change detected: $baseline_code → $status_code${NC}"
            bypasses_found+=("$header: Status changed to $status_code")

            # Check for specific bypass indicators
            if [[ $status_code == "200" ]] && [[ $baseline_code != "200" ]]; then
                echo -e "${RED}🚨 Potential access bypass detected!${NC}"
            elif [[ $status_code == "302" ]] || [[ $status_code == "301" ]]; then
                echo -e "${YELLOW}⚠ Redirect behavior changed${NC}"
            fi
        fi

        # Check for additional response headers
        if [[ $response == *"X-Forwarded"* ]] || [[ $response == *"X-Real"* ]]; then
            echo -e "${YELLOW}⚠ Server processes forwarded headers${NC}"
            bypasses_found+=("$header: Server processes header")
        fi
    done

    # Summary
    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    if [ ${#bypasses_found[@]} -gt 0 ]; then
        echo -e "${YELLOW}⚠ POTENTIAL BYPASSES DETECTED:${NC}"
        for bypass in "${bypasses_found[@]}"; do
            echo -e "${YELLOW}  • $bypass${NC}"
        done
        echo -e "\n${YELLOW}Recommendations:${NC}"
        echo -e "• Validate and sanitize all HTTP headers"
        echo -e "• Implement proper access controls"
        echo -e "• Don't rely solely on IP-based restrictions"
        echo -e "• Monitor for unusual header patterns"
        return 0
    else
        echo -e "${GREEN}✓ No obvious bypass techniques detected${NC}"
        return 1
    fi
}

# Function to test for HTTP response splitting
test_response_splitting() {
    local url="$1"
    local vulnerable=false

    echo -e "\n${GREEN}🔍 Testing for HTTP Response Splitting...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Target: $url${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    # Test response splitting payloads
    local splitting_payloads=(
        "X-Test: value%0d%0aSet-Cookie: evil=true"
        "X-Custom: test%0d%0aLocation: http://evil.com"
        "User-Agent: Mozilla%0d%0aX-Injected: true"
        "Referer: http://test.com%0d%0aContent-Length: 0"
    )

    for payload in "${splitting_payloads[@]}"; do
        echo -e "${CYAN}Testing response splitting payload...${NC}"

        local response
        if response=$(curl -s -I -H "$payload" "$url" 2>&1); then
            # Check for response splitting indicators
            if [[ $response == *"Set-Cookie: evil"* ]] || [[ $response == *"Location: http://evil.com"* ]]; then
                echo -e "${RED}🚨 HTTP Response Splitting vulnerability detected!${NC}"
                vulnerable=true
            fi

            # Check for malformed responses
            if [[ $response == *"Content-Length: 0"* ]] && [[ $payload == *"Content-Length"* ]]; then
                echo -e "${RED}🚨 Response manipulation detected!${NC}"
                vulnerable=true
            fi
        fi
    done

    if [ "$vulnerable" = true ]; then
        echo -e "${RED}🚨 HTTP RESPONSE SPLITTING VULNERABILITY!${NC}"
        echo -e "${YELLOW}Recommendations:${NC}"
        echo -e "• Validate and encode all user input in headers"
        echo -e "• Remove or encode CRLF characters"
        echo -e "• Use secure header handling libraries"
        return 0
    else
        echo -e "${GREEN}✓ No response splitting vulnerabilities detected${NC}"
        return 1
    fi
}

# Function to test custom headers
test_custom_headers() {
    local url="$1"
    shift
    local headers=("$@")

    echo -e "\n${GREEN}🔍 Testing custom headers...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Target: $url${NC}"
    echo -e "${YELLOW}Headers: ${#headers[@]}${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    # Build curl command with custom headers
    local curl_args=()
    for header in "${headers[@]}"; do
        curl_args+=("-H" "$header")
        echo -e "${CYAN}Header: $header${NC}"
    done

    echo -e "\n${CYAN}Sending request with custom headers...${NC}"

    # Send request and analyze response
    local response
    if response=$(curl -s -I "${curl_args[@]}" "$url" 2>&1); then
        local status_code
        status_code=$(echo "$response" | head -1 | grep -o '[0-9]\{3\}' | head -1)

        echo -e "${GREEN}✓ Request completed${NC}"
        echo -e "${BLUE}Status Code: ${status_code:-Unknown}${NC}"

        # Analyze response headers
        echo -e "\n${YELLOW}Response Analysis:${NC}"

        # Check for reflected headers
        local reflected_headers=0
        for header in "${headers[@]}"; do
            local header_name
            header_name=$(echo "$header" | cut -d':' -f1)
            if [[ $response == *"$header_name"* ]]; then
                echo -e "${YELLOW}⚠ Header reflected in response: $header_name${NC}"
                ((reflected_headers++))
            fi
        done

        # Check for security headers
        local security_headers=(
            "X-Frame-Options"
            "X-Content-Type-Options"
            "X-XSS-Protection"
            "Content-Security-Policy"
            "Strict-Transport-Security"
        )

        echo -e "\n${CYAN}Security Headers Analysis:${NC}"
        for sec_header in "${security_headers[@]}"; do
            if [[ $response == *"$sec_header"* ]]; then
                echo -e "${GREEN}✓ $sec_header present${NC}"
            else
                echo -e "${YELLOW}⚠ $sec_header missing${NC}"
            fi
        done

        # Check for unusual response patterns
        if [[ $response == *"Server: "* ]]; then
            local server_header
            server_header=$(echo "$response" | grep -i "server:" | head -1)
            echo -e "${BLUE}Server: ${server_header#*: }${NC}"
        fi

        return 0
    else
        echo -e "${RED}❌ Request failed: $response${NC}"
        return 1
    fi
}

# Function to perform comprehensive header abuse testing
comprehensive_header_test() {
    local url="$1"
    local vulnerabilities_found=0
    local tests_performed=0

    echo -e "\n${GREEN}🔍 Starting comprehensive HTTP header abuse testing...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Target URL: $url${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    # Test Header Injection
    ((tests_performed++))
    if test_header_injection "$url"; then
        ((vulnerabilities_found++))
    fi

    # Test Security Bypasses
    ((tests_performed++))
    if test_security_bypasses "$url"; then
        ((vulnerabilities_found++))
    fi

    # Test Response Splitting
    ((tests_performed++))
    if test_response_splitting "$url"; then
        ((vulnerabilities_found++))
    fi

    # Summary
    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}📊 HTTP Header Abuse Testing Summary${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Target tested: $url${NC}"
    echo -e "${CYAN}Tests performed: $tests_performed${NC}"
    echo -e "${CYAN}Vulnerabilities found: $vulnerabilities_found${NC}"

    if [ $vulnerabilities_found -gt 0 ]; then
        echo -e "${RED}🚨 HEADER ABUSE VULNERABILITIES DETECTED!${NC}"
        echo -e "${YELLOW}Immediate Actions Required:${NC}"
        echo -e "• Implement proper header validation and sanitization"
        echo -e "• Remove or encode CRLF characters from user input"
        echo -e "• Validate X-Forwarded-For and similar headers"
        echo -e "• Implement proper access controls"
        echo -e "• Add security headers to responses"
        echo -e "• Monitor for unusual header patterns"
        echo -e "• Consider using a Web Application Firewall (WAF)"
    else
        echo -e "${GREEN}✅ NO OBVIOUS HEADER ABUSE VULNERABILITIES DETECTED${NC}"
        echo -e "${GREEN}The target appears to handle HTTP headers securely.${NC}"
        echo -e "${YELLOW}Note: This does not guarantee complete security. Consider:${NC}"
        echo -e "• Professional penetration testing"
        echo -e "• Code security review"
        echo -e "• Regular security assessments"
    fi

    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    return $vulnerabilities_found
}

# Educational information function
show_educational_info() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║         📚 HTTP Header Abuse Guide      ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}\n"

    echo -e "${GREEN}What is HTTP Header Abuse?${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "HTTP header abuse involves manipulating HTTP headers to bypass security"
    echo -e "controls, inject malicious content, or exploit application vulnerabilities."
    echo -e "Headers can be modified by attackers to achieve various malicious goals.\n"

    echo -e "${GREEN}Common HTTP Header Abuse Techniques${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}1. Header Injection${NC}"
    echo -e "   • Inject additional headers using CRLF characters"
    echo -e "   • Can lead to response splitting and cache poisoning"
    echo -e "   • Example: X-Test: value\\r\\nSet-Cookie: evil=true"
    echo -e "${YELLOW}2. IP Spoofing via Headers${NC}"
    echo -e "   • Use X-Forwarded-For, X-Real-IP to bypass IP restrictions"
    echo -e "   • Trick applications into trusting spoofed IPs"
    echo -e "   • Example: X-Forwarded-For: 127.0.0.1"
    echo -e "${YELLOW}3. HTTP Method Override${NC}"
    echo -e "   • Use X-HTTP-Method-Override to bypass method restrictions"
    echo -e "   • Convert POST to GET or enable restricted methods"
    echo -e "   • Example: X-HTTP-Method-Override: DELETE"
    echo -e "${YELLOW}4. Host Header Injection${NC}"
    echo -e "   • Manipulate Host header for password reset poisoning"
    echo -e "   • Can lead to cache poisoning and routing attacks"
    echo -e "   • Example: Host: evil.com\n"

    echo -e "${GREEN}Security Implications${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${RED}• Authentication Bypass:${NC} Circumvent IP-based access controls"
    echo -e "${RED}• Cache Poisoning:${NC} Poison web caches with malicious content"
    echo -e "${RED}• Session Hijacking:${NC} Inject malicious cookies or session data"
    echo -e "${RED}• Information Disclosure:${NC} Access restricted resources"
    echo -e "${RED}• Cross-Site Scripting:${NC} Inject scripts via reflected headers\n"

    echo -e "${GREEN}Detection Techniques${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}1. Header Injection Testing:${NC}"
    echo -e "   • Test for CRLF injection in custom headers"
    echo -e "   • Check if injected headers appear in responses"
    echo -e "${CYAN}2. Bypass Testing:${NC}"
    echo -e "   • Test various forwarded-for headers"
    echo -e "   • Check for status code changes with different headers"
    echo -e "${CYAN}3. Response Analysis:${NC}"
    echo -e "   • Monitor for reflected headers in responses"
    echo -e "   • Check for security header presence\n"

    echo -e "${GREEN}Defensive Measures${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}✓ Input Validation:${NC}"
    echo -e "  • Validate and sanitize all HTTP headers"
    echo -e "  • Remove or encode CRLF characters (\\r\\n)"
    echo -e "${GREEN}✓ Header Whitelisting:${NC}"
    echo -e "  • Only accept known, safe headers"
    echo -e "  • Reject headers with suspicious patterns"
    echo -e "${GREEN}✓ Proper Access Controls:${NC}"
    echo -e "  • Don't rely solely on IP-based restrictions"
    echo -e "  • Validate forwarded headers against trusted proxies"
    echo -e "${GREEN}✓ Security Headers:${NC}"
    echo -e "  • Implement X-Frame-Options, CSP, HSTS"
    echo -e "  • Use X-Content-Type-Options: nosniff"
    echo -e "${GREEN}✓ Web Application Firewall:${NC}"
    echo -e "  • Deploy WAF to filter malicious headers"
    echo -e "  • Monitor for header injection patterns\n"

    echo -e "${GREEN}Legal and Ethical Considerations${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${RED}⚠ IMPORTANT:${NC} Only test applications you own or have explicit permission"
    echo -e "${RED}⚠ LEGAL:${NC} Unauthorized header manipulation may violate computer crime laws"
    echo -e "${RED}⚠ ETHICAL:${NC} Always follow responsible disclosure practices"
    echo -e "${RED}⚠ PROFESSIONAL:${NC} Document findings and provide remediation guidance\n"
}

# Main interactive function
interactive_mode() {
    while true; do
        show_banner

        echo -e "${GREEN}Welcome to WetMonkey HTTP Header Abuse Tester!${NC}"
        echo -e "${YELLOW}This tool helps test web applications for HTTP header vulnerabilities.${NC}\n"
        echo -e "${RED}⚠ WARNING: Only test applications you own or have permission to test!${NC}\n"

        # Step 1: Test type selection
        echo -e "${GREEN}Step 1: Test Type${NC}"
        echo -e "Choose the type of HTTP header test:"
        echo -e "  ${YELLOW}1)${NC} Comprehensive Header Abuse Test - Test for multiple vulnerabilities"
        echo -e "  ${YELLOW}2)${NC} Custom Header Test - Send specific headers and analyze response"
        echo -e "  ${YELLOW}3)${NC} Security Bypass Test - Test IP spoofing and access bypasses"
        echo -e "  ${YELLOW}4)${NC} Educational Information - Learn about HTTP header abuse"

        local test_type
        while true; do
            choice=$(simple_input "Select test type (1-4)")
            case "$choice" in
                "1") test_type="comprehensive"; break ;;
                "2") test_type="custom"; break ;;
                "3") test_type="bypass"; break ;;
                "4") test_type="educational"; break ;;
                *) echo -e "${RED}Please select a number between 1-4${NC}" ;;
            esac
        done

        case "$test_type" in
            "comprehensive")
                # Comprehensive header abuse test
                echo -e "\n${GREEN}Step 2: Target URL${NC}"
                echo -e "Enter the URL you want to test for header abuse vulnerabilities"

                local url
                while true; do
                    url=$(simple_input "Target URL")
                    if [ -z "$url" ]; then
                        echo -e "${RED}URL is required!${NC}"
                        continue
                    fi

                    if validate_url "$url"; then
                        break
                    else
                        echo -e "${RED}Please enter a valid URL (http:// or https://)${NC}"
                    fi
                done

                # Check connectivity
                check_url_reachable "$url"

                # Step 3: Execute comprehensive test
                echo -e "\n${GREEN}Step 3: Header Abuse Testing${NC}"

                if ask_yes_no "Start comprehensive header abuse testing?" "y"; then
                    echo -e "\n${CYAN}Starting header abuse tests...${NC}"

                    # Log start
                    log_json "httpheader_start" "url=$url mode=comprehensive" 2>/dev/null || true

                    # Perform comprehensive test
                    comprehensive_header_test "$url"
                    local test_result=$?

                    # Log end
                    log_json "httpheader_end" "url=$url vulnerabilities=$test_result" 2>/dev/null || true
                else
                    echo -e "${YELLOW}Test cancelled.${NC}"
                fi
                ;;

            "custom")
                # Custom header test
                echo -e "\n${GREEN}Step 2: Target URL${NC}"

                local url
                while true; do
                    url=$(simple_input "Target URL")
                    if [ -z "$url" ]; then
                        echo -e "${RED}URL is required!${NC}"
                        continue
                    fi

                    if validate_url "$url"; then
                        break
                    else
                        echo -e "${RED}Please enter a valid URL (http:// or https://)${NC}"
                    fi
                done

                # Step 3: Custom headers input
                echo -e "\n${GREEN}Step 3: Custom Headers${NC}"
                echo -e "Enter custom headers one by one (press Enter with empty input to finish)"
                echo -e "${YELLOW}Format: Header-Name: Header-Value${NC}"
                echo -e "${YELLOW}Maximum $MAX_HEADERS headers${NC}"

                local headers=()
                local header_count=0

                while true; do
                    header=$(simple_input "Header $((header_count + 1)) (or press Enter to finish)")
                    if [ -z "$header" ]; then
                        if [ ${#headers[@]} -eq 0 ]; then
                            echo -e "${RED}Please enter at least one header${NC}"
                            continue
                        else
                            break
                        fi
                    fi

                    # Basic header format validation
                    if [[ $header == *":"* ]]; then
                        headers+=("$header")
                        ((header_count++))
                        echo -e "${GREEN}✓ Added: $header${NC}"
                    else
                        echo -e "${RED}Invalid header format (should contain ':'), skipping${NC}"
                    fi

                    if [ ${#headers[@]} -ge $MAX_HEADERS ]; then
                        echo -e "${YELLOW}Maximum $MAX_HEADERS headers reached${NC}"
                        break
                    fi
                done

                # Step 4: Execute custom header test
                echo -e "\n${GREEN}Step 4: Custom Header Testing${NC}"

                if ask_yes_no "Send custom headers to target?" "y"; then
                    echo -e "\n${CYAN}Sending custom headers...${NC}"

                    # Log start
                    log_json "httpheader_start" "url=$url headers=${#headers[@]} mode=custom" 2>/dev/null || true

                    # Perform custom header test
                    test_custom_headers "$url" "${headers[@]}"

                    # Log end
                    log_json "httpheader_end" "url=$url headers=${#headers[@]}" 2>/dev/null || true
                else
                    echo -e "${YELLOW}Test cancelled.${NC}"
                fi
                ;;

            "bypass")
                # Security bypass test
                echo -e "\n${GREEN}Step 2: Target URL${NC}"

                local url
                while true; do
                    url=$(simple_input "Target URL")
                    if [ -z "$url" ]; then
                        echo -e "${RED}URL is required!${NC}"
                        continue
                    fi

                    if validate_url "$url"; then
                        break
                    else
                        echo -e "${RED}Please enter a valid URL (http:// or https://)${NC}"
                    fi
                done

                # Check connectivity
                check_url_reachable "$url"

                # Step 3: Execute bypass test
                echo -e "\n${GREEN}Step 3: Security Bypass Testing${NC}"

                if ask_yes_no "Start security bypass testing?" "y"; then
                    echo -e "\n${CYAN}Starting bypass tests...${NC}"

                    # Log start
                    log_json "httpheader_start" "url=$url mode=bypass" 2>/dev/null || true

                    # Perform bypass test
                    test_security_bypasses "$url"
                    local test_result=$?

                    # Log end
                    log_json "httpheader_end" "url=$url bypasses=$test_result" 2>/dev/null || true
                else
                    echo -e "${YELLOW}Test cancelled.${NC}"
                fi
                ;;

            "educational")
                # Show educational information
                show_educational_info
                echo -e "\n${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;
        esac

        echo -e "\n${YELLOW}Press Enter to continue...${NC}"
        read -r

        if ! ask_yes_no "Perform another test?" "y"; then
            break
        fi
    done
}

# Legacy mode function
legacy_mode() {
    local url="$1"
    shift
    local headers=("$@")

    echo -e "${YELLOW}Running in legacy mode...${NC}"
    echo -e "${RED}⚠ WARNING: Only test URLs you own or have permission to test!${NC}\n"

    # Validate URL
    if ! validate_url "$url"; then
        echo -e "${RED}Error: Invalid URL format${NC}" >&2
        exit 1
    fi

    if [ ${#headers[@]} -eq 0 ]; then
        echo -e "${RED}Error: At least one header is required${NC}" >&2
        exit 1
    fi

    # Log start
    log_json "httpheader_start" "url=$url headers=${#headers[@]} mode=legacy" 2>/dev/null || true

    # Perform custom header test
    echo -e "${CYAN}Testing custom headers in legacy mode...${NC}"
    test_custom_headers "$url" "${headers[@]}"

    # Log end
    log_json "httpheader_end" "url=$url headers=${#headers[@]}" 2>/dev/null || true
}

# Main function
main() {
    local url=""
    local headers=()
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
                -H|--header)
                    if [ -z "${2:-}" ]; then
                        echo -e "${RED}Error: -H requires a header${NC}" >&2
                        exit 1
                    fi
                    headers+=("$2")
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
            echo -e "${GREEN}Quick HTTP Header Test: $test_url${NC}"

            if ! validate_url "$test_url"; then
                echo -e "${RED}Error: Invalid URL format${NC}" >&2
                exit 1
            fi

            # Log start
            log_json "httpheader_start" "url=$test_url mode=quick" 2>/dev/null || true

            # Perform comprehensive test
            comprehensive_header_test "$test_url"
            local test_result=$?

            # Log end
            log_json "httpheader_end" "url=$test_url vulnerabilities=$test_result" 2>/dev/null || true

            exit $test_result
        fi

        # Handle legacy mode
        if [ -n "$url" ]; then
            if [ ${#headers[@]} -eq 0 ]; then
                echo -e "${RED}Error: At least one header (-H) is required with -u${NC}" >&2
                echo "Use -h for help or run without arguments for interactive mode." >&2
                exit 1
            fi

            legacy_mode "$url" "${headers[@]}"
            exit $?
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
        echo -e "${YELLOW}HTTP header testing requires curl.${NC}\n"
        exit 1
    fi

    # Start interactive mode
    interactive_mode
}

# Run the main function with all arguments
main "$@"
