#!/usr/bin/env bash
# wetmonkey webrecon – Interactive Web Reconnaissance & Analysis Suite v2.0
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
    echo "║    🌐 WetMonkey Web Reconnaissance Suite║"
    echo "║         Interactive Mode v2.0           ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Show usage information
show_help() {
    echo "WetMonkey Web Reconnaissance Module v${VERSION}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  -u, --url <url>         Target URL (legacy mode)"
    echo "  --method <method>       Recon method: basic|advanced|stealth (legacy mode)"
    echo "  --wordlist <path>       Custom wordlist path (legacy mode)"
    echo "  --scan <url>            Quick web reconnaissance scan"
    echo ""
    echo "This module provides interactive web reconnaissance and analysis."
    echo "Supported features: Directory enumeration, technology detection, security analysis"
    echo ""
    echo "Example:"
    echo "  $0                      # Run in interactive mode"
    echo "  $0 -h                   # Show this help"
    echo "  $0 --scan http://example.com  # Quick web recon scan"
    echo "  $0 -u http://example.com --method basic  # Legacy mode"
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

# Function to check tool availability
check_tool_availability() {
    local tools_available=()
    local tools_missing=()

    # Check common web recon tools
    local tools=("curl" "wget" "nmap" "dirb" "gobuster" "whatweb" "nikto" "wfuzz")

    for tool in "${tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            tools_available+=("$tool")
        else
            tools_missing+=("$tool")
        fi
    done

    echo -e "${GREEN}Available tools: ${tools_available[*]:-none}${NC}" >&2
    if [ ${#tools_missing[@]} -gt 0 ]; then
        echo -e "${YELLOW}Missing tools: ${tools_missing[*]}${NC}" >&2
        echo -e "${YELLOW}Some features may have reduced functionality${NC}" >&2
    fi
    echo "" >&2

    # Return available tools count
    echo "${#tools_available[@]}"
}

# Function to perform basic web reconnaissance
basic_web_reconnaissance() {
    local target_url="$1"

    echo -e "\n${GREEN}🌐 Basic web reconnaissance...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Target: $target_url${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    local recon_results=()
    local findings=()

    # Step 1: Basic connectivity and response analysis
    echo -e "${CYAN}Step 1: Basic Connectivity Analysis${NC}"

    if command -v curl >/dev/null 2>&1; then
        echo -e "${BLUE}  Using curl for basic analysis...${NC}"

        # Get basic response information
        local response_info
        if response_info=$(timeout 15 curl -s -I -L "$target_url" 2>/dev/null); then
            echo -e "${GREEN}  ✓ Successfully connected to target${NC}"

            # Extract key information
            local http_status=$(echo "$response_info" | head -1 | cut -d' ' -f2)
            local server_header=$(echo "$response_info" | grep -i "^server:" | cut -d' ' -f2- | tr -d '\r')
            local content_type=$(echo "$response_info" | grep -i "^content-type:" | cut -d' ' -f2- | tr -d '\r')
            local powered_by=$(echo "$response_info" | grep -i "^x-powered-by:" | cut -d' ' -f2- | tr -d '\r')

            echo -e "${CYAN}    HTTP Status: $http_status${NC}"
            recon_results+=("HTTP Status: $http_status")

            if [ -n "$server_header" ]; then
                echo -e "${CYAN}    Server: $server_header${NC}"
                recon_results+=("Server: $server_header")
                findings+=("Server header reveals: $server_header")
            fi

            if [ -n "$content_type" ]; then
                echo -e "${CYAN}    Content-Type: $content_type${NC}"
                recon_results+=("Content-Type: $content_type")
            fi

            if [ -n "$powered_by" ]; then
                echo -e "${CYAN}    X-Powered-By: $powered_by${NC}"
                recon_results+=("X-Powered-By: $powered_by")
                findings+=("Technology stack revealed: $powered_by")
            fi

            # Check for security headers
            local security_headers=("X-Frame-Options" "X-XSS-Protection" "X-Content-Type-Options" "Strict-Transport-Security" "Content-Security-Policy")
            local missing_headers=()

            for header in "${security_headers[@]}"; do
                if ! echo "$response_info" | grep -qi "^$header:"; then
                    missing_headers+=("$header")
                fi
            done

            if [ ${#missing_headers[@]} -gt 0 ]; then
                echo -e "${YELLOW}    Missing security headers: ${missing_headers[*]}${NC}"
                findings+=("Missing security headers: ${missing_headers[*]}")
            else
                echo -e "${GREEN}    ✓ All common security headers present${NC}"
                findings+=("Good security header implementation")
            fi

        else
            echo -e "${RED}  ❌ Failed to connect to target${NC}"
            recon_results+=("Connection: FAILED")
        fi
    else
        echo -e "${YELLOW}  ⚠ curl not available for connectivity analysis${NC}"
    fi

    # Step 2: Technology detection
    echo -e "\n${CYAN}Step 2: Technology Detection${NC}"

    if command -v whatweb >/dev/null 2>&1; then
        echo -e "${BLUE}  Using whatweb for technology detection...${NC}"

        local whatweb_output
        if whatweb_output=$(timeout 30 whatweb --color=never --no-errors -a 3 "$target_url" 2>/dev/null); then
            echo -e "${GREEN}  ✓ Technology detection completed${NC}"

            # Parse whatweb output for key technologies
            if [[ $whatweb_output == *"WordPress"* ]]; then
                findings+=("WordPress CMS detected")
            fi
            if [[ $whatweb_output == *"Apache"* ]]; then
                findings+=("Apache web server detected")
            fi
            if [[ $whatweb_output == *"nginx"* ]]; then
                findings+=("Nginx web server detected")
            fi
            if [[ $whatweb_output == *"PHP"* ]]; then
                findings+=("PHP technology detected")
            fi
            if [[ $whatweb_output == *"MySQL"* ]]; then
                findings+=("MySQL database detected")
            fi

            # Show condensed output
            echo "$whatweb_output" | head -5 | sed 's/^/    /'
            recon_results+=("Technology detection: COMPLETED")
        else
            echo -e "${YELLOW}  ⚠ Technology detection failed or timed out${NC}"
            recon_results+=("Technology detection: FAILED")
        fi
    else
        echo -e "${YELLOW}  ⚠ whatweb not available for technology detection${NC}"

        # Fallback: Basic technology detection using curl
        if command -v curl >/dev/null 2>&1; then
            echo -e "${BLUE}  Using curl for basic technology detection...${NC}"

            local page_content
            if page_content=$(timeout 15 curl -s -L "$target_url" 2>/dev/null | head -50); then
                # Check for common technologies in HTML
                if [[ $page_content == *"wp-content"* ]] || [[ $page_content == *"wordpress"* ]]; then
                    findings+=("WordPress indicators found in HTML")
                fi
                if [[ $page_content == *"drupal"* ]]; then
                    findings+=("Drupal indicators found in HTML")
                fi
                if [[ $page_content == *"joomla"* ]]; then
                    findings+=("Joomla indicators found in HTML")
                fi

                echo -e "${GREEN}  ✓ Basic HTML analysis completed${NC}"
                recon_results+=("Basic technology detection: COMPLETED")
            else
                echo -e "${YELLOW}  ⚠ Could not retrieve page content${NC}"
                recon_results+=("Basic technology detection: FAILED")
            fi
        fi
    fi

    # Step 3: Directory enumeration (basic)
    echo -e "\n${CYAN}Step 3: Basic Directory Enumeration${NC}"

    # Common directories to check
    local common_dirs=("admin" "login" "wp-admin" "administrator" "phpmyadmin" "backup" "test" "dev" "api" "robots.txt" "sitemap.xml")
    local found_dirs=()

    if command -v curl >/dev/null 2>&1; then
        echo -e "${BLUE}  Checking common directories and files...${NC}"

        for dir in "${common_dirs[@]}"; do
            local test_url="$target_url/$dir"
            local http_code

            if http_code=$(timeout 8 curl -s -o /dev/null -w "%{http_code}" "$test_url" 2>/dev/null); then
                if [[ $http_code =~ ^[2-3][0-9][0-9]$ ]]; then
                    echo -e "${GREEN}    ✓ Found: /$dir ($http_code)${NC}"
                    found_dirs+=("$dir")
                    findings+=("Accessible directory/file: /$dir")
                fi
            fi
        done

        if [ ${#found_dirs[@]} -gt 0 ]; then
            echo -e "${CYAN}  Found directories/files: ${found_dirs[*]}${NC}"
            recon_results+=("Directory enumeration: ${#found_dirs[@]} items found")
        else
            echo -e "${YELLOW}  ⚠ No common directories found${NC}"
            recon_results+=("Directory enumeration: No common items found")
        fi
    else
        echo -e "${YELLOW}  ⚠ curl not available for directory enumeration${NC}"
    fi

    # Summary
    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}📊 Basic Web Reconnaissance Summary${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Target: $target_url${NC}"
    echo -e "${CYAN}Reconnaissance Steps: 3${NC}"
    echo -e "${CYAN}Results Collected: ${#recon_results[@]}${NC}"
    echo -e "${CYAN}Security Findings: ${#findings[@]}${NC}"

    if [ ${#recon_results[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}Reconnaissance Results:${NC}"
        for result in "${recon_results[@]}"; do
            echo -e "  • $result"
        done
    fi

    if [ ${#findings[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}Security Findings:${NC}"
        for finding in "${findings[@]}"; do
            echo -e "  • $finding"
        done

        echo -e "\n${YELLOW}Security Recommendations:${NC}"
        echo -e "• Review server header disclosure"
        echo -e "• Implement missing security headers"
        echo -e "• Restrict access to sensitive directories"
        echo -e "• Regular security assessments and updates"
        echo -e "• Monitor for unauthorized access attempts"
    else
        echo -e "\n${GREEN}✓ No obvious security issues found in basic scan${NC}"
        echo -e "${CYAN}Consider running advanced reconnaissance for deeper analysis${NC}"
    fi

    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    return 0
}

# Function to perform advanced web reconnaissance
advanced_web_reconnaissance() {
    local target_url="$1"

    echo -e "\n${GREEN}🔬 Advanced web reconnaissance...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}Target: $target_url${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    local advanced_results=()
    local security_findings=()
    local vulnerabilities=()

    # Step 1: Comprehensive directory enumeration
    echo -e "${CYAN}Step 1: Comprehensive Directory Enumeration${NC}"

    if command -v gobuster >/dev/null 2>&1; then
        echo -e "${BLUE}  Using gobuster for directory enumeration...${NC}"

        # Try common wordlist locations
        local wordlists=(
            "/usr/share/wordlists/dirb/common.txt"
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
            "/usr/share/seclists/Discovery/Web-Content/common.txt"
            "/usr/share/wordlists/wfuzz/general/common.txt"
        )

        local wordlist_found=""
        for wl in "${wordlists[@]}"; do
            if [ -f "$wl" ]; then
                wordlist_found="$wl"
                break
            fi
        done

        if [ -n "$wordlist_found" ]; then
            echo -e "${BLUE}  Using wordlist: $wordlist_found${NC}"

            local gobuster_output
            if gobuster_output=$(timeout 120 gobuster dir -u "$target_url" -w "$wordlist_found" -q --no-error 2>/dev/null | head -20); then
                if [ -n "$gobuster_output" ]; then
                    echo -e "${GREEN}  ✓ Directory enumeration completed${NC}"
                    echo "$gobuster_output" | sed 's/^/    /'

                    local dir_count=$(echo "$gobuster_output" | wc -l)
                    advanced_results+=("Gobuster enumeration: $dir_count directories found")
                    security_findings+=("Multiple directories discovered - review for sensitive content")
                else
                    echo -e "${YELLOW}  ⚠ No directories found with gobuster${NC}"
                    advanced_results+=("Gobuster enumeration: No directories found")
                fi
            else
                echo -e "${YELLOW}  ⚠ Gobuster scan failed or timed out${NC}"
                advanced_results+=("Gobuster enumeration: FAILED")
            fi
        else
            echo -e "${YELLOW}  ⚠ No wordlists found for gobuster${NC}"
            advanced_results+=("Gobuster enumeration: No wordlists available")
        fi
    elif command -v dirb >/dev/null 2>&1; then
        echo -e "${BLUE}  Using dirb for directory enumeration...${NC}"

        local dirb_output
        if dirb_output=$(timeout 120 dirb "$target_url" -S -w 2>/dev/null | grep "^+" | head -15); then
            if [ -n "$dirb_output" ]; then
                echo -e "${GREEN}  ✓ Directory enumeration completed${NC}"
                echo "$dirb_output" | sed 's/^/    /'

                local dir_count=$(echo "$dirb_output" | wc -l)
                advanced_results+=("Dirb enumeration: $dir_count directories found")
                security_findings+=("Multiple directories discovered - review for sensitive content")
            else
                echo -e "${YELLOW}  ⚠ No directories found with dirb${NC}"
                advanced_results+=("Dirb enumeration: No directories found")
            fi
        else
            echo -e "${YELLOW}  ⚠ Dirb scan failed or timed out${NC}"
            advanced_results+=("Dirb enumeration: FAILED")
        fi
    else
        echo -e "${YELLOW}  ⚠ No directory enumeration tools available${NC}"
        advanced_results+=("Directory enumeration: Tools not available")
    fi

    # Step 2: Vulnerability scanning
    echo -e "\n${CYAN}Step 2: Vulnerability Scanning${NC}"

    if command -v nikto >/dev/null 2>&1; then
        echo -e "${BLUE}  Using nikto for vulnerability scanning...${NC}"

        local nikto_output
        if nikto_output=$(timeout 180 nikto -h "$target_url" -Format txt -nointeractive 2>/dev/null | grep "^+" | head -10); then
            if [ -n "$nikto_output" ]; then
                echo -e "${GREEN}  ✓ Vulnerability scan completed${NC}"
                echo "$nikto_output" | sed 's/^/    /'

                # Parse nikto output for vulnerabilities
                if [[ $nikto_output == *"OSVDB"* ]]; then
                    vulnerabilities+=("OSVDB vulnerabilities detected")
                fi
                if [[ $nikto_output == *"outdated"* ]]; then
                    vulnerabilities+=("Outdated software detected")
                fi
                if [[ $nikto_output == *"XSS"* ]]; then
                    vulnerabilities+=("Potential XSS vulnerability")
                fi

                local vuln_count=$(echo "$nikto_output" | wc -l)
                advanced_results+=("Nikto scan: $vuln_count findings")
            else
                echo -e "${YELLOW}  ⚠ No vulnerabilities found by nikto${NC}"
                advanced_results+=("Nikto scan: No vulnerabilities found")
            fi
        else
            echo -e "${YELLOW}  ⚠ Nikto scan failed or timed out${NC}"
            advanced_results+=("Nikto scan: FAILED")
        fi
    else
        echo -e "${YELLOW}  ⚠ nikto not available for vulnerability scanning${NC}"

        # Fallback: Basic vulnerability checks using curl
        echo -e "${BLUE}  Performing basic vulnerability checks...${NC}"

        if command -v curl >/dev/null 2>&1; then
            # Check for common vulnerabilities
            local vuln_tests=(
                "/.git/config"
                "/.env"
                "/config.php"
                "/wp-config.php"
                "/admin/config.php"
                "/phpinfo.php"
                "/test.php"
            )

            local found_vulns=()
            for test_path in "${vuln_tests[@]}"; do
                local test_url="$target_url$test_path"
                local http_code

                if http_code=$(timeout 8 curl -s -o /dev/null -w "%{http_code}" "$test_url" 2>/dev/null); then
                    if [[ $http_code =~ ^2[0-9][0-9]$ ]]; then
                        echo -e "${RED}    ⚠ Potential vulnerability: $test_path ($http_code)${NC}"
                        found_vulns+=("$test_path")
                        vulnerabilities+=("Sensitive file accessible: $test_path")
                    fi
                fi
            done

            if [ ${#found_vulns[@]} -gt 0 ]; then
                advanced_results+=("Basic vuln check: ${#found_vulns[@]} potential issues")
            else
                advanced_results+=("Basic vuln check: No obvious issues")
            fi
        fi
    fi

    # Step 3: SSL/TLS analysis
    echo -e "\n${CYAN}Step 3: SSL/TLS Analysis${NC}"

    if [[ $target_url == https://* ]]; then
        if command -v nmap >/dev/null 2>&1; then
            echo -e "${BLUE}  Using nmap for SSL analysis...${NC}"

            # Extract hostname and port from URL
            local hostname=$(echo "$target_url" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)
            local port="443"

            if [[ $target_url == *:* ]] && [[ $target_url != *:///* ]]; then
                port=$(echo "$target_url" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f2)
            fi

            local ssl_output
            if ssl_output=$(timeout 60 nmap --script ssl-enum-ciphers -p "$port" "$hostname" 2>/dev/null | grep -E "(TLS|SSL|cipher)" | head -10); then
                if [ -n "$ssl_output" ]; then
                    echo -e "${GREEN}  ✓ SSL analysis completed${NC}"
                    echo "$ssl_output" | sed 's/^/    /'

                    # Check for weak SSL/TLS
                    if [[ $ssl_output == *"SSLv"* ]]; then
                        vulnerabilities+=("Weak SSL protocol detected")
                    fi
                    if [[ $ssl_output == *"TLSv1.0"* ]] || [[ $ssl_output == *"TLSv1.1"* ]]; then
                        vulnerabilities+=("Outdated TLS version detected")
                    fi

                    advanced_results+=("SSL analysis: COMPLETED")
                else
                    echo -e "${YELLOW}  ⚠ No SSL information retrieved${NC}"
                    advanced_results+=("SSL analysis: No information")
                fi
            else
                echo -e "${YELLOW}  ⚠ SSL analysis failed or timed out${NC}"
                advanced_results+=("SSL analysis: FAILED")
            fi
        else
            echo -e "${YELLOW}  ⚠ nmap not available for SSL analysis${NC}"
            advanced_results+=("SSL analysis: Tool not available")
        fi
    else
        echo -e "${YELLOW}  ⚠ Target is not HTTPS - SSL analysis skipped${NC}"
        security_findings+=("Website not using HTTPS - data transmitted in plaintext")
        advanced_results+=("SSL analysis: Not applicable (HTTP)")
    fi

    # Summary
    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}📊 Advanced Web Reconnaissance Summary${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Target: $target_url${NC}"
    echo -e "${CYAN}Advanced Steps: 3${NC}"
    echo -e "${CYAN}Results Collected: ${#advanced_results[@]}${NC}"
    echo -e "${CYAN}Security Findings: ${#security_findings[@]}${NC}"
    echo -e "${CYAN}Vulnerabilities: ${#vulnerabilities[@]}${NC}"

    if [ ${#advanced_results[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}Advanced Results:${NC}"
        for result in "${advanced_results[@]}"; do
            echo -e "  • $result"
        done
    fi

    if [ ${#security_findings[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}Security Findings:${NC}"
        for finding in "${security_findings[@]}"; do
            echo -e "  • $finding"
        done
    fi

    if [ ${#vulnerabilities[@]} -gt 0 ]; then
        echo -e "\n${RED}Potential Vulnerabilities:${NC}"
        for vuln in "${vulnerabilities[@]}"; do
            echo -e "  • $vuln"
        done

        echo -e "\n${RED}⚠ CRITICAL RECOMMENDATIONS:${NC}"
        echo -e "• Immediately review and secure identified vulnerabilities"
        echo -e "• Implement proper access controls for sensitive files"
        echo -e "• Update software and apply security patches"
        echo -e "• Configure proper SSL/TLS settings"
        echo -e "• Regular security assessments and monitoring"
    else
        echo -e "\n${GREEN}✓ No critical vulnerabilities found in advanced scan${NC}"
        echo -e "${CYAN}Continue with regular security monitoring and updates${NC}"
    fi

    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    return 0
}

# Educational information function
show_educational_info() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║      📚 Web Reconnaissance Guide        ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}\n"

    echo -e "${GREEN}What is Web Reconnaissance?${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "Web reconnaissance (web recon) is the process of gathering information"
    echo -e "about web applications, servers, and infrastructure to identify potential"
    echo -e "attack vectors, security weaknesses, and system configurations. It's a"
    echo -e "critical phase in security testing and penetration testing.\n"

    echo -e "${GREEN}Web Reconnaissance Phases${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${YELLOW}1. Passive Reconnaissance${NC}"
    echo -e "   • Information gathering without direct interaction"
    echo -e "   • DNS enumeration and subdomain discovery"
    echo -e "   • Search engine reconnaissance (Google dorking)"
    echo -e "   • Social media and public records analysis"
    echo -e "${YELLOW}2. Active Reconnaissance${NC}"
    echo -e "   • Direct interaction with target systems"
    echo -e "   • Port scanning and service enumeration"
    echo -e "   • Directory and file enumeration"
    echo -e "   • Technology fingerprinting and banner grabbing"
    echo -e "${YELLOW}3. Vulnerability Assessment${NC}"
    echo -e "   • Automated vulnerability scanning"
    echo -e "   • Manual security testing"
    echo -e "   • Configuration analysis"
    echo -e "   • SSL/TLS security evaluation\n"

    echo -e "${GREEN}Common Web Reconnaissance Techniques${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Directory Enumeration:${NC}"
    echo -e "• Discover hidden directories and files"
    echo -e "• Identify admin panels and sensitive areas"
    echo -e "• Find backup files and configuration files"
    echo -e "• Locate API endpoints and documentation"
    echo -e "${CYAN}Technology Fingerprinting:${NC}"
    echo -e "• Identify web server software and versions"
    echo -e "• Detect content management systems (CMS)"
    echo -e "• Discover programming languages and frameworks"
    echo -e "• Analyze client-side technologies"
    echo -e "${CYAN}Security Header Analysis:${NC}"
    echo -e "• Check for missing security headers"
    echo -e "• Evaluate HTTPS implementation"
    echo -e "• Analyze cookie security settings"
    echo -e "• Review CORS and CSP policies"
    echo -e "${CYAN}Vulnerability Scanning:${NC}"
    echo -e "• Automated security vulnerability detection"
    echo -e "• Common vulnerability assessment"
    echo -e "• SSL/TLS configuration analysis"
    echo -e "• Web application security testing\n"

    echo -e "${GREEN}Essential Web Reconnaissance Tools${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}1. Directory Enumeration:${NC}"
    echo -e "   • gobuster: Fast directory/file brute-forcer"
    echo -e "   • dirb: Web content scanner"
    echo -e "   • dirbuster: GUI-based directory brute-forcer"
    echo -e "   • wfuzz: Web application fuzzer"
    echo -e "${CYAN}2. Technology Detection:${NC}"
    echo -e "   • whatweb: Web technology identifier"
    echo -e "   • wappalyzer: Technology profiler"
    echo -e "   • builtwith: Technology stack analyzer"
    echo -e "   • retire.js: JavaScript library vulnerability scanner"
    echo -e "${CYAN}3. Vulnerability Scanning:${NC}"
    echo -e "   • nikto: Web vulnerability scanner"
    echo -e "   • nmap: Network and service scanner"
    echo -e "   • OWASP ZAP: Web application security scanner"
    echo -e "   • Burp Suite: Web application testing platform"
    echo -e "${CYAN}4. SSL/TLS Analysis:${NC}"
    echo -e "   • sslyze: SSL configuration analyzer"
    echo -e "   • testssl.sh: SSL/TLS tester"
    echo -e "   • sslscan: SSL/TLS scanner"
    echo -e "   • nmap ssl scripts: SSL enumeration scripts\n"

    echo -e "${GREEN}Security Applications${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Penetration Testing:${NC}"
    echo -e "• Identify attack surface and entry points"
    echo -e "• Discover hidden functionality and admin areas"
    echo -e "• Find configuration weaknesses and misconfigurations"
    echo -e "• Locate sensitive files and information disclosure"
    echo -e "${CYAN}Security Assessment:${NC}"
    echo -e "• Evaluate web application security posture"
    echo -e "• Identify missing security controls"
    echo -e "• Assess SSL/TLS implementation quality"
    echo -e "• Review security header implementation"
    echo -e "${CYAN}Vulnerability Management:${NC}"
    echo -e "• Discover known vulnerabilities in web technologies"
    echo -e "• Identify outdated software and components"
    echo -e "• Find common security misconfigurations"
    echo -e "• Assess patch management effectiveness"
    echo -e "${CYAN}Compliance and Auditing:${NC}"
    echo -e "• Verify security control implementation"
    echo -e "• Document security configuration status"
    echo -e "• Assess compliance with security standards"
    echo -e "• Generate security assessment reports\n"

    echo -e "${GREEN}Common Findings and Vulnerabilities${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}Information Disclosure:${NC}"
    echo -e "• Server version and technology stack exposure"
    echo -e "• Directory listing and file exposure"
    echo -e "• Error messages revealing system information"
    echo -e "• Backup files and configuration files accessible"
    echo -e "${CYAN}Security Misconfigurations:${NC}"
    echo -e "• Missing security headers (HSTS, CSP, X-Frame-Options)"
    echo -e "• Weak SSL/TLS configuration"
    echo -e "• Default credentials and configurations"
    echo -e "• Unnecessary services and features enabled"
    echo -e "${CYAN}Access Control Issues:${NC}"
    echo -e "• Admin panels accessible without authentication"
    echo -e "• Sensitive directories and files exposed"
    echo -e "• Weak authentication mechanisms"
    echo -e "• Insufficient authorization controls"
    echo -e "${CYAN}Known Vulnerabilities:${NC}"
    echo -e "• Outdated software with known CVEs"
    echo -e "• Vulnerable third-party components"
    echo -e "• Common web application vulnerabilities"
    echo -e "• Framework and CMS specific vulnerabilities\n"

    echo -e "${GREEN}Best Practices and Methodology${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}✓ Systematic Approach:${NC}"
    echo -e "  • Start with passive reconnaissance"
    echo -e "  • Progress to active enumeration"
    echo -e "  • Perform comprehensive vulnerability assessment"
    echo -e "  • Document all findings and evidence"
    echo -e "${GREEN}✓ Tool Combination:${NC}"
    echo -e "  • Use multiple tools for comprehensive coverage"
    echo -e "  • Cross-validate findings with different methods"
    echo -e "  • Combine automated and manual testing"
    echo -e "  • Verify results to reduce false positives"
    echo -e "${GREEN}✓ Stealth Considerations:${NC}"
    echo -e "  • Control scan intensity and timing"
    echo -e "  • Use appropriate user agents and headers"
    echo -e "  • Implement delays to avoid detection"
    echo -e "  • Monitor for defensive responses"
    echo -e "${GREEN}✓ Documentation:${NC}"
    echo -e "  • Record all reconnaissance activities"
    echo -e "  • Screenshot important findings"
    echo -e "  • Maintain detailed testing logs"
    echo -e "  • Create comprehensive reports\n"

    echo -e "${GREEN}Legal and Ethical Considerations${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${RED}⚠ IMPORTANT:${NC} Only perform web reconnaissance on systems you own or have permission"
    echo -e "${RED}⚠ LEGAL:${NC} Unauthorized web reconnaissance may violate computer crime laws"
    echo -e "${RED}⚠ ETHICAL:${NC} Use reconnaissance techniques for legitimate security purposes only"
    echo -e "${RED}⚠ PROFESSIONAL:${NC} Follow responsible disclosure for discovered vulnerabilities"
    echo -e "${RED}⚠ SCOPE:${NC} Stay within authorized testing scope and boundaries\n"
}

# Main interactive function
interactive_mode() {
    while true; do
        show_banner

        echo -e "${GREEN}Welcome to WetMonkey Web Reconnaissance Suite!${NC}"
        echo -e "${YELLOW}This tool helps perform comprehensive web application reconnaissance.${NC}\n"
        echo -e "${RED}⚠ WARNING: Only test websites you own or have permission to test!${NC}\n"

        # Show available tools
        local tools_count=$(check_tool_availability)

        # Step 1: Reconnaissance type selection
        echo -e "${GREEN}Step 1: Reconnaissance Type${NC}"
        echo -e "Choose the type of web reconnaissance:"
        echo -e "  ${YELLOW}1)${NC} Basic Reconnaissance - Quick web analysis and technology detection"
        echo -e "  ${YELLOW}2)${NC} Advanced Reconnaissance - Comprehensive scanning and vulnerability assessment"
        echo -e "  ${YELLOW}3)${NC} Educational Information - Learn about web reconnaissance techniques"

        local recon_type
        while true; do
            choice=$(simple_input "Select reconnaissance type (1-3)")
            case "$choice" in
                "1") recon_type="basic"; break ;;
                "2") recon_type="advanced"; break ;;
                "3") recon_type="educational"; break ;;
                *) echo -e "${RED}Please select a number between 1-3${NC}" ;;
            esac
        done

        case "$recon_type" in
            "educational")
                # Show educational information
                show_educational_info
                echo -e "\n${YELLOW}Press Enter to continue...${NC}"
                read -r
                ;;

            *)
                # Web reconnaissance
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
                echo -e "\n${GREEN}Step 3: Reconnaissance Summary${NC}"
                echo -e "${BLUE}═══════════════════════════════════════${NC}"
                echo -e "${CYAN}Target URL: $target_url${NC}"
                echo -e "${CYAN}Reconnaissance Type: $recon_type${NC}"
                echo -e "${CYAN}Available Tools: $tools_count${NC}"
                echo -e "${BLUE}═══════════════════════════════════════${NC}"

                echo -e "\n${RED}⚠ WARNING: This will perform web reconnaissance against the target!${NC}"
                echo -e "${RED}⚠ Only proceed if you have authorization to test this website!${NC}"

                if ask_yes_no "Start web reconnaissance?" "n"; then
                    echo -e "\n${CYAN}Starting web reconnaissance...${NC}"

                    # Log start
                    log_json "webrecon_start" "url=$target_url type=$recon_type" 2>/dev/null || true

                    # Perform reconnaissance based on type
                    case "$recon_type" in
                        "basic")
                            basic_web_reconnaissance "$target_url"
                            ;;
                        "advanced")
                            basic_web_reconnaissance "$target_url"
                            echo -e "\n${MAGENTA}═══ Advanced Reconnaissance ═══${NC}"
                            advanced_web_reconnaissance "$target_url"
                            ;;
                    esac

                    # Log end
                    log_json "webrecon_end" "url=$target_url type=$recon_type" 2>/dev/null || true
                else
                    echo -e "${YELLOW}Web reconnaissance cancelled.${NC}"
                fi
                ;;
        esac

        echo -e "\n${YELLOW}Press Enter to continue...${NC}"
        read -r

        if ! ask_yes_no "Perform another web reconnaissance?" "y"; then
            break
        fi
    done
}

# Legacy mode function
legacy_mode() {
    local url="$1"
    local method="$2"
    local wordlist="$3"

    echo -e "${YELLOW}Running in legacy mode...${NC}"
    echo -e "${RED}⚠ WARNING: Only test websites you own or have permission to test!${NC}\n"

    # Validate URL
    if ! validate_url "$url"; then
        echo -e "${RED}Error: Invalid URL format${NC}" >&2
        exit 1
    fi

    # Log start
    log_json "webrecon_start" "url=$url method=$method legacy=true" 2>/dev/null || true

    # Perform legacy reconnaissance
    echo -e "${CYAN}Performing legacy web reconnaissance...${NC}"
    echo -e "${BLUE}Target URL: $url${NC}"
    echo -e "${BLUE}Method: $method${NC}"
    if [ -n "$wordlist" ]; then
        echo -e "${BLUE}Wordlist: $wordlist${NC}"
    fi
    echo ""

    case "$method" in
        "basic")
            echo -e "${GREEN}Running basic reconnaissance...${NC}"
            basic_web_reconnaissance "$url"
            ;;
        "advanced")
            echo -e "${GREEN}Running advanced reconnaissance...${NC}"
            basic_web_reconnaissance "$url"
            echo -e "\n${MAGENTA}═══ Advanced Analysis ═══${NC}"
            advanced_web_reconnaissance "$url"
            ;;
        "stealth")
            echo -e "${GREEN}Running stealth reconnaissance...${NC}"
            echo -e "${YELLOW}Note: Stealth mode uses basic reconnaissance with reduced intensity${NC}"
            basic_web_reconnaissance "$url"
            ;;
        "dirb")
            # Legacy dirb mode
            if command -v dirb >/dev/null 2>&1; then
                echo -e "${GREEN}Running dirb directory enumeration...${NC}"
                if [ -f "$wordlist" ]; then
                    dirb "$url" "$wordlist" || true
                else
                    echo -e "${YELLOW}Wordlist not found: $wordlist${NC}"
                    echo -e "${YELLOW}Using dirb with default wordlist${NC}"
                    dirb "$url" || true
                fi
            else
                echo -e "${RED}❌ dirb is not available${NC}"
                exit 1
            fi
            ;;
        "whatweb")
            # Legacy whatweb mode
            if command -v whatweb >/dev/null 2>&1; then
                echo -e "${GREEN}Running whatweb technology detection...${NC}"
                whatweb "$url"
            else
                echo -e "${RED}❌ whatweb is not available${NC}"
                exit 1
            fi
            ;;
        "gobuster")
            # Legacy gobuster mode
            if command -v gobuster >/dev/null 2>&1; then
                echo -e "${GREEN}Running gobuster directory enumeration...${NC}"
                if [ -f "$wordlist" ]; then
                    gobuster dir -u "$url" -w "$wordlist"
                else
                    echo -e "${RED}❌ Wordlist not found: $wordlist${NC}"
                    exit 1
                fi
            else
                echo -e "${RED}❌ gobuster is not available${NC}"
                exit 1
            fi
            ;;
        *)
            echo -e "${RED}Error: Unknown method '$method'${NC}" >&2
            echo -e "${YELLOW}Available methods: basic, advanced, stealth, dirb, whatweb, gobuster${NC}" >&2
            exit 1
            ;;
    esac

    # Log end
    log_json "webrecon_end" "url=$url method=$method" 2>/dev/null || true
}

# Main function
main() {
    local url=""
    local method="basic"
    local wordlist="/usr/share/wordlists/dirb/common.txt"
    local scan_url=""

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
                --method)
                    if [ -z "${2:-}" ]; then
                        echo -e "${RED}Error: --method requires a method${NC}" >&2
                        exit 1
                    fi
                    method="$2"
                    shift 2
                    ;;
                --wordlist)
                    if [ -z "${2:-}" ]; then
                        echo -e "${RED}Error: --wordlist requires a path${NC}" >&2
                        exit 1
                    fi
                    wordlist="$2"
                    shift 2
                    ;;
                --scan)
                    if [ -z "${2:-}" ]; then
                        echo -e "${RED}Error: --scan requires a URL${NC}" >&2
                        exit 1
                    fi
                    scan_url="$2"
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
        if [ -n "$scan_url" ]; then
            echo -e "${GREEN}Quick Web Reconnaissance Scan: $scan_url${NC}"

            if ! validate_url "$scan_url"; then
                echo -e "${RED}Error: Invalid URL format${NC}" >&2
                exit 1
            fi

            # Log start
            log_json "webrecon_start" "url=$scan_url mode=quick" 2>/dev/null || true

            # Perform quick reconnaissance
            basic_web_reconnaissance "$scan_url"

            # Log end
            log_json "webrecon_end" "url=$scan_url" 2>/dev/null || true

            exit 0
        fi

        # Handle legacy mode
        if [ -n "$url" ]; then
            legacy_mode "$url" "$method" "$wordlist"
            exit $?
        fi

        # If we get here, invalid combination of arguments
        echo -e "${RED}Error: Invalid argument combination${NC}" >&2
        echo "Use -h for help or run without arguments for interactive mode." >&2
        exit 1
    fi

    # Check dependencies for interactive mode
    echo -e "${GREEN}WetMonkey Web Reconnaissance Suite v${VERSION}${NC}"
    echo -e "${CYAN}Checking available tools...${NC}\n"

    local tools_count=$(check_tool_availability)

    if [ "$tools_count" -eq 0 ]; then
        echo -e "${RED}❌ No web reconnaissance tools are available!${NC}"
        echo -e "${YELLOW}Please install at least curl for basic functionality${NC}"
        echo -e "${YELLOW}Recommended tools: curl, wget, nmap, dirb, gobuster, whatweb, nikto${NC}"
        exit 1
    fi

    # Start interactive mode
    interactive_mode
}

# Run the main function with all arguments
main "$@"
