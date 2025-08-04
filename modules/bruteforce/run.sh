#!/usr/bin/env bash
# wetmonkey bruteforce – Interactive Brute Force Module v1.1
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$SCRIPT_DIR/../../"
source "$BASE_DIR/core/utils.sh"

# Configuration
VERSION="1.1"
MAX_THREADS=64
MIN_TIMEOUT=1
MAX_TIMEOUT=300

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Available services
declare -A SERVICES=(
    ["ssh"]=22
    ["ftp"]=21
    ["http-get"]=80
    ["http-post"]=80
    ["https"]=443
    ["rdp"]=3389
    ["smb"]=445
    ["mysql"]=3306
    ["mssql"]=1433
    ["postgres"]=5432
    ["telnet"]=23
)

show_banner() {
    clear
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║         🚀 WetMonkey BruteForce         ║"
    echo "║         Interactive Mode v1.1          ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Function to display a menu and get user selection
show_menu() {
    local prompt="$1"
    shift
    local options=("$@")
    local choice=0
    
    while true; do
        echo -e "\n${YELLOW}$prompt${NC}"
        for i in "${!options[@]}"; do
            printf "${GREEN}%3d)${NC} %s\n" "$((i+1))" "${options[i]}"
        done
        echo -ne "\n${BLUE}Enter your choice (1-${#options[@]}): ${NC}"
        
        read -r choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 )) && (( choice <= ${#options[@]} )); then
            return $((choice-1))
        fi
        echo -e "${RED}Invalid choice. Please enter a number between 1 and ${#options[@]}.${NC}"
        sleep 1
    done
}

# Function to get input with default value
get_input() {
    local prompt="$1"
    local default_value="${2:-}"
    local input
    
    while true; do
        if [ -n "$default_value" ]; then
            echo -ne "${BLUE}$prompt [${YELLOW}$default_value${BLUE}]: ${NC}"
        else
            echo -ne "${BLUE}$prompt: ${NC}"
        fi
        
        read -r input
        input="${input:-$default_value}"
        
        # Validate required fields
        if [ -z "$input" ] && [ -z "$default_value" ] && [ "$prompt" != "Save results to file" ]; then
            echo -e "${RED}This field is required. Please enter a value.${NC}"
            continue
        fi
        
        echo "$input"
        break
    done
}

# Function to validate file exists
validate_file() {
    local file="$1"
    local type="$2"
    
    while [ ! -f "$file" ]; do
        echo -e "${RED}Error: $type file not found: $file${NC}"
        file=$(get_input "Enter path to $type file" "$file")
    done
    
    echo "$file"
}



# Function to run hydra
run_hydra() {
    echo -e "\n${GREEN}🚀 Starting Brute Force Attack...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"

    # Build hydra command
    local hydra_cmd=("hydra" "-L" "$userlist" "-P" "$passlist")

    # Add common options
    hydra_cmd+=("-t" "$threads" "-w" "$timeout")

    # Add verbose output
    hydra_cmd+=("-v")

    # Add SSL if needed
    if [ "$ssl" = true ]; then
        hydra_cmd+=("-S")
    fi

    # Add output file if specified
    if [ -n "$output_file" ]; then
        hydra_cmd+=("-o" "$output_file")
    fi

    # Add service and target
    hydra_cmd+=("$service://$target:$port")

    # Show command being executed
    echo -e "${YELLOW}Command:${NC} ${hydra_cmd[*]}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}\n"

    # Log start
    log_json "bruteforce_start" "target=$target service=$service tool=hydra" 2>/dev/null || true

    # Execute hydra with error handling
    local start_time=$(date +%s)
    local exit_code=0

    echo -e "${GREEN}Attack in progress... Press Ctrl+C to stop${NC}\n"

    # Run hydra and capture exit code
    "${hydra_cmd[@]}" || exit_code=$?

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    # Log end
    log_json "bruteforce_end" "target=$target service=$service duration=${duration}s" 2>/dev/null || true

    echo -e "\n${BLUE}═══════════════════════════════════════${NC}"

    # Interpret results
    case $exit_code in
        0)
            echo -e "${GREEN}✓ Attack completed successfully!${NC}"
            echo -e "${GREEN}  Credentials may have been found.${NC}"
            ;;
        1)
            echo -e "${YELLOW}⚠ Attack completed - no valid credentials found.${NC}"
            ;;
        2)
            echo -e "${RED}✗ Error: Service connection failed.${NC}"
            echo -e "${RED}  Check if the target is reachable and the service is running.${NC}"
            ;;
        3)
            echo -e "${RED}✗ Error: Invalid service or protocol.${NC}"
            ;;
        4)
            echo -e "${YELLOW}⚠ Attack stopped by user (Ctrl+C).${NC}"
            ;;
        *)
            echo -e "${RED}✗ Attack failed with exit code: $exit_code${NC}"
            ;;
    esac

    echo -e "${BLUE}Duration: ${duration} seconds${NC}"

    if [ -n "$output_file" ] && [ -f "$output_file" ]; then
        echo -e "${GREEN}Results saved to: $output_file${NC}"
    fi

    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "\n${YELLOW}Press Enter to continue...${NC}"
    read -r
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

# Main interactive function
interactive_mode() {
    # Reset terminal settings
    stty sane

    while true; do
        show_banner

        echo -e "${GREEN}Welcome to WetMonkey BruteForce!${NC}"
        echo -e "${YELLOW}Let's set up your brute force attack step by step.${NC}\n"

        # Step 1: Get target
        echo -e "${GREEN}Step 1: Target Information${NC}"
        echo -e "Enter the target you want to attack (IP address or hostname)"
        target=$(simple_input "Target")

        if [ -z "$target" ]; then
            echo -e "${RED}Target is required!${NC}"
            sleep 1
            continue
        fi

        echo -e "\n${GREEN}Step 2: Service Selection${NC}"
        echo -e "Choose the service you want to attack:"
        echo -e "  ${YELLOW}1)${NC} SSH (port 22)"
        echo -e "  ${YELLOW}2)${NC} FTP (port 21)"
        echo -e "  ${YELLOW}3)${NC} HTTP (port 80)"
        echo -e "  ${YELLOW}4)${NC} HTTPS (port 443)"
        echo -e "  ${YELLOW}5)${NC} RDP (port 3389)"
        echo -e "  ${YELLOW}6)${NC} SMB (port 445)"
        echo -e "  ${YELLOW}7)${NC} MySQL (port 3306)"
        echo -e "  ${YELLOW}8)${NC} Telnet (port 23)"

        while true; do
            choice=$(simple_input "Select service (1-8)")
            case "$choice" in
                "1") service="ssh"; port=22; break ;;
                "2") service="ftp"; port=21; break ;;
                "3") service="http-get"; port=80; break ;;
                "4") service="https"; port=443; break ;;
                "5") service="rdp"; port=3389; break ;;
                "6") service="smb"; port=445; break ;;
                "7") service="mysql"; port=3306; break ;;
                "8") service="telnet"; port=23; break ;;
                *) echo -e "${RED}Please select a number between 1-8${NC}" ;;
            esac
        done

        # Step 3: Port confirmation
        echo -e "\n${GREEN}Step 3: Port Configuration${NC}"
        new_port=$(simple_input "Port number" "$port")
        if [[ "$new_port" =~ ^[0-9]+$ ]] && (( new_port >= 1 )) && (( new_port <= 65535 )); then
            port="$new_port"
        else
            echo -e "${YELLOW}Using default port: $port${NC}"
        fi

        # Step 4: Username wordlist
        echo -e "\n${GREEN}Step 4: Username Wordlist${NC}"
        echo -e "Provide a file containing usernames to try (one per line)"

        while true; do
            userlist=$(simple_input "Username wordlist path")
            if [ -z "$userlist" ]; then
                echo -e "${RED}Username wordlist is required!${NC}"
                continue
            fi

            if [ ! -f "$userlist" ]; then
                echo -e "${RED}File not found: $userlist${NC}"
                continue
            fi

            if [ ! -r "$userlist" ]; then
                echo -e "${RED}Cannot read file: $userlist${NC}"
                continue
            fi

            user_count=$(wc -l < "$userlist" 2>/dev/null || echo "0")
            echo -e "${GREEN}✓ Found $user_count usernames${NC}"
            break
        done

        # Step 5: Password wordlist
        echo -e "\n${GREEN}Step 5: Password Wordlist${NC}"
        echo -e "Provide a file containing passwords to try (one per line)"

        while true; do
            passlist=$(simple_input "Password wordlist path")
            if [ -z "$passlist" ]; then
                echo -e "${RED}Password wordlist is required!${NC}"
                continue
            fi

            if [ ! -f "$passlist" ]; then
                echo -e "${RED}File not found: $passlist${NC}"
                continue
            fi

            if [ ! -r "$passlist" ]; then
                echo -e "${RED}Cannot read file: $passlist${NC}"
                continue
            fi

            pass_count=$(wc -l < "$passlist" 2>/dev/null || echo "0")
            echo -e "${GREEN}✓ Found $pass_count passwords${NC}"
            break
        done

        # Step 6: Basic options
        echo -e "\n${GREEN}Step 6: Attack Options${NC}"

        threads=$(simple_input "Number of parallel threads (1-16)" "4")
        if ! [[ "$threads" =~ ^[0-9]+$ ]] || (( threads < 1 )) || (( threads > 16 )); then
            threads=4
            echo -e "${YELLOW}Using default: 4 threads${NC}"
        fi

        timeout=$(simple_input "Connection timeout in seconds (5-60)" "10")
        if ! [[ "$timeout" =~ ^[0-9]+$ ]] || (( timeout < 5 )) || (( timeout > 60 )); then
            timeout=10
            echo -e "${YELLOW}Using default: 10 seconds${NC}"
        fi

        # SSL option for HTTPS
        ssl=false
        if [ "$service" = "https" ]; then
            ssl=true
            echo -e "${YELLOW}SSL/TLS enabled for HTTPS${NC}"
        else
            if ask_yes_no "Use SSL/TLS encryption?" "n"; then
                ssl=true
            fi
        fi

        # Output file
        echo -e "\n${GREEN}Step 7: Output Options${NC}"
        if ask_yes_no "Save results to a file?" "n"; then
            output_file=$(simple_input "Output filename" "bruteforce_results.txt")
        else
            output_file=""
        fi

        # Show summary and confirm
        echo -e "\n${GREEN}=== Attack Summary ===${NC}"
        echo -e "${YELLOW}Target:${NC} $target"
        echo -e "${YELLOW}Service:${NC} $service"
        echo -e "${YELLOW}Port:${NC} $port"
        echo -e "${YELLOW}Usernames:${NC} $user_count entries from $userlist"
        echo -e "${YELLOW}Passwords:${NC} $pass_count entries from $passlist"
        echo -e "${YELLOW}Threads:${NC} $threads"
        echo -e "${YELLOW}Timeout:${NC} $timeout seconds"
        echo -e "${YELLOW}SSL/TLS:${NC} $([ "$ssl" = true ] && echo "Yes" || echo "No")"
        echo -e "${YELLOW}Output file:${NC} ${output_file:-"None (display only)"}"

        total_attempts=$((user_count * pass_count))
        echo -e "${YELLOW}Total attempts:${NC} $total_attempts"

        echo -e "\n${RED}⚠ WARNING: Only use this against systems you own or have permission to test!${NC}"

        if ask_yes_no "Start the brute force attack?" "n"; then
            run_hydra
            break
        else
            echo -e "${YELLOW}Attack cancelled.${NC}"
            if ! ask_yes_no "Configure a new attack?" "y"; then
                break
            fi
        fi
    done
}

# Function to show help
show_help() {
    echo -e "${GREEN}WetMonkey BruteForce Module v${VERSION}${NC}"
    echo ""
    echo -e "${CYAN}Usage:${NC} $0 [OPTIONS]"
    echo ""
    echo -e "${CYAN}Options:${NC}"
    echo "  -h, --help                    Show this help message"
    echo "  -t, --target HOST             Target hostname or IP address"
    echo "  -s, --service SERVICE         Service to attack (ssh, ftp, http-get, etc.)"
    echo "  -p, --port PORT               Port number (default: service default)"
    echo "  -U, --userlist FILE           Username wordlist file"
    echo "  -P, --passlist FILE           Password wordlist file"
    echo "  -T, --threads NUM             Number of threads (default: 4)"
    echo "  -w, --timeout SEC             Connection timeout (default: 10)"
    echo "  -S, --ssl                     Use SSL/TLS"
    echo "  -o, --output FILE             Save results to file"
    echo "  --non-interactive             Run without prompts (fails if required args missing)"
    echo ""
    echo -e "${YELLOW}Interactive Mode:${NC}"
    echo "  $0              # Guided step-by-step setup"
    echo ""
    echo -e "${YELLOW}Non-Interactive Mode:${NC}"
    echo "  $0 -t 192.168.1.100 -s ssh -U users.txt -P passwords.txt"
    echo "  $0 --target example.com --service ftp --userlist /path/to/users.txt --passlist /path/to/passwords.txt --threads 8"
    echo ""
    echo -e "${BLUE}Supported services:${NC} ssh, ftp, http-get, http-post, https, rdp, smb, mysql, mssql, postgres, telnet"
    echo ""
    echo -e "${RED}Note:${NC} This tool requires hydra to be installed."
    echo "      Use only for authorized penetration testing!"
}

# Parse command line arguments
if [[ $# -gt 0 ]]; then
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Use -h for help."
            exit 1
            ;;
    esac
fi

# Check if hydra is installed
if ! command -v hydra &> /dev/null; then
    echo -e "${RED}Error: hydra is not installed. Please install it first.${NC}"
    exit 1
fi

# Start interactive mode
interactive_mode
