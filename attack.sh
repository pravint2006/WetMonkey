#!/usr/bin/env bash
# wetmonkey V0 – main dispatcher with interactive menus
set -euo pipefail

# Initialize colors for better UI
init_colors() {
    # Check if stdout is a terminal
    if [ -t 1 ]; then
        COLOR_TITLE="\033[1;36m"  # Cyan
        COLOR_MENU="\033[1;37m"   # White
        COLOR_INPUT="\033[1;33m"  # Yellow
        COLOR_ERROR="\033[1;31m"  # Red
        COLOR_SUCCESS="\033[1;32m" # Green
        COLOR_INFO="\033[1;34m"   # Blue
        COLOR_OPTION="\033[1;35m" # Purple
        RESET="\033[0m"
        BOLD="\033[1m"
    else
        # No colors if not a terminal
        COLOR_TITLE=""
        COLOR_MENU=""
        COLOR_INPUT=""
        COLOR_ERROR=""
        COLOR_SUCCESS=""
        COLOR_INFO=""
        COLOR_OPTION=""
        RESET=""
        BOLD=""
    fi
}

# Initialize colors
init_colors

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$BASE_DIR/modules"

# Build an indexed array of module names for UI purposes
modules=()
for d in "$MODULE_DIR"/*/; do
    [[ -d "$d" ]] || continue
    modules+=("$(basename "$d")")
done

# shellcheck source=core/utils.sh
[[ -f "$BASE_DIR/core/utils.sh" ]] && source "$BASE_DIR/core/utils.sh"

# Function to display a header
show_header() {
    clear
    echo -e "${COLOR_TITLE}===== WetMonkey Network Testing Toolkit =====${RESET}\n"
    if [ -n "$CURRENT_MODULE" ]; then
        echo -e "${COLOR_INFO}Module: ${COLOR_SUCCESS}${CURRENT_MODULE}${RESET}"
        echo -e "${COLOR_INFO}Target: ${COLOR_INPUT}${CURRENT_TARGET:-Not set}${RESET}"
        echo -e "${COLOR_INFO}Port:   ${COLOR_INPUT}${CURRENT_PORT:-Not set}${RESET}"
        echo -e "${COLOR_INFO}Status: ${COLOR_SUCCESS}Ready${RESET}\n"
    fi
}

# Function to show the main module menu
show_module_menu() {
    while true; do
        CURRENT_MODULE=""
        show_header
        
        # Print welcome message on first run
        if [ -z "${FIRST_RUN:-}" ]; then
            echo -e "${COLOR_TITLE}╔══════════════════════════════════════════╗"
            echo -e "║    🐒 ${BOLD}WetMonkey Network Testing Toolkit${RESET}${COLOR_TITLE}    ║"
            echo -e "╚══════════════════════════════════════════╝${RESET}\n"
            echo -e "${COLOR_MENU}This toolkit provides various network testing modules."
            echo -e "Select a module to get started or press 0 to exit.\n"
            echo -e "${COLOR_ERROR}⚠  WARNING: For educational and authorized testing only!${RESET}\n"
            FIRST_RUN=1
        fi
        
        # Print module categories
        echo -e "${COLOR_TITLE}📦 Available Modules:${RESET}\n"
        
        # Split modules into two columns (9 in first column, 8 in second)
        local total_modules=${#modules[@]}
        local mid_point=9  # First column shows 9 modules
        
        # Print column headers
        printf "${COLOR_OPTION}%-3s %-2s %-20s %-25s" "" "" "Module" "Description"
        printf "${COLOR_OPTION}%-3s %-2s %-20s %s\n" "" "" "Module" "Description"
        echo -e "${COLOR_MENU}─────────────────────────────────────────────────────────────────────────────${RESET}"
        
        # Print modules in two columns
        for ((i=0; i<mid_point; i++)); do
            # First column module
            local m1="${modules[i]}"
            local emoji1="🔹" desc1="Generic module"
            
            # Set emoji and description for first column module
            case "$m1" in
                "bruteforce")
                    emoji1="🔑"; desc1="Password testing" ;;
                "dataexfiltration")
                    emoji1="📤"; desc1="Data exfiltration" ;;
                "ddos")
                    emoji1="💥"; desc1="DDoS simulation" ;;
                "dnstunnel")
                    emoji1="🌐"; desc1="DNS tunneling" ;;
                "dnszonetransfer")
                    emoji1="🔄"; desc1="DNS zone transfer" ;;
                "exploitation")
                    emoji1="💉"; desc1="Vulnerability testing" ;;
                "geoipanomaly")
                    emoji1="🌍"; desc1="GeoIP analysis" ;;
                "httpheaderabuse")
                    emoji1="📋"; desc1="HTTP header abuse" ;;
                "malwarebeacon")
                    emoji1="📡"; desc1="Malware beaconing" ;;
                "malwaredrop")
                    emoji1="💾"; desc1="Malware dropper" ;;
                "osfingerprint")
                    emoji1="🔍"; desc1="OS fingerprinting" ;;
                "packetcraft")
                    emoji1="📦"; desc1="Packet crafting" ;;
                "portscan")
                    emoji1="🔍"; desc1="Port scanning" ;;
                "torproxy")
                    emoji1="🧅"; desc1="Tor proxy testing" ;;
                "unknownproto")
                    emoji1="🔍"; desc1="Protocol analysis" ;;
                "urlobfuscation")
                    emoji1="🔗"; desc1="URL obfuscation" ;;
                "webrecon")
                    emoji1="🌐"; desc1="Web reconnaissance" ;;
                *)
                    emoji1="🔹"; desc1="Generic module" ;;
            esac
            
            # Second column module (if exists)
            local col2=""
            local idx2=$((i + mid_point))
            if [ $idx2 -lt $total_modules ]; then
                local m2="${modules[idx2]}"
                local emoji2="🔹" desc2="Generic module"
                
                # Set emoji and description for second column module
                case "$m2" in
                    "bruteforce")
                        emoji2="🔑"; desc2="Password testing" ;;
                    "dataexfiltration")
                        emoji2="📤"; desc2="Data exfiltration" ;;
                    "ddos")
                        emoji2="💥"; desc2="DDoS simulation" ;;
                    "dnstunnel")
                        emoji2="🌐"; desc2="DNS tunneling" ;;
                    "dnszonetransfer")
                        emoji2="🔄"; desc2="DNS zone transfer" ;;
                    "exploitation")
                        emoji2="💉"; desc2="Vulnerability testing" ;;
                    "geoipanomaly")
                        emoji2="🌍"; desc2="GeoIP analysis" ;;
                    "httpheaderabuse")
                        emoji2="📋"; desc2="HTTP header abuse" ;;
                    "malwarebeacon")
                        emoji2="📡"; desc2="Malware beaconing" ;;
                    "malwaredrop")
                        emoji2="💾"; desc2="Malware dropper" ;;
                    "osfingerprint")
                        emoji2="🔍"; desc2="OS fingerprinting" ;;
                    "packetcraft")
                        emoji2="📦"; desc2="Packet crafting" ;;
                    "portscan")
                        emoji2="🔍"; desc2="Port scanning" ;;
                    "torproxy")
                        emoji2="🧅"; desc2="Tor proxy testing" ;;
                    "unknownproto")
                        emoji2="🔍"; desc2="Protocol analysis" ;;
                    "urlobfuscation")
                        emoji2="🔗"; desc2="URL obfuscation" ;;
                    "webrecon")
                        emoji2="🌐"; desc2="Web reconnaissance" ;;
                    *)
                        emoji2="🔹"; desc2="Generic module" ;;
                esac
                
                col2=$(printf "${COLOR_OPTION}%2d) ${emoji2} %-15s ${COLOR_MENU}%-20s" "$((idx2+1))" "$m2" "$desc2")
            fi
            
            # Print the row
            printf "${COLOR_OPTION}%2d) ${emoji1} %-15s ${COLOR_MENU}%-20s${RESET} %s\n" \
                   "$((i+1))" "$m1" "$desc1" "$col2"
        done
        
        # Add footer with version and help
        echo -e "\n${COLOR_INFO}┌──────────────────────────────────────────┐"
        echo -e "│ ${COLOR_MENU}Enter module number to select${RESET}${COLOR_INFO}           │"
        echo -e "│ ${COLOR_MENU}Type '0' or 'q' to exit${RESET}${COLOR_INFO}                 │"
        echo -e "└──────────────────────────────────────────┘${RESET}"
        
        # Get user input with a clean prompt
        echo -ne "\n> "
        read -r sel
        
        # Handle input
        if [[ -z "$sel" ]]; then
            continue
        elif [[ "$sel" == "0" || "$sel" == "q" || "$sel" == "exit" ]]; then
            echo -e "\n${COLOR_INFO}Thank you for using WetMonkey!${RESET}\n"
            exit 0
        elif [[ "$sel" =~ ^[0-9]+$ ]] && (( sel > 0 && sel <= ${#modules[@]} )); then
            CURRENT_MODULE="${modules[$((sel-1))]}"
            echo -e "\n${COLOR_INFO}Loading ${CURRENT_MODULE}...${RESET}"
            sleep 0.5
            show_module_options "${modules[$((sel-1))]}"
        else
            echo -e "\n${COLOR_ERROR}✗ Invalid selection: '$sel'${RESET}"
            echo -e "${COLOR_MENU}Please enter a number between 1 and ${#modules[@]}.${RESET}"
            sleep 1.5
        fi
    done
}

# Function to show module options and handle input
show_module_options() {
    local module="$1"
    local module_path="$MODULE_DIR/$module/run.sh"
    
    if [[ ! -x "$module_path" ]]; then
        echo -e "\n${COLOR_ERROR}Error: Module '$module' not found or not executable.${RESET}\n"
        sleep 1
        return 1
    fi
    
    # Get module help
    local help_text
    help_text=$("$module_path" -h 2>&1 || true)
    
    while true; do
        show_header
        
        # Module header with emoji
        local emoji="🔧"
        [[ "$module" == *"ddos"* ]] && emoji="💥"
        [[ "$module" == *"scan"* ]] && emoji="🔍"
        [[ "$module" == *"brute"* ]] && emoji="🔑"
        [[ "$module" == *"exploit"* ]] && emoji="💉"
        
        echo -e "${COLOR_TITLE}Module: ${COLOR_SUCCESS}${emoji} ${module}${RESET}\n"
        
        # Display module help (modules now handle their own formatting)
        echo -e "${COLOR_INFO}=== Module Help ===${RESET}"
        echo -e "${help_text}\n"
        
        # Display menu options
        echo -e "${COLOR_INFO}=== Actions ===${RESET}"
        echo -e "  ${COLOR_OPTION}1)${RESET} Run module"
        echo -e "  ${COLOR_OPTION}2)${RESET} View module code"
        echo -e "  ${COLOR_OPTION}0)${RESET} Back to main menu\n"
        
        echo -ne "${COLOR_INPUT}❯ ${RESET}"
        read -r choice
        
        case "$choice" in
            1)
                echo -e "\n${COLOR_INFO}Enter the required parameters:${RESET}"
                echo -e "${COLOR_MENU}Example: -t 127.0.0.1 --ports 1-1000${RESET}"
                echo -ne "${COLOR_INPUT}Parameters: ${RESET}"
                read -r cmd_args
                
                echo -e "\n${COLOR_INFO}Running: ${COLOR_SUCCESS}${module} ${cmd_args}${RESET}\n"
                # Execute the module with error handling
                echo -e "\n${COLOR_INFO}Executing module...${RESET}\n"
                set +e  # Allow errors for command execution
                "$module_path" $cmd_args
                local exit_code=$?
                set -e  # Re-enable error checking
                
                echo -e "\n"
                if [ $exit_code -eq 0 ]; then
                    echo -e "${COLOR_SUCCESS}✓ Module execution completed successfully.${RESET}"
                else
                    echo -e "${COLOR_ERROR}✗ Module execution failed with exit code $exit_code.${RESET}"
                fi
                
                echo -e "\n${COLOR_MENU}Press Enter to return to the module menu...${RESET}"
                read -r
                ;;
            2)
                # View module code
                show_header
                echo -e "${COLOR_TITLE}Module Code: ${COLOR_SUCCESS}${module}${RESET}\n"
                
                if command -v bat &> /dev/null; then
                    bat --style=numbers --color=always "$module_path"
                else
                    echo -e "${COLOR_INFO}Tip: Install 'bat' for syntax highlighting${RESET}\n"
                    # Use less if available, otherwise use cat
                    if command -v less &> /dev/null; then
                        less -R "$module_path"
                    else
                        cat -n "$module_path"
                    fi
                fi
                echo -e "\n${COLOR_MENU}Press Enter to return to the module menu...${RESET}"
                read -r
                ;;
            0|q)
                return
                ;;
            *)
                echo -e "${RED}Invalid choice. Please try again.${NC}"
                sleep 1
                ;;
        esac
    done
}

# Main execution
if [[ $# -eq 0 ]]; then
    # Interactive mode
    show_module_menu
    exit 0
else
    # Command-line mode
    COMMAND="$1"; shift || true
    
    case "$COMMAND" in
        list)
            echo "Available modules:"
            i=1
            for m in "${modules[@]}"; do
                echo " $i) $m"
                i=$((i+1))
            done
            exit 0
            ;;
        run)
            MODULE_INPUT="${1:-}"; shift || true
            if [[ -z "$MODULE_INPUT" ]]; then
                echo "Usage: $0 run <module|number> [module-args]" >&2
                echo "       $0" >&2
                echo "       $0 list" >&2
                exit 1
            fi
            # Allow numeric selection
            if [[ "$MODULE_INPUT" =~ ^[0-9]+$ ]]; then
                idx=$((MODULE_INPUT-1))
                if (( idx < 0 || idx >= ${#modules[@]} )); then
                    echo "Invalid module number" >&2; exit 1
                fi
                MODULE="${modules[$idx]}"
            else
                MODULE="$MODULE_INPUT"
            fi
            MODULE_PATH="$MODULE_DIR/$MODULE/run.sh"
            if [[ ! -x "$MODULE_PATH" ]]; then
                echo "Module '$MODULE' not found or not executable." >&2; exit 1
            fi
            "$MODULE_PATH" "$@"
            exit $?
            ;;
        -h|--help|help)
            cat <<EOF
WetMonkey V0 - Network Anomaly Testing Toolkit

Usage:
  $0 [command] [options]

Commands:
  list                 List available modules
  run <module> [...]   Execute module with its own flags
  (no command)         Start interactive mode

Examples:
  $0 list
  $0 run portscan -t 127.0.0.1 --ports 1-1000
  $0  # Start interactive mode

For module-specific help, run: $0 run <module> -h
EOF
            exit 0
            ;;
        *)
            echo "Unknown command: $COMMAND" >&2
            echo "Try '$0 --help' for more information." >&2
            exit 1
            ;;
    esac
fi
