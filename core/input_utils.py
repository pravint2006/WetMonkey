"""
Common input utilities for WetMonkey modules.
Provides consistent ways to get and validate user input.
"""
import re
import socket
from typing import Tuple, Optional, List, Any, Callable

def is_valid_ip(ip: str) -> bool:
    """Check if the given string is a valid IPv4 address."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def is_valid_hostname(hostname: str) -> bool:
    """Check if the given string is a valid hostname."""
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    allowed = re.compile(r"^(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

def get_valid_input(prompt: str, 
                  validator: Callable[[str], bool],
                  error_msg: str = "Invalid input. Please try again.",
                  default: Any = None) -> str:
    """
    Get input from user with validation.
    
    Args:
        prompt: The prompt to display
        validator: Function that returns True if input is valid
        error_msg: Message to show on invalid input
        default: Default value if user enters empty string
        
    Returns:
        Validated user input
    """
    while True:
        user_input = input(prompt).strip()
        
        # Return default if input is empty and default is provided
        if not user_input and default is not None:
            return str(default)
            
        if not user_input or not validator(user_input):
            print(f"❌ {error_msg}")
            continue
            
        return user_input

def get_target() -> Tuple[str, int]:
    """
    Get a target (hostname/IP) and port from the user.
    
    Returns:
        Tuple of (host, port)
    """
    print("\n=== Target Selection ===")
    
    # Get host
    host = get_valid_input(
        "Enter target hostname or IP: ",
        lambda x: is_valid_ip(x) or is_valid_hostname(x),
        "Please enter a valid IP address or hostname"
    )
    
    # Get port
    port_str = get_valid_input(
        "Enter port [80]: ",
        lambda x: x.isdigit() and 1 <= int(x) <= 65535,
        "Port must be a number between 1 and 65535",
        "80"
    )
    port = int(port_str)
    
    return host, port

def select_from_menu(options: List[Tuple[str, Any]], 
                   title: str = "Select an option") -> Any:
    """
    Display a menu and get user's selection.
    
    Args:
        options: List of (display_text, return_value) tuples
        title: Menu title
        
    Returns:
        The selected option's return value
    """
    print(f"\n=== {title} ===")
    for i, (text, _) in enumerate(options, 1):
        print(f"{i}. {text}")
    
    while True:
        choice = input("\nEnter your choice: ").strip()
        if not choice.isdigit() or not (1 <= int(choice) <= len(options)):
            print("❌ Invalid choice. Please try again.")
            continue
            
        return options[int(choice)-1][1]  # Return the associated value
