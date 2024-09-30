from scapy.all import sniff
import subprocess
import platform

# ASCII Art Banner
BANNER = """
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$                                                                                                                         $
$   #     #                                                               #####                                           $
$   #  #  # ###### #       ####   ####  #    # ######    #####  ####     #     # #    # # ###### ######    #####  #   #   $
$   #  #  # #      #      #    # #    # ##  ## #           #   #    #    #       ##   # # #      #         #    #  # #    $
$   #  #  # #####  #      #      #    # # ## # #####       #   #    #     #####  # #  # # #####  #####     #    #   #     $
$   #  #  # #      #      #      #    # #    # #           #   #    #          # #  # # # #      #         #####    #     $
$   #  #  # #      #      #    # #    # #    # #           #   #    #    #     # #   ## # #      #      ## #        #     $
$    ## ##  ###### ######  ####   ####  #    # ######      #    ####      #####  #    # # #      #      ## #        #     $
$                                                                                                                         $
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
"""

def main():
    while True:
        display_interfaces()

        interface = get_user_input("Select the interface you want to sniff on: ")
        limit = get_sniff_limit()
        protocol_filter = get_protocol_filter()

        # Sniff based on user input
        sniff_packets(interface, limit, protocol_filter)

        if exit_requested():
            break

def sniff_packets(interface, limit, protocol_filter):
    """Starts the sniffing process based on user input."""
    sniff_kwargs = {"iface": interface, "prn": PcktInfo}
    
    if protocol_filter:
        sniff_kwargs["filter"] = protocol_filter
    if limit > 0:
        sniff_kwargs["count"] = limit
    
    sniff(**sniff_kwargs)

def PcktInfo(packet):
    """Callback function to display packet details."""
    packet.show()

def display_interfaces():
    """Displays available network interfaces based on the OS."""
    if platform.system() == "Windows":
        display_windows_interfaces()
    else:
        display_linux_interfaces()

def display_windows_interfaces():
    """Displays network interfaces on Windows using the 'netsh' command."""
    try:
        result = subprocess.run(['netsh', 'interface', 'show', 'interface'], capture_output=True, text=True, check=True)
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.stderr}")

def display_linux_interfaces():
    """Displays network interfaces on Linux using the 'ip link' command."""
    try:
        result = subprocess.run(['ip', 'link'], capture_output=True, text=True, check=True)
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.stderr}")

def get_user_input(prompt):
    """Helper to get user input with error handling."""
    return input(prompt).strip()

def get_sniff_limit():
    """Prompt the user to specify the number of packets to sniff."""
    while True:
        try:
            limit = int(input("Enter the number of packets to sniff (0 for unlimited): "))
            if limit >= 0:
                return limit
            print("Limit cannot be negative.")
        except ValueError:
            print("Please enter a valid number.")

def get_protocol_filter():
    """Prompt the user if they wish to filter by protocol."""
    answer = get_user_input("Do you wish to filter by a specific protocol? (Y/N) ").lower()
    if answer == "y":
        return get_user_input("Specify the protocol: ")
    return None

def exit_requested():
    """Prompt the user if they wish to exit."""
    answer = get_user_input("Do you want to exit? (Y/N) ").lower()
    return answer == "y"

if __name__ == "__main__":
    print(BANNER)
    main()
