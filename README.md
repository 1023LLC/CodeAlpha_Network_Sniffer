# Network Sniffer

This is a Python-based packet sniffing tool built using the **Scapy** library. It allows you to capture packets on a specified network interface and display detailed packet information. You can filter packets by protocol or capture a limited number of packets based on user input.

## Features

- **Interface Selection**: Allows the user to select a network interface for packet sniffing.
- **Protocol Filtering**: Optional filtering of packets by protocol (e.g., TCP, UDP, ICMP).
- **Packet Limit**: Option to specify a limit for the number of packets to capture or run continuously.
- **Detailed Packet Display**: Shows detailed information about captured packets, including protocol-specific details.

## Prerequisites

1. **Python 3.x**: Ensure you have Python installed. You can download it from [here](https://www.python.org/downloads/).
2. **Scapy**: The Python library used for packet sniffing. Install using:
   ```
   pip install scapy
   ```
3. **Npcap (Windows)**: On Windows, you need to install Npcap for packet sniffing. Download and install Npcap from the [official site](https://nmap.org/npcap/). Ensure you enable the "WinPcap API compatibility" option during installation.

## Installation

1. Clone or download this repository.
   ```
   git clone https://github.com/1023LLC/CodeAlpha_Network_Sniffer.git
   ```

2. Navigate to the project directory.
   ```
   cd network-sniffer
   ```

3. Install the required Python dependencies.
   ```
   pip install -r requirements.txt
   ```

## Running the Program

1. Activate the virtual environment if you have one.
   ```
   source venv/bin/activate  # Linux/Mac
   venv\Scripts\activate     # Windows
   ```

2. Run the `sniffer.py` script.
   ```
   python sniffer.py
   ```

3. Follow the on-screen instructions:
   - Select a network interface from the list displayed.
   - Specify the number of packets to sniff (`0` for unlimited).
   - Optionally, filter by a specific protocol (e.g., TCP, UDP, ICMP).
   
   Example:
   ```
   Select the interface you want to sniff on: Wi-Fi
   Enter the number of packets to sniff (0 for unlimited): 5
   Do you wish to filter by a specific protocol? (Y/N) N
   ```

## Output

The program displays detailed information about each captured packet, including protocol-specific details such as headers, flags, and payload.

Example output:

```
###[ Ethernet ]###
  dst       = ff:ff:ff:ff:ff:ff
  src       = 00:0c:29:3d:71:aa
  type      = 0x800
###[ IP ]###
  version   = 4
  ihl       = 5
  tos       = 0x0
  len       = 78
  id        = 12345
  flags     = 
  frag      = 0
  ttl       = 64
  proto     = udp
  chksum    = 0x1b44
  src       = 192.168.1.10
  dst       = 192.168.1.255
...
```

## Dependencies

- **Scapy**: For packet sniffing.
- **Npcap**: Required for sniffing on Windows. Ensure you have it installed for the program to work on Windows platforms.

## Troubleshooting

### Scapy Warning: "No libpcap provider available! pcap won't be used"
- This error indicates that Scapy cannot find **Npcap** or **WinPcap**. Make sure **Npcap** is installed and you have enabled the "WinPcap compatibility" option during installation.

### RuntimeError: "Sniffing and sending packets is not available at layer 2"
- If you encounter this error, make sure Npcap is installed, or switch to using Layer 3 sniffing by modifying the code to use `conf.L3socket = L3RawSocket`.

## License

This project is licensed under the MIT License.

## Contact

For any issues or questions, feel free to reach out to the project author:

- **Email**: nyerereoffice@example.com

