from scapy.all import sniff, IP, TCP, UDP, Ether
from Poto import extract_source_ip, extract_destination_ip, is_tcp_packet, is_udp_packet, is_http_packet, is_icmp_packet, is_dns_packet, extract_source_mac, extract_destination_mac
from scapy.layers.http import HTTP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS
from Mylogo import logo
import time
import sys
from prettytable import PrettyTable
import colorama
from colorama import Fore, Style
import logging

GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
RESET = Style.RESET_ALL
BOLD = Style.BRIGHT

table = PrettyTable()
table.field_names = [f"{BOLD}Type{RESET}", f"{BOLD}Result{RESET}"]

print(logo)

GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
MAGENTA = '\033[95m'
BLUE = '\u001b[34m'
BLACK = '\033[30m'
BROWN = '\033[90m'

logo_printed = False

# Configure logging
logging.basicConfig(filename='packet_log.txt', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def log_packet(packet):
    if IP in packet or IPv6 in packet:
        source_ip = extract_source_ip(packet)
        destination_ip = extract_destination_ip(packet)
        logging.info(f"Details Packet:")
        current_time = time.strftime("%Y-%m-%d %H:%M:%S")
        logging.info(f"Time: {current_time}")
        logging.info(f"Summary: {packet.summary()}")

        data = []

        if IP in packet:
            source_ip = extract_source_ip(packet)
            destination_ip = extract_destination_ip(packet)
            data.append(["Source IP", f"{source_ip}"])
            data.append(["Destination IP", f"{destination_ip}"])
        elif IPv6 in packet:
            source_ip = extract_source_ip(packet)
            destination_ip = extract_destination_ip(packet)
            data.append(["Source IPv6", f"{source_ip}"])
            data.append(["Destination IPv6", f"{destination_ip}"])
        else:
            data.append([f"No IP find?"])

        if Ether in packet:
            source_mac = extract_source_mac(packet)
            destination_mac = extract_destination_mac(packet)
            data.append(["Source MAC Address", f"{source_mac}"])
            data.append(["Destination MAC Address", f"{destination_mac}"])

        table.clear_rows()
        for entry in data:
            table.add_row(entry)

        # Log packet details
        for entry in data:
            logging.info(f"  {entry[0]}: {entry[1]}")


def packet_callback(packet):
    global logo_printed
    if not logo_printed:
        print(logo)
        logo_printed = True

    current_time = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"{GREEN}\nDetails Packet :{RESET}")
    print(f"{YELLOW}Time: {current_time}{RESET}")
    print(f"Summary: {packet.summary()}")

    data = []

    if IP in packet:
        source_ip = extract_source_ip(packet)
        destination_ip = extract_destination_ip(packet)
        data.append([f"{BOLD}Source IP{RESET}", f"{GREEN}{source_ip}{RESET}"])
        data.append([f"{BOLD}Destination IP{RESET}", f"{YELLOW}{destination_ip}{RESET}"])
    elif IPv6 in packet:
        source_ip = extract_source_ip(packet)
        destination_ip = extract_destination_ip(packet)
        data.append([f"{BOLD}Source IPv6{RESET}", f"{GREEN}{source_ip}{RESET}"])
        data.append([f"{BOLD}Destination IPv6{RESET}", f"{YELLOW}{destination_ip}{RESET}"])
    else:
        data.append([f"{BOLD}No IP find?{RESET}", ""])  # Ensure there are two values in this row

    if Ether in packet:
        source_mac = extract_source_mac(packet)
        destination_mac = extract_destination_mac(packet)
        data.append([f"{BOLD}Source MAC Address{RESET}", f"{GREEN}{source_mac}{RESET}"])
        data.append([f"{BOLD}Destination MAC Address{RESET}", f"{YELLOW}{destination_mac}{RESET}"])

    table.clear_rows()
    for entry in data:
        table.add_row(entry)

    print(table)
    time.sleep(0.5)

    # Log packet details
    log_packet(packet)

    if is_tcp_packet(packet):
        source_ip = extract_source_ip(packet)
        destination_ip = extract_destination_ip(packet)
        print(f"{YELLOW}TCP packet from {source_ip} to {destination_ip}{RESET}")
        print(f"{MAGENTA}Source Port: {packet[TCP].sport}{RESET}")
        print(f"{MAGENTA}Destination Port: {packet[TCP].dport}{RESET}\n")
        if is_tcp_packet(packet):
            tcp_payload = bytes(packet[TCP].payload)
        print(f"{RED}TCP Payload (Text):\n{tcp_payload[:500].decode('utf-8', 'ignore')}{RESET}\n")
        payload_hex = ":".join("{:02x}".format(c) for c in tcp_payload)
        print(f"{BROWN}TCP Payload (Hex):\n{payload_hex[:200]}{RESET}\n")

    elif is_udp_packet(packet):
        source_ip = extract_source_ip(packet)
        destination_ip = extract_destination_ip(packet)
        print(f"{BLUE}UDP packet from {source_ip} to {destination_ip}{RESET}")
        if is_udp_packet(packet):
            udp_payload = bytes(packet[UDP].payload)
        print(f"{RED}UDP Payload (Text):\n{udp_payload[:500].decode('utf-8', 'ignore')}{RESET}\n")
        payload_hex = ":".join("{:02x}".format(c) for c in udp_payload)
        print(f"{BROWN}UDP Payload (Hex):\n{payload_hex[:200 ]}{RESET}\n")

    elif is_http_packet(packet):
        source_ip = extract_source_ip(packet)
        destination_ip = extract_destination_ip(packet)
        print(f"{RED}HTTP packet from {source_ip} to {destination_ip}{RESET}")
        if is_http_packet(packet):
            http_payload = bytes(packet[HTTP].payload)
        print(f"{GREEN}HTTP Payload (Text):\n{http_payload[:500].decode('utf-8', 'ignore')}{RESET}\n")
        payload_hex = ":".join("{:02x}".format(c) for c in http_payload)
        print(f"{GREEN}HTTP Payload (Hex):\n{payload_hex[:200 ]}{RESET}\n")

    elif is_icmp_packet(packet):
        source_ip = extract_source_ip(packet)
        destination_ip = extract_destination_ip(packet)
        print(f"{GREEN}ICMP packet from {source_ip} to {destination_ip}{RESET}")

    elif is_dns_packet(packet):
        source_ip = extract_source_ip(packet)
        destination_ip = extract_destination_ip(packet)
        print(f"{RED}DNS packet from {source_ip} to {destination_ip}{RESET}")
        if is_dns_packet(packet):
            dns_payload = bytes(packet[DNS].payload)
        print(f"{GREEN}DNS Payload (Text):\n{dns_payload[:500].decode('utf-8', 'ignore')}{RESET}\n")
        payload_hex = ":".join("{:02x}".format(c) for c in dns_payload)
        print(f"{GREEN}DNS Payload (Hex):\n{payload_hex[:200]}{RESET}\n")

    time.sleep(0.5)

def start_stop_capture():
    while True:
        user_input = input("\033[92mEnter '1.start' to begin packet capture or '2.stop(): \033[0m")
        if user_input.lower() == 'start' or user_input == '1':
            print("\033[92mStarting packet capture...\033[0m")
            filter_expression = ""
            sniff(filter=filter_expression, prn=packet_callback)
        elif user_input.lower() == 'stop' or user_input == '2':
            print("\033[92mStopping packet capture.\033[0m")
            break
        else:
            print("\033[92mInvalid input. Please enter 'start' to begin or 'stop' to stop.\033[0m")
    time.sleep(0.5)

def start_stop_capture_with_logging():
    while True:
        user_input = input("\033[92mEnter '1.start' to begin packet capture or '2.stop() or '3.save': \033[0m")
        if user_input.lower() == 'start' or user_input == '1':
            print("\033[92mStarting packet capture...\033[0m")
            filter_expression = ""
            sniff(filter=filter_expression, prn=packet_callback)
        elif user_input.lower() == 'stop' or user_input == '2':
            print("\033[92mStopping packet capture.\033[0m")
            break
        elif user_input.lower() == 'save' or user_input == '3':
            print("\033[92mSaving logged packets to 'packet_log.txt'.\033[0m")
            logging.shutdown()
            break
        else:
            print("\033[92mInvalid input. Please enter 'start' to begin, 'stop' to stop, or 'save' to save.\033[0m")
    time.sleep(0.5)

try:
    user_input = input("\033[92mDo you want to start packet capture? (1: yes / 2: no): \033[0m")
    if user_input.lower() == '1' or user_input == 'yes' or user_input == 'y':
        start_stop_capture_with_logging()
    elif user_input.lower() == '2' or user_input == 'no' or user_input == 'n':
        print("\033[92mPacket capture is not started. You can start it later again.\033[0m")
except KeyboardInterrupt:
    print("\033[92mExiting the program \nThank you for using.\033[0m")
    sys.exit(0)
