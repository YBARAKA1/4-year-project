import scapy.all as scapy

scapy.conf.iface = "wlan0"
packets = scapy.sniff(count=5)
for packet in packets:
    print(packet.summary())