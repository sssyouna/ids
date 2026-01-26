import scapy.all as scapy

if __name__ == "__main__":
    print("Available interfaces:")
    print(scapy.get_if_list())

    p = scapy.sniff(count=1)
    print("Captured packet:")
    p.show()
