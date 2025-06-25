from scapy.all import conf, IFACES
import ethernet_protocol

def sniffer(sock, iface : str) -> None:
    """
    Sniffes given interface, parsing using my protocol functions.
    """
    my_interface = IFACES.get(iface)
    if my_interface is None:
        return
    my_mac = my_interface.mac
    if my_mac is None:
        return

    my_numeric_mac = ethernet_protocol.raw_mac(my_mac)
    while True: 
        raw_frame = sock.recv_raw()
        if raw_frame[1] is None:
            continue
        ethernet_response = ethernet_protocol.parse_ethernet(raw_frame[1], my_numeric_mac, False)
        if ethernet_response is not None:
            payload, src, eth_type = ethernet_response
            print(payload, src, eth_type)


def main() -> None:
    iface = "wlo1"

    sock = conf.L2socket(iface=iface, promisc=True)
    sniffer(sock, iface)


if __name__ == "__main__":
    main()
