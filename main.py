from scapy.all import conf, IFACES
import ethernet_protocol
import arp_protocol

def sniffer(sock, iface : str) -> None:
    """
    Sniffes given interface, parsing using my protocol functions.
    """
    my_interface = IFACES.get(iface)
    if my_interface is None:
        return
    my_mac : str | None = my_interface.mac
    if my_mac is None:
        return

    my_numeric_mac : bytes = ethernet_protocol.numeric_mac(my_mac)
    while True: 
        raw_frame = sock.recv_raw()
        if raw_frame[1] is None:
            continue
        ethernet_data = ethernet_protocol.ethernet_protcol(raw_frame[1], my_numeric_mac, False)
        if ethernet_data is None:
            continue
        dispatch_ethernet(ethernet_data[0], ethernet_data[1], ethernet_data[2])


def dispatch_ethernet(data : bytes, src_mac : bytes, eth_type : bytes) -> None:
    """
    Dispatches the next protocol, based on the eth_type and data.
    """
    if eth_type == ethernet_protocol.ARP_TYPE:
         arp_protocol.arp_protcol(data, src_mac)


def main() -> None:
    #IFACES.show()

    iface = "wlo1"

    sock = conf.L2socket(iface=iface, promisc=True)
    sniffer(sock, iface)


if __name__ == "__main__":
    main()
