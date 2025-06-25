from scapy.all import conf
import ethernet_protocol

def sniffer(sock, iface : str) -> None:
    """
    Sniffes given interface, parsing using my protocol functions.
    """
    while True: 
        raw_frame = sock.recv_raw()
        if raw_frame[1] is None:
            continue
        response = ethernet_protocol.handle_ethernet(raw_frame[1], iface, False)
        if response is not None:
            sock.send(response)



def main() -> None:
    #IFACES.show()

    iface = "wlo1"

    sock = conf.L2socket(iface=iface, promisc=True)
    sniffer(sock, iface)


if __name__ == "__main__":
    main()
