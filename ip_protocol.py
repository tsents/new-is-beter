import struct

IP_PROTOCOL = "!2sHH2sBBH4s4s"
# info | length | identification | flags+offest | TTL | PROTO | checksum | src | dst

def handle_ip(payload : bytes, my_ip : bytes) -> Optional[Tuple[bytes, bytes]]:

    """
    Implements the ip protocol, including parsing of ip requests,
    forwarding them to other protocols (TCP/ICMP..) and crafting the responses.

    @param parload: The raw data from the above level to parse. (AKA from ethernet)
    @param my_mac:   My own mac, used to check.
    @return:         The destenation to replay to and the ip payload, if one is needed.
    """
    return None 
