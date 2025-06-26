

def handle_ip(payload : bytes, my_mac : bytes, my_ip : bytes) -> Optional[Tuple[bytes, bytes]]:

    """
    Implements the ip protocol, including parsing of arp requests & responses,
    and responding to those request (Dummy response not to break my network).

    @param parload: The raw data from the above level to parse. (AKA from ethernet)
    @param my_mac:   My own mac, used to check.
    @return:         The destenation to replay to, and the arp replay, if one is needed.
    """


