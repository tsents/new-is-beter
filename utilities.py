


def pretty_ip(raw_ip : bytes) -> str:
    """
    Formats ip bytes from raw format, to *.*.*.* string
    """
    return ".".join([str(i) for i in raw_ip])

def raw_mac(mac : str) -> bytes:
    """
    Convert mac from string format 0c:fa:78:54:32:12 to bytes.
    """
    return bytes.fromhex(mac.replace(":",""))

def pretty_mac(raw_mac : bytes) -> str:
    """
    Convert mac form raw bytes format, into ff:ff:ff:.. format.
    """
    return ":".join(hex(i)[2:] for i in raw_mac)
