from scapy.all import IFACES

def my_mac(interface : str) -> bytes:
    """
    Return the mac address of the interface. in bytes format.
    """
    return bytes_mac(IFACES.get(interface).mac)

def my_ip(interface : str) -> bytes:
    """
    return the ip address of the interface. in bytes format.
    """
    return bytes_ip(IFACES.get(interface).ip)

def bytes_ip(pretty_ip : str) -> bytes:
    """
    Formats ip from *.*.*.* string to network bytes format. 
    """
    return bytes(int(i) for i in pretty_ip.split("."))

def pretty_ip(raw_ip : bytes) -> str:
    """
    Formats ip bytes from network bytes format, to *.*.*.* string
    """
    return ".".join([str(i) for i in raw_ip])

def bytes_mac(mac : str) -> bytes:
    """
    Convert mac from string format 0c:fa:78:54:32:12 to bytes.
    """
    return bytes.fromhex(mac.replace(":",""))

def pretty_mac(raw_mac : bytes) -> str:
    """
    Convert mac form raw bytes format, into ff:ff:ff:.. format.
    """
    return ":".join(hex(i)[2:] for i in raw_mac)
