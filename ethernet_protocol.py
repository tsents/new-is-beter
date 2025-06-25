import struct
from typing import Optional, Tuple

ETH_PROTOCOL="!6s6sH"
HEADER_SIZE = 14
BROADCAST = b"\xff\xff\xff\xff\xff\xff"

def raw_mac(mac : str) -> bytes:
    """
    Convert mac from string format 0c:fa:78:54:32:12 to bytes.
    """
    return bytes(int(mac[i:i + 2], 16) for i in range(0, len(mac), 3))

def pretty_mac(raw_mac : bytes) -> str:
    """
    Convert mac form raw bytes format, into ff:ff:ff:.. format.
    """
    return ":".join(hex(i)[2:] for i in raw_mac)

def parse_ethernet(raw_frame : bytes, my_mac : bytes, promisc : bool) -> Optional[Tuple[bytes, bytes, int]]:
    """
    Parses raw bytes (raw_frame) into payload, src_mac, and ether_type.
    Additionaly, it checks if the frame has the currect destination based on
    the mode (promisc) and its own mac.

    @param raw_frame:   Raw bytes given to parse.
    @param my_mac:      The interface mac, used to check vs the mac of the frame.
    @param promisc:     Choose if throw the frame if mac doesn't match
    @return:            The payload, src_mac of the frame, and ether_type field.
    """
    dst_mac, src_mac, ether_type = struct.unpack(ETH_PROTOCOL, raw_frame[:HEADER_SIZE])
    if not promisc:
        if not (dst_mac == my_mac or dst_mac == BROADCAST):
            return None
    payload = raw_frame[HEADER_SIZE:]
    return payload, src_mac, ether_type

def craft_ethernet(src_mac : bytes, dst_mac : bytes, payload : bytes, protocol_type : int) -> bytes:
    """
    Crafts an ethernet frame, based on all fields that exist in ethernet.
    """
    return dst_mac + src_mac + struct.pack("!H", protocol_type) + payload
