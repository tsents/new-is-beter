import struct
from typing import Optional, Tuple

ETH_PROTOCOL="6s6s2s"
HEADER_SIZE = 14
# VLAN_STRUCT = "h2s"
# VLAN_STRUCT_SIZE = 4
# VLAN_TYPE = b"\x81\x00"
BROADCAST = b"\xff\xff\xff\xff\xff\xff"
ARP_TYPE = b"\x08\x06"

def numeric_mac(mac : str) -> bytes:
    """
    Convert mac from string format 0c:fa:78:54:32:12 to bytes.
    """
    return bytes(int(mac[i:i + 2], 16) for i in range(0, len(mac), 3))

def pretty_mac(raw_mac : bytes) -> str:
    """
    Convert mac form raw bytes format, into ff:ff:ff:.. format.
    """
    return ":".join(hex(i)[2:] for i in raw_mac)

def ethernet_protcol(raw_frame : bytes, my_mac : bytes, promisc : bool) -> Optional[Tuple[bytes, bytes, bytes]]:
    """
    Parses raw bytes (raw_frame) into the packet using ethernet protocol.

    @param raw_frame:   Raw bytes given to parse.
    @param my_mac:      The interface mac, used to check vs the mac of the frame.
    @param promisc:     Choose if throw the frame if mac doesn't match
    @return:            The data if given. 
    """
    dst_mac, src_mac, ether_type = struct.unpack(ETH_PROTOCOL, raw_frame[:HEADER_SIZE])
    if not promisc:
        if not (dst_mac == my_mac or dst_mac == BROADCAST):
            return None
    unparsed_data = raw_frame[HEADER_SIZE:]
    return unparsed_data, src_mac, ether_type

def craft_ethernet(src_mac : bytes, dst_mac : bytes, data : bytes, protocol_type : bytes) -> bytes:
    """
    Crafts an ethernet frame, based on all fields that exist in ethernet.
    """
    return dst_mac + src_mac + protocol_type + data
