import struct
from typing import Optional
import arp_protocol

ETH_PROTOCOL="!6s6sH"
HEADER_SIZE = 14
# VLAN_STRUCT = "h2s"
# VLAN_STRUCT_SIZE = 4
# VLAN_TYPE = b"\x81\x00"
BROADCAST = b"\xff\xff\xff\xff\xff\xff"
ARP_TYPE = 0x0806


def ethernet_protcol(raw_frame : bytes, my_mac : bytes, promisc : bool) -> Optional[bytes]:
    """
    Parses raw bytes (raw_frame) into the packet using ethernet protocol.
    and then calls the next layers.

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
    return dispatch_ethernet(unparsed_data, src_mac, ether_type, my_mac)

def craft_ethernet(src_mac : bytes, dst_mac : bytes, data : bytes, protocol_type : int) -> bytes:
    """
    Crafts an ethernet frame, based on all fields that exist in ethernet.
    """
    return dst_mac + src_mac + struct.pack("!H",protocol_type) + data


def dispatch_ethernet(data : bytes, src_mac : bytes, eth_type : bytes, my_mac : bytes) -> Optional[bytes]:
    """
    Dispatches the next protocol, based on the eth_type and data.
    """
    if eth_type == ARP_TYPE:
        response = arp_protocol.parse_arp(data, my_mac)
        if not response is None:
            response_data, dst_mac = response
            return craft_ethernet(my_mac, dst_mac, response_data, ARP_TYPE)
    return 

