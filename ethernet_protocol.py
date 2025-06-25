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


def handle_ethernet(raw_frame : bytes, my_mac : bytes, promisc : bool) -> Optional[bytes]:
    """
    Parses raw bytes (raw_frame) into the payload, and the additional fields
    that are in the frame (src_mac, dst_mac, and ether_type).
    Calls dispatch_ethernet for handeling of the frame. 

    @param raw_frame:   Raw bytes given to parse.
    @param my_mac:      The interface mac, used to check vs the mac of the frame.
    @param promisc:     Choose if throw the frame if mac doesn't match
    @return:            The payload if given. 
    """
    dst_mac, src_mac, ether_type = struct.unpack(ETH_PROTOCOL, raw_frame[:HEADER_SIZE])
    if not promisc:
        if not (dst_mac == my_mac or dst_mac == BROADCAST):
            return None
    payload = raw_frame[HEADER_SIZE:]
    return dispatch_ethernet(payload, src_mac, ether_type, my_mac)

def craft_ethernet(src_mac : bytes, dst_mac : bytes, payload : bytes, protocol_type : int) -> bytes:
    """
    Crafts an ethernet frame, based on all fields that exist in ethernet.
    """
    return dst_mac + src_mac + struct.pack("!H",protocol_type) + payload


def dispatch_ethernet(payload : bytes, src_mac : bytes, eth_type : bytes, my_mac : bytes) -> Optional[bytes]:
    """
    Given parsed ethernet frame, calls the functions of the next layers needed,
    and calls "craft_ethernet" if an ethernet response is needed.
    """
    if eth_type == ARP_TYPE:
        response = arp_protocol.parse_arp(payload, my_mac)
        if not response is None:
            response_payload, dst_mac = response
            return craft_ethernet(my_mac, dst_mac, response_payload, ARP_TYPE)
    return 

