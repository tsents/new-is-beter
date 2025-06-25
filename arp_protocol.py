import struct
from typing import Optional, Tuple
from utilities import pretty_ip
from utilities import pretty_mac


HEADER_BASE = "!HHBBH" #Hardware type | protocol type | hardware length | protocol length | operation
BASE_LEN = 8
OPERATION_REQUEST = 1
OPERATION_REPLY = 2
ETHERNET_TYPE = 1
IP_PROTOCOL = 0x0800
OPERATION_OFFSET = 6

def parse_arp(raw_data : bytes, my_mac : bytes) -> Optional[Tuple[bytes, bytes]]:
    """
    Implements the arp protocol, including parsing of arp requests & responses,
    and responding to those request (Dummy response not to break my network).

    @param raw_data: The raw data from the above level to parse. (AKA from ethernet)
    @param my_mac:   My own mac, used to check.
    """
    hardware_type, protocol, hardware_length, protocol_length, operation = struct.unpack_from(HEADER_BASE, raw_data)
    data_protocol = (str(hardware_length) + "s" + str(protocol_length) + "s") * 2
    src_hardware, src_net, resolve_hardware, resolve_net = struct.unpack_from(data_protocol, raw_data, BASE_LEN)
    # WARNINGS DEFINITIONS
    if hardware_type != ETHERNET_TYPE:
        print(f"WARNING: Unexpected packet, Hardware type is not Ethernet {hardware_type}")
        return None
    if protocol != IP_PROTOCOL:
        print(f"WARNING: Unexpected packet, protocol type is not IP {protocol}")
        return None
    # PRINT TRAFFIC
    if operation == OPERATION_REPLY:
        print(f"Tell {pretty_ip(resolve_net)} on {pretty_mac(resolve_hardware)}, that {pretty_ip(src_net)} is at {pretty_mac(src_hardware)}")
        return None
    elif operation == OPERATION_REQUEST:
        print(">>>>>>>>>")
        print(f"Who has {pretty_ip(resolve_net)}, tell {pretty_ip(src_net)} at {pretty_mac(src_hardware)}")
        arp_response = raw_data[:OPERATION_OFFSET]
        arp_response += struct.pack("!H",OPERATION_REPLY)
        arp_response += my_mac + resolve_net
        arp_response += src_hardware + src_net
        print(len(arp_response), len(raw_data))
        print("Possible arp response:")
        parse_arp(arp_response, my_mac)
        print("<<<<<<<<<\n")
        # return arp_response, src_hardware
    return None

