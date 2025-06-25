import struct
from ip_protocol import pretty_ip
from ethernet_protocol import pretty_mac


HEADER_BASE = "!HHBBH" #Hardware type | protocol type | hardware length | protocol length | operation
BASE_LEN = 8
OPERATION_REQUEST = 1
OPERATION_REPLY = 2
ETHERNET_TYPE = 1
IP_PROTOCOL = 0x0800

def arp_protcol(raw_frame : bytes, from_src : bytes) -> None:
    """
    parses arp protocol, can be used over more then IP, but used mostly for IP.
    """
    hardware_type, protocol, hardware_length, protocol_length, operation = struct.unpack_from(HEADER_BASE, raw_frame)
    data_protocol = (str(hardware_length) + "s" + str(protocol_length) + "s") * 2
    src_hardware, src_net, resolve_hardware, resolve_net = struct.unpack_from(data_protocol, raw_frame, BASE_LEN)
    # WARNINGS DEFINITIONS
    if hardware_type != ETHERNET_TYPE:
        print(f"WARNING: Unexpected packet, Hardware type is not Ethernet {hardware_type}")
    if protocol != IP_PROTOCOL:
        print(f"WARNING: Unexpected packet, protocol type is not IP {protocol}")

    # PRINT TRAFFIC
    if operation == OPERATION_REQUEST:
        print(f"Who has {pretty_ip(resolve_net)}, tell {pretty_ip(src_net)} at {pretty_mac(src_hardware)}")
    if operation == OPERATION_REPLY:
        print(f"Tell {pretty_ip(resolve_net)} on {resolve_hardware}, that {pretty_ip(src_net)} is at {src_hardware}")

