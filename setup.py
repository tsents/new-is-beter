from scapy.all import conf, IFACES
IFACES.show()

iface = "wlo1"

sock = conf.L2socket(iface=iface, promisc=True)
#recv = sock.recv_raw() 
#sock.send(b"…") 

