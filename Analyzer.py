from winpcapy import pcap_pkthdr
import time, inspect, dpkt

class Analyer():
    def __init__(self):
        self.statistics = Statistics()
        
    def analize(self, pkt):
        header, data = pkt
        
        pktItem = PktItem()
        pktItem.link = header
        pktItem.data = data
        
        frame = dpkt.ethernet.Ethernet(data)
        
        self.handle_frame(pktItem, header, frame)
        
        if frame.type == dpkt.ethernet.ETH_TYPE_ARP:
            self.handle_arp(pktItem, frame.data)
        elif frame.type == dpkt.ethernet.ETH_TYPE_IP:
            self.handle_ip(pktItem, frame.data)
        elif frame.type == dpkt.ethernet.ETH_TYPE_IP6:
            self.handle_ipv6(pktItem, frame.data)
        else:
            self.handle_unknown(pktItem,frame.data)
        return pktItem
        
    def handle_frame(self, pktItem, header, frame):
        local_tv_sec = header.ts.tv_sec
        ltime = time.localtime(local_tv_sec);
        pktItem.time = time.strftime("%H:%M:%S", ltime) # time
        
        pktItem.len = header.len    # length
        
        pktItem.protocol = 'Ethernet'   # protocol
        pktItem.src_mac = self.ntoa_mac(frame.src)  # src_mac
        pktItem.dst_mac = self.ntoa_mac(frame.dst)  # dst_mac
        
        self.statistics.total += 1
    
    def handle_arp(self, pktItem, data):
        if data.op == dpkt.arp.ARP_OP_REQUEST:
            pktItem.protocol = 'ARP'
            self.statistics.arp += 1
        elif data.op == dpkt.arp.ARP_OP_REPLY:
            pktItem.protocol = 'ARP'
            self.statistics.arp += 1
        elif data.op == dpkt.arp.ARP_OP_REVREQUEST:
            pktItem.protocol = 'RARP'
            self.statistics.rarp += 1
        elif data.op == dpkt.arp.ARP_OP_REVREPLY:
            pktItem.protocol = 'RARP'
            self.statistics.rarp += 1
        else:
            self.handle_error(pktItem)
    
    def handle_ip(self, pktItem, data):
        pktItem.src_ip = self.ntoa_ip(data.src)
        pktItem.dst_ip = self.ntoa_ip(data.dst)
        pktItem.protocol = 'IP'
        if data.p == dpkt.ip.IP_PROTO_TCP:
            self.handle_tcp(pktItem, data.data)
        elif data.p == dpkt.ip.IP_PROTO_UDP:
            self.handle_udp(pktItem, data.data)
        elif data.p == dpkt.ip.IP_PROTO_ICMP:
            self.handle_icmp(pktItem, data.data)
        elif data.p == dpkt.ip.IP_PROTO_IGMP:
            self.handle_igmp(pktItem, data.data)
        else:
            self.handle_unknown(pktItem, data.data)
    
    def handle_ipv6(self, pktItem, data):
        pktItem.src_ip = self.ntoa_ipv6(data.src)
        pktItem.dst_ip = self.ntoa_ipv6(data.dst)
        pktItem.protocol = 'IPv6'
        if data.p == dpkt.ip.IP_PROTO_TCP:
            self.handle_tcp(pktItem, data.data)
        elif data.p == dpkt.ip.IP_PROTO_UDP:
            self.handle_udp(pktItem, data.data)
        elif data.p == dpkt.ip.IP_PROTO_ICMP6:
            self.handle_icmp(pktItem, data.data)
        else:
            self.handle_unknown(pktItem, data.data)
    
    def handle_tcp(self, pktItem, data):
        pktItem.src_port = data.sport
        pktItem.dst_port = data.dport
        pktItem.protocol = "TCP"
    
    def handle_udp(self, pktItem, data):
        pktItem.src_port = data.sport
        pktItem.dst_port = data.dport
        pktItem.protocol = "UDP"
    
    def handle_icmp(self, pktItem, data):
        pktItem.protocol = "ICMP"
    
    def handle_igmp(self, pktItem, data):
        pktItem.protocol = "IGMP"
    
    def handle_icmpv6(self,pktItem, data):
        pktItem.protocol = "ICMPv6"
    
    def handle_unknown(self, pktItem, data):
        pktItem.protocol = data.__class__.__name__
        self.statistics.unknown += 1
    
    def handle_error(self, pktItem):
        pktItem.info = 'error occur in %s() while processing the packet' % inspect.stack()[2][3]
        self.statistics.error += 1
    
    def ntoa_mac(self, nmac):
        return '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x' % tuple(map(ord, list(nmac)))
    
    def ntoa_ip(self, nip):
        return '%d.%d.%d.%d' % tuple(map(ord, list(nip)))
    
    def ntoa_ipv6(self, nipv6):
        # TODO: format the ipv6 address
        return '%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x' % tuple(map(ord, list(nipv6)))


class Statistics:
    def __init__(self):
        self.ip = 0
        self.ipv6 = 0
        self.arp = 0
        self.rarp = 0
        self.tcp = 0
        self.udp = 0
        self.icmp = 0
        self.icmpv6 = 0
        self.igmp = 0
        self.error = 0
        self.unknown = 0
        self.total = 0


class PktItem():
    def __init__(self):
        self.link = None
        self.data = None
        self.time = None
        self.len = None
        self.protocol = None
        self.src_mac = None
        self.dst_mac = None
        self.src_ip = None
        self.dst_ip = None
        self.src_port = None
        self.dst_port = None
        self.info = None
        
        
