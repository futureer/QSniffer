import threading, dpkt, socket
from PyQt4.QtCore import QString
from PyQt4.QtGui import QTreeWidgetItem

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
        
    def updateStatistics(self, window):
        window.totalCountLabel.setText(QString(str(self.total)))
        window.arpCountLabel.setText(QString(str(self.arp)))
        window.rarpCountLabel.setText(QString(str(self.rarp)))
        window.ipCountLabel.setText(QString(str(self.ip)))
        window.ipv6CountLabel.setText(QString(str(self.ipv6)))
        window.tcpCountLabel.setText(QString(str(self.tcp)))
        window.udpCountLabel.setText(QString(str(self.udp)))
        window.icmpCountLabel.setText(QString(str(self.icmp)))
        window.igmpCountLabel.setText(QString(str(self.igmp)))
        window.icmpv6CountLabel.setText(QString(str(self.icmpv6)))
        window.othersCountLabel.setText(QString(str(self.unknown)))
        window.errorCountLabel.setText(QString(str(self.error)))

class PktItem():
    def __init__(self):
        self.rawpkt = None
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

class PktList():
    def __init__(self):
        self.pktlist = []
        self.mutex = threading.Lock()
    def clear(self):
        del self.pktlist[:]

class PktContent():
    def __init__(self):
        pass
    @staticmethod
    def pkt0xContent(pktdata):
        content = ''
        for i, c in enumerate(pktdata):
            content += '%-3.2x' % ord(c)
            if i % 8 == 7:
                content += '\n'
        return content
    
    @staticmethod
    def pktAsciiContent(pktdata):
        content = ''
        for i, c in enumerate(pktdata):
            if ord(c) < 0x20 or ord(c) > 0x7e:
                c = '.'
            content += '%c' % ord(c)
            if i % 8 != 7:
                content += ' '
            else:
                content += '\n'
        return content
            
        

class ProtocolTree():
    def __init__(self, fatherNode, pktdata):
        self.fatherNode = fatherNode
        self.pktdata = pktdata
        self.TreeList = []
        
    def parseProtocol(self):
        frame = dpkt.ethernet.Ethernet(self.pktdata)
        
        self.parseEthernetTree(self.fatherNode, frame)
        
        return self.TreeList
        
        
    def parseEthernetTree(self, fatherNode, frame):
        if frame.__class__.__name__ != 'Ethernet':
            print 'parseTree: error in parseEthernetTree. Classname is %s' % frame.__class__.__name__
            return None
        EthernetTree = QTreeWidgetItem(fatherNode)
        EthernetTree.setText(0, 'Ethernet')
        EthernetTup = (('dst', "Destination: %s" % NetFormat.ntoa_mac(frame.dst)),
                        ('src', "Source: %s" % NetFormat.ntoa_mac(frame.src)),
                        ('type', "Type: 0x%.4x" % frame.type)
                        )
        # TODO: explain the type code
        self.parseDetail(EthernetTree, EthernetTup)
        self.TreeList.append(EthernetTree)
        
        if frame.type == dpkt.ethernet.ETH_TYPE_ARP:
            self.parseARPTree(fatherNode, frame.data)
        elif frame.type == dpkt.ethernet.ETH_TYPE_IP:
            self.parseIPTree(fatherNode, frame.data)
        elif frame.type == dpkt.ethernet.ETH_TYPE_IP6:
            self.parseIPv6Tree(fatherNode, frame.data)
        else:
            self.parseUnknownTree(fatherNode, frame.data)

    def parseARPTree(self, fatherNode, arp):
        ARPTree = QTreeWidgetItem(fatherNode)
        ARPTree.setText(0, 'ARP')
        ARPTup = (('hrd', 'Hardware type: %d' % arp.hrd),
                ('pro', 'Protocol type: %d' % arp.pro),
                ('hln', 'Hardware length: %d' % arp.hln),
                ('pln', 'Protocol length: %d' % arp.pln),
                ('op', 'Opcode: %d' % arp.op),
                ('sha', 'Sender MAC address: %s' % NetFormat.ntoa_mac(arp.sha)),
                ('spa', 'Sender IP address: %s' % NetFormat.ntoa_ip(arp.spa)),
                ('tha', 'Target MAC address: %s' % NetFormat.ntoa_mac(arp.tha)),
                ('tpa', 'Target IP address: %s' % NetFormat.ntoa_ip(arp.tpa))
                )
        
        self.parseDetail(ARPTree, ARPTup)
        self.TreeList.append(ARPTree)

        
    def parseIPTree(self, fatherNode, ip):
        IPTree = QTreeWidgetItem(fatherNode)
        IPTree.setText(0, 'IP')
        IPTup = (('v', 'Version: %d' % ip.v),
                  ('hl', 'Header Length: %d' % (ip.hl << 4)),
                  ('tos', 'Differentiated Services: 0x%.2x' % ip.tos),
                  ('len', 'Total Length: %d' % ip.len),
                  ('id', 'Identification: 0x%.4x' % ip.id),
                  ('flag', 'Flags: 0x%.2x' % (ip.off >> 13)),
                  ('off', 'Fragment Offset: %d' % (ip.off & 0x1fff)),
                  ('ttl', 'Time To Live: %d' % ip.ttl),
                  ('p', 'Protocol: %d' % ip.p),
                  ('sum', 'Header Checksum: 0x%.4x' % ip.sum),
                  ('src', 'Source: %s' % NetFormat.ntoa_ip(ip.src)),
                  ('dst', 'Destination: %s' % NetFormat.ntoa_ip(ip.dst))
                  )
        
        self.parseDetail(IPTree, IPTup)
        self.TreeList.append(IPTree)
        
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            self.parseTCPTree(fatherNode, ip.data)
        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            self.parseUDPTree(fatherNode, ip.data)
        elif ip.p == dpkt.ip.IP_PROTO_ICMP:
            self.parseICMPTree(fatherNode, ip.data)
        elif ip.p == dpkt.ip.IP_PROTO_IGMP:
            self.parseIGMPTree(fatherNode, ip.data)
        else:
            self.parseUnknownTree(fatherNode, ip.data)
        
    
    def parseIPv6Tree(self, fatherNode, ipv6):
        IPv6Tree = QTreeWidgetItem(fatherNode)
        IPv6Tree.setText(0, 'IPv6')
        IPv6Tup = (('v', 'Version: %d' % ipv6.v),
                   ('fc', 'Traffic class: 0x%.8x' % ipv6.fc),
                   ('flow', 'Flow label: 0x%.8x' % ipv6.flow),
                   ('plen', 'Payload length: %d' % ipv6.plen),
                   ('nxt', 'Next header: %d' % ipv6.nxt),
                   ('hlim', 'Hop limit: %d' % ipv6.hlim),
                   ('src', 'Source: %s' % NetFormat.ntoa_ipv6(ipv6.src)),
                   ('dst', 'Destination: %s' % NetFormat.ntoa_ipv6(ipv6.dst))
                   )
        
        self.parseDetail(IPv6Tree, IPv6Tup)
        self.TreeList.append(IPv6Tree)
        
        if ipv6.p == dpkt.ip.IP_PROTO_TCP:
            self.parseTCPTree(fatherNode, ipv6.data)
        elif ipv6.p == dpkt.ip.IP_PROTO_UDP:
            self.parseUDPTree(fatherNode, ipv6.data)
        elif ipv6.p == dpkt.ip.IP_PROTO_ICMP6:
            self.parseICMPv6Tree(fatherNode, ipv6.data)
        else:
            self.parseUnknownTree(fatherNode, ipv6.data)
        
    
    def parseTCPTree(self, fatherNode, tcp):
        TCPTree = QTreeWidgetItem(fatherNode)
        TCPTree.setText(0, 'TCP')
        TCPTup = (('sport', 'Source port: %d' % tcp.sport),
                  ('dport', 'Destination port: %d' % tcp.dport),
                  ('seq', 'Sequence number: %d' % tcp.seq),
                  ('ack', 'Acknowledgment number: %d' % tcp.ack),
                  ('off_x2', 'Header length: %d' % tcp.off),
                  ('flags', 'Flags: 0x%.4x' % tcp.flags),
                  ('win', 'Window Size: %d' % tcp.win),
                  ('sum', 'Checksum: 0x%.4x' % tcp.sum),
                  ('urp', 'Urgent pointer: 0x%.4x' % tcp.urp)
                   )
        
        self.parseDetail(TCPTree, TCPTup)
        self.TreeList.append(TCPTree)
    
    def parseUDPTree(self, fatherNode, udp):
        UDPTree = QTreeWidgetItem(fatherNode)
        UDPTree.setText(0, 'UDP')
        UDPTup = (('sport', 'Source port: %d' % udp.sport),
                  ('dport', 'Destination port: %d' % udp.dport),
                  ('ulen', 'Length: %d' % udp.ulen),
                  ('sum', 'Checksum: 0x%.4x' % udp.sum)
                   )
                  
        self.parseDetail(UDPTree, UDPTup)
        self.TreeList.append(UDPTree)
    
    def parseICMPTree(self, fatherNode, icmp):
        ICMPTree = QTreeWidgetItem(fatherNode)
        ICMPTree.setText(0, 'ICMP')
        ICMPTup = (('type', 'Type: %d' % icmp.type),
                   ('code', 'Code: %d' % icmp.code),
                   ('sum', 'Checksum: 0x%.4x' % icmp.sum)
                    )
        
        self.parseDetail(ICMPTree, ICMPTup)
        self.TreeList.append(ICMPTree)
    
    def parseIGMPTree(self, fatherNode, igmp):
        IGMPTree = QTreeWidgetItem(fatherNode)
        IGMPTree.setText(0, 'IGMP')
        IGMPTup = (('type', 'Type: 0x%.2x' % igmp.type),
                   ('maxresp', 'Max Resp Code: %d' % igmp.maxresp),
                   ('sum', 'Checksum: 0x%.4x' % igmp.sum),
                   ('group', 'Group Address: %d' % igmp.group)
                    )
        
        self.parseDetail(IGMPTree, IGMPTup)
        self.TreeList.append(IGMPTree)
    
    def parseICMPv6Tree(self, fatherNode, icmpv6):
        ICMPv6Tree = QTreeWidgetItem(fatherNode)
        ICMPv6Tree.setText(0, 'ICMPv6')
        ICMPv6Tup = (('type', 'Type: %d' % icmpv6.type),
                     ('code', 'Code: %d' % icmpv6.code),
                     ('sum', 'Checksum: 0x%.4x' % icmpv6.sum)
                      )
        
        self.parseDetail(ICMPv6Tree, ICMPv6Tup)
        self.TreeList.append(ICMPv6Tree)
        
    def parseUnknownTree(self, fatherNode, data):
        UnknownTree = QTreeWidgetItem(fatherNode)
        UnknownTree.setText(0, 'Other parts')
    
    def parseDetail(self, fatherNode, Tuple):
        for t in Tuple:
            node = QTreeWidgetItem(fatherNode)
            node.setText(0, t[1])
    
        
        
class NetFormat():
    def __init__(self):
        pass
    
    @staticmethod
    def ntoa_mac(nmac):
        return '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x' % tuple(map(ord, list(nmac)))
    
    @staticmethod
    def ntoa_ip(nip):
        return '%d.%d.%d.%d' % tuple(map(ord, list(nip)))
    
    @staticmethod
    def ntoa_ipv6(nipv6):
        # TODO: format the ipv6 address
        addr = '%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x' % tuple(map(ord, list(nipv6)))
        return socket.getnameinfo((addr, 0), socket.NI_NUMERICHOST)[0]

