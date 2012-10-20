from winpcapy import pcap_pkthdr
import time, inspect, dpkt
from PyQt4 import QtGui, QtCore
from Util import Statistics, PktItem, NetFormat

class Analyer():
    def __init__(self, pktList, table, window):
        self.statistics = Statistics()
        self.pktList = pktList
        self.table = table  #tablewidget
        self.window = window
        self.itemlist = []
        self.goon = False
        
    def start_analize(self):
        self.goon = True
        while self.goon:
            if len(self.pktList.pktlist) > 0:
                self.pktList.mutex.acquire()
                p = self.pktList.pktlist.pop(0)
                self.pktList.mutex.release()
                
                item = self.analize(p)
                self.itemlist.append(item)
                self.show_item(item)
            else:
                time.sleep(0.01)
            self.statistics.updateStatistics(self.window)
    def stop_analize(self):
        self.goon = False
    def clear(self):
        self.statistics = Statistics()
        self.statistics.updateStatistics(self.window)
        del self.itemlist[:]
    
    def analize(self, pkt):
        header, data = pkt
        pktItem = PktItem()
        pktItem.rawpkt = pkt
        
        frame = dpkt.ethernet.Ethernet(data)
        
        self.handle_frame(pktItem, header, frame)
        
        if frame.type == dpkt.ethernet.ETH_TYPE_ARP:
            self.handle_arp(pktItem, frame.data)
        elif frame.type == dpkt.ethernet.ETH_TYPE_IP:
            self.handle_ip(pktItem, frame.data)
        elif frame.type == dpkt.ethernet.ETH_TYPE_IP6:
            self.handle_ipv6(pktItem, frame.data)
        else:
            self.handle_unknown(pktItem, frame.data)
            print '0x%.4x'%frame.type
        return pktItem
        
    def handle_frame(self, pktItem, header, frame):
        """
        assume that no error occur in the header section
        """
        local_tv_sec = header.ts.tv_sec
        ltime = time.localtime(local_tv_sec);
        pktItem.time = time.strftime("%H:%M:%S", ltime) # time
        
        pktItem.len = header.len    # length
        
        pktItem.protocol = 'Ethernet'   # protocol
        pktItem.src_mac = NetFormat.ntoa_mac(frame.src)  # src_mac
        pktItem.dst_mac = NetFormat.ntoa_mac(frame.dst)  # dst_mac
        
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
        pktItem.src_ip = NetFormat.ntoa_ip(data.src)
        pktItem.dst_ip = NetFormat.ntoa_ip(data.dst)
        pktItem.protocol = 'IP'
        self.statistics.ip += 1
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
        pktItem.src_ip = NetFormat.ntoa_ipv6(data.src)
        pktItem.dst_ip = NetFormat.ntoa_ipv6(data.dst)
        pktItem.protocol = 'IPv6'
        self.statistics.ipv6 += 1
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
        self.statistics.tcp += 1
    
    def handle_udp(self, pktItem, data):
        pktItem.src_port = data.sport
        pktItem.dst_port = data.dport
        pktItem.protocol = "UDP"
        self.statistics.udp += 1
    
    def handle_icmp(self, pktItem, data):
        pktItem.protocol = "ICMP"
        self.statistics.icmp += 1
    
    def handle_igmp(self, pktItem, data):
        pktItem.protocol = "IGMP"
        self.statistics.igmp += 1
    
    def handle_icmpv6(self, pktItem, data):
        pktItem.protocol = "ICMPv6"
        self.statistics.icmpv6 += 1
    
    def handle_unknown(self, pktItem, data):
#        pktItem.protocol = data.__class__.__name__
#        if pktItem.protocol == 'str':
#            pktItem.protocol = 'Unknown'
        self.statistics.unknown += 1
    
    def handle_error(self, pktItem):
        pktItem.info = 'error occur in %s() while processing the packet' % inspect.stack()[2][3]
        self.statistics.error += 1
    

    def show_item(self, item):
#        table = self.pktTableWidget
        row = self.table.rowCount()
        self.table.insertRow(row)
        
        source = item.src_ip
        if source == None:
            source = item.src_mac
        destination = item.dst_ip
        if destination == None:
            destination = item.dst_mac
        
        if item.protocol == 'TCP' or item.protocol == 'UDP':
            source += ':' + str(item.src_port)
            destination += ':' + str(item.dst_port)

        
        No = QtGui.QTableWidgetItem(QtCore.QString(str(row + 1)))
        No.setFlags(No.flags() ^ QtCore.Qt.ItemIsEditable)
        self.table.setItem(row, 0, No)
        
        Time = QtGui.QTableWidgetItem(QtCore.QString(item.time))
        Time.setFlags(Time.flags() ^ QtCore.Qt.ItemIsEditable)
        self.table.setItem(row, 1, Time)
        
        Source = QtGui.QTableWidgetItem(QtCore.QString(source))
        Source.setFlags(Source.flags() ^ QtCore.Qt.ItemIsEditable)
        self.table.setItem(row, 2, Source)
        
        Destination = QtGui.QTableWidgetItem(QtCore.QString(destination))
        Destination.setFlags(Destination.flags() ^ QtCore.Qt.ItemIsEditable)
        self.table.setItem(row, 3, Destination)
        
        Protocol = QtGui.QTableWidgetItem(QtCore.QString(item.protocol))
        Protocol.setFlags(Protocol.flags() ^ QtCore.Qt.ItemIsEditable)
        self.table.setItem(row, 4, Protocol)
        
        Length = QtGui.QTableWidgetItem(QtCore.QString(str(item.len)))
        Length.setFlags(Length.flags() ^ QtCore.Qt.ItemIsEditable)
        self.table.setItem(row, 5, Length)

    
        
