import threading
from PyQt4 import QtCore
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
        window.totalCountLabel.setText(QtCore.QString(str(self.total)))
        window.arpCountLabel.setText(QtCore.QString(str(self.arp)))
        window.rarpCountLabel.setText(QtCore.QString(str(self.rarp)))
        window.ipCountLabel.setText(QtCore.QString(str(self.ip)))
        window.ipv6CountLabel.setText(QtCore.QString(str(self.ipv6)))
        window.tcpCountLabel.setText(QtCore.QString(str(self.tcp)))
        window.udpCountLabel.setText(QtCore.QString(str(self.udp)))
        window.icmpCountLabel.setText(QtCore.QString(str(self.icmp)))
        window.igmpCountLabel.setText(QtCore.QString(str(self.igmp)))
        window.icmpv6CountLabel.setText(QtCore.QString(str(self.icmpv6)))
        window.othersCountLabel.setText(QtCore.QString(str(self.unknown)))
        window.errorCountLabel.setText(QtCore.QString(str(self.error)))

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
