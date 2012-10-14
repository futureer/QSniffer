from ctypes import *
from winpcapy import *
import time
import platform
import copy

if platform.python_version()[0] == "3":
    raw_input = input

errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
header = POINTER(pcap_pkthdr)()
pkt_data = POINTER(c_ubyte)()

class Capturer():
    def __init__(self, pktlist):
        self.pktlist = pktlist      # packet list
        self.devlist = []           # device list
        self.__ispromisc = False      # promisc flag
        self.ifindex = 0            # choosed interface
        self.adhandle = None        # interface handler
        self.filter = ""            # filter string
        self.fcode= bpf_program()   # filter code
        self.goon = True
        self.get_device_list()
    
    def get_device_list(self):
        """ get the device list. return bool to indicate success or not. """
        alldevs = POINTER(pcap_if_t)()
        ## Retrieve the device list
        if (pcap_findalldevs(byref(alldevs), errbuf) == -1):
            print ("Error in pcap_findalldevs: %s\n" % errbuf.value)
            return False

        i = 0
        try:
            d = alldevs.contents
        except:
            print ("Error in pcap_findalldevs: %s" % errbuf.value)
            print ("Maybe you need admin privilege?\n")
            return False
        while d:
            i = i + 1
            self.devlist.append(d)
            if d.next:
                d = d.next.contents
            else:
                d = False
        
        if (i == 0):
            print ("\nNo interfaces found! Make sure WinPcap is installed.\n")
        return True
    
    def print_device_list(self):
        if len(self.devlist) == 0:
            print "No interfaces found!"
        else:
            for i, d in enumerate(self.devlist):
                print("%d. %s" % (i + 1, d.name))
                if (d.description):
                    print (" (%s)\n" % (d.description))
                else:
                    print (" (No description available)\n")
    
    def set_promisc(self, ispromisc = False):
        self.__ispromisc = ispromisc
        print "promisc: %r"%self.__ispromisc
    
    def open_dev(self, ifindex = 0):
        self.ifindex = ifindex
        if(len(self.devlist) == 0):
            print "\nNo device in the device list!\n"
            return False
        if(self.ifindex < 0 or self.ifindex >= len(self.devlist)):
            print ("\nInterface number(%d) out of range(%d).\n" % (self.ifindex,len(self.devlist)))
            return False
        d = self.devlist[self.ifindex]
        self.adhandle = pcap_open_live(d.name, 65536, int(self.__ispromisc), 1000, errbuf)
        if (self.adhandle == None):
            print("\nUnable to open the adapter. %s is not supported by Pcap-WinPcap\n" % d.name)
            return False
        return True
    
    def compile_filter(self, filterstr = ""):
        self.filter = filterstr
        netmask = 0xffffff
        if pcap_compile(self.adhandle,byref(self.fcode),self.filter,1,netmask) < 0:
            print('\nError compiling filter: wrong syntax.\n')
            return False
        return True
            
    def set_filter(self):
        if pcap_setfilter(self.adhandle,byref(self.fcode)) <0:
            print('\nError setting the filter\n')
            return False
        return True
    
    def start_capture(self):
        count = 0
        res = 1
        while res >= 0 and count<20000 and self.goon:
            res = pcap_next_ex(self.adhandle, byref(header), byref(pkt_data))
            if res == 0:
                print "timeout"
                continue
            self.pktlist.append((copy.deepcopy(header.contents), 
                                 buffer(bytearray(pkt_data[:header.contents.len]))))
            count = count + 1
        if res == -1:
            print("Error reading the packets: %s\n", pcap_geterr(self.adhandle));
            pcap_close(self.adhandle)
            return False
        pcap_close(self.adhandle)
        return True
    
    def stop_capture(self):
        pass
    
    def print_pkts(self):
        for h, d in self.pktlist:
            local_tv_sec = h.ts.tv_sec
            ltime = time.localtime(local_tv_sec);
            timestr = time.strftime("%H:%M:%S", ltime)
            print
            print("%s,%.6d len:%d" % (timestr, h.ts.tv_usec, h.len))


if __name__ == '__main__':
    pktlist = []
    cap = Capturer(pktlist)
    print cap.open_dev()
    print cap.compile_filter()

        
