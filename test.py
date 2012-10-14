import Capturer
import dpkt
import threading, time
pktlist = []
cap = Capturer.Capturer(pktlist)
cap.print_device_list()
print cap.open_dev()
print cap.compile_filter("")
print cap.set_filter()
goon = True
t = threading.Thread(target=cap.start_capture)
t.start()
time.sleep(5)
cap.goon = False
t.join()

for i,(h,d) in enumerate(pktlist):
    frame = dpkt.ethernet.Ethernet(d)
    print "num %d"%(i+1)

    print 'src mac:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x'% tuple(map(ord,list(frame.src)))
    print 'dst mac:%.2x:%.2x:%.2x:%.2x:%.2x:%.2x'% tuple(map(ord,list(frame.dst)))
    
    if frame.type == dpkt.ethernet.ETH_TYPE_ARP:
        print "arp type:0x%x"%frame.data.op
        print 'class:%s'%frame.data.__class__.__name__
        print 'who has %d.%d.%d.%d? Tell %d.%d.%d.%d'% (tuple(map(ord,list(frame.data.tpa)))+tuple(map(ord,list(frame.data.spa))))
    elif frame.type == dpkt.ethernet.ETH_TYPE_IP:
        print "type:%d"%frame.data.p
        print 'class:%s'%frame.data.__class__.__name__
        print 'src ip:%d.%d.%d.%d'%tuple(map(ord,list(frame.data.src)))
        print 'dst ip:%d.%d.%d.%d'%tuple(map(ord,list(frame.data.dst)))
        print "sport:%d"%frame.data.data.sport
        print "dport:%d"%frame.data.data.dport
        print
    elif frame.type == dpkt.ethernet.ETH_TYPE_IP6:
        print "type:%d"%frame.data.p
        print 'src ip:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x'%tuple(map(ord,list(frame.data.src)))
        print 'dst ip:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x'%tuple(map(ord,list(frame.data.dst)))
#        print "sport:%d"%frame.data.data.sport
#        print "dport:%d"%frame.data.data.dport
        print
    else:
        print "type = %d"%frame.type
print 'just a test'