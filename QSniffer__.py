from MainWindow import MainWindow, pyqtSignature
from Capturer import Capturer, WIN32
from PyQt4 import QtCore, QtGui
from Analyzer import Analyer, Statistics, PktItem
import sys, threading, time
from mercurial.revset import destination

class QSniffer(MainWindow):
    def __init__(self):
        MainWindow.__init__(self)
        self.pktlist = []
        self.pktlist_mutex = threading.Lock()
        self.capturer = Capturer(self.pktlist, self.pktlist_mutex)
        self.cap_thread = threading.Thread(target=self.capturer.start_capture)
        
        self.analyzer = Analyer()
        self.itemlist = []
#        self.ana_thread = threading.Thread(target=self.start_analize)
#        self.ana_thread.start()
        qslist = QtCore.QStringList()
        if WIN32:
            for dev in self.capturer.devlist:
                qslist.append(QtCore.QString(dev.description))
        else:
            for dev in self.capturer.devlist:
                qslist.append(QtCore.QString(dev.name))
        self.devComboBox.addItems(qslist)
        
#        self.testTableWidget()
        
        self.show()
    
    def testTableWidget(self):
        table = self.pktTableWidget
#        table.setRowCount(20)
        table.insertRow(0)

        item = QtGui.QTableWidgetItem(QtCore.QString("hello dfafdsafdafdsafdsafdsafsa"))
        item.setFlags(item.flags()^QtCore.Qt.ItemIsEditable)
        table.setItem(0,0,item)
    
    @pyqtSignature("int")
    def on_promisCheckBox_stateChanged(self, p0):
        MainWindow.on_promisCheckBox_stateChanged(self, p0)
#        print "check int:%d"%p0
        if(self.promisCheckBox.isChecked()):
            self.capturer.set_promisc(True)
        else:
            self.capturer.set_promisc(False)
    
    @pyqtSignature("")
    def on_startButton_clicked(self):
        MainWindow.on_startButton_clicked(self)
        if self.capturer.adhandle == None:
            curindex = self.devComboBox.currentIndex()
            if not self.capturer.open_dev(curindex):
#                TODO: handle open error
                return
        self.cap_thread.start()
    
    @pyqtSignature("")
    def on_stopButton_clicked(self):
        MainWindow.on_stopButton_clicked(self)
        if self.cap_thread.is_alive():
            self.capturer.stop_capture()
            self.cap_thread.join()
    
    @pyqtSignature("")
    def on_clearButton_clicked(self):
        MainWindow.on_clearButton_clicked(self)
        # TODO:
    
    @pyqtSignature("")
    def on_filterApplyButton_clicked(self):
        MainWindow.on_filterApplyButton_clicked(self)
        if self.capturer.adhandle == None:
            curindex = self.devComboBox.currentIndex()
            if not self.capturer.open_dev(curindex):
                return
        filterstr = str(self.filterLineEdit.text())
#        print "%r" % filterstr
        if filterstr == "":
            return 
        msg = self.filterMsgLable
        if self.capturer.compile_filter(filterstr):
            if self.capturer.set_filter():
                msg.setText(QtCore.QString("<font style='color: green;'>Success</font>"))
            else:
                msg.setText(QtCore.QString("<font style='color: red;'>Error occur</font>"))
        else:
            msg.setText(QtCore.QString("<font style='color: red;'>Wrong syntax</font>"))
    
    @pyqtSignature("")
    def on_filterClearButton_clicked(self):
        MainWindow.on_filterClearButton_clicked(self)
        self.filterLineEdit.clear()
    
    @pyqtSignature("QString")
    def on_filterLineEdit_textChanged(self, p0):
        MainWindow.on_filterLineEdit_textChanged(self, p0)
        self.filterMsgLable.clear()
    
    @pyqtSignature("int")
    def on_devComboBox_currentIndexChanged(self, index):
        MainWindow.on_devComboBox_currentIndexChanged(self, index)
#        print "combobox index:%d" % index
    
    def start_analize(self):
        while True:
            if len(self.pktlist) > 0:
                self.pktlist_mutex.acquire()
                p = self.pktlist.pop(0)
                self.pktlist_mutex.release()
                
                item = self.analyzer.analize(p)
                self.itemlist.append(item)
                self.show_item(item)
            time.sleep(0.01)
                
    
    def show_item(self, item):
        table = self.pktTableWidget
        row = table.rowCount()
        table.insertRow(row)
        
        source = item.src_ip
        destination = item.dst_ip
        
        if item.protocol == 'TCP' or item.protocol == 'UDP':
            source += ':' + str(item.src_port)
            destination += ':' + str(item.dst_port)
        elif item.protocol == 'ARP':
            source = item.src_mac
            destination = item.dst_mac
        if source == None:
            source = 'un'
        if destination == None:
            destination = 'un'
        
        No = QtGui.QTableWidgetItem(QtCore.QString(str(row+1)))
        No.setFlags(No.flags()^QtCore.Qt.ItemIsEditable)
        table.setItem(row,0,No)
        
        Time = QtGui.QTableWidgetItem(QtCore.QString(item.time))
        Time.setFlags(Time.flags()^QtCore.Qt.ItemIsEditable)
        table.setItem(row,1,Time)
        
        Source = QtGui.QTableWidgetItem(QtCore.QString(source))
        Source.setFlags(Source.flags()^QtCore.Qt.ItemIsEditable)
        table.setItem(row,2,Source)
        
        Destination = QtGui.QTableWidgetItem(QtCore.QString(destination))
        Destination.setFlags(Destination.flags()^QtCore.Qt.ItemIsEditable)
        table.setItem(row,3,Destination)
        
        Protocol = QtGui.QTableWidgetItem(QtCore.QString(item.protocol))
        Protocol.setFlags(Protocol.flags()^QtCore.Qt.ItemIsEditable)
        table.setItem(row,4,Protocol)
        
        Length = QtGui.QTableWidgetItem(QtCore.QString(str(item.len)))
        Length.setFlags(Length.flags()^QtCore.Qt.ItemIsEditable)
        table.setItem(row,5,Length)
    

if __name__ == "__main__":
    app = QtGui.QApplication(sys.argv)
    qsniffer = QSniffer()
    qsniffer.ana_thread = threading.Thread(target = qsniffer.start_analize)
    qsniffer.ana_thread.start()
    sys.exit(app.exec_())
        
