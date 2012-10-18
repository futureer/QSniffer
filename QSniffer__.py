from MainWindow import MainWindow, pyqtSignature
from Capturer import Capturer, WIN32
from PyQt4 import QtCore, QtGui
from Analyzer import Analyer
from Util import PktList
import sys, threading

class QSniffer(MainWindow):
    def __init__(self):
        MainWindow.__init__(self)
#        self.pktlist = []
#        self.pktlist_mutex = threading.Lock()
        self.pktList = PktList()
        
        self.capturer = Capturer(self.pktList)
        self.cap_thread = None
        self.analyzer = Analyer(self.pktList, self.pktTableWidget, self)
        self.ana_thread = None
        
        MainWindow.set_devlist(self, self.capturer.devlist, WIN32)
        
        self.show()
    
    def testTableWidget(self):
        table = self.pktTableWidget
#        table.setRowCount(20)
        table.insertRow(0)

        item = QtGui.QTableWidgetItem(QtCore.QString("hello dfafdsafdafdsafdsafdsafsa"))
        item.setFlags(item.flags() ^ QtCore.Qt.ItemIsEditable)
        table.setItem(0, 0, item)
    
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
        self.cap_thread = threading.Thread(target=self.capturer.start_capture)
        self.cap_thread.start()
        self.ana_thread = threading.Thread(target=self.analyzer.start_analize)
        self.ana_thread.start()
    
    @pyqtSignature("")
    def on_stopButton_clicked(self):
        MainWindow.on_stopButton_clicked(self)
        if self.cap_thread.is_alive():
            self.capturer.stop_capture()
            self.cap_thread.join()
        if self.ana_thread.is_alive():
            self.analyzer.stop_analize()
            self.ana_thread.join()
    
    @pyqtSignature("")
    def on_clearButton_clicked(self):
        MainWindow.on_clearButton_clicked(self)
        if self.cap_thread == None or self.ana_thread == None:
            return
        elif self.cap_thread.is_alive() or self.ana_thread.is_alive():
            QtGui.QMessageBox.information(self, "Information", self.tr("You must stop capture first."))
            return 
        self.capturer.clear()
        self.analyzer.clear()
        self.pktList.clear()
        count = self.pktTableWidget.rowCount()
        for i in range(count):
            self.pktTableWidget.removeRow(0)
    
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
        
    @pyqtSignature("int, int")
    def on_pktTableWidget_cellClicked(self, row, column):
        MainWindow.on_pktTableWidget_cellClicked(self, row, column)
        tree = self.pktTreeWidget
        
    

if __name__ == "__main__":
    app = QtGui.QApplication(sys.argv)
    qsniffer = QSniffer()
    
    sys.exit(app.exec_())
        
