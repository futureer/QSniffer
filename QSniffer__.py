from MainWindow import MainWindow, pyqtSignature
from Capturer import Capturer
from PyQt4 import QtCore, QtGui
from winpcapy import WIN32
import sys

class QSniffer(MainWindow):
    def __init__(self):
        MainWindow.__init__(self)
        self.pktlist = []
        self.capturer = Capturer(self.pktlist)
        qslist = QtCore.QStringList()
        if WIN32:
            for dev in self.capturer.devlist:
                qslist.append(QtCore.QString(dev.description))
        else:
            for dev in self.capturer.devlist:
                qslist.append(QtCore.QString(dev.name))
        self.devComboBox.addItems(qslist)
        self.testTableWidget()
        self.show()
    
    def testTableWidget(self):
        table = self.pktTableWidget
#        table.setRowCount(20)
        table.insertRow(0)
        table
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
        # TODO:
    
    @pyqtSignature("")
    def on_stopButton_clicked(self):
        MainWindow.on_stopButton_clicked(self)
        # TODO:
    
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

    

if __name__ == "__main__":
    app = QtGui.QApplication(sys.argv)
    qsniffer = QSniffer()
    sys.exit(app.exec_())
        
