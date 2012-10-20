# -*- coding: utf-8 -*-

"""
Module implementing MainWindow.
"""

from PyQt4.QtGui import QMainWindow, QApplication
from PyQt4.QtCore import pyqtSignature, QStringList, QString
from PyQt4.QtGui import QTableWidget
from Ui_QSniffer import Ui_MainWindow

class MainWindow(QMainWindow, Ui_MainWindow):
    """
    Class documentation goes here.
    """
    def __init__(self, parent = None):
        """
        Constructor
        """
        QMainWindow.__init__(self, parent)
        self.setupUi(self)
        
        self.pktTableWidget.setColumnWidth(0,50)
        self.pktTableWidget.setColumnWidth(1,75)
        self.pktTableWidget.setColumnWidth(2,150)
        self.pktTableWidget.setColumnWidth(3,150)
        self.pktTableWidget.setColumnWidth(4,65)
        self.pktTableWidget.setColumnWidth(5,60)
        self.pktTableWidget.setColumnWidth(6,160)
        self.pktTableWidget.setEditTriggers(QTableWidget.NoEditTriggers)
        self.pktTableWidget.setSelectionBehavior(QTableWidget.SelectRows)
        self.pktTableWidget.setSelectionMode(QTableWidget.SingleSelection)
        self.pktTableWidget.setAlternatingRowColors(True)
        
        self.pktTreeWidget.setHeaderHidden(True)
    
    def set_devlist(self, devlist, isWIN32):
        qslist = QStringList()
        if isWIN32:
            for dev in devlist:
                qslist.append(QString(dev.description))
        else:
            for dev in self.capturer.devlist:
                qslist.append(QString(dev.name))
        self.devComboBox.addItems(qslist)
    
    @pyqtSignature("")
    def on_filterApplyButton_clicked(self):
        """
        Slot documentation goes here.
        """
        pass
    
    @pyqtSignature("")
    def on_filterClearButton_clicked(self):
        """
        Slot documentation goes here.
        """
        pass
    
    @pyqtSignature("")
    def on_stopButton_clicked(self):
        """
        Slot documentation goes here.
        """
        pass
    
    @pyqtSignature("")
    def on_startButton_clicked(self):
        """
        Slot documentation goes here.
        """
        pass
    
    @pyqtSignature("")
    def on_clearButton_clicked(self):
        """
        Slot documentation goes here.
        """
        pass
    
    @pyqtSignature("")
    def on_exportButton_clicked(self):
        """
        Slot documentation goes here.
        """
        pass
    
    @pyqtSignature("")
    def on_importButton_clicked(self):
        """
        Slot documentation goes here.
        """
        pass
    
    @pyqtSignature("int")
    def on_promisCheckBox_stateChanged(self,p0):
        """
        Slot documentation goes here.
        """
        pass
    
    @pyqtSignature("QString")
    def on_filterLineEdit_textChanged(self, p0):
        """
        Slot documentation goes here.
        """
        pass
    
    @pyqtSignature("int")
    def on_devComboBox_currentIndexChanged(self, index):
        """
        Slot documentation goes here.
        """
        pass
    
    @pyqtSignature("QModelIndex")
    def on_pktTableWidget_activated(self, index):
        """
        Slot documentation goes here.
        """
        pass
    
    @pyqtSignature("int, int")
    def on_pktTableWidget_cellClicked(self, row, column):
        """
        Slot documentation goes here.
        """
        pass
    

if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    mainWindow = MainWindow()

    mainWindow.show()
    sys.exit(app.exec_())   
