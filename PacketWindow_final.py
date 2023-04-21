from PyQt6 import QtCore, QtGui, QtWidgets
import threading
import time
import Sniffer
import SnifferClass
from scapy.all import *



class Ui_SnifferWindow(object):
    collection= []
    record_keep= {}
    index=0
    def setupUi(self, SnifferWindow):
        SnifferWindow.setObjectName("SnifferWindow")
        SnifferWindow.resize(802, 607)
        SnifferWindow.setAutoFillBackground(False)
        SnifferWindow.setStyleSheet("background-color: rgb(68, 68, 68);")
        self.centralwidget = QtWidgets.QWidget(parent=SnifferWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.label_2 = QtWidgets.QLabel(parent=self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(60, 460, 47, 13))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_2.setFont(font)
        self.label_2.setAutoFillBackground(False)
        self.label_2.setStyleSheet("color: rgb(0, 255, 0);")
        self.label_2.setObjectName("label_2")
        self.sniff_button = QtWidgets.QPushButton(parent=self.centralwidget)
        self.sniff_button.setGeometry(QtCore.QRect(190, 460, 161, 81))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.sniff_button.setFont(font)
        self.sniff_button.setAutoFillBackground(False)
        self.sniff_button.setStyleSheet("color: rgb(0, 255, 0);")
        self.sniff_button.setObjectName("sniff_button")
        self.port_lineEdit = QtWidgets.QLineEdit(parent=self.centralwidget)
        self.port_lineEdit.setGeometry(QtCore.QRect(90, 530, 81, 20))
        self.port_lineEdit.setObjectName("port_lineEdit")
        self.tcp_label = QtWidgets.QLabel(parent=self.centralwidget)
        self.tcp_label.setGeometry(QtCore.QRect(40, 490, 47, 13))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.tcp_label.setFont(font)
        self.tcp_label.setAutoFillBackground(False)
        self.tcp_label.setStyleSheet("color: rgb(0, 255, 0);")
        self.tcp_label.setObjectName("tcp_label")
        self.udp_label = QtWidgets.QLabel(parent=self.centralwidget)
        self.udp_label.setGeometry(QtCore.QRect(40, 510, 47, 13))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.udp_label.setFont(font)
        self.udp_label.setAutoFillBackground(False)
        self.udp_label.setStyleSheet("color: rgb(0, 255, 0);")
        self.udp_label.setObjectName("udp_label")
        self.port_label = QtWidgets.QLabel(parent=self.centralwidget)
        self.port_label.setGeometry(QtCore.QRect(40, 530, 47, 13))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.port_label.setFont(font)
        self.port_label.setAutoFillBackground(False)
        self.port_label.setStyleSheet("color: rgb(0, 255, 0);")
        self.port_label.setObjectName("port_label")
        self.tcp_radio = QtWidgets.QRadioButton(parent=self.centralwidget)
        self.tcp_radio.setGeometry(QtCore.QRect(100, 490, 82, 17))
        self.tcp_radio.setText("")
        self.tcp_radio.setObjectName("tcp_radio")
        self.udp_radio = QtWidgets.QRadioButton(parent=self.centralwidget)
        self.udp_radio.setGeometry(QtCore.QRect(100, 510, 82, 17))
        self.udp_radio.setText("")
        self.udp_radio.setObjectName("udp_radio")
        self.listWidget = QtWidgets.QListWidget(parent=self.centralwidget)
        self.listWidget.setGeometry(QtCore.QRect(10, 30, 371, 421))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(8)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(50)
        self.listWidget.setFont(font)
        self.listWidget.setStyleSheet("background-color: rgb(0, 0, 0);\n"
"color: rgb(0, 255, 0);\n"
"font: 8pt \"MS Shell Dlg 2\";\n"
"font: 8pt \"Times New Roman\";\n"
"border-color: rgb(0, 255, 0);")
        self.listWidget.setObjectName("listWidget")
        self.horizontalLayoutWidget_2 = QtWidgets.QWidget(parent=self.centralwidget)
        self.horizontalLayoutWidget_2.setGeometry(QtCore.QRect(10, 0, 371, 31))
        self.horizontalLayoutWidget_2.setObjectName("horizontalLayoutWidget_2")
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout(self.horizontalLayoutWidget_2)
        self.horizontalLayout_3.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.label = QtWidgets.QLabel(parent=self.horizontalLayoutWidget_2)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label.setFont(font)
        self.label.setAutoFillBackground(False)
        self.label.setStyleSheet("color: rgb(0, 255, 0);")
        self.label.setObjectName("label")
        self.horizontalLayout_3.addWidget(self.label)
        self.label_3 = QtWidgets.QLabel(parent=self.horizontalLayoutWidget_2)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_3.setFont(font)
        self.label_3.setAutoFillBackground(False)
        self.label_3.setStyleSheet("color: rgb(0, 255, 0);")
        self.label_3.setObjectName("label_3")
        self.horizontalLayout_3.addWidget(self.label_3)
        self.label_4 = QtWidgets.QLabel(parent=self.horizontalLayoutWidget_2)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.label_4.setFont(font)
        self.label_4.setAutoFillBackground(False)
        self.label_4.setStyleSheet("color: rgb(0, 255, 0);")
        self.label_4.setObjectName("label_4")
        self.horizontalLayout_3.addWidget(self.label_4)
        self.follow_button_2 = QtWidgets.QPushButton(parent=self.centralwidget)
        self.follow_button_2.setGeometry(QtCore.QRect(650, 520, 141, 41))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.follow_button_2.setFont(font)
        self.follow_button_2.setAutoFillBackground(False)
        self.follow_button_2.setStyleSheet("color: rgb(0, 255, 0);")
        self.follow_button_2.setObjectName("follow_button_2")
        self.progressBar = QtWidgets.QProgressBar(parent=self.centralwidget)
        self.progressBar.setGeometry(QtCore.QRect(190, 540, 161, 21))
        self.progressBar.setProperty("value", 0)
        self.progressBar.setObjectName("progressBar")
        self.tabWidget = QtWidgets.QTabWidget(parent=self.centralwidget)
        self.tabWidget.setGeometry(QtCore.QRect(400, 0, 381, 471))
        self.tabWidget.setObjectName("tabWidget")
        self.tab = QtWidgets.QWidget()
        self.tab.setObjectName("tab")
        self.textEdit = QtWidgets.QTextEdit(parent=self.tab)
        self.textEdit.setGeometry(QtCore.QRect(0, 0, 381, 451))
        self.textEdit.setStyleSheet("background-color: rgb(0, 0, 0);\n"
"color: rgb(0, 255, 0);\n"
"font: 12pt \"MS Shell Dlg 2\";\n"
"font: 12pt \"Times New Roman\";\n"
"border-color: rgb(0, 255, 0);")
        self.textEdit.setObjectName("textEdit")
        self.tabWidget.addTab(self.tab, "")
        self.tab_2 = QtWidgets.QWidget()
        self.tab_2.setObjectName("tab_2")
        self.textEdit_2 = QtWidgets.QTextEdit(parent=self.tab_2)
        self.textEdit_2.setGeometry(QtCore.QRect(0, 0, 381, 451))
        self.textEdit_2.setStyleSheet("background-color: rgb(0, 0, 0);\n"
"color: rgb(0, 255, 0);\n"
"font: 12pt \"MS Shell Dlg 2\";\n"
"font: 12pt \"Times New Roman\";\n"
"border-color: rgb(0, 255, 0);")
        self.textEdit_2.setObjectName("textEdit_2")
        self.tabWidget.addTab(self.tab_2, "")
        SnifferWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(parent=SnifferWindow)
        self.statusbar.setObjectName("statusbar")
        SnifferWindow.setStatusBar(self.statusbar)
        self.actionOpen = QtGui.QAction(parent=SnifferWindow)
        self.actionOpen.setObjectName("actionOpen")
        self.actionClose = QtGui.QAction(parent=SnifferWindow)
        self.actionClose.setObjectName("actionClose")

        self.retranslateUi(SnifferWindow)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(SnifferWindow)

        self.sniff_button.clicked.connect(self.sniff)
        self.listWidget.clicked.connect(self.follow_click)
        self.follow_button_2.clicked.connect(self.save_pcap)

    def follow_click(self, qmodelindex):
        self.textEdit.clear()
        self.textEdit_2.clear()
        item = self.listWidget.currentItem()

        string_txt= str(item.text()).partition(" ")
        



        print(string_txt)
        print(string_txt[0])

        # this code is a hard code for indicing the string partitions to remove [] when stored
        ind= (string_txt[0])[1:-1]
        print(ind)
        #self.textEdit.setText(str(self.totals[index]))
        #print(type(self.record_keep[ind]))
        self.textEdit.append("-------IP SOURCE---------")
        self.textEdit.append(str(self.record_keep[ind].get_data('ip_src')))
        self.textEdit.append("-------IP DESTINATION---------")
        self.textEdit.append(str(self.record_keep[ind].get_data('ip_dest')))
        self.textEdit.append("-------PORT SOURCE/DESTINATION---------")
        source = self.record_keep[ind].get_data('port_src')
        destination = self.record_keep[ind].get_data('port_dst')
        self.textEdit.append(str(source))
        self.textEdit.append(str(destination))
        self.textEdit.append("-------SEQ/ACK---------")
        seq = self.record_keep[ind].get_data('seq_number')
        self.textEdit.append(str(seq))
        self.textEdit.append(str(self.record_keep[ind].get_data('ack_number')))
        self.textEdit.append("-------FLAGS---------")
        self.textEdit.append(str(self.record_keep[ind].get_data('flags')))
        self.textEdit.append("-------MAC---------")
        self.textEdit.append(('SOURCE'))
        self.textEdit.append(str(self.record_keep[ind].get_data('mac_src')))
        self.textEdit.append(('DESTINATION'))
        self.textEdit.append(str(self.record_keep[ind].get_data('mac_dst')))
        self.textEdit_2.append("-------PAYLOAD---------")

        hexinfo = self.record_keep[ind].get_data('payload')
        
        self.textEdit_2.append((self.record_keep[ind].get_data('payload')))

        if 'POST' in hexstr(hexinfo):
            self.textEdit.append('---Check Payload for POST--')
            split = hexstr(hexinfo).split("..")
            self.textEdit_2.clear()
            self.textEdit_2.append("POST IDENTIFIED")
            for i in split[1:]:
                self.textEdit_2.append(i)
                self.textEdit_2.append(" ")
        elif 'GET' in hexstr(hexinfo):
            self.textEdit.append('---Check Payload for GET--')
            split = hexstr(hexinfo).split("..")
            self.textEdit_2.clear()
            self.textEdit_2.append("GET IDENTIFIED")
            
            for i in split[1:]:
                
                self.textEdit_2.append(i)
                self.textEdit_2.append(" ")
            
            #self.textEdit.append("GET IDENTIFIED")
            #self.textEdit.append(str(hexinfo).partition("GET")[1])
            #self.textEdit.append(str(hexinfo).partition("GET")[2])
            
        elif 'HTTP' in hexstr(hexinfo):
            self.textEdit.append('---Check Payload for HTTP--')
            split = hexstr(hexinfo).split("..")
            self.textEdit_2.clear()
            self.textEdit_2.append("HTTP HEADER IDENTIFIED")
            for i in split[1:]:
                self.textEdit_2.append(i)
                self.textEdit_2.append(" ")

        self.textEdit_2.append('----TCP STREAM----')
        packets_1= self.pcap
        print(f'{source},{destination},{seq}')
        tcpstream = Sniffer.MainSniffer.follow_tcp_stream(self, packets_1, source, destination, seq)
        for i in tcpstream:
            self.textEdit_2.append(i)
        
            #self.textEdit.clear()
            #self.textEdit.append("HTTP HEADER IDENTIFIED")
            #self.textEdit.append(str(hexinfo).partition("HTTP")[1])
            #self.textEdit.append(str(hexinfo).partition("HTTP")[2])

    def save_pcap(self):
        pcaphandler= SnifferClass.Sniffed()
        for i in self.sniffer_handler:
            pcaphandler.pcap_write(self.pcap)

    def sniff(self):
        self.listWidget.clear()
        self.collection.clear()
        self.completed= 0
        self.progressBar.setProperty("value", self.completed)

        while self.completed < 100:
            
            filterport= self.port_lineEdit.text()
            self.completed+= 30
            self.progressBar.setProperty("value", self.completed)

            engine = Sniffer.MainSniffer(filterport)

            if self.tcp_radio.isChecked():
                print("TCP CHECKED")
                engine.is_tcp()
                print("UDP CHECKED")
            elif self.udp_radio.isChecked():
                engine.is_udp()

            t1 = threading.Thread(target=engine.start)

            
            t1.start()
            
            while self.completed < 90:
                self.completed += .00001
                self.progressBar.setProperty("value", self.completed)
                if not t1.is_alive():
                    break

            #engine.handler(filtertcp, filterport)
            self.pcap= engine.getpkt()
            self.sniffer_handler = engine.get_result()
            self.trigger(self.sniffer_handler)
            self.completed+= 70
            self.progressBar.setProperty("value", self.completed)
        
            for i in self.collection:
                self.completed += 5
                self.progressBar.setProperty("value", self.completed)
                charlen= len(str(i[1]))
                if 11 < charlen < 13:
                    format=str('['+str(i[6]) +'] '+ str(i[1]) +" "*24 + str(i[0])+ " "*20+ str(i[5]))
                elif charlen > 14:
                    format=str('['+str(i[6]) +'] '+str(i[1]) +" "*19 + str(i[0])+ " "*20+ str(i[5]))
                else:
                    format=str('['+str(i[6]) +'] '+str(i[1]) +" "*25 + str(i[0])+ " "*20+ str(i[5]))
                self.listWidget.addItem(format)
                
            
            

            if len(self.collection) < 1:
                #print(len(self.collection))
                self.sniff()
                print("Restarting Sniff")
                time.sleep(2)
                
            else:
                print(len(self.collection))
                
            
            self.completed = 100
            self.progressBar.setProperty("value", self.completed)



    def trigger(self, sniffer_handler):
        self.index=0
        keys = ['ip_dest',
            'ip_src',
            'payload',
            'seq_number',
            'ack_number',
            'port_dst',
        ]

        for i in sniffer_handler:
                #print(self.index)
                self.record_keep[str(self.index)]= i
                item=[]
                for key in keys:
                    key= i.get_data(key)
                    item.append(key)
                item.append(self.index)
                self.collection.append(item)
                self.index += 1

    def retranslateUi(self, SnifferWindow):
        _translate = QtCore.QCoreApplication.translate
        SnifferWindow.setWindowTitle(_translate("SnifferWindow", "Packet Sniffer - Net-Scent @ Mark Miranda"))
        self.label_2.setText(_translate("SnifferWindow", "FILTERS:"))
        self.sniff_button.setText(_translate("SnifferWindow", "Start Sniffer"))
        self.tcp_label.setText(_translate("SnifferWindow", "TCP"))
        self.udp_label.setText(_translate("SnifferWindow", "UDP"))
        self.port_label.setText(_translate("SnifferWindow", "Port :"))
        self.label.setText(_translate("SnifferWindow", "IP Source"))
        self.label_3.setText(_translate("SnifferWindow", "IP Destination"))
        self.label_4.setText(_translate("SnifferWindow", "Port"))
        self.follow_button_2.setText(_translate("SnifferWindow", "SAVE AS PCAP"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("SnifferWindow", "Header Info"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("SnifferWindow", "Payload"))
        self.actionOpen.setText(_translate("SnifferWindow", "Open File"))
        self.actionClose.setText(_translate("SnifferWindow", "Close"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    SnifferWindow = QtWidgets.QMainWindow()
    ui = Ui_SnifferWindow()
    ui.setupUi(SnifferWindow)
    SnifferWindow.show()
    sys.exit(app.exec())
