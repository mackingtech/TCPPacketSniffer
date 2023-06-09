from PyQt6 import QtCore, QtGui, QtWidgets
from PacketWindow_final import Ui_SnifferWindow
from AttackWindow import Attack_MainWindow
import os


class Ui_MainWindow(object):
    def art_header(self):
        art= (""" 

         /$$   /$$             /$$           /$$$$$$                                  /$$                                      
        | $$$ | $$            | $$          /$$__  $$                                | $$                                      
        | $$$$| $$  /$$$$$$  /$$$$$$       | $$  \__/  /$$$$$$$  /$$$$$$  /$$$$$$$  /$$$$$$                                    
        | $$ $$ $$ /$$__  $$|_  $$_//$$$$$$|  $$$$$$  /$$_____/ /$$__  $$| $$__  $$|_  $$_/                                    
        | $$  $$$$| $$$$$$$$  | $$ |______/ \____  $$| $$      | $$$$$$$$| $$  \ $$  | $$                                      
        | $$\  $$$| $$_____/  | $$ /$$      /$$  \ $$| $$      | $$_____/| $$  | $$  | $$ /$$                                  
        | $$ \  $$|  $$$$$$$  |  $$$$/     |  $$$$$$/|  $$$$$$$|  $$$$$$$| $$  | $$  |  $$$$/                                  
        |__/  \__/ \_______/   \___/        \______/  \_______/ \_______/|__/  |__/   \___/                                    
                                                                                                                            
                                                                                                                            
                                                                                                                            
                                                /$$                     /$$                                    /$$          
                                                | $$                    |__/                                   | $$          
                /$$$$$$/$$$$   /$$$$$$   /$$$$$$ | $$   /$$ /$$$$$$/$$$$  /$$  /$$$$$$  /$$$$$$  /$$$$$$$   /$$$$$$$  /$$$$$$ 
        /$$$$$$| $$_  $$_  $$ |____  $$ /$$__  $$| $$  /$$/| $$_  $$_  $$| $$ /$$__  $$|____  $$| $$__  $$ /$$__  $$ |____  $$
        |______/| $$ \ $$ \ $$  /$$$$$$$| $$  \__/| $$$$$$/ | $$ \ $$ \ $$| $$| $$  \__/ /$$$$$$$| $$  \ $$| $$  | $$  /$$$$$$$
                | $$ | $$ | $$ /$$__  $$| $$      | $$_  $$ | $$ | $$ | $$| $$| $$      /$$__  $$| $$  | $$| $$  | $$ /$$__  $$
                | $$ | $$ | $$|  $$$$$$$| $$      | $$ \  $$| $$ | $$ | $$| $$| $$     |  $$$$$$$| $$  | $$|  $$$$$$$|  $$$$$$$
                |__/ |__/ |__/ \_______/|__/      |__/  \__/|__/ |__/ |__/|__/|__/      \_______/|__/  |__/ \_______/ \_______/
                                                                                                                       
                                                                                                                                                                                                                                                                                                                                                                                                            
        """)

        print(art)

    def setupUi(self, MainWindow):
        
        self.art_header()


        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(479, 253)
        
        MainWindow.setStyleSheet("background-color: rgb(24, 24, 24);")
        self.centralwidget = QtWidgets.QWidget(parent=MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.pushButton = QtWidgets.QPushButton(parent=self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(80, 50, 141, 111))
        self.pushButton.setStyleSheet("background-color:rgb(106, 200, 106)")
        self.pushButton.setObjectName("pushButton")
        self.pushButton_2 = QtWidgets.QPushButton(parent=self.centralwidget)
        self.pushButton_2.setGeometry(QtCore.QRect(270, 50, 141, 111))
        self.pushButton_2.setStyleSheet("background-color:rgb(106, 200, 106)")
        self.pushButton_2.setObjectName("pushButton_2")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(parent=MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 479, 21))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(parent=MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)




        self.pushButton.clicked.connect(self.packet_window)
        self.pushButton_2.clicked.connect(self.attack_window)

    def packet_window(self):
        self.window= QtWidgets.QMainWindow()
        self.ui = Ui_SnifferWindow()
        self.ui.setupUi(self.window)
        self.window.show()
        MainWindow.close()

    def attack_window(self):
        self.window= QtWidgets.QMainWindow()
        self.ui = Attack_MainWindow()
        self.ui.setupUi(self.window)
        self.window.show()
        MainWindow.close()

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "NetScent- Mark Miranda"))
        self.pushButton.setText(_translate("MainWindow", "Packet Sniffer"))
        self.pushButton_2.setText(_translate("MainWindow", "PenTest"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec())
