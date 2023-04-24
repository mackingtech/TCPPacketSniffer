<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/mackingtech/TCPPacketSniffer/">
    <img src="https://user-images.githubusercontent.com/82029531/234121288-df886c2f-973f-42b4-b992-bc1d61ebf9d0.png" alt="Logo" width="800" height="400">
  </a>

  <h2 align="center">Net-Scent</h3>
  <h3 align="center">"A study on networking fundamentals and a creation of a TCP packet sniffer"</h2>
</div>





<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project


This is my Captstone project for my final year at Shepherd University. It is a TCP/UDP Packet sniffer that provides a very minimalistic and simple design for beginners to be able to use it with ease. It is focused mainly on important header values that are parsed for the user to see. It tackles the idea of what packet sniffing fundamentally is and be able to give the main factors students would be looking for and be able to acclimate themselves to networking tools before moving on to the industry tools such as, WireShark. 

As an educational tool it is very important to note that this sniffer have 2 main modules, the main <b>Packet Sniffer:</b> that focuses on the local network traffic of the device being used, and the <b>PenTest Module:</b> which is a simulator of an ARP SPOOFING attack on a device that is in the same network. 


<p align="right">(<a href="#readme-top">back to top</a>)</p>



### Built with only Python and readily available libraries 

* SCAPY
* PyQT6
* LIBPCAP

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- GETTING STARTED -->
## Getting Started

### Prerequisites

Scapy is a Python-based packet manipulation tool that allows you to create, send, and capture network packets. Here are the steps to install Scapy on your system:

Open your terminal and type
```
pip install scapy
```

PyQt6

PyQt6 is a set of Python bindings for the Qt application framework and runs on all platforms supported by Qt, including Windows, OS X, Linux, iOS, and Android. Here are the steps to install PyQt6 on your system:

Open your terminal and type
```
pip install PyQt6
```

libpcap

libpcap is a portable C/C++ library for network traffic capture. It provides a portable framework for low-level network monitoring. Here are the steps to install libpcap on your system:
Windows

```
Download the WinPcap installer from https://www.winpcap.org/install/default.htm.
```


<!-- USAGE EXAMPLES -->
## Usage
Once you have installed all of the prerequisites you can download the zip file from this repository. Then extract the file, and once you do look for the file named <b>STARTME.bat</b>

![image](https://user-images.githubusercontent.com/82029531/234121974-edd314c2-db16-4ef5-963c-f8bd30dc6afe.png)

After opening that file you are now ready to use the tool!
![image](https://user-images.githubusercontent.com/82029531/234122193-7c25747a-636e-4ec4-8d64-9f3aeb789359.png)


## You have 2 options Packet Sniffer or Pentest.

### Packet Sniffer module will be focused on capturing TCP traffic within your local device.
![image](https://user-images.githubusercontent.com/82029531/234122734-34c4316f-5382-4937-b884-2ca5ab31f3df.png)

Filters:
TCP
UDP
Ports:
80 - HTTP
443 - HTTPS

### The PenTest module is an experimental module. This allows for showcasing ARP Spoofing, being able to capture network from a targetted device within your local are network
![image](https://user-images.githubusercontent.com/82029531/234123578-a7282e42-7bac-4a91-9510-a120abcbf5f1.png)



Router IP: ``` This is where you put the IP of your gateway ``` EX: 10.0.0.1, 192.168.0.1



Target IP: ``` This is where you put the IP of your target ``` EX: 10.0.0.54, 192.168.0.23




<!-- CONTACT -->
## Contact

Mark Dante R. Miranda - mmiran01@rams.shepherd.edu

Project Link: [https://github.com/mackingtech/TCPPacketSniffer](https://github.com/mackingtech/TCPPacketSniffer)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- ACKNOWLEDGMENTS -->
## Acknowledgments
Dr. Weidong Liao


Professor Ahmed Salem


Agatha Mariano

<p align="right">(<a href="#readme-top">back to top</a>)</p>



