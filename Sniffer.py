import os
from scapy.all import *
import SnifferClass as sc

ports=[]
ipsrcs=[]

conf.promisc= True


class MainSniffer():
    DEFAULT_COUNT= 10

    def __init__(self, port = None, count= DEFAULT_COUNT):
        self.item_collection = list()
        self.port = str(port)
        self.packets = list()
        self.count = count
        self.tcp = False
        self.udp = False
        self.nofilters = True
    
    def sniffer(self, pkt):
        item= sc.Sniffed()
        print(pkt)
        try:
            if TCP in pkt:
                lyst=[
                    [pkt[IP].src, 'ip_src'],
                    [pkt[IP].dst, 'ip_dest'],
                    [pkt[TCP].dport, 'port_dst'],
                    [pkt[TCP].sport, 'port_src'],
                    [pkt[TCP].payload, 'payload'],
                    [pkt[TCP].seq, 'seq_number'],
                    [pkt[TCP].ack, 'ack_number'],
                    [pkt[TCP].flags, 'flags'],
                    [pkt[Ether].src, 'mac_src'],
                    [pkt[Ether].dst, 'mac_dst'],
                ]
                for i in lyst:
                    item.dat_input(i[0], i[1])

                #item.pcap_write(pkt)
            else:
                print('skip')
            self.item_collection.append(item)
            self.packets.append(pkt)
        except Exception as e:
            print(e)

    def is_tcp(self):
        self.tcp = True
        self.udp = False
        self.nofilters = False
    
    def is_udp(self):
        self.udp = True
        self.tcp = False
        self.nofilters = False

    def follow_tcp_stream(self, packetlyst, src_port, dst_port, seq_num):
        print('im called')
        print(f'{src_port},{dst_port},{seq_num}')
        tcp_packets= list()
        tcp_payloads= list()
        for pkts in packetlyst:
            if str(pkts[TCP].sport) == src_port and str(pkts[TCP].dport) == dst_port and str(pkts[TCP].seq) == seq_num:
                print('a packet passed')
                tcp_packets.append(pkts)
                print(pkts[TCP].payload)

        #tcp_packets = [pkt for pkt in packetlyst if TCP in pkt and pkt[TCP].sport == src_port and pkt[TCP].dport == dst_port and pkt[TCP].seq == seq_num]

        for i in tcp_packets:
            payload = i[TCP].payload
            payload = str(pkts[TCP].sport)+"--->"+str(pkts[TCP].dport)+"--->"+hexstr(payload)
            tcp_payloads.append(payload)
        return(tcp_payloads)
    
    def start(self):
        if self.tcp:
            print('hello')
            sniff(filter="tcp and port "+self.port, count= 20, promisc=True, prn=self.sniffer)
        elif self.udp:
            sniff(filter="udp", prn=self.sniffer, count=10)

        elif self.nofilters:
            sniff(filter= "tcp", prn = self.sniffer, count= 100)


    
    def get_result(self):
        for i in self.item_collection:
            print(i)
        return self.item_collection
    
    def getpkt(self):
        for i in self.packets:
            print(i)
        return self.packets
    
