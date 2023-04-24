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
                # Define the data frame that the class would handle based on keys
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

    def follow_tcp_stream1(self, packetlyst, src_port, dst_port):
        print('Following TCP STREAM')
        stream_dict = {}

        # group packets by connection
        for pkt in packetlyst:
            if pkt.haslayer(TCP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                seq = pkt[TCP].seq
                key = (src_ip, dst_ip, sport, dport)

                # add new connection to dictionary
                if key not in stream_dict:
                    stream_dict[key] = []
                stream_dict[key].append(pkt)

        # sort packets by sequence number and concatenate payloads
        for key, pkts in stream_dict.items():
            pkts.sort(key=lambda x: x[TCP].seq)
            stream = b''
            for pkt in pkts:
                stream += bytes(pkt[TCP].payload)
            print(f'TCP STREAM {key[0]}:{key[2]} -> {key[1]}:{key[3]}')
            print(stream.decode('utf-8', errors='ignore'))

    def follow_tcp_stream(self, packetlyst, src_port, dst_port, seq_num):
        print('-------------------------------------------------------------------------------------------------------------------')
        print('-------------------------------------------------------------------------------------------------------------------')
        print('-------------------------------------------------------------------------------------------------------------------')
        print('Following TCP STREAM')
        print('-------------------------------------------------------------------------------------------------------------------')
        print('-------------------------------------------------------------------------------------------------------------------')
        print('-------------------------------------------------------------------------------------------------------------------')
        print(f'{src_port},{dst_port},{seq_num}')
        exchange = ''
        tcp_packets= list()
        for pkts in packetlyst:
            # Filter the based on src/dst port and seq number 
            if str(pkts[TCP].sport) == src_port and str(pkts[TCP].dport) == dst_port and str(pkts[TCP].seq) == seq_num:
                exchange += str(f'{str(pkts[TCP].sport)} -----> {str(pkts[TCP].dport)} (SEQ #: {str(pkts[TCP].seq)} ) (ACK #:{str(pkts[TCP].ack)})' + '\n')
                print('-------------------------------------------------------------------------------------------------------------------')
                print(f'--------CONNECTION::{str(pkts[TCP].sport)} -----> {str(pkts[TCP].dport)} (SEQ #: {str(pkts[TCP].seq)} )--------')
                print('-------------------------------------------------------------------------------------------------------------------')
                print('---------------------------------------------------PAYLOAD---------------------------------------------------------')
                if isinstance(pkts[TCP].payload, NoPayload):
                    print('No Payload')
                else:
                    rawpayload=bytes(pkts[TCP].payload)
                    #print(rawpayload.decode('utf-8', errors='ignore'))
                    print(rawpayload)

            # reverse the filter so you can filter the acknowledgement packets
            elif str(pkts[TCP].sport) == dst_port and str(pkts[TCP].dport) == src_port and str(pkts[TCP].ack) == seq_num:
                exchange += str(f'{str(pkts[TCP].sport)} <----- {str(pkts[TCP].dport)} (SEQ #: {str(pkts[TCP].ack)} )(ACK #:{str(pkts[TCP].seq)})' + '\n')
                print('-------------------------------------------------------------------------------------------------------------------')
                print(f'--------CONNECTION:{str(pkts[TCP].sport)} <----- {str(pkts[TCP].dport)} (ACKNOWLEDGED SEQ #: {str(pkts[TCP].ack)}) (ACK #:{str(pkts[TCP].seq)})--------')
                print('-------------------------------------------------------------------------------------------------------------------')
                print('---------------------------------------------------PAYLOAD---------------------------------------------------------')
                if isinstance(pkts[TCP].payload, NoPayload):
                    print('No Payload')
                else:
                    rawpayload=bytes(pkts[TCP].payload)
                    #print(rawpayload.decode('utf-8', errors='ignore'))
                    print(rawpayload)
    
                

        #tcp_packets = [pkt for pkt in packetlyst if TCP in pkt and pkt[TCP].sport == src_port and pkt[TCP].dport == dst_port and pkt[TCP].seq == seq_num]
        return exchange
    
    def start(self):
        if self.tcp:
            if self.port is None:
                sniff(filter= "tcp", prn = self.sniffer,promisc=True, count= 100)
            else:
                sniff(filter="tcp and port "+self.port, count= 20, promisc=True, prn=self.sniffer)
        elif self.udp:
            sniff(filter="udp", prn=self.sniffer, count=10)

        elif self.nofilters:
            sniff(filter= "tcp", prn = self.sniffer, promisc=True, count= 100)


    
    def get_result(self):
        '''
        for i in self.item_collection:
            print(i)
        '''
        return self.item_collection
        
    
    def getpkt(self):
        '''
        for i in self.packets:
            print(i)
        '''
        return self.packets
    
