from scapy.all import *


class Sniffed():
    def __init__(self):
        
        self.pcap_file = None
        self.packet_frame = {
            'ip_dest': None,
            'ip_src': None,
            'payload': None,
            'seq_number': None,
            'ack_number': None,
            'port_dst': None,
            'port_src': None,
            'flags': None,
            'mac_src': None,
            'mac_dst': None,
        }
    def dat_input(self, data, typedat):
        x= str(typedat)
        self.packet_frame[x] = data
    
    def pcap_write(self, data):
        pkt = PcapWriter("Data.pcap", append=True)
        pkt.write(data)

    def pcap_read(self, pcapfile):
        fn= str(pcapfile)
        reader= rdpcap(fn)
        return reader

    def get_data(self, datatype):
        x=datatype
        if datatype == 'payload' and not None:
            return hexstr(self.packet_frame[x])
        
        elif not None:
            return str(self.packet_frame[x])
        
        else:
            print('None')
    
    def __str__(self):
        return str(self.packet_frame)






