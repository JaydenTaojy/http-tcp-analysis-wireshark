import dpkt
import math
import pandas as pd
import matplotlib.pyplot as plt
import struct

class InValidPacket(Exception):
    pass

packets = [] #store the list of parsed packets
flows=[]   #store the list of processed flows

class Packet:
    #Encapsulate TCP's header fields of a packet from pcap.
    def __init__(self, time, buff):
        #Init a packet
        self.time_stamp = time
        self.byte_info  = buff
        self.size = len(buff)
        self.isValid = True

    #pass the buff byte by byte to get the packet info
    def parse_info(self):
      try:
        #Convert the byte format information of a packet into human readable fields
        self.source_port = int(struct.unpack('>H', self.byte_info[34:36])[0])
        self.dest_port= int(struct.unpack('>H', self.byte_info[36:38])[0])
        self.sequence_num = int(struct.unpack('>I', self.byte_info[38:42])[0])
        self.ack_num= int(struct.unpack('>I', self.byte_info[42:46])[0])
        self.head_len= 4*(int.from_bytes(self.byte_info[46:47], byteorder='big')>>4)
        flags = int.from_bytes(self.byte_info[47:48], byteorder='big')
        self.syn = (flags>>1)&1
        self.ack = (flags>>4)&1
        self.checksum    = int(struct.unpack('>H', self.byte_info[50:52])[0])
        self.urgent      = int(struct.unpack('>H', self.byte_info[52:54])[0])
        self.receive_win = int(struct.unpack('>H', self.byte_info[48:50])[0])
        self.payload     = len(self.byte_info[34+packet.head_len:])
        self.mss = int(struct.unpack('>H', self.byte_info[56:58])[0])
      except:
        self.isValid=False
        
    def parse_window_scale(self):
        shift = int.from_bytes(self.byte_info[73:74], byteorder='big')
        self.scale = 1<<shift

class Flow:
    #Encapsulate a flow of packets from one port of sender to another port of receiver
    
    def __init__(self, packet):
        self.port1 = packet.source_port
        self.port2 = packet.dest_port
        self.packets  = []   # all packets
        self.source_packets=[] #packets sent by sender
        self.dest_packets  = []   #packets sent by reciever
        self.scale   = 1
        #self.mss=packet.mss
        #print('mss is {}'.format(self.mss))
    
    def mss(self):
        self.mss=self.dest_packets[0].mss
        #print(self.mss)
        print('mss is {}'.format(self.mss))
        
    def B2(self):
        time_stamp=[]
        for packet in self.source_packets:
            time_stamp.append(packet.time_stamp)
        start=time_stamp[0]
        time_stamp.pop(0)
        time_stamp.pop(0)
        for i in range(len(time_stamp)):
            time_stamp[i]=time_stamp[i]-start
        mybin=[0, 0.08, 0.16, 0.24, 0.32, 0.40, 0.48, 0.56, 0.64, 0.72, 0.80, 0.88, 0.96]
        window_list=[]
        for i in range(len(mybin)-1):
           window_size=0
           for ts in time_stamp:
               if ts>mybin[i] and ts<mybin[i+1]:
                   window_size+=1
           if window_size:
               window_list.append(window_size)
        print(window_list)
        n=range(len(window_list))
        plt.bar(n,window_list)
        plt.show()
        cwns=[] #window_list*self.mss
        for window in window_list:
           cwn=window*self.mss
           cwns.append(cwn)
        print(cwns)
       
if __name__ == '__main__':

    f = open('assignment2.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    
    #initialize and parse the packets
    for time, buff in pcap:
        packet = Packet(time, buff)
        packet.parse_info()
        #if packet.isValid:
        packets.append(packet)
           
    #compute the number of flows, and initialize the the flow lists
    flow_counter = 0
    for packet in packets:
        if (packet.syn==1 and packet.ack==0):
            flow_counter+=1
            flow = Flow(packet)
            flows.append(flow)
        
    print('\nThere are {} TCP flows initiated from the sender\n'.format(flow_counter))
    
    #add packets to folws it should belong to, packets defines the all packets, source_packets defines packets sent by sender, dest_packets define sent by reciever
    for packet in packets:
        for index in range(0,len(flows)):
            if ((int(packet.source_port) == flows[index].port1) and (packet.dest_port == flows[index].port2)):
               flows[index].packets.append(packet)
               flows[index].source_packets.append(packet)
            elif ((int(packet.source_port) == flows[index].port2) and (packet.dest_port == flows[index].port1)):
                flows[index].packets.append(packet)
                flows[index].dest_packets.append(packet)
    for flow in flows:
       flow.mss()
       flow.B2()
   
    f.close
