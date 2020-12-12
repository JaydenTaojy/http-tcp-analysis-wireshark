import dpkt
import math
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
        self.mss=packet.mss
        
    def print_first_2_transaction(self):
        index = 0
        for packet in self.packets:
            index += 1
            if packet.syn == 1 and packet.ack== 0:
                packet.parse_window_scale()
                self.scale = packet.scale
            elif packet.syn == 1 and packet.ack == 1:
                continue
            elif packet.syn == 0 and packet.ack== 1:
                break
                
        sender_1 = self.packets[index]
        sender_2 = self.packets[index+1]
        payload_1 = sender_1.payload
        payload_2 = sender_2.payload
        seq_1     = sender_1.sequence_num
        seq_2     = sender_2.sequence_num
        ack_1     = seq_1 + payload_1
        ack_2     = seq_2 + payload_2
        receiver_1, receiver_2 = None, None
        
        for packet in self.packets:
            if (receiver_1 != None and receiver_2 != None):
                break
            if packet.ack_num == ack_1:
                receiver_1 = packet
            elif packet.ack_num == ack_2:
                receiver_2 = packet
        print('Task A-2-1:')
        print('Transaction 1:')
        print('Sender:  sequence  = {}  acknowledge  = {}  receive window = {}'.format(sender_1.sequence_num, sender_1.ack_num, sender_1.receive_win))
        print('Receiver: sequence  = {}  acknowledge  = {}  receive window = {}'.format(receiver_1.sequence_num, receiver_1.ack_num, receiver_1.receive_win))
        
        print('Transaction 2:')
        print('Sender:  sequence  = {}  acknowledge  = {}  receive window = {}'.format(sender_2.sequence_num, sender_2.ack_num, sender_2.receive_win))
        print('Receiver: sequence  = {}  acknowledge  = {}  receive window = {}'.format(receiver_2.sequence_num, receiver_2.ack_num, receiver_2.receive_win))
        
    def compute_throughput(self):
        
        data_size = 0
        for packet in self.source_packets:
            data_size += packet.size
        elapse =self.source_packets[len(self.source_packets)-1].time_stamp-self.source_packets[0].time_stamp
        self.throughput_emp = (data_size*8.0)/(elapse*1000000)
        print('Task A-2-2:')
        print('Throughput is {0:1.5f} Mbps\n'.format(self.throughput_emp))
        
        
    def compute_loss_rate(self):
       
        seq_counter = {}
        for packet in self.source_packets:
            seq = packet.sequence_num
            if not (seq_counter.get(seq)):
                seq_counter[seq]=1
            else:
                seq_counter[seq]+= 1
                
        total_send = 0
        for counter in seq_counter.values():
            total_send += counter
        retransmission = total_send - len(seq_counter) - 1
        self.loss_rate = retransmission*1.0/len(self.source_packets)
        
        print('Task A-2-3:')
        print('The packets sent of this flow is {}'.format(len(self.source_packets)))
        print('The loss of this flow is {}'.format(retransmission))
        print('Hence the loss rate is {0:1.5f}\n'.format(self.loss_rate))
        
    def compute_dta_timeout(self):
           #for task B-2
           sender_dic,receiver_dic, retransmit_dic= {},{},{}    #  {seq --> [packet]}  {ack --> [packet]} {seq --> [packet]}
           for packet in self.source_packets:   # sender's packet
               seq =packet.sequence_num
               packet_list = sender_dic.get(seq)
               if not packet_list:
                   sender_dic[seq] = [packet]
               else:
                   packet_list.append(packet)
           for packet in self.dest_packets:                        # receiver's packet
               packet_list = receiver_dic.get(packet.ack_num)
               if not packet_list:
                   receiver_dic[packet.ack_num] = [packet]
               else:
                   packet_list.append(packet)
                       
           for seq, packet_list in sender_dic.items():  # get the retrasmitted packets
               if len(packet_list) > 1:
                   retransmit_dic[seq] = packet_list
                   
           tda_counter = 0  # triple duplicate ack counter
           for seq, packet_list in retransmit_dic.items():
               ack = seq
               timestamp_1 = packet_list[0].time_stamp # from data, oberserve no retransmission twice
               timestamp_2 = packet_list[1].time_stamp
               packet_list = receiver_dic.get(ack)
               if packet_list:
                   ack_counter = 0
                   for packet in packet_list:
                       timestamp = packet.time_stamp
                       if timestamp > timestamp_1 and timestamp < timestamp_2:
                           ack_counter += 1
                       if ack_counter >3:
                           tda_counter += 1
                           break
           self.tda = tda_counter
           total_retransmission = len(retransmit_dic)-1
           self.timeout = total_retransmission - self.tda
           print('Task B-2:')
           print('Number of triple duplicate ack = {}'.format(self.tda))
           print('Number of timeout = {}\n'.format(self.timeout))
        
    def estimateRTT(self):
        
        payload = 1448       # 1448 is the max amount of payload in a TCP segment
        sender_dic,sender_dic_ret, receiver_dic = {},{},{}
        for packet in self.packets:
            if packet.source_port == self.port1:  # sender --> receiver
                seq = packet.sequence_num
                if sender_dic.get(seq):    # retransmmision happened, remove the items for computing rtt
                    sender_dic_ret[seq] = packet
                    sender_dic.pop(seq)
                elif sender_dic_ret.get(seq):  # retransmmision happened twice
                    sender_dic_ret[seq] = packet
                else:
                    sender_dic[seq] = packet
            else:                          # receiver --> sender
                receiver_dic[packet.ack_num] = packet
                
        total_time,counter = 0,0
        for ack, ack_packet in receiver_dic.items():
            seq_packet = sender_dic.get(ack - payload)
            if seq_packet:
                counter += 1
                total_time += (ack_packet.time_stamp - seq_packet.time_stamp)
        self.rtt = total_time/counter
        print('Task A-2-4:')
        print('Estimated RTT is {0:1.5f} second'.format(self.rtt))
        try:
            self.throughput_the = (1460*8)/(self.rtt*math.sqrt(self.loss_rate))
            print('Theoretical throughput is {0:1.5f} Mbps\n'.format(self.throughput_the/1000000))
        except ZeroDivisionError as ze:
            print('Theoretical throughput is infinity')
        except Exception as e:
            print(e)
            
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
        #use syn and ack to identify the first packet of the flow
        if (packet.syn==1 and packet.ack==0):
            flow_counter+=1
            flow = Flow(packet)
            flows.append(flow)
        
    print('\n{} TCP flows are initiated from the sender\n'.format(flow_counter))
    
    #add packets to folws it should belong to, packets defines the all packets, source_packets defines packets sent by sender, dest_packets define sent by reciever
    for packet in packets:
        for index in range(0,len(flows)):
            if ((int(packet.source_port) == flows[index].port1) and (packet.dest_port == flows[index].port2)):
               flows[index].packets.append(packet)
               flows[index].source_packets.append(packet)
            elif ((int(packet.source_port) == flows[index].port2) and (packet.dest_port == flows[index].port1)):
                flows[index].packets.append(packet)
                flows[index].dest_packets.append(packet)
                
    #complete the required tasks for each flow:
    flow_no=1
    for flow in flows:
        print('These are the results for flow {}'.format(flow_no))
        flow.print_first_2_transaction()
        flow.compute_throughput()
        flow.compute_loss_rate()
        flow.estimateRTT()
        flow.compute_dta_timeout()
        flow_no+=1
    f.close
