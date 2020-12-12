import dpkt
import sys
import struct

class InValidPacket(Exception):
    pass

packets_80,packets_81,packets_82 = [],[],[] #store the list of parsed packets
flows_80,flows_81,flows_82=[],[],[]  #store the list of processed flows

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
      #parse the tcp info
      try:
        #Convert the byte format information of a packet into human readable fields
        self.source_port = int(struct.unpack('>H', self.byte_info[34:36])[0])
        self.dest_port= int(struct.unpack('>H', self.byte_info[36:38])[0])
        self.sequence_num = int(struct.unpack('>I', self.byte_info[38:42])[0])
        self.ack_num= int(struct.unpack('>I', self.byte_info[42:46])[0])
        self.head_len= 4*(int.from_bytes(self.byte_info[46:47], byteorder='big')>>4)
        flags = int.from_bytes(self.byte_info[47:48], byteorder='big')
        self.fin = flags&1
        self.syn = (flags>>1)&1
        self.ack = (flags>>4)&1
        self.checksum    = int(struct.unpack('>H', self.byte_info[50:52])[0])
        self.urgent      = int(struct.unpack('>H', self.byte_info[52:54])[0])
        self.receive_win = int(struct.unpack('>H', self.byte_info[48:50])[0])
        self.payload     = self.byte_info[34+packet.head_len:]
        self.mss = int(struct.unpack('>H', self.byte_info[56:58])[0])
        #self.httprequest=''
        #self.httpresponse=''
      except:
        self.isValid=False

class Flow:
    #Encapsulate a flow of packets from one port of sender to another port of receiver
    def __init__(self, packet):
        self.port1 = packet.source_port
        self.port2 = packet.dest_port
        self.packets  = []   # all packets
        self.source_packets=[] #packets sent by sender
        self.dest_packets  = []   #packets sent by reciever
        self.get_packets = []
        self.scale   = 1
        self.packet_dict = {}
        
    def preprocessC1(self):
        for packet in self.source_packets:       # find all the get packets
            if str(packet.payload).find('GET') != -1:
                self.get_packets.append(packet)
        for packet in self.packets:
            self.packet_dict[packet.sequence_num] = packet
    
    def reassemble_http(self):
        reassembles =[]
        for get in self.get_packets:
            reassemble = HTTP(get)
            next_seq = get.ack_num
            next_packet = self.packet_dict.get(next_seq) # start from the ack of GET request
            while next_packet:
                reassemble.add_tcp_segment(next_packet)
                payload_len = len(next_packet.payload)
                next_seq =next_seq + payload_len
                next_packet = self.packet_dict.get(next_seq)
                if next_packet.fin== 1:
                    break
            reassembles.append(reassemble)
    
        for reassemble in reassembles:
            reassemble.print_reassembleHTTP()
            
class HTTP:

    def __init__(self, get_packet):
        start = str(get_packet.payload).find('GET')
        end = str(get_packet.payload).find('Connection')
        self.request = str(get_packet.payload)[start:end]
        self.tcp_segment = []

    def print_reassembleHTTP(self):
        print(self.request)
        print('The TCP segments are below:')
        for segment in self.tcp_segment:
            print(segment)
    
    def add_tcp_segment(self, packet):
        self.tcp_segment.append((packet.source_port, packet.dest_port, packet.sequence_num, packet.ack_num))

            
def partC3(flow_list):
    smallest_time  = sys.maxsize
    largest_time, packet_counter, byte_counter=0,0,0
    for flow in flow_list:
        time0=flow.packets[0].time_stamp
        packet_1 = flow.packets[0]
        for packet_2 in flow.packets:
            time1 = packet_1.time_stamp
            time2 = packet_2.time_stamp
            if time2 - time1 > 2:
                break
            packet_1 = packet_2
        smallest_time = time0 if time0 < smallest_time else smallest_time
        largest_time  = time1 if time1 > largest_time else largest_time
        packet_counter += len(flow.dest_packets)
        data_from_server=0
        for packet in flow.dest_packets:
            data_from_server += len(packet.payload)
        byte_counter += data_from_server
    print('\nLoad time         = {0:4.4f} s'.format(largest_time - smallest_time))
    print('Number of packets = {}'.format(packet_counter))
    print('Raw bytes         = {} byte'.format(byte_counter))
    
def partC2(flows_list):
    secure_data, flow_counter, total_data= 3500,0,0     # typical amount of data for SSL key exchange number of flow that actually send website data, not merely SSL data
    flow_server_data = []
    for flow in flows_list:
        data_from_server=0
        for packet in flow.dest_packets:
            data_from_server += len(packet.payload)
        flow_server_data.append(data_from_server)
    for data in flow_server_data:
        if data > secure_data:
            flow_counter += 1
        total_data += data
    print('\nTotal data sent: {}'.format(total_data))
    print('\nThe number of TCP connection opened on server side is {}.'.format(flow_counter))
    
    #if flow_counter < len(flow_server_data):
    #    print('1 TCP connection opened merely for TLS key exchange')
    if flow_counter > 1:
        print('\nThis is HTTP/1.1 as it uses parallel TCP connections')
    else:
        print('\nThis is HTTP/2.0 as it uses single TCP connection')
        
if __name__ == '__main__':
    f_80= open('http_1080.pcap', 'rb')
    pcap_80 = dpkt.pcap.Reader(f_80)
    
    #initialize and parse the packets
    for time, buff in pcap_80:
        packet = Packet(time, buff)
        packet.parse_info()
        #if packet.isValid:
        packets_80.append(packet)
           
    #compute the number of flows, and initialize the the flow lists
    flow_counter = 0
    for packet in packets_80:
        if (packet.syn==1 and packet.ack==0):
            flow_counter+=1
            flow = Flow(packet)
            flows_80.append(flow)
        
    #print('\nThere are {} TCP flows initiated from the sender\n'.format(flow_counter))
    
    #add packets to folws it should belong to, packets defines the all packets, source_packets defines packets sent by sender, dest_packets define sent by reciever
    for packet in packets_80:
        for index in range(0,len(flows_80)):
            if ((int(packet.source_port) == flows_80[index].port1) and (packet.dest_port == flows_80[index].port2)):
               flows_80[index].packets.append(packet)
               flows_80[index].source_packets.append(packet)
            elif ((int(packet.source_port) == flows_80[index].port2) and (packet.dest_port == flows_80[index].port1)):
                flows_80[index].packets.append(packet)
                flows_80[index].dest_packets.append(packet)
    for flow in flows_80:
        flow.preprocessC1()
    print('Task C1:')
    for flow in flows_80:
        flow.reassemble_http()
    f_80.close
    
    f_81= open('http_1081.pcap', 'rb')
    pcap_81 = dpkt.pcap.Reader(f_81)
       
       #initialize and parse the packets
    for time, buff in pcap_81:
        packet = Packet(time, buff)
        packet.parse_info()
        #if packet.isValid:
        packets_81.append(packet)
              
       #compute the number of flows, and initialize the the flow lists
    flow_counter = 0
    for packet in packets_81:
        if (packet.syn==1 and packet.ack==0):
            flow_counter+=1
            flow = Flow(packet)
            flows_81.append(flow)
           
    #print('\nThere are {} TCP flows initiated from the sender\n'.format(flow_counter))
       
       #add packets to folws it should belong to, packets defines the all packets, source_packets defines packets sent by sender, dest_packets define sent by reciever
    for packet in packets_81:
        for index in range(0,len(flows_81)):
            if ((int(packet.source_port) == flows_81[index].port1) and (packet.dest_port == flows_81[index].port2)):
                flows_81[index].packets.append(packet)
                flows_81[index].source_packets.append(packet)
            elif ((int(packet.source_port) == flows_81[index].port2) and (packet.dest_port == flows_81[index].port1)):
                flows_81[index].packets.append(packet)
                flows_81[index].dest_packets.append(packet)
    f_81.close
    partC2(flows_81)
    
    f_82= open('http_1082.pcap', 'rb')
    pcap_82 = dpkt.pcap.Reader(f_82)
          
          #initialize and parse the packets
    for time, buff in pcap_82:
        packet = Packet(time, buff)
        packet.parse_info()
        #if packet.isValid:
        packets_82.append(packet)
                 
          #compute the number of flows, and initialize the the flow lists
    flow_counter = 0
    for packet in packets_82:
        if (packet.syn==1 and packet.ack==0):
            flow_counter+=1
            flow = Flow(packet)
            flows_82.append(flow)
              
       #print('\nThere are {} TCP flows initiated from the sender\n'.format(flow_counter))
          
          #add packets to folws it should belong to, packets defines the all packets, source_packets defines packets sent by sender, dest_packets define sent by reciever
    for packet in packets_82:
        for index in range(0,len(flows_82)):
            if ((int(packet.source_port) == flows_82[index].port1) and (packet.dest_port == flows_82[index].port2)):
                flows_82[index].packets.append(packet)
                flows_82[index].source_packets.append(packet)
            elif ((int(packet.source_port) == flows_82[index].port2) and (packet.dest_port == flows_82[index].port1)):
                flows_82[index].packets.append(packet)
                flows_82[index].dest_packets.append(packet)
    f_82.close
    partC2(flows_82)
    partC3(flows_80)
    partC3(flows_81)
    partC3(flows_82)
