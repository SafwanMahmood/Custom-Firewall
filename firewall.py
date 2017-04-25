import socket, sys
from struct import *
from Rules import *
import time
 
# for k,v in rules_table.items():
#     print(k,v)
opti = input("Optimized version of adding rules? 1. Yes 2. No")
try:
    opti = int(opti)
except ValueError:
    print ("Enter an integer as option")
if opti != 1 and opti != 2:
    print ("Wrong option, exiting")
    sys.exit(0) 
menu_on = True
while menu_on:
    option = input("What operation to be implemented in the rule table: 1. Add 2. Delete 3. Update 4. Print 5. Exit\n")
    try:
        option = int(option)
    except ValueError:
        print ("Enter an integer as option")
    if option == 1: #ADD
        first, second, third = rules_menu ()
        if first != -1 and second != -1 and third != -1:
            if opti == 1 and not optimize_rules(first, second, third):
                    print ("Redundant Rule, improvised or ignored!")
            elif opti == 1 and third1 in rules_table[first1][second1]:
                print ("Rule already exists!")
            else:
                rules_table[first][second].append(third)
        print ("Done Adding Rule:",first,second,third)
    elif option == 2: #DELETE
        first, second, third = rules_menu ()
        if first != -1 and second != -1 and third != -1:
            if opti == 1 and not optimize_rules(first, second, third):
                print ("Redundant Rule, improvised or ignored!")
            elif third in rules_table[first][second]:   
                rules_table[first][second].remove(third)
            else:
                print ("Rule to delete does not exist")
    elif option == 3: #UPDATE
        print ("Which rule do you want to update")
        first1, second1, third1 = rules_menu ()
        if first1 != -1 and second1 != -1 and third1 != -1:
            if third1 in rules_table[first1][second1]:  
                print ("What do you want to update in that rule")
                first2, second2, third2 = rules_menu ()
                if opti == 1 and third2 in rules_table[first2][second2]:
                    print ("Rule already exists!")
                else:
                    rules_table[first2][second2].append(third2) 
                    rules_table[first1][second1].remove(third1)     
            else:
                print ("Rule to update does not exist")
    elif option == 4: #PRINT
        print ("Printing current rules table:")
        print ("{") 
        for k, v in rules_table.items():
            print (k, v)
        print ("}")
    elif option == 5: #EXIT
        print ("Exiting")
        break
    else: #WRONG OPTION
        print ("Wrong option")
     
#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b
 
#create a AF_PACKET type raw socket (thats basically packet level)
#define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
    start = time.time() 
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()
mega_cache = dict()
count1=0
#cache =[-1,-1,-1,-1,-1,-1]
#cache1 =[-1,-1,-1,-1,-1,-1] 
#cache2 =[-1,-1,-1,-1,-1,-1]
# receive a packet'
prev = time.time()
while True:
    packet = s.recvfrom(65565)
              
    #packet string from tuple
    packet = packet[0]
     
    #parse ethernet header
    eth_length = 14
     
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    a= False    
    #print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)
    
    if len(packet)>0 and eth_addr(packet[6:12]) == '74:e6:e2:36:9b:f0' and eth_addr(packet[0:6]) == '08:00:27:21:f1:bc':    
        count1 = count1 + 1
    now = time.time()                            #throughput logic
    if now-prev >=1 :
            #count1 = count1 + 1
        # print count1
        prev = now
        count1=0     
    #Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8 :
        #Parse IP header
        #take first 20 characters for the ip header
        ip_header = packet[eth_length:28+eth_length]
         
        #now unpack them :)
        iph = unpack('!HHIIHHHHHHHH' , ip_header)
    #print iph
        iph_length = iph[2]
        version=iph[0]
        ttl = iph[3]
        protocol = iph[1]
    #print(protocol)
        s_addr = str(iph[8])+'.'+str(iph[9])+'.'+str(iph[10])+'.'+str(iph[11]);
        d_addr = str(iph[4])+'.'+str(iph[5])+'.'+str(iph[6])+'.'+str(iph[7]);
        
        #print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
 
        #TCP protocol
        if protocol == 6 :
            t = iph_length + eth_length
            tcp_header = packet[t:t+12]

            #now unpack them :)
            tcph = unpack('!HHLL' , tcp_header)
            print(tcph)                 
            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            #doff_reserved = tcph[4]
            #tcph_length = doff_reserved >> 4
             
            #print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)
            tcph_length = 12 
            h_size = eth_length + iph_length + tcph_length
            data_size = len(packet) - h_size
             
            #get data from the packet
            data = packet[h_size:]
            if eth_addr(packet[6:12]) == '74:e6:e2:36:9b:f0' and eth_addr(packet[0:6]) == '08:00:27:21:f1:bc':             
                print 'Data : ' + data
                print("Packet from: ",s_addr," source address ","to ",d_addr,dest_port)
            #print source_port
            cache = ('INCOMING','TCP',source_port,eth_addr(packet[6:12]),s_addr)
            if opti==1 and cache in mega_cache and mega_cache[cache]:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
             
                addr = (d_addr,dest_port)
        
                sock.connect(addr)
                sock.sendall(packet)
                print("Packet already verified\n")
            else:

                    if verify_rules('INCOMING','TCP',source_port) and verify_rules('INCOMING','MAC',eth_addr(packet[6:12])) and verify_rules('INCOMING','IPv4',s_addr)==True:       
                
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
             
                        addr = (d_addr,dest_port)
        
                        sock.connect(addr)
                        sock.sendall(packet)
                        print("Packet verified\n")
                        save = True
                    else:
                        save = False
                        continue
            mega_cache[cache] = save
        
                            

        #ICMP Packets
        elif protocol == 1 :
            u = iph_length + eth_length
            icmph_length = 4
            icmp_header = packet[u:u+4]

            #now unpack them :)
            icmph = unpack('!BBH' , icmp_header)
             
            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]
             
            #print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)
             
            h_size = eth_length + iph_length + icmph_length
            data_size = len(packet) - h_size
             
            #get data from the packet
            data = packet[h_size:]
             
            if eth_addr(packet[6:12]) == '74:e6:e2:36:9b:f0' and eth_addr(packet[0:6]) == '08:00:27:21:f1:bc':                
                print 'Data : ' + data
                print("Packet from: ",s_addr," source address ","to ",d_addr,dest_port)
            #print source_port
            cache = ('INCOMING','ICMP',source_port,eth_addr(packet[6:12]),s_addr)
            if opti==1 and cache in mega_cache and mega_cache[cache]:
                sockets = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
                dest_port = 5556
                addr = (d_addr,dest_port)       
                sockets.sendto(packet,addr)
                print("Packet already verified")
            else:
                if verify_rules('INCOMING','ICMP',source_port) and verify_rules('INCOMING','MAC',eth_addr(packet[6:12])) and verify_rules('INCOMING','IPv4',s_addr)==True:      
                    
                    sockets = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
                    dest_port = 5556
                    addr = (d_addr,dest_port)       
                    sockets.sendto(packet,addr)
                    print("Packet verified")
                    save = True
                else:
                    save = False    
                    continue    
            mega_cache[cache] = save        


        #UDP packets
        elif protocol == 17 :
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u+8]

            #now unpack them :)
            udph = unpack('!HHHH' , udp_header)
             
            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]
             
            #print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)
             
            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size
             
            #get data from the packet
            data = packet[h_size:]
            if eth_addr(packet[6:12]) == '74:e6:e2:36:9b:f0' and eth_addr(packet[0:6]) == '08:00:27:21:f1:bc':                
                print 'Data : ' + data
                print("Packet from: ",s_addr," source address ","to ",d_addr,dest_port)
            # print source_port
            cache = ('INCOMING','UDP',source_port,eth_addr(packet[6:12]),s_addr)    
            if opti==1 and cache in mega_cache and mega_cache[cache]:
                socketC = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                addr = (d_addr,dest_port)       
                socketC.sendto(packet,addr)
                print("Packet already verified\n") 
            else:

                if verify_rules('INCOMING','UDP',source_port) and verify_rules('INCOMING','MAC',eth_addr(packet[6:12])) and verify_rules('INCOMING','IPv4',s_addr)==True:       
                     
                    socketC = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    addr = (d_addr,dest_port)       
                    socketC.sendto(packet,addr)
                    print("Packet verified\n")
                    save = True
                else:
                    save = False
                    continue  
            mega_cache[cache] = save

        