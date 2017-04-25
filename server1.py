import socket
from thread import *
import struct

try:
	sockets = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.ntohs(0x0800))
	interface="eth0"
	sockets.bind((interface,socket.ntohs(0x0800)))
	src_mac = [0x08,0x00,0x27,0x21,0xf1,0xbc,0x74,0xe6,0xe2,0x36,0x9b,0xf0,0x08,0x00]
	payload = "".join(map(chr,src_mac))
        source = "192.168.114.142"
        dest = "192.168.114.142"
        list_d=[]
        ss = ""
        for i in range(0,len(dest)):
                if dest[i]=='.':
                        list_d.append(int(ss))
                        ss=""
                else:
                        ss = ss+dest[i]
                        if i==len(dest)-1:
                                list_d.append(int(ss))
        ss = ""
        list_s=[]
        for i in range(0,len(source)):
                if source[i]=='.':
                        list_s.append(int(ss))
                        ss=""
                else:
                        ss = ss+source[i]
                        if i==len(source)-1:
                                list_s.append(int(ss))
        
        srcport = 5651
        dstport = 1234
        syn=0
        ack=0
	header = struct.pack('!HHIIHHHHHHHH',4,17,28,20,list_d[0],list_d[1],list_d[2],list_d[3],list_s[0],list_s[1],list_s[2],list_s[3])
	tcp = struct.pack('!HHLL',srcport,dstport,syn,ack)
        udp= struct.pack('!HHHH',srcport,dstport,0,0)
        icmp = struct.pack('!BBH',9,0,1000)
        i=0
        while i!=10000:
        	pass
        	# msg = raw_input("Enter msg")
        	msg = str(i)
        	sockets.send(payload+header+udp+msg)
        	i=i+1

	print "Message sent to destination"
except Exception as e:
	print e 
	print "error"


