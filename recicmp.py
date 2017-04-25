
from time import time
from socket import *

sockets = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP)
sockets.setsockopt(SOL_IP, IP_HDRINCL, 1)    
sockets.bind(("192.168.114.142", 1234))  #binding to port

while True:
    message = sockets.recvfrom(1024)      #receiving from client
    # sockets.sendto(message,address)
    print (message)                #sending back to client 	 



