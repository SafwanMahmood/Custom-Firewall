from time import time
from socket import *

sockets = socket(AF_INET, SOCK_STREAM)
sockets.bind(("192.168.114.142", 1234))
sockets.listen(6)  #binding to port

while True:
	connec,address = sockets.accept()
	message = connec.recv(1024)
	print(message)               



