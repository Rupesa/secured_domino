import socket

class Network:
    def __init__(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server = socket.gethostbyname('localhost')
        self.port = 5555
        self.addr = (self.server, self.port)
        self.stack = []
        self.stack.append(self.connect())

    def connect(self):
        try:
            self.client.connect(self.addr)
            return self.client.recv(2048).decode()
        except:
            pass

    def send(self, data):
        try:
            self.client.send(str.encode(data))
            return ""
        except socket.error as e:
            print(e)
            
    def send2(self,data):
        try:
            self.client.send(data)
            return ""
        except socket.error as e:
            print(e)

    def recv(self):
        try:
            return self.client.recv(16384).decode()
        except socket.error as e:
            print(e)
            return ""

    def recv2(self,size):
        try:
            return self.client.recv(size)
        except socket.error as e:
            print(e)
            return 

#n = Network()
#print(n.send("1"))
