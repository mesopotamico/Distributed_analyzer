import socket
import pickle
from scapy.all import IP

class PortFilterHandler:
    def __init__(self, port, server_address):
        self.port = port
        self.server_address = server_address
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', self.port))

    def start(self):
        print(f"PortFilterHandler listening on port {self.port}")
        while True:
            data, addr = self.sock.recvfrom(4096)
            packet = pickle.loads(data)
            result = self.process_packet(packet)
            self.sock.sendto(result.encode(), self.server_address)

    def process_packet(self, packet):
        # Aquí agregas la lógica de filtro de puerto
        print("PortFilterHandler processing packet.")
        return "Accepted"  # o "Rejected"

if __name__ == "__main__":
    server_address = ('127.0.0.1', 9999)
    handler = PortFilterHandler(port=9002, server_address=server_address)
    handler.start()
