import socket
import pickle
from scapy.all import IP

class IPFilterHandler:
    def __init__(self, port, server_address):
        self.port = port
        self.server_address = server_address
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('0.0.0.0', self.port))

    def start(self):
        print(f"IPFilterHandler listening on port {self.port}")
        while True:
            data, addr = self.sock.recvfrom(4096)
            packet = pickle.loads(data)  # Deserializar el paquete
            result = self.process_packet(packet)

            # Enviar resultado al servidor
            self.sock.sendto(result.encode(), self.server_address)

    def process_packet(self, packet):
        if packet.haslayer(IP):
            ip = packet.getlayer(IP)
            if self.is_allowed_ip(ip.src):
                print(f"Packet from {ip.src} allowed by IP filter.")
                return "Accepted"
            else:
                print(f"Packet from {ip.src} blocked by IP filter.")
                return "Rejected"
        else:
            print("Packet does not contain an IP layer.")
            return "Rejected"

    def is_allowed_ip(self, ip):
        allowed_ips = ['192.168.1.10', '10.0.0.5']
        return ip in allowed_ips

if __name__ == "__main__":
    server_address = ('127.0.0.1', 9999)  # IP y puerto del servidor del firewall
    handler = IPFilterHandler(port=9001, server_address=server_address)
    handler.start()
