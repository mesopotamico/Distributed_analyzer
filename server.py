import socket
import pickle
from scapy.all import sniff
import os


class Firewall:
    def __init__(self, handler_addresses, response_port):
        self.handler_addresses = handler_addresses
        self.response_port = response_port
        self.response_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.response_socket.bind(('0.0.0.0', self.response_port))

    def process_packet(self, packet):
        serialized_packet = pickle.dumps(packet)

        # Enviar el paquete a cada handler
        for address in self.handler_addresses:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(serialized_packet, address)

        print("Packet sent to all handlers for parallel processing.")

        # Escuchar respuestas de los handlers
        for _ in self.handler_addresses:
            response, addr = self.response_socket.recvfrom(1024)
            print(f"Response from {addr}: {response.decode()}")

def main():
    handler_addresses = [
        ('127.0.0.1', 9001),  # IP y puerto del IPFilterHandler
        ('192.168.1.11', 9002),  # IP y puerto del PortFilterHandler
        ('192.168.1.12', 9003),  # IP y puerto del ProtocolFilterHandler
        ('192.168.1.13', 9004),  # IP y puerto del LoggingHandler
        ('192.168.1.14', 9005)   # IP y puerto del StatefulHandler
    ]
    response_port = 9999  # Puerto en el que el firewall escuchará las respuestas

    firewall = Firewall(handler_addresses, response_port)

    def packet_callback(packet):
        firewall.process_packet(packet)
        print("Processed packet in parallel.")

    print("Starting the firewall...")
    sniff(prn=packet_callback, count= 3)

if __name__ == "__main__":
    main()
