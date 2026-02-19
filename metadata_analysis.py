import pyshark
import pandas 

capture = pyshark.FileCapture(
    input_file='data/shortCommand_ls_01.pcap', 
    display_filter='tcp.port == 22'
)

for packet in capture:
    print(f'packet_length = {packet.length},'
      f'timestamp = {packet.sniff_time},'
      f'source_ip = {packet.ip.src},'
      f'destination_ip = {packet.ip.dst}')

client_ip = "192.168.56.102"
server_ip = "192.168.56.103"

if packet.ip.src == client_ip and packet.ip.dst == server_ip:
    print("Packet from client to server")
elif packet.ip.src == server_ip and packet.ip.dst == client_ip:
    print("Packet from server to client")
