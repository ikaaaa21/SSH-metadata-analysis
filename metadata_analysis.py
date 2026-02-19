import pyshark
import pandas 

client_ip = "192.168.56.102"
server_ip = "192.168.56.103"

capture = pyshark.FileCapture(
    input_file='data/shortCommand_ls_01.pcap', 
    display_filter='tcp.port == 22'
)

for packet in capture:
    
   if packet.ip.src == client_ip and packet.ip.dst == server_ip:
    direction = "client to server"

   elif packet.ip.src == server_ip and packet.ip.dst == client_ip:
      direction = "server to client"

   if previous_packet_time == 0:
      time_difference = (packet.sniff_time - 0).total_seconds()
   else:
      time_difference = (packet.sniff_time - previous_packet_time).total_seconds()
   
   previous_packet_time = packet.sniff_time

   print(f'packet_length = {packet.length},'
      f'timestamp = {packet.sniff_time},'
      f'source_ip = {packet.ip.src},'
      f'destination_ip = {packet.ip.dst},'
      f'time_difference = {time_difference},'
      f'direction = {direction}')

capture.close()
