import pyshark
import pandas 
import csv
client_ip = "192.168.56.102"
server_ip = "192.168.56.103"

previous_packet_time = None

capture = pyshark.FileCapture(
    input_file='data/shortCommand_ls_01.pcap', 
    display_filter='tcp.port == 22'
)

for packet in capture:
    
   if packet.ip.src == client_ip and packet.ip.dst == server_ip:
    direction = "client to server"

   elif packet.ip.src == server_ip and packet.ip.dst == client_ip:
      direction = "server to client"

   if previous_packet_time is None:
      time_difference = 0 
   else:
      time_difference = (packet.sniff_time - previous_packet_time).total_seconds()
   
   previous_packet_time = packet.sniff_time

   print(f'packet_length = {packet.length},'
      f'timestamp = {packet.sniff_time},'
      f'source_ip = {packet.ip.src},'
      f'destination_ip = {packet.ip.dst},'
      f'time_difference = {time_difference},'
      f'direction = {direction}')
   
   filename = "shortCommand_ls_01.csv"
   with open(filename, 'a') as csvfile:
      csvwriter = csv.writer(csvfile)
      csvwriter.writerow(['packet_length', 'timestamp', 'source_ip', 'destination_ip', 'time_difference', 'direction'])

      csvwriter.writerow([packet.length, packet.sniff_time, packet.ip.src, packet.ip.dst, time_difference, direction]) 

capture.close()
