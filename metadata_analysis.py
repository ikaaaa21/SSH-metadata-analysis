import pyshark
import pandas 
import csv

client_ip = "192.168.56.102"
server_ip = "192.168.56.103"

previous_packet_time = {}

capture = pyshark.FileCapture(
    input_file='data/shortCommand_ls_01.pcap', 
    display_filter='tcp.port == 22'
)

filename = "shortCommand_ls_01.csv"

with open(filename, 'a', newline='') as csvfile:
   csvwriter = csv.writer(csvfile)

   csvwriter.writerow([
      'packet_length', 'timestamp', 'source_ip', 
      'destination_ip', 'time_difference', 'direction'
   ])

   for packet in capture:
      try:
         if int(packet.tcp.srcport) == 22:
            direction = "client to server"

         elif int(packet.tcp.dstport) == 22:
            direction = "server to client"


         if packet.sniff_time not in previous_packet_time:
            time_difference = 0 
         else:
            time_difference = (packet.sniff_time - previous_packet_time[packet.sniff_time]).total_seconds()
      
         previous_packet_time[packet.sniff_time] = packet.sniff_time

         print(
            f'packet_length = {packet.length},'
            f'timestamp = {packet.sniff_time},'
            f'source_ip = {packet.ip.src},'
            f'destination_ip = {packet.ip.dst},'
            f'time_difference = {time_difference},'
            f'direction = {direction}'
         )
         
         csvwriter.writerow([
            packet.length,
            packet.sniff_time,
            packet.ip.src,
            packet.ip.dst,
            time_difference,
            direction
         ])

      except AttributeError:
         continue

capture.close()
