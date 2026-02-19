import pyshark
import pandas 
import csv

client_ip = "192.168.56.102" # this is my client VM's IP address
server_ip = "192.168.56.103" # this is my server VM's IP address

previous_packet_time = {} # the inital previous packet 

# read the pcap file and filter for TCP packets on port 22 (SSH)
capture = pyshark.FileCapture(
    input_file='data/shortCommand_ls_01.pcap', 
    display_filter='tcp.port == 22'
)

# open a CSV file
csv_file = "shortCommand_ls_01.csv"

with open(csv_file, 'a', newline='') as csvfile:
   csvwriter = csv.writer(csvfile)

   csvwriter.writerow([
      'stream', 'packet_length', 'timestamp', 'source_ip', 
      'destination_ip', 'time_difference', 'direction'
   ])
# loop through the filtered packets and extract the required metadata
   for packet in capture:
      try:

         stream = int(packet.tcp.stream)
         timestamp = packet.sniff_time
         source_ip = packet.ip.src
         destination_ip = packet.ip.dst  
         packet_length = int(packet.tcp.len)

         if int(packet.tcp.dstport) == 22:
            direction = "client to server"

         elif int(packet.tcp.srcport) == 22:
            direction = "server to client"


         if stream not in previous_packet_time:
            time_difference = 0.0
         else:
            time_difference = (
               timestamp - previous_packet_time[stream]
            ).total_seconds()
      
         previous_packet_time[stream] = timestamp

         print(
            f'stream: {stream}, tcp_len: {packet_length}, timestamp: {timestamp}, source_ip: {source_ip}, '
            f'destination_ip: {destination_ip}, time_difference: {time_difference},'
            f'direction: {direction}'
         )
         
         csvwriter.writerow([
            stream, packet_length, timestamp, source_ip, destination_ip, time_difference, direction
         ])

      except AttributeError:
         continue

capture.close()
