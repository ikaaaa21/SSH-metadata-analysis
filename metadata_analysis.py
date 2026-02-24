import pyshark
import pandas as pd #this is a data analysis library 
import csv

client_ip = "192.168.56.102" # this is my client VM's IP address
server_ip = "192.168.56.103" # this is my server VM's IP address

previous_packet_time = {} # the inital previous packet 

# read the pcap file and filter for TCP packets on port 22 (SSH)
capture = pyshark.FileCapture(
    input_file='data/typedCommand_whoami_01.pcap', 
    display_filter='tcp.port == 22'
)

# open a CSV file
csv_file = "typedCommand_whoami_01.csv"

with open(csv_file, 'w', newline='') as csvfile:
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
print(f"Metadata extracted and saved to {csv_file}")

# typing vs pasting commands

df = pd.read_csv("typedCommand_whoami_01.csv") # loads the CSV file into a pandas DataFrame

# we only want to analyse the client to server packets so this is a filter
#.copy prevents panda warning issues 
client_df =df[df['direction'] == 'client to server'].copy() 

keystroke_length = 60 #bytes
paste_length = 0.01 #seconds

def typingPasting(row): #check every row
   if row['packet_length'] <= keystroke_length and row['time_difference'] > paste_length:
      return "typing"
   elif row['packet_length'] > keystroke_length or row['time_difference'] <= paste_length:
      return "pasting"
   else:
      return "unknown"
   
client_df['input_method'] = client_df.apply(typingPasting, axis=1) # apply the function to each row 
print(client_df[['timestamp', 'packet_length', 'time_difference', 'input_method']])