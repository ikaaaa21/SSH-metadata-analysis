import pyshark
import pandas 

capture = pyshark.FileCapture(input_file='data/shortCommand_ls_01.pcap', display_filter='tcp.port == 22')

for packet in capture:
   # do something with the packet
    print(packet.length,packet.sniff_time, packet.ip.src, packet.ip.dst)