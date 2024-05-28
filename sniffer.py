import socket
from geoip import geolite2
from scapy.all import *
       ################
def get_serv(src_port,dst_port):
    try:
       service = socket.getservbyport(src_port)
    except :
       service = socket.getservbyport(dst_port)
       ################
def locate(ip):
    loc = geolite2.lookup(ip)
    if loc is not None :
       return loc.country , loc.timezone
    else :
       return None
         
       ################
def analyzer(pkt):
    if pkt.haslayer(TCP):
       print("- - - - - - - - - - - - - -")
       print("TCP Packet")
       src_ip = pkt[IP].src
       dst_ip = pkt[IP].dst
       ################
       
       loc_src = locate(src_ip)
       loc_dst = locate(dst_ip)
       
       ################
       mac_src = pkt.src
       mac_dst = pkt.dst
       #################
       src_port = pkt.sport
       dst_port = pkt.sport
       #################
       print("SRC-IP : " + src_ip)
       print("DST-IP : " + dst_ip)
       print("SRC-MAC : " + mac_src)
       print("DST-MAC : " + mac_dst)
       print("SRC-PORT : " + str(src_port) )
       print("DST-PORT : " + str(dst_port) )
       
       #################
       
       if pkt.haslayer(Raw) :
          print(pkt[Raw].load)
       print("- - - - - - - - - - - - - -")
       
    if pkt.haslayer(UDP):
       print("- - - - - - - - - - - - - -")
       print("UDP Packet")
      
       src_ip = pkt[IP].src
       dst_ip = pkt[IP].dst
       ################
       loc_src = locate(src_ip)
       loc_dst = locate(dst_ip)
      
       ################
       mac_src = pkt.src
       mac_dst = pkt.dst
       #################
       src_port = pkt.sport
       dst_port = pkt.sport 
       #################
       print("SRC-IP : " + src_ip)
       print("DST-IP : " + dst_ip)
       print("SRC-MAC : " + mac_src)
       print("DST-MAC : " + mac_dst)
       print("SRC-PORT : " + str(src_port) )
       print("DST-PORT : " + str(dst_port) )
      
       if pkt.haslayer(Raw) :
          print(pkt[Raw].load)
       print("- - - - - - - - - - - - - -")
       
       
    if pkt.haslayer(ICMP) :
       print("- - - - - - - - - - - - - -")
       print("ICMP Packet")
      
       src_ip = pkt[IP].src
       dst_ip = pkt[IP].dst
       ################
       loc_src = locate(src_ip)
       loc_dst = locate(dst_ip)
       
       #################
       mac_src = pkt.src
       mac_dst = pkt.dst
       #################
       src_port = pkt.sport
       dst_port = pkt.sport 
       #################
       print("SRC-IP : " + src_ip)
       print("DST-IP : " + dst_ip)
       print("SRC-MAC : " + mac_src)
       print("DST-MAC : " + mac_dst)
       print("SRC-PORT : " + str(src_port) )
       print("DST-PORT : " + str(dst_port) )
   
      
       if pkt.haslayer(Raw) :
          print(pkt[Raw].load)
       print("- - - - - - - - - - - - - -")
       
print("********* STARTED *********")
sniff(iface="eth0",prn=analyzer)

