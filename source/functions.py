from ipaddress import *
from scapy.all import *

def match(rule,packet):
	if not checkProtocol(rule,packet):
		return False
	if not checkIps(rule,packet):
		return False
	if not checkPorts(rule,packet):
		return False
	if not checkOptions(rule,packet):
		return False
	return True
def checkProtocol(rule, packet):
	check = False
	if "tcp" == rule["protocol"] and TCP in packet:
		check = True
	elif "udp" == rule["protocol"] and UDP in packet:
		check = True
	elif "http" == rule["protocol"] and TCP in packet:
		if isHTTP(packet):
			check = True
	return check

def checkIPs(rule, packet):
	check = False
	if IP in packet:
		src_IP = ip_address(packet[IP].src)
		dst_IP = ip_address(packet[IP].dst)
		if src_IP in rule["SrcIP"] and dst_IP in rule["DstIP"]:
			check = True
	return check

def contains(a,b):
	if a=="any":
		return True
	elif type(a)=="int":
		return a==b
def checkPorts(rule, packet):
	check = False
	if UDP in packet:
		srcPort = packet[UDP].sport
		dstPort = packet[UDP].dport
		if 
"""if string --> True
if int --> solo
if dictio --> range
		  --> list"""