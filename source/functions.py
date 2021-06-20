from ipaddress import *
from scapy.all import *
from termcolor import colored
import datetime
from scapy.layers.http import *
import binascii


def match(rule,packet):
	if not checkProtocol(rule,packet):
		return False
	if not checkIPs(rule,packet):
		return False
	if not checkPorts(rule,packet):
		return False
	if not checkOptions(rule,packet):
		return False
	return True
def checkProtocol(rule, packet):
	check = False
	if "icmp" == rule["protocol"] and ICMP in packet:
		check = True
	if "tcp" == rule["protocol"] and TCP in packet:
		check = True
	elif "udp" == rule["protocol"] and UDP in packet:
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
	elif type(a)==int:
		return a==b
	elif type(a)==dict:
		if "range" in a.keys():
			return a["range"][0]<= b and b <= a["range"][1]
		elif "list" in a.keys():
			return b in a["list"]
	return False

def checkPorts(rule, packet):
	check = False
	if ICMP in packet:
		return True
	if UDP in packet:
		srcPort = packet[UDP].sport
		dstPort = packet[UDP].dport
		if contains(rule["SrcPorts"],srcPort) and contains(rule["DstPorts"],dstPort):
			check = True
	elif TCP in packet:
		srcPort = packet[TCP].sport
		dstPort = packet[TCP].dport
		if contains(rule["SrcPorts"],srcPort) and contains(rule["DstPorts"],dstPort):
			check = True
	return check

def checkOptions(rule, packet):
	if "tos" in rule.keys():
		if IP in packet:
			if rule["tos"] != str(packet[IP].tos):
				return False
		else:
			return False
	if "ttl" in rule.keys():
		if IP in packet:
			if rule["ttl"] != str(packet[IP].ttl):
				return False
		else:
			return False
	if "seq" in rule.keys():
		if IP in packet:
			if rule["seq"] != str(packet[IP].seq):
				return False
		else:
			return False
	if "ack" in rule.keys():
		if IP in packet:
			if rule["ack"] != str(packet[IP].ack):
				return False
		else:
			return False
	if "flags" in rule.keys():
		if TCP not in packet:
			return False
		else:
			for flag in rule["flags"]:
				packetFlags = packet[TCP].underlayer.sprintf("%TCP.flags%")
				if len(packetFlags)==0:
					packetFlags = "0"
				if flag not in packetFlags:
					return False
	if "offset" in rule.keys():
		if IP in packet:
			if rule["offset"] != str(packet[IP].off):
				return False
		else:
			return False
	if "http_request" in rule.keys():
		if HTTP in packet:
			if HTTPRequest in packet:
				method = packet[HTTPRequest].Method.decode()
				if rule["http_request"]!=method:
					return False
		elif TCP in packet and packet[TCP].payload:
			http = packet[TCP].payload.show(dump=True).split(' ')
			if len(http)< 1 or http[0] in rule["http_request"]:
				return False
		else:
			return False
	if "content" in rule.keys():
		payload = None
		if TCP in packet:
			payload = packet[TCP].payload
		elif UDP in packet:
			payload = packet[UDP].payload
		data = payload
		if data:
			if rule["content"] not in str(data):
				return False
		else:
			return False
	if "dsize" in rule.keys():
		if len(packet[ICMP].payload)!=int(rule["dsize"]):
			return False
	return True

def log(rule, packet):
	message = "ALERT:\t"
	if "msg" in rule.keys():
		message += rule["msg"]+":"
	message += "\tRule Matched:"+str(rule)
	message += "\tPacket:"+packet.show(dump=True).replace("\n",":").replace("       ","").replace("     ","")[:-1]
	return message

def console(rule, packet):
	message = colored("ALERT:","red")+"\t"
	if "msg" in rule.keys():
		message += colored(rule["msg"],"cyan")+"\n"
	message+=colored("Rule Matched:\t","green")+colored(str(rule),"magenta")+"\n"
	print(message)