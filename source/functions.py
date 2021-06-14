from ipaddress import *
from scapy.all import *
from termcolor import colored
HTTPcommands = ["GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "OPTIONS", "CONNECT", "PATCH"]

def isHTTP(packet):
    if (TCP in packet and packet[TCP].payload):
        data = str(packet[TCP].payload)
        words = data.split('/')
        if (len(words) >= 1 and words[0].rstrip() == "HTTP"):
            return True
            
        words = data.split(' ')
        if (len(words) >= 1 and words[0].rstrip() in HTTPcommands):
            return True
        else:
            return False
    else:
        return False
def match(rule,packet):
	if not checkProtocol(rule,packet):
		return False
	if not checkIPs(rule,packet):
		return False
	if not checkPorts(rule,packet):
		print("lmochklil f ports")
		return False
	if not checkOptions(rule,packet):
		print("lmochklil f options")
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
	elif type(a)=="dict":
		if "range" in a.keys():
			return a["range"][0]<= b and b <= a["range"][1]
		elif "list" in a.keys():
			return b in a["range"]

def checkPorts(rule, packet):
	check = False
	if UDP in packet:
		srcPort = packet[UDP].sport
		dstPort = packet[UDP].dport
		if contains(rule["SrcPorts"],srcPort) and contains(rule["DstPorts"],dstPort):
			check = True
	elif TCP in packet:
		srcPort = packet[TCP].sport
		dstPort = packet[TCP].dport
		print(contains(rule["SrcPorts"],srcPort),contains(rule["SrcPorts"],srcPort))
		if contains(rule["SrcPorts"],srcPort) and contains(rule["SrcPorts"],srcPort):
			check = True
	return check

def checkOptions(rule, packet):
	if "tos" in rule.keys():
		if IP in packet:
			if rule["tos"] != packet[IP].tos:
				return False
		else:
			return False
	if "len" in rule.keys():
		if IP in packet:
			if rule["len"] != packet[IP].ihl:
				return False
		else:
			return False
	if "seq" in rule.keys():
		if IP in packet:
			if rule["seq"] != packet[IP].seq:
				return False
		else:
			return False
	if "ack" in rule.keys():
		if IP in packet:
			if rule["ack"] != packet[IP].tos:
				return False
		else:
			return False
	if "flags" in rule.keys():
		if TCP not in packet:
			return False
		else:
			for flag in rule["flags"]:
				packetFlags = packet[TCP].underlayer.sprint("%TCP.flags%")
				if flag not in packetFlags:
					return False
	if "http_request" in rule.keys():
		if not isHTTP(packet):
			return False
		elif TCP in packet and packet[TCP].payload:
			data = str(packet[TCP].payload)
			words = data.split(' ')
			if len(words)< 1 or words[0] in rule["http_request"]:
				return False
		else:
			return False
	if "content" in rule.keys():
		payload = None
		if TCP in packet:
			payload = packet[TCP].payload
		elif UDP in packet:
			payload = packet[UDP].payload
		if payload:
			if rule["content"] not in str(payload):
				return False
		else:
			return False
	return True
def log(rule, packet):
	message = "ALERT"
	if "msg" in rule.keys():
		message += rule["msg"]+"\n"
	message += "Rule Matched: \n"+str(rule)+"\n"
	return message