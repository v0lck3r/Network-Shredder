from ipaddress import *
from termcolor import colored
import sys
sys.tracebacklimit = 0


def readrules(file):

	rulesList = []
	with open(file,'r') as f:
		for line in f:
			d={}
			rule = line.strip().split(' ')
			if len(rule) >= 7:
				action = rule[0]
				if action != "alert":
					raise ValueError(colored("[!] Invalid Rule : Incorrect  action : '" + action + "'.","red"))
				d["action"]="alert"
				protocol = rule[1]
				if protocol not in ["tcp","udp","icmp"]:
					raise ValueError(colored("[!] Invalid Rule : Incorrect  protocol : '" + protocol + "'.","red"))
				d["protocol"]=protocol
				src_ip = rule[2]
				try:
					if src_ip == "any":
						ip = ip_network(u'0.0.0.0/0')
						d["SrcIP"]=ip
					elif len(src_ip.split("/"))==2:
						ip = ip_network(src_ip)
						d["SrcIP"]=ip
					else:
						ip = ip_network(src_ip+"/32")
						d["SrcIP"]=ip
				except:
					raise ValueError(colored("[!] Invalid Rule : Incorrect  source IP : '" + src_ip + "'.","red"))
				src_ports = rule[3]
				valid_ports=False
				try:
					if src_ports == "any":
						valid_ports = True
						d["SrcPorts"]="any"
					elif ":" in src_ports:
						temp = src_ports.split(":")
						temp.remove("")
						if len(temp)==2:
							if(int(temp[0])<int(temp[1])):
								valid_ports = True
								d["SrcPorts"]={"range":[int(temp[0]),int(temp[1])]}
						elif len(temp)==1:
							p = int(temp[0])
							if src_ports[0]==":":
								d["SrcPorts"]={"range":[0,int(temp[0])]}
							elif src_ports[len(src_ports-1)]==":":
								d["SrcPorts"]={"range":[int(temp[0]),65535]}
							valid_ports=True
					elif "," in src_ports:
						temp = [int(x) for x in src_ports.split(",")]
						valid_ports=True
						d["SrcPorts"]={"list":temp}
					else:
						p =int(src_ports)
						valid_ports = True
						d["SrcPorts"]=p

				except:
					raise ValueError(colored("[!] Invalid Rule : Incorrect  source ports : '" + src_ports + "'.","red"))
				if(valid_ports==False):
					raise ValueError(colored("[!] Invalid Rule : Incorrect  source ports : '" + src_ports + "'.","red"))
				dst_ip = rule[5]
				try:
					if dst_ip == "any":
						ip = ip_network(u'0.0.0.0/0')
						d["DstIP"]=ip
					elif len(dst_ip.split("/"))==2:
						ip = ip_network(dst_ip)
						d["DstIP"]=ip
					else:
						ip = ip_network(dst_ip+"/32")
						d["DstIP"]=ip
				except:
					raise ValueError(colored("[!] Invalid Rule : Incorrect  destination IP : '" + dst_ip + "'.","red"))
				dst_ports = rule[6]
				valid_ports=False
				try:
					if dst_ports == "any":
						valid_ports = True
						d["DstPorts"]="any"
					elif ":" in dst_ports:
						temp = dst_ports.split(":")
						temp.remove("")
						if len(temp)==2:
							if(int(temp[0])<int(temp[1])):
								valid_ports = True
								d["DstPorts"]={"range":[int(temp[0]),int(temp[1])]}
						elif len(temp)==1:
							p = int(temp[0])
							if dst_ports[0]==":":
								d["DstPorts"]={"range":[0,int(temp[0])]}
							elif dst_ports[len(dst_ports)-1]==":":
								d["DstPorts"]={"range":[int(temp[0]),65535]}
							valid_ports=True
					elif "," in dst_ports:
						temp = [int(x) for x in dst_ports.split(",")]
						valid_ports=True
						d["DstPorts"]={"list":temp}
					else:
						p =int(dst_ports)
						valid_ports=True
						d["DstPorts"]=p

				except:
					raise ValueError(colored("[!] Invalid Rule : Incorrect  destination ports : '" + dst_ports + "'.","red"))
				if(valid_ports==False):
					raise ValueError(colored("[!] Invalid Rule : Incorrect  destination ports : '" + dst_ports + "'.","red"))
				temp = line.strip().split("(")
				if len(temp)==2:
					try:
						options = temp[1].replace(')','')
						options = options.split(';')
						for option in options:
							if option.split(":")[0].strip() not in ["msg","tos","ttl","offset","seq","ack","flags","http_request","content","dsize", "count", "time"]:
								raise ValueError(colored("[!] Invalid Rule : Incorrect  option : '" + option.split(":")[0].strip() + "'.","red"))
							elif option.split(":")[0].strip() in ["tos","ttl","offset","seq","ack","dsize", "count", "time"]:
								var = int(option.split(":")[1].strip())
							d[option.split(":")[0].strip()]=option.split(":")[1].strip().replace('"','')
					except:
						raise ValueError(colored("[!] Invalid Rule : Incorrect  options.","red"))
			else:
				raise ValueError("[!] Invalid Rule : A rule must include mandatory elements : action protocol srcIPs srcPorts -> dstIPs dstPorts")
			rulesList.append(d)
	return rulesList

