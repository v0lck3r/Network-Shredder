from threading import Thread
from scapy.all import *
from functions import *
import sys
#sys.tracebacklimit = 0
class Sniffer(Thread):
	

	def __init__(self, rules_list, interface, pcap_file, quiet):
		Thread.__init__(self)
		self.stopped = False
		self.rules_list = rules_list
		self.interface = interface
		self.pcap_file = pcap_file
		self.quiet = quiet
	def stop(self):
		self.stopped = True

	def stop_filter(self, x):
		return self.stopped

	def incomingPacket(self, packet):
		for rule in self.rules_list:

			matched = match(rule, packet)
			if (matched):
				message = log(rule, packet)
				logging.warning(message)
				if not self.quiet:
					console(rule,packet)


	def run(self):
		print(colored("[~] Starting Network Sniffing...","blue"))
		if self.interface == None and self.pcap_file == None:
			sniff(prn=self.incomingPacket, filter="", store=0, stop_filter=self.stop_filter)
		elif self.pcap_file == None:
			try:
				sniff(prn=self.incomingPacket, filter="", store=0, stop_filter=self.stop_filter, iface=self.interface)
			except:
				raise OSError(colored("[!] Interface "+self.interface+" Not Found!", "red"))
		else:
			try:
				sniff(offline=self.pcap_file,prn=self.incomingPacket,store=0)
			except:
				raise Exception(colored("[!] Error Reading PCAP File!","red"))
		