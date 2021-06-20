from threading import Thread
from scapy.all import *
from functions import *
import sys
sys.tracebacklimit = 0
import time

class Sniffer(Thread):

	def __init__(self, rules_list, interface, pcap_file, quiet, counters, timers):
		Thread.__init__(self)
		self.stopped = False
		self.rules_list = rules_list
		self.interface = interface
		self.pcap_file = pcap_file
		self.quiet = quiet
		self.counters = counters
		self.timers = timers

	def stop(self):
		self.stopped = True

	def stop_filter(self, x):
		return self.stopped

	def incomingPacket(self, packet):
		c = 0
		for rule in self.rules_list:
			matched = match(rule, packet)
			if (matched):
				if "count" in rule.keys():
					if self.counters[c][0] == 0:
						self.timers[c][0] = int(time.time())
					self.counters[c][0] += 1
					if self.counters[c][0]==self.counters[c][1] and int(time.time())-self.timers[c][0]<=self.timers[c][1]:
						message = log(rule, packet)
						logging.warning(message)
						if not self.quiet:
							console(rule,packet)
						self.counters[c][0] = 0
				else:
					message = log(rule, packet)
					logging.warning(message)
					if not self.quiet:
						console(rule,packet)
			if "count" in rule.keys():
				c += 1




	def run(self):
		print(colored("[~] Starting Network Sniffing...","blue"))
		if self.interface == None and self.pcap_file == None:
			sniff(prn=self.incomingPacket, store=0)
		elif self.pcap_file == None:
			try:
				sniff(prn=self.incomingPacket, store=0, iface=self.interface)
			except:
				raise OSError(colored("[!] Interface "+self.interface+" Not Found!", "red"))
		else:
			try:
				sniff(offline=self.pcap_file,prn=self.incomingPacket,store=0)
			except:
				raise Exception(colored("[!] Error Reading PCAP File!","red"))
		