from threading import Thread
from scapy.all import *
from functions import *

class Sniffer(Thread):
	

	def __init__(self, rules_list):
		Thread.__init__(self)
		self.stopped = False
		self.rules_list = rules_list

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

				print(colored(message,"green"))


	def run(self):
		print(colored("[~] Starting Network Sniffing...","blue"))
		sniff(prn=self.incomingPacket, filter="", store=0, stop_filter=self.stop_filter)