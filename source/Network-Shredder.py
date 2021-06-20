#!/usr/bin/env python3
from pyfiglet import Figlet
import datetime
import argparse
from scapy.all import *
import logging
from ReadRules import *
from Sniffer import *
import sys
sys.tracebacklimit = 0
from subprocess import DEVNULL, STDOUT, check_call




def main():

	now = datetime.datetime.now()
	print_banner()
	print("\n")
	args = vars(args_parser())
	arg = args_parser()
	rules_file = args['file']
	log_dir = args['logdir']
	pcap_file = args['pcap']
	interface = args['interface']
	
	if pcap_file != None and interface != None:
		raise Exception(colored("[!] You can not use PCAP option for Live Detection !!","red"))
	if log_dir==None:
		log_dir='.'
	filename = log_dir+"/Network-Shredder_" + str(now).replace(' ','_') + ".log"
	logging.basicConfig(filename=filename , format='%(asctime)s %(name)-4s %(levelname)-4s %(message)s',level=logging.INFO)

	print(colored("[+] Starting Network-Shreddering...", "green"))

	print(colored("[~] Reading Rules File "+rules_file+"...", "blue"))

	rules_list = readrules(rules_file)

	print(colored("[+] Finished Processing Rules File "+rules_file+"...", "green"))
	counter_rules = []
	timers = []
	for rule in rules_list:
		if "count" in rule.keys():
			counter_rules.append([0,int(rule["count"])])
		if "time" in rule.keys():
			timers.append([0,int(rule["time"])])

	if arg.quiet:
		if pcap_file == None:
			sniffer = Sniffer(rules_list=rules_list,interface=interface,pcap_file=None,quiet=True, counters=counter_rules, timers=timers)
			sniffer.start()

		else:
			sniffer = Sniffer(rules_list=rules_list,pcap_file=pcap_file,interface=None,quiet=True, counters=counter_rules, timers=timers)
			sniffer.start()
	else:
		if pcap_file == None:
			sniffer = Sniffer(rules_list=rules_list,interface=interface,pcap_file=None,quiet=False, counters=counter_rules, timers=timers)
			sniffer.start()

		else:
			sniffer = Sniffer(rules_list=rules_list,pcap_file=pcap_file,interface=None,quiet=False, counters=counter_rules, timers=timers)
			sniffer.start()

	if arg.web:
		print(colored("[+] You Can Access The Web Interface Via : ","yellow")+colored("http://127.0.0.1:5000/logs","green"))
		check_call(['/usr/bin/python3','web.py','-a',filename],stdout=DEVNULL, stderr=STDOUT)



def print_banner():

	fig = Figlet(font="future")
	banner = fig.renderText("  Network Shredder")
	print(colored(banner, 'blue'))
	with open("./banner.txt") as f:
		for line in f:
			print(colored(line,'magenta',attrs=['blink']),end='')
	print(colored("|_ Version :", 'red',attrs=['bold']),colored(" 1.0#beta","cyan"))
	print(colored("|_ Authors :", 'red',attrs=['bold']),colored(" AOUAJ & RAHALI","cyan"))
	print(colored("|_ Usage :",'red',attrs=['bold']),colored(" python3 Network-Shredder.py rules.txt","cyan"))



def args_parser():
	parser = argparse.ArgumentParser()
	parser.add_argument('--pcap', help='PCAP file (Exclusive for PCAP Mode)')
	parser.add_argument('file',  help='Rules file')
	parser.add_argument('--logdir',  help='Log Directory (FULL PATH) e.g: /path/to/log/')
	parser.add_argument('--interface', help='Sniff Interface (e.g: tun0)')
	parser.add_argument('--web', help='Show Logs In Web Interface', action="store_true")
	parser.add_argument('--quiet', help='Quiet Mode', action="store_true")
	return parser.parse_args()

main()