#!/usr/bin/env python3
from pyfiglet import Figlet
import datetime
import argparse
from scapy.all import *
import logging
from ReadRules import *
from Sniffer import *
def main():

	now = datetime.now()
	print_banner()
	print("\n")
	args = vars(args_parser())
	rules_file = args['file']
	log_dir = args['logdir']
	pcap_file = args['pcap']
	if log_dir==None:
		log_dir='.'
	logging.basicConfig(filename= log_dir+"/Network-Shredder_" + str(now).replace(' ','_') + '.log',level=logging.INFO)

	print(colored("[+] Starting Network-Shreddering...", "green"))

	print(colored("[~] Reading Rules File "+rules_file+"...", "blue"))

	rules_list = readrules(rules_file)

	print(colored("[+] Finished Processing Rules File "+rules_file+"...", "green"))

	#we should add mods (if ....)

	sniffer = Sniffer(rules_list)
	sniffer.start()














#Make two mods, live IDS and PCAP file based!!
"""
Steps:
-
-
-
"""
def print_banner():
	fig = Figlet(font="future")
	banner = fig.renderText("Network Shredder")
	print(colored(banner, 'blue'))
	print(colored("|_ Version : 1.0#beta", 'red'))
	print(colored("|_ Authors : AOUAJ & RAHALI", 'red'))
	print(colored("|_ Usage : python3 Network-Shredder.py rules/rules.txt logdir/",'red'))



def args_parser():
	parser = argparse.ArgumentParser()
	parser.add_argument('--pcap', help='PCAP file (Exclusive for PCAP Mod)')
	parser.add_argument('file',  help='Rules file')
	parser.add_argument('--logdir',  help='Log Directory (FULL PATH) e.g: /path/to/log/')
	return parser.parse_args()

main()