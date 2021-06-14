#!/usr/bin/env python3
from pyfiglet import Figlet
from termcolor import colored





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
	print(colored("|_ Usage : python3 Network-Shredder.py <OPTIONS>",'red'))
print_banner()
