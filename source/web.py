from flask import *
from flask_table import Table
from argparse import ArgumentParser
import datetime, time


app = Flask(__name__)
parser = ArgumentParser()
parser.add_argument('-a')
args = parser.parse_args()
app.config['filename'] = args.a


@app.route("/logs")
def show_tables():
	M=[]
	with open(app.config['filename'],'r') as f:
		for line in f.readlines():
			l = []
			timepkt = ' '.join(line.split(' ')[0:2])
			timestp = timepkt.replace('-','').replace(':','').replace(',','').replace(' ','')[::-1]
			user = line.split(' ')[2]
			warning_type = line.split(':\t')[0].split(' ')[-1]
			if "'msg'" not in line:
				message = "No Message Specified"
			else:
				message = line.split(':\t')[1]
			srcIP = line.split('###[ IP ]###')[1].split('src= ')[1].split(':')[0].strip()
			dstIP = line.split('###[ IP ]###')[1].split('dst= ')[1].split(':')[0].strip()

			if "TCP" in line:
				srcPort = line.split('###[ TCP ]### : ')[1].split('sport= ')[1].split(':')[0].strip()
				dstPort = line.split('###[ TCP ]### : ')[1].split('dport= ')[1].split(':')[0].strip()
			elif "UDP" in line:
				srcPort = line.split('###[ UDP ]### : ')[1].split('sport= ')[1].split(':')[0].strip()
				dstPort = line.split('###[ UDP ]### : ')[1].split('dport= ')[1].split(':')[0].strip()
			elif "ICMP" in line:
				srcPort = "None"
				dstPort = "None"
			M.append([timepkt,user,warning_type,srcIP,dstIP,srcPort,dstPort,message,timestp])
	return render_template('logs.html',M=M)


@app.route("/logs/<timestamp>")
def show_details(timestamp):
	timestamp = timestamp[::-1]
	timepkt = timestamp[:4]+"-"+timestamp[4:6]+"-"+timestamp[6:8]+" "+timestamp[8:10]+":"+timestamp[10:12]+":"+timestamp[12:14]+","+timestamp[14:]
	l=[]
	with open(app.config['filename'],'r') as f:
		lines = f.readlines()
		index = 0
		for line in lines:
			index = lines.index(line)
			if ' '.join(line.split(' ')[0:2])==timepkt:
				#ETHERNET
				dstMac = line.split('###[ Ethernet ]###')[1].split(":  dst= ")[1].split(":  src= ")[0].strip()
				srcMac = line.split('###[ Ethernet ]###')[1].split(":  src= ")[1].split(":  type = ")[0].strip()
				#IP
				timepkt = ' '.join(line.split(' ')[0:2])
				srcIP = line.split('###[ IP ]###')[1].split('src= ')[1].split(':')[0].strip()
				dstIP = line.split('###[ IP ]###')[1].split('dst= ')[1].split(':')[0].strip()
				version = line.split('###[ IP ]###')[1].split('version   = ')[1].split(':')[0].strip()
				ihl = line.split('###[ IP ]###')[1].split('ihl= ')[1].split(':')[0].strip()
				tos = line.split('###[ IP ]###')[1].split('tos= ')[1].split(':')[0].strip()
				ip_length = line.split('###[ IP ]###')[1].split('len= ')[1].split(':')[0].strip()
				identifier = line.split('###[ IP ]###')[1].split('id = ')[1].split(':')[0].strip()
				ip_flags = line.split('###[ IP ]###')[1].split('flags= ')[1].split(':')[0].strip()
				fragOffset = line.split('###[ IP ]###')[1].split('frag = ')[1].split(':')[0].strip()
				ttl = line.split('###[ IP ]###')[1].split('ttl= ')[1].split(':')[0].strip()
				protocol = line.split('###[ IP ]###')[1].split('proto= ')[1].split(':')[0].strip()
				ip_checksum = line.split('###[ IP ]###')[1].split('chksum    = ')[1].split(':')[0].strip()
				l.append(timepkt)
				l.append(dstMac)
				l.append(srcMac)
				l.append(version)
				l.append(ihl)
				l.append(tos)
				l.append(ip_length)
				l.append(identifier)
				l.append(ip_flags)
				l.append(fragOffset)
				l.append(ttl)
				l.append(protocol)
				l.append(ip_checksum)
				l.append(srcIP)
				l.append(dstIP)

				if protocol == "tcp":
					srcPort = line.split('###[ TCP ]### : ')[1].split('sport= ')[1].split(':')[0].strip()
					dstPort = line.split('###[ TCP ]### : ')[1].split('dport= ')[1].split(':')[0].strip()
					seq = line.split('###[ TCP ]### : ')[1].split('seq= ')[1].split(':')[0].strip()
					ack = line.split('###[ TCP ]### : ')[1].split('ack= ')[1].split(':')[0].strip()
					dataOffset = line.split('###[ TCP ]### : ')[1].split('dataofs   = ')[1].split(':')[0].strip()
					reserved = line.split('###[ TCP ]### : ')[1].split('reserved  = ')[1].split(':')[0].strip()
					tcp_flags = line.split('###[ TCP ]### : ')[1].split('flags= ')[1].split(':')[0].strip()
					window = line.split('###[ TCP ]### : ')[1].split('window    = ')[1].split(':')[0].strip()
					tcp_checksum = line.split('###[ TCP ]###')[1].split('chksum    = ')[1].split(':')[0].strip()
					l.append(srcPort)
					l.append(dstPort)
					l.append(seq)
					l.append(ack)
					l.append(dataOffset)
					l.append(reserved)
					l.append(tcp_flags)
					l.append(window)
					l.append(tcp_checksum)
				
				elif protocol == "udp":
					srcPort = line.split('###[ UDP ]### : ')[1].split('sport= ')[1].split(':')[0].strip()
					dstPort = line.split('###[ UDP ]### : ')[1].split('dport= ')[1].split(':')[0].strip()
					udp_length = line.split('###[ UDP ]###')[1].split('len= ')[1].split(':')[0].strip()
					udp_checksum = line.split('###[ UDP ]###')[1].split('chksum    = ')[1].split(':')[0].strip()
					l.append(srcPort)
					l.append(dstPort)
					l.append(udp_length)
					l.append(udp_checksum)

				elif protocol == "icmp":
					icmp_type = line.split('###[ ICMP ]### : ')[1].split('type =')[1].split(':')[0].strip()
					code = line.split('###[ ICMP ]### : ')[1].split('code =')[1].split(':')[0].strip()
					icmp_checksum = line.split('###[ ICMP ]### : ')[1].split('chksum    =')[1].split(':')[0].strip()
					icmp_id = line.split('###[ ICMP ]### : ')[1].split('id =')[1].split(':')[0].strip()
					seq = line.split('###[ ICMP ]### : ')[1].split('seq= ')[1].split(':')[0].strip()
					l.append(icmp_type)
					l.append(code)
					l.append(icmp_checksum)
					l.append(icmp_id)
					l.append(seq)
	return render_template('packet.html',l=l,index=index,filename=app.config['filename'])




if __name__ == "__main__":
    app.run()