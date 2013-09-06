import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import logging.handlers
import socket
from scapy.all import *
import threading
import SocketServer
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import datetime
import random, string
import argparse
import sys
import subprocess
from array import array


#################################################
# Spoof Sniffer                                 #
#   -A tool to catch spoofed NBNS responses     #
#     Spoofed responses are alerterd on with    #
#     email and/or SYSLOG                       #
#                                               #
# Written by Karl Fosaaen                       #
#     Twitter: @kfosaaen                        #
#################################################

#Some static variables
QUERY_NAME = "NETSPITEST"
SENT = 'false'
BADIPs = [] 

#Parser Starter
parser = argparse.ArgumentParser(description='A tool to catch spoofed NBNS responses')

#Required Flags
parser.add_argument('-i', action="store", metavar='192.168.1.110', help='The IP of this host', required=True)
parser.add_argument('-b', action="store", metavar='192.168.1.255', help='The Broadcast IP of this host', required=True)

#Optional Flags
parser.add_argument('-f','-F', action="store", metavar='/home/nbns.log', help='File name to save a log file')
parser.add_argument('-S', action="store", metavar='true', help='Log to local Syslog - this is pretty beta')
parser.add_argument('-e', action="store", metavar='you@example.com', help='The email to receive alerts at')
parser.add_argument('-s', action="store", metavar='192.168.1.109', help='Email Server to Send Emails to')
parser.add_argument('-n', action="store", metavar='EXAMPLEDOMAIN', help='The string to query with NBNS, this should be unique')
parser.add_argument('-R', action="store", metavar='5', help='The number of Garbage SMB Auth requests to send to the attacker')
parser.add_argument('-c', action="store", metavar='true', help='Continue Emailing After a Detection, could lead to spam')
parser.add_argument('-d', action="store", metavar='5', help='Time delay (in seconds) between NBNS broadcasts, reduces network noise')

args = parser.parse_args()

#Handle Custom Queries
if args.n:
	QUERY_NAME = args.n

# Random String Generation
def randomword(length):
   return ''.join(random.choice(string.lowercase) for j in range(length))
	
	
#Scapy broadcast packet creation
pkt = IP(src=args.i,dst=args.b)/UDP(sport=137, dport='netbios_ns')/NBNSQueryRequest(SUFFIX="file server service",QUESTION_NAME=QUERY_NAME, QUESTION_TYPE='NB')

#What time is it?
now = datetime.datetime.now()

#Email function
def sendEmail(REMAIL, ESERVER, IP, MAC):
	me = 'spoofspotter@netspi.com'
	you = REMAIL
	server = ESERVER

	msg = MIMEMultipart('alternative')

	msg['Subject'] = 'A spoofed NBNS response was detected'
	msg['From'] = me
	msg['To'] = you

	now1 = datetime.datetime.now()
	BODY = 'A spoofed NBNS response for %s was detected by %s at %s from host %s - %s' %(QUERY_NAME, args.i, str(now1), IP, MAC)

	part1 = MIMEText(BODY, 'plain')

	msg.attach(part1)

	s = smtplib.SMTP(server)
	s.sendmail(me, [you], msg.as_string())
	s.quit()
	#Thanks Python Example Code
	
	#Flag for preventing email spamming
	if not args.c:
		global SENT
		SENT = 'true'
	print "Email Sent"

#Sends out the queries
def sender():
	while 1:
		send (pkt, verbose=0)
		# If there's a delay set, then wait
		if args.d:
			time.sleep(float(args.d))

#Handler for incoming NBNS responses
def get_packet(pkt):
	if not pkt.getlayer(NBNSQueryRequest):
		return
	if pkt.FLAGS == 0x8500:
		now2 = datetime.datetime.now()
		print 'A spoofed NBNS response for %s was detected by %s at %s from host %s - %s' %(QUERY_NAME, args.i, str(now2), pkt.getlayer(IP).src, pkt.getlayer(Ether).src)
		logged = 0
		for i in BADIPs:
			if i == pkt.getlayer(IP).src:
				logged = 1
		if logged == 0:
			BADIPs.append(str(pkt.getlayer(IP).src))
			global SENT
			SENT = 'false'

		#if the file flag is set, then write the log
		if args.f:
			f = open(args.f, 'a')
			f.write('A spoofed NBNS response for %s was detected by %s at %s from host %s - %s\n' %(QUERY_NAME, args.i, str(now2), pkt.getlayer(IP).src, pkt.getlayer(Ether).src))
			f.close()
		#if email flags set, call the email function
		if args.e and args.s and SENT=='false':
			sendEmail(args.e, args.s, pkt.getlayer(IP).src, pkt.getlayer(Ether).src)
		#if syslog flag is set, then log it
		if args.S:
			NBNSLogger = logging.getLogger('NBNSLogger')
			NBNSLogger.setLevel(logging.DEBUG)
			#change your syslog stuff here - this is pretty beta, feel free to change this.
			handler = logging.handlers.SysLogHandler(address = ('localhost',514), facility=19)
			NBNSLogger.addHandler(handler)
			NBNSLogger.critical('A spoofed NBNS response for %s was detected by %s at %s from host %s - %s\n' %(QUERY_NAME, args.i, str(now2), pkt.getlayer(IP).src, pkt.getlayer(Ether).src))
			#Seriously, I didn't test this with an actual syslog server, please let me know if this works for you
		                #if the respond flag is set, respond with x number of hashes

		if args.R:
			print 'Sending %d hashes to %s'%(int(args.R), pkt.getlayer(IP).src)
			for x in range(0, int(args.R)):
				randpass = 'demo/myadmin%%%s'%(randomword(8))
				pathstr = '//%s/C$'%(pkt.getlayer(IP).src)
				ftpstr = 'ftp://myadmin:%s@%s'%(randomword(8), pkt.getlayer(IP).src)
				wwwstr = 'http://myadmin:%s@%s/test'%(randomword(8), pkt.getlayer(IP).src)

				#Sends SMB, FTP, and WWW Auth
				subprocess.Popen(['smbclient', '-U', randpass, pathstr], stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
				subprocess.Popen(['wget', ftpstr, '-o', '/dev/null'], stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]
				subprocess.Popen(['wget', wwwstr, '-o', '/dev/null'], stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]

def main():
	try:
		if args.f:
			f = open(args.f, 'a')
                        f.write('Starting Server at %s\n' %(str(now)))
                        f.close()
		print "Starting NBNS Request Thread..."
		thread.start_new(sender,())
		try:
			print "Starting UDP Response Server..."
			sniff(iface='eth0',filter="udp and port 137",store=0,prn=get_packet)
		except KeyboardInterrupt:
                        print "\nStopping Server and Exiting...\n"
			now3 = datetime.datetime.now()
			if args.f:
                        	f = open(args.f, 'a')
	                        f.write('Stopping Server at %s\n' %(str(now3)))
        	                f.close()
		except:
			print "Server could not be started, confirm you're running this as root.\n"
	except KeyboardInterrupt:
		exit()
	except:
		print "Server could not be started, confirm you're running this as root.\n"
main()

