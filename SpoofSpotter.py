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
import argparse
import sys
from array import array

#################################################
# Spoof Sniffer                                 #
#   -A tool to catch spoofed NBNS responses     #
#     Spoofed responses are alerterd on with    #
#     email and/or SYSLOG                       #
#                                               #
#################################################


UDP_PORT = 137
QUERY_NAME = "NETSPITEST"
RESP_SMB = 'false'
SENT = 'false'

BADIPs = [] 

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
parser.add_argument('-R', action="store", metavar='true', help='The option to send Garbage SMB Auth requests to the attacker(not implemented yet)')
parser.add_argument('-c', action="store", metavar='true', help='Continue Emailing After a Detection, could lead to spam')

args = parser.parse_args()

if args.n:
	QUERY_NAME = args.n

#Scapy packet creation
pkt = IP(src=args.i,dst=args.b)/UDP(sport=137, dport='netbios_ns')/NBNSQueryRequest(SUFFIX="file server service",QUESTION_NAME=QUERY_NAME, QUESTION_TYPE='NB')

now = datetime.datetime.now()

#Email function
def sendEmail(REMAIL, ESERVER, IP):
	me = 'spoofspotter@netspi.com'
	you = REMAIL
	server = ESERVER

	msg = MIMEMultipart('alternative')

	msg['Subject'] = 'A spoofed NBNS response was detected'
	msg['From'] = me
	msg['To'] = you

	now1 = datetime.datetime.now()
	BODY = 'A spoofed NBNS response for %s was detected by %s at %s from host %s' %(QUERY_NAME, args.i, str(now1), IP)

	part1 = MIMEText(BODY, 'plain')

	msg.attach(part1)

	s = smtplib.SMTP(server)
	s.sendmail(me, [you], msg.as_string())
	s.quit()

	if not args.c:
		global SENT
		SENT = 'true'
	print "Email Sent"

def sender():
	while 1:
		send (pkt, verbose=0)

class MyTCPHandler(SocketServer.BaseRequestHandler):
	def handle(self):
		request, socket = self.request
		now2 = datetime.datetime.now()
		print 'A spoofed NBNS response for %s was detected by %s at %s from host %s' %(QUERY_NAME, args.i, str(now2), self.client_address[0])
		logged = 0
		for i in BADIPs:
			if i == self.client_address[0]:
				logged = 1
		if logged == 0:
			BADIPs.append(str(self.client_address[0]))
			global SENT
			SENT = 'false'

		#if the file flag is set, then write the log
		if args.f:
			f = open(args.f, 'a')
			f.write('A spoofed NBNS response for %s was detected by %s at %s from host %s\n' %(QUERY_NAME, args.i, str(now2), self.client_address[0]))
			f.close()
		#if email flags set, call the email function
		if args.e and args.s and SENT=='false':
			sendEmail(args.e, args.s, self.client_address[0])
		if args.S:
			NBNSLogger = logging.getLogger('NBNSLogger')
			NBNSLogger.setLevel(logging.DEBUG)
			#change your syslog stuff here - this is pretty beta, feel free to change this.
			handler = logging.handlers.SysLogHandler(address = ('localhost',514), facility=19)
			NBNSLogger.addHandler(handler)
			NBNSLogger.critical('A spoofed NBNS response for %s was detected by %s at %s from host %s\n' %(QUERY_NAME, args.i, str(now2), self.client_address[0]))	
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
			server = SocketServer.UDPServer((args.i, UDP_PORT), MyTCPHandler)
			server.serve_forever()
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
