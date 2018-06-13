usage: sudo python spoofspotter.py [-h] -i 192.168.1.110 -b 192.168.1.255
                       [-f /home/nbns.log] [-S true] [-e you@example.com]
                       [-s 192.168.1.109] [-n EXAMPLEDOMAIN] [-R 5]
                       [-c true] [-d 5]

A tool to catch spoofed NBNS responses.

Required arguments:
  -i 192.168.1.110      The IP of this host
  -b 192.168.1.255      The Broadcast IP of this host
  
Optional arguments:
  -h, --help            Show this help message and exit
  -f /home/nbns.log, 
  -F /home/nbns.log		File name to save a log file
  -S true               Log to local Syslog - this is pretty beta
  -e you@example.com    The email to receive alerts at
  -s 192.168.1.109      Email Server to Send Emails to
  -n EXAMPLEDOMAIN      The string to query with NBNS, this should be unique
  -R 5               The number of Garbage SMB Auth requests to send to the attacker
  -c true               Continue Emailing After a Detection, could lead to spam
  -d 5                  Time delay (in seconds) between NBNS broadcasts, reduces network noise
  			Default is set to 1 second between NBNS broadcasts.

Example Usage:
	sudo python spoofspotter.py -i 192.168.1.161 -b 192.168.1.255 -n NBNSHOSTQUERY -s 192.168.1.2 -e karl.fosaaen@example.com -f test.log
		- this will send an email alert to karl.fosaaen@example.com when an attack is identified
		- this will also log to test.log

Requires Scapy
		
To Do List:
	Randomize NBNS Requests
		-Make it harder for attackers to detect this script
	Detection of Responder versus MSF
		-Make it easier to identify the tool that's spoofing
