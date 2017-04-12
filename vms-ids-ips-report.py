import atexit
from time import clock
from pyVim import connect
from pyVmomi import vim
from tools import cli
from tools import pchelper
import qualysapi
import socket
import atexit
from pyVim import connect
from pyVmomi import vmodl
import tools.cli as cli
import lxml
from lxml import etree,objectify
from pyVim import connect
from pyVmomi import vmodl
import tools.cli as cli
import csv, operator
import requests
import ssl
import glob
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.mime.text import MIMEText
from email import Encoders
import datetime
import urllib2
import base64
import xml.etree.ElementTree as ET


#*******************************************#
#*******THESE WILL NEED TO BE EDITED********#
#*******************************************#
vSphere_user = ""
vSphere_password = ""
vSphere_port = 443
#*******************************************#
#*******************************************#
#*******************************************#

#*******************************************#
#*******Qualys Configuration is in hidden file in script directory, generated if there isn't one********#
#*******************************************#

#Name of results file
results_file = "results.csv"  

qualys_hosts = []
vm_hosts = []
tripwire_hosts = []

#Ugly way of counting # of hosts within main, but it works
n_VMnotQualys = 0
n_VMnotTW = 0
n_QualysnotTW = 0
n_TWnotQualys = 0


def main():
	#vSphere addresses
	vSphere("")
	Qualys()
	TripWire()

	print "Generating results.."
	with open(results_file, "wb") as outfile:
		wtr = csv.writer(outfile)
		wtr.writerow(["VMs not in Qualys"])
		wtr.writerow(["Host", "IP"])
		for i in vm_hosts:
			if i not in qualys_hosts:
				try:
					wtr.writerow([socket.gethostbyaddr(i)[0], i])
					global n_VMnotQualys
					n_VMnotQualys += 1
				except socket.error:
					pass

		
		wtr.writerow([""])
		wtr.writerow(["VMs not in TripWire"])
		wtr.writerow(["Host", "IP"])
		for i in vm_hosts:
			if i not in tripwire_hosts:
				try:
					wtr.writerow([socket.gethostbyaddr(i)[0], i])
					global n_VMnotTW
					n_VMnotTW += 1
				except socket.error:
					pass


		wtr.writerow([""])
		wtr.writerow(["Qualys Hosts not in TripWire"])
		wtr.writerow(["Host", "IP"])
		for i in qualys_hosts:
			if i not in tripwire_hosts:
				try:
					wtr.writerow([socket.gethostbyaddr(i)[0], i])
					global n_QualysnotTW
					n_QualysnotTW += 1
				except socket.error:
					pass

		wtr.writerow([""])
		wtr.writerow(["TripWire Hosts not in Qualys"])
		wtr.writerow(["Host", "IP"])
		for i in tripwire_hosts:
			if i not in qualys_hosts:
				try:
					wtr.writerow([socket.gethostbyaddr(i)[0], i])
					global n_TWnotQualys
					n_TWnotQualys += 1
				except socket.error:
					pass
		
		print "Results generated to ", results_file
		outfile.close()

		email()
		print "Sending email..."

def vSphere(vSphere_address):
	print "Pulling VMs..."
	# for list of properties
	# visit: http://goo.gl/fjTEpW
	vm_properties = ["guest.ipAddress"] #More properties can be added

	service_instance = None

	#Ignore SSL Warning, sslContext = ctx
	requests.packages.urllib3.disable_warnings()
	ctx = ssl.create_default_context()
	ctx.check_hostname = False
	ctx.verify_mode = ssl.CERT_NONE

	try:
		service_instance = connect.SmartConnect(host=vSphere_address,
												user=vSphere_user,
												pwd=vSphere_password,
												port=vSphere_port, sslContext=ctx)
		atexit.register(connect.Disconnect, service_instance)
	except IOError as e:
		pass

	if not service_instance:
		raise SystemExit("Unable to connect to host with supplied info.")

	root_folder = service_instance.content.rootFolder
	view = pchelper.get_container_view(service_instance,
									   obj_type=[vim.VirtualMachine])
	vm_data = pchelper.collect_properties(service_instance, view_ref=view,
										  obj_type=vim.VirtualMachine,
										  path_set=vm_properties,
										  include_mors=True)
	for vm in vm_data:
		try:
			  #print "IP:       {0}".format(vm["guest.ipAddress"])
			  vm_hosts.append(format(vm["guest.ipAddress"]))
		except KeyError:
			#print "IP address could not be pulled, VM may be OFF"
			pass

	#print("Found {0} VirtualMachines.".format(len(vm_data)))

def Qualys():
	### Configuration with ip, user, and password is a hidden file in the same directory ###
	print "Pulling Qualys hosts.."

	# Setup connection to QualysGuard API -- only perform once per script.
	qgc = qualysapi.connect(remember_me=True)
	# API CALL
	call = '/api/2.0/fo/asset/host/'
	parameters = {'action': 'list'}
	xml_output = qgc.request(call, parameters)

	#Format XML output
	root = objectify.fromstring(xml_output)

	doc = etree.fromstring(xml_output)
	hosts = doc.xpath('//RESPONSE/HOST_LIST/HOST/IP')
	for ip in hosts:
		try:
			#print socket.gethostbyaddr(ip.text)[0]
			qualys_hosts.append(ip.text)
		except socket.error:
			pass

def TripWire():

	####### CSV USAGE ########
	'''
	print "TripWire hosts.."
	file = max(glob.glob('*report.csv'))
	with open(file, "rwb") as infile:
		rdr = csv.reader(infile)
		for host in rdr:
			try:
				tripwire_hosts.append(socket.gethostbyname(host[0]))
			except socket.error:
				pass
	'''

	print "Pulling TripWire hosts..."
	#make request to tripwire rest api
	request = urllib2.Request("")
	base64string = base64.encodestring('%s:%s' % ("", "")).replace('\n', '')
	request.add_header("Authorization", "Basic %s" % base64string)   
	result = urllib2.urlopen(request)

	root = ET.fromstring(result.read())

	for e in root.iter('ip-v4'):
		x = ET.tostring(e, method="text").strip()
		tripwire_hosts.append(x)


def email():
	now = datetime.datetime.now()

	SUBJECT = "VM Assets missing from other systems " + now.strftime("%m-%d-%Y")
	EMAIL_FROM = "pythonscript"
	EMAIL_TO = ""
	EMAIL_SERVER = ""

	msg = MIMEMultipart()
	msg['Subject'] = SUBJECT 
	msg['From'] = EMAIL_FROM
	msg['To'] = EMAIL_TO
	msg_string = """
		Total VMs: %s
		Total Qualys Hosts: %s
		Total TripWire Hosts: %s
		Total VMs not in Qualys: %s
		Total VMs not in Tripwire: %s
		Total Qualys Hosts not in TripWire: %s
		Total TripWire Hosts not in Qualys: %s

		Note: Only online VMs are accounted for.
		""" % (len(vm_hosts), len(qualys_hosts), len(tripwire_hosts), n_VMnotQualys, n_VMnotTW, n_QualysnotTW, n_TWnotQualys)

	msg.attach( MIMEText(msg_string) )

	part = MIMEBase('application', "octet-stream")
	part.set_payload(open("results.csv", "rb").read())
	Encoders.encode_base64(part)

	part.add_header('Content-Disposition', 'attachment; filename="results.csv"')

	msg.attach(part)

	server = smtplib.SMTP(EMAIL_SERVER)
	server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())

#Start script
if __name__ == "__main__":
	main()
