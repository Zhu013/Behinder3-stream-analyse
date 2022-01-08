'''
Descripttion: 
Author: Zhu013
Date: 2021-09-16 10:50:35
'''
# encoding=utf8
from os import error
import dpkt
import re

from dpkt import pcap
from Crypto.Cipher import AES
import base64
import io
import sys
import json

import jpype 

# sys.stdout = io.TextIOWrapper(sys.stdout.buffer,encoding='gb18030')
banner='''
________   __ _____         ___   _   _   ___   _   __   _______ _____ 
| ___ \ \ / /|____ |       / _ \ | \ | | / _ \ | |  \ \ / /  ___|  ___|
| |_/ /\ V /     / /______/ /_\ \|  \| |/ /_\ \| |   \ V /\ `--.| |__  
| ___ \/   \     \ \______|  _  || . ` ||  _  || |    \ /  `--. \  __| 
| |_/ / /^\ \.___/ /      | | | || |\  || | | || |____| | /\__/ / |___ 
\____/\/   \/\____/       \_| |_/\_| \_/\_| |_/\_____/\_/ \____/\____/ 
                                                                      
Author: D²LAB-Zhu013
Introduction: Analyse tools for Behinder stream which version >= 3.0   
Useage:
	python version 3.8
	python bx3-analyse.py key pcap language shellname
Example：
	python bx3-analyse.py e45e329feb5d925b bxtest.pcap php shell.php
'''

def tcp_flags(flags):
	ret = ''
	if flags & dpkt.tcp.TH_FIN:
		ret = ret + 'F'
	if flags & dpkt.tcp.TH_SYN:
		ret = ret + 'S'
	if flags & dpkt.tcp.TH_RST:
		ret = ret + 'R'
	if flags & dpkt.tcp.TH_PUSH:
		ret = ret + 'P'
	if flags & dpkt.tcp.TH_ACK:
		ret = ret + 'A'
	if flags & dpkt.tcp.TH_URG:
		ret = ret + 'U'
	if flags & dpkt.tcp.TH_ECE:
		ret = ret + 'E'
	if flags & dpkt.tcp.TH_CWR:
		ret = ret + 'C'

	return ret

def parse_http_stream(stream):
	while len(stream) == 0:
		if stream[:4] == 'HTTP':
			http = dpkt.http.Response(stream)
			print(http.status)
		else:
			http = dpkt.http.Request(stream)
			print(http.method, http.uri)
		stream = stream[len(http):]


def parse_pcap_file(language,key,pcap,name):
	# Open the pcap file
	f = open(pcap, 'rb')
	pcap = dpkt.pcap.Reader(f)
	# I need to reassmble the TCP flows before decoding the HTTP
	conn = dict() # Connections with current buffer
	for ts, buf in pcap:
		eth = dpkt.ethernet.Ethernet(buf)
		if eth.type != dpkt.ethernet.ETH_TYPE_IP:
			continue
	
		ip = eth.data
		if ip.p != dpkt.ip.IP_PROTO_TCP:
			continue
	
		tcp = ip.data
	
		tupl = (ip.src, ip.dst, tcp.sport, tcp.dport)
		#print tupl, tcp_flags(tcp.flags)
	
		# Ensure these are in order! TODO change to a defaultdict
		if tupl in conn:
			conn[ tupl ] = conn[ tupl ] + tcp.data
		else:
			conn[ tupl ] = tcp.data
	
		# TODO Check if it is a FIN, if so end the connection
	
		# Try and parse what we have
		try:
			stream = conn[ tupl ]
			if stream[:4] == 'HTTP':
				http = dpkt.http.Response(stream)
				#print http.status
			else:
				http = dpkt.http.Request(stream)
				#print http.method, http.uri
            
			# print(str(http))
			pcap_decode(http,language,key,name)

			# If we reached this part an exception hasn't been thrown
			stream = stream[len(http):]
			if len(stream) == 0:
				del conn[ tupl ]
			else:
				conn[ tupl ] = stream
		except dpkt.UnpackError:
			# print(e)
			pass
	f.close()

def bx3_xor(key,data):
	destr=''
	datastr = data.decode()
	for i in range(len(datastr)):
		newstr= ord(datastr[i])^ord(key[i+1&15])
		destr = destr+chr(newstr)
	return destr

def regexphp(regexphp,destr):
	match = re.findall(regexphp,str(destr))
	try:
		restr = base64.decodebytes(match[0].encode('utf-8'))
	except Exception as e :
		print(e)
		restr = base64.decodebytes(match[0].encode('gb2312'))
	return restr

def regexjava(regexjava,destr):
	match = re.findall(regexjava,str(destr))
	try:
		restr = match[0].encode('utf-8')
	except Exception as e :
		print(e)
		restr = match[0].encode('gb2312')

	return restr
 
def javade():
	jvmPath = jpype.getDefaultJVMPath() 
	jpype.startJVM(jvmPath) 
	jpype.java.lang.System.out.println("hello world!") 
	jpype.shutdownJVM()

def decode_method():
	pass

def pcap_decode(http,language,key,name=''):
	if name in http.uri:
		print("*"*44+"发现目标webshell"+"*"*44)
		print(http.uri)
		x = [b'']
		# print(http.body)
		if b'POST /' in http.body:
			print("[+]"+"-"*44+"发现POST包未拆开！"+"-"*44)
			x = http.body.split(b'POST /',1)
			# print(x[0])
			print("[+]"+"-"*44+"尝试拆包"+"-"*44)
			exit
		if language == 'java':
			try:
				(base64.decodebytes(http.body))
				print("*"*88)
				# print(http.body)
				aes = AES.new(str.encode(key),AES.MODE_ECB)
				destr = aes.decrypt(base64.decodebytes(http.body))
				# print(destr)

				#BasicInfo
				if b"BasicInfo.java" in destr:
					print("BasicInfo")

				#Bshell
				if b"Bshell.java" in destr:
					print("Bshell")

				#Cmd
				if b"Cmd.java" in destr:
					print("Cmd")
					cmdstr = regexjava(r'\"\&(.*)\\x08\\x00\\x08\\x01',destr)
					print("命令执行:"+cmdstr.decode())
				#ConnectBack
				if b"ConnectBack.java" in destr:
					print("ConnectBack")

				#Database
				if b"Database.java" in destr:
					print("Database")

				#Echo
				if b"Echo.java" in destr:
					print("Echo")

				#FileOperation
				if b"FileOperation.java" in destr:
					print("FileOperation")

				#Loader
				if b"Loader.java" in destr:
					print("Loader")
				#LoadNativeLibrary
				if b"LoadNativeLibrary.java" in destr:
					print("LoadNativeLibrary")
				#MemShell
				if b"MemShell.java" in destr:
					print("MemShell")

				#NewScan
				if b"NewScan.java" in destr:
					print("NewScan")

				#Ping
				if b"Ping.java" in destr:
					print("Ping")

				#Plugin
				if b"Plugin.java" in destr:
					print("Plugin")

				#PortMap
				if b"PortMap.java" in destr:
					print("PortMap")

				#RealCMD
				if b"RealCMD.java" in destr:
					print("RealCMD")
					# print(destr)
					f = open(("java/test.class"),"w+b")
					f.write(destr)
					f.close
				#RemoteSocksProxy
				if b"RemoteSocksProxy.java" in destr:
					print("RemoteSocksProxy")
					
				#ReversePortMap
				if b"ReversePortMap.java" in destr:
					print("ReversePortMap")

				#Scan
				if b"Scan.java" in destr:
					print("Scan")

				#SocksProxy
				if b"SocksProxy.java" in destr:
					print("SocksProxy")
			except Exception as e :
				pass
				# print("decode:="+destr)
		elif language == 'php':
			try:
# 				print(len(x[0]))
				if len(x[0]) > 0:
					http.body=x[0]
				if len(http.body) >150000:
					print("[-]"+"-"*44+"包太大了，已存入large.log"+"-"*44)
					f = open("error/large.log","a+")
					f.write("\n\r 包太大了！ \n\r")
					f.write(str(http.body))
					f.close
					return
				(base64.decodebytes(http.body))
				print("[+]"+"-"*44+"发现BASE64加密"+"-"*44)
				try:
					aes = AES.new(str.encode(key),AES.MODE_CBC)
					try:
						destr = ''
						#OPENSSL ON
						destr = str(aes.decrypt(base64.decodebytes(http.body)))
						# print(destr)
					except Exception as e:
						#OPENSSL OFF
						destr = bx3_xor(key,base64.decodebytes(http.body))
						# print(destr)
					destr2 = regexphp(r"64_decode\('(.*)'\)",destr)
					print("[+]"+"-"*44+"Behinder - AES/XOR解密"+"-"*44)

					# cmd
					if '$cmd,$path' in str(destr2):
						print("普通cmd操作解密中...")
						recmd = regexphp(r'}\$cmd="(.*)";\$c',destr2)
						print("攻击命令:"+recmd.decode())
					# RealCMD
					elif '$type, $bashPath' in str(destr2):
						print("Realcmd操作解密中...")
						rcmdtype = regexphp(r'\$type="(.*)";\$type=',destr2)
						# print(destr2)
						if rcmdtype == b'read':
							pass
							#无有效信息
							print("Realcmd readbuffer from session")
						elif rcmdtype == b'create':
							print("Realcmd create")
							bashPath = regexphp(r'\$bashPath="(.*)";\$bashPath=',destr2)
							print("Realcmd create bashpath:"+bashPath.decode('gb2312'))
						elif rcmdtype == b'stop':
							print("Realcmd stop")
						elif rcmdtype == b'write':
							print("Realcmd write")
							print("Realcmd writebuffer to session")
							cmd = regexphp(r'\$cmd="(.*)";\$cmd=',destr2)
							print("Realcmd cmd:"+base64.decodebytes(cmd).decode('gb2312'))
					# elif'$content' in str(destr2):
					# 	print("[+]Echo操作-无有效数据...")

					#FileOperation
					elif'$mode' in str(destr2):
						print("FileOperation操作解密中...")
						mode = regexphp(r'\$mode="(.*)";\$mode=',destr2)
						if mode == b"list":
							print("FileOperation list")
							listpath = regexphp(r'\$path="(.*)";\$path=',destr2)
							print("FileOperation list path: "+listpath.decode('gb2312'))
						elif mode == b'show':
							print("FileOperation show")
						elif mode == b'download':
							print("FileOperation download")
							# print(destr2)
							downloadpath = regexphp(r'\$path="(.*)";\$path=',destr2)
							print("FileOperation download file path: "+downloadpath.decode('gb2312'))
						elif mode == b'delete':
							print("FileOperation detele")
							deletepath = regexphp(r'\$path="(.*)";\$path=',destr2)
							print("FileOperation delete file path: "+deletepath.decode('gb2312'))
						elif mode == b'create':
							print("FileOperation create")
							createstr = regexphp(r'\$content="(.*)";\$content=',destr2)
							createpath = regexphp(r'\$path="(.*)";\$path=',destr2)
							namelist = re.findall(r'.+\/(.+)$',createpath.decode('gb2312'))
							filename = namelist[0]
							f = open("out/"+str(filename),"w+b")
							print("upload filename:"+filename)
							print("size:"+str(len(createstr)))
							f.write(base64.decodebytes(createstr))
							f.close
							# with open ('/out/'):							
						elif mode == b'createDirectory':
							print("FileOperation createDirectory")
						elif mode == b'append':
							print("FileOperation append")
							# print(destr2)
							createstr = regexphp(r'\$content="(.*)";\$content=',destr2)
							createpath = regexphp(r'\$path="(.*)";\$path=',destr2)
							namelist = re.findall(r'.+\/(.+)$',createpath.decode('gb2312'))
							filename = namelist[0]
							f = open("out/"+str(filename),"a+b")
							print("upload filename:"+filename)
							print("size:"+str(len(createstr)))
							f.write(base64.decodebytes(createstr))
							f.close
						elif mode == b'rename':
							print("FileOperation rename")
					elif'$whatever' in str(destr2):
						print("BasicInfo操作解密中...")

					#PortMap
					elif'$action, $targetIP' in str(destr2):
						print("PortMap操作解密中...")
						actionstr = regexphp(r'\$action="(.*)";\$action=',destr2)
						print("action:"+actionstr.decode())
						if actionstr == b"createRemote":
							print("PortMap createRemote")
							targetIPstr = regexphp(r'\$targetIP="(.*)";\$targetIP=',destr2)
							print("targetIP:"+targetIPstr.decode())
							targetPortstr = regexphp(r'\$targetPort="(.*)";\$targetPort=',destr2)
							print("targetPort:"+targetPortstr.decode())
							remoteIPstr = regexphp(r'\$remoteIP="(.*)";\$remoteIP=',destr2)
							print("remoteIP:"+remoteIPstr.decode())		
							remotePortstr = regexphp(r'\$remotePort="(.*)";\$remotePort=',destr2)
							print("remotePort:"+remotePortstr.decode())		

					#RemoteSocksProxy				
					elif'$action, $remoteIP' in str(destr2):
						print("RemoteSocksProxy操作解密中...")
						actionstr = regexphp(r'\$action="(.*)";\$action=',destr2)
						print("action:"+actionstr.decode())
						if actionstr == b"create":
							remoteIPstr = regexphp(r'\$remoteIP="(.*)";\$remoteIP=',destr2)
							print("remoteIP:"+remoteIPstr.decode())
							remotePortstr = regexphp(r'\$remotePort="(.*)";\$remotePort=',destr2)
							print("remotePort:"+remotePortstr.decode())
						if actionstr == b"stop":
							print("RemoteSocksProxy stop")

					#ReversePortMap
					elif'$action, $listenPort' in str(destr2):
						print("ReversePortMap操作解密中...")
						actionstr = regexphp(r'\$action="(.*)";\$action=',destr2)
						print("action:"+actionstr.decode())
						if actionstr == b"create":
							print("ReversePortMap create")
							listenPortstr = regexphp(r'\$listenPort="(.*)";\$listenPort=',destr2)
							print("listenPort:"+listenPortstr.decode())
						if actionstr == b"list":
							print("ReversePortMap list")
						if actionstr == b"stop":
							print("ReversePortMap stop")
							listenPortstr = regexphp(r'\$listenPort="(.*)";\$listenPort=',destr2)
							print("listenPort:"+listenPortstr.decode())
						
					#SocksProxy
					elif'$cmd,$targetIP=' in str(destr2):
						print("SocksProxy操作解密中...")
						actionstr = regexphp(r'\$action="(.*)";\$action=',destr2)
						print("SocksProxy action:"+actionstr.decode())
						if actionstr == b"create":
							listenPortstr = regexphp(r'\$listenPort="(.*)";\$listenPort=',destr2)
							print("SocksProcy listenPort:"+listenPortstr.decode())
						if actionstr == b"list":
							print("SocksProcy listenPort list")
					
					#Connectback
					elif'$ip,$port' in str(destr2):
						print("Connectback操作解密中...")
						ctypestr = regexphp(r'}\$type="(.*)";\$type=base',destr2)
						print("ConnectbackTYPE:"+ctypestr.decode())
						ipstr = regexphp(r'\$ip="(.*)";\$ip=',destr2)
						print("Connectbackip:"+ipstr.decode())
						portstr = regexphp(r'\$port="(.*)";\$port=',destr2)
						print("ConnectbackPort:"+portstr.decode())

					#database
					elif'$database' in str(destr2):
						print("Database操作解密中...")
						typestr = regexphp(r'\$type="(.*)";\$type=',destr2)
						print("TYPE:"+typestr.decode())
						hoststr = regexphp(r'\$host="(.*)";\$host=',destr2)
						print("IP:"+hoststr.decode())
						portstr = regexphp(r'\$port="(.*)";\$port=',destr2)
						print("PORT:"+portstr.decode())
						userstr = regexphp(r'\$user="(.*)";\$user=',destr2)
						print("USER:"+userstr.decode())
						passstr = regexphp(r'\$pass="(.*)";\$pass=',destr2)
						print("PASS:"+passstr.decode())
						databasestr = regexphp(r'\$database="(.*)";\$database=',destr2)
						print("DATABASE:"+databasestr.decode())
						sqlstr = regexphp(r'\$sql="(.*)";\$sql=',destr2)
						print("SQL:"+sqlstr.decode())
				except Exception as e:
					print(e)
					pass
			except Exception as e :
				print("*"*88)
				print("出现无法正常解析的流量，请检查重新尝试读取。")
				f = open("error/error.log","a+")
				f.write("\n\r somethin error \n\r")
				f.write(str(http.body))
				f.close
	else:
		pass
if __name__ == '__main__':
	print(banner)
	import sys
	# print(sys.argv)
	if len(sys.argv) ==5:
		print("key="+sys.argv[1]+",pcap="+sys.argv[2]+",language="+sys.argv[3]+",name="+sys.argv[4])
		pcap=sys.argv[2]
		language = sys.argv[3]
		key = sys.argv[1]
		name = sys.argv[4]
	# pcap  = 'bx_upload.pcap'
	# language = "php"
	# key = "e45e329feb5d925b"
	# uri = "shell.php"
	parse_pcap_file(language,key,pcap,name)
	
