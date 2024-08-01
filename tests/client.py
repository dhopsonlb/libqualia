#!/usr/bin/env python3

import os, sys, time
sys.path.append('../build')
import libqualia

RootCertLocation: str = sys.argv[1]
Hostname: str = sys.argv[2]
Stringy: str = sys.argv[3]

with open(RootCertLocation, 'r') as Desc:
	RootCert = Desc.read()
	
print(RootCert)

def OnRecvCB(Conn: libqualia.TLSConnection, Stream: libqualia.Stream):
	S: str = Stream.Pop_String()
	print(f'TLSConnection received a stream with string {S}')
	
	Msg = libqualia.Stream()
	Msg.Push_String('nyipplez')
	
	Conn.SendStream(Msg)
	Msg = libqualia.Stream()
	Msg.Push_String('fartwartz')
	
	Conn.SendStream(Msg)

Connection = libqualia.TLSConnection(OnRecvCB, None, None, RootCert, Hostname, 4122)

print('Qualia TLSConnection initialized successfully.')

Msg = libqualia.Stream()
Msg.Push_String(Stringy)

Connection.SendStream(Msg)

while True:
	match ECode := Connection.EventLoop():
		case libqualia.QUALIA_QLS_OK:
			time.sleep(0.05)
		case libqualia.QUALIA_QLS_RUNAGAIN:
			continue
		case _ :
			print(f'Got event loop return code {ECode}')
			sys.exit(0)

