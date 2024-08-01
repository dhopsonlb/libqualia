#!/usr/bin/env python3

import os, sys, time
sys.path.append('../build')
import libqualia

PrivateKeyLocation: str = sys.argv[1]
CertLocation: str = sys.argv[2]

with open(PrivateKeyLocation, 'r') as Desc:
	PrivateKey = Desc.read()
with open(CertLocation, 'r') as Desc:
	Cert = Desc.read()

print(PrivateKey)
print(Cert)

def OnRecvCB(Server: libqualia.TLSServer, ClientID: int, Stream: libqualia.Stream):
	S: str = Stream.Pop_String()
	print(f'ClientID {ClientID} received a stream with string {S}')

	Msg = libqualia.Stream()
	Msg.Push_String(S[::-1])
	
	Server.SendStream(ClientID, Msg)
	
	Msg = libqualia.Stream()
	Msg.Push_String('boogershitz')
	
	Server.SendStream(ClientID, Msg)

Server = libqualia.TLSServer(OnRecvCB, None, None, Cert, PrivateKey, 4122)

print('Qualia TLSServer initialized successfully.')

while True:
	match ECode := Server.EventLoop():
		case libqualia.QUALIA_QLS_OK:
			time.sleep(0.05)
		case libqualia.QUALIA_QLS_RUNAGAIN:
			continue
		case _ :
			print(f'Got event loop return code {ECode}')
			sys.exit(0)
