/*MIT License

Copyright (c) 2024 Daniel Hopson

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#ifndef __LIBQUALIA_QUALIATLS_HEADER_H__
#define __LIBQUALIA_QUALIATLS_HEADER_H__

#ifdef __cplusplus
extern "C"
{
#endif //__cplusplus

#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <stdarg.h>

#include "qualia.h"


#define QUALIA_STRIZE(s) #s

#define QUALIA_TLS_DEFAULT_PORT 4122
#define QUALIA_TLS_DEFAULT_PORT_STR QUALIA_STRIZE(QUALIA_TLS_PORT)

typedef enum QualiaLoopStatus
{
	QUALIA_QLS_ERROR = -1, //Socket has an actual error, other than just being closed.
	QUALIA_QLS_RUNAGAIN,
	QUALIA_QLS_OK,
	QUALIA_QLS_SHUTDOWN, //Socket has closed
	QUALIA_QLS_MAX
} QualiaLoopStatus;

typedef struct QualiaTLSServer
{
	void *Internal;
} QualiaTLSServer;

typedef struct QualiaTLSConnection
{
	void *Internal;
} QualiaTLSConnection;

typedef struct QualiaTLSConnectionParams
{ //All parameters are required to be valid and non-NULL unless otherwise specified. Arranged for alignment.
	QualiaContext *Ctx;

	int (*Snprintf)(char *Buf, size_t Size, const char *, ...);

	//Our callbacks.
	void (*OnRecvStream)(QualiaTLSConnection *const Conn, QualiaStream *const Stream, void *Userdata);
	void (*OnDisconnect)(QualiaTLSConnection *const Conn, void *Userdata);
	void (*OnConnect)(QualiaTLSConnection *const Conn, const char *Hostname, const uint16_t PortNum, void *Userdata);

	void *CBUserdata; //Optional

	const void *CACertData;
	const char *Hostname;

	size_t CACertLen;
	uint16_t PortNum;

} QualiaTLSConnectionParams;

typedef struct QualiaTLSServerParams
{ //All parameters are required to be valid and non-NULL unless otherwise specified. Arranged for alignment.
	QualiaContext *Ctx; //Do NOT create multiple contexts and be passing them around to this! wolfSSL requires exactly one context.

	int (*Snprintf)(char *Buf, size_t Size, const char *, ...);

	//Our callbacks.
	void (*OnRecvStream)(QualiaTLSServer *const Server, const uint32_t ClientID, QualiaStream *const Stream, void *Userdata);
	void (*OnClientDisconnect)(QualiaTLSServer *const Server, const uint32_t ClientID, void *Userdata);
	void (*OnClientConnect)(QualiaTLSServer *const Server, const uint32_t ClientID, const char *IP, void *Userdata);

	void *CBUserdata; //Optional

	const void *ServerCertData;
	const void *PrivateKeyData;

	size_t ServerCertLen;
	size_t PrivateKeyLen;
	uint16_t PortNum;

} QualiaTLSServerParams;

//None of this is thread-safe. It's not meant to be.
/// Server side
QualiaTLSServer *QualiaTLSServer_Init(const QualiaTLSServerParams *const Params, char *const ErrOut, const size_t ErrOutCapacity);
QualiaLoopStatus QualiaTLSServer_EventLoop(QualiaTLSServer *Server,	char *ErrOut, const size_t ErrOutCapacity);
bool QualiaTLSServer_SendStream(QualiaTLSServer *const Server, const uint32_t ClientID, QualiaStream *const Stream);
void QualiaTLSServer_Shutdown(QualiaTLSServer *const Server);


///Client side
QualiaTLSConnection *QualiaTLSConnection_Init(const QualiaTLSConnectionParams *const Params, char *ErrOut, const size_t ErrOutCapacity);
QualiaLoopStatus QualiaTLSConnection_EventLoop(QualiaTLSConnection *const Conn, char *const ErrOut, const size_t ErrOutCapacity);
bool QualiaTLSConnection_SendStream(QualiaTLSConnection *const Conn, QualiaStream *const Stream);
void QualiaTLSConnection_Destroy(QualiaTLSConnection *const Conn);

//Returns total number of events. Set timeout to zero to exit immediately.


#ifdef __cplusplus
}
#endif //__cplusplus

#endif //__LIBQUALIA_QUALIATLS_HEADER_H__
