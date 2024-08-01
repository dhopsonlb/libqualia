///Qualia is copyright (c) 2024 Daniel Hopson.
///All rights reserved.
//The tests require a POSIX compatible, hosted compiler, and C11.
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdatomic.h>
#include <pthread.h>
#include <stdbool.h>
#include "../include/qualia.h"

#define QUALIA_TEST_FAIL(s) { fprintf(stderr, "Test %s failed, got error \"%s\"", __func__, s); return false; }
#define QUALIA_TEST_FAIL_IF(cond, s) if (cond) QUALIA_TEST_FAIL(s)

#ifndef QUALIA_NO_TLS

#include "../include/qualiatls.h"
#include "keys/tests_serverprivkey.h"
#include "keys/tests_rootcert.h"
#include "keys/tests_servercert.h"

#define TLS_TEST_STRING "boogers"

static atomic_bool TLSStringMatches;

static void QualiaTLSTest_OnRecvStream(QualiaTLSConnection *const Conn, QualiaStream *const Stream, void *const Userdata)
{
	const char *const Stringy = Qualia_Stream_Pop_String(Stream);
	
	fprintf(stderr, "Got QualiaStream string %s\n", Stringy);

	atomic_store(&TLSStringMatches, strcmp(TLS_TEST_STRING, Stringy) == 0);
}

static void QualiaTLSTest_OnConnect(QualiaTLSConnection *const Conn, const char *IP, const uint16_t PortNum, void *const Userdata)
{
	fprintf(stderr, "QualiaTLSConnection connected at hostname %s and port %u, userdata is %u\n", IP, (unsigned)PortNum, (unsigned)(uintptr_t)Userdata);
}

static void QualiaTLSTest_OnDisconnect(QualiaTLSConnection *const Conn, void *const Userdata)
{
	fprintf(stderr, "QualiaTLSConnection disconnected, userdata is %u\n", (unsigned)(uintptr_t)Userdata);
}

static void QualiaTLSTest_OnRecvClientStream(QualiaTLSServer *const Server, const uint32_t ClientID, QualiaStream *const Stream, void *const Userdata)
{
	const char *const Stringy = Qualia_Stream_Pop_String(Stream);
	
	fprintf(stderr, "Got QualiaStream string %s for ClientID %u\n", Stringy, (unsigned)ClientID);
	
	QualiaTLSServer_SendStream(Server, ClientID, Stream); //Send it right back into the Tx buffer for that client.
}

static void QualiaTLSTest_OnClientConnect(QualiaTLSServer *const Server, const uint32_t ClientID, const char *IP, void *const Userdata)
{
	fprintf(stderr, "ClientID %u has connected from IP %s, userdata is %u\n", ClientID, IP, (unsigned)(uintptr_t)Userdata);
}

static void QualiaTLSTest_OnClientDisconnect(QualiaTLSServer *const Server, const uint32_t ClientID, void *const Userdata)
{
}

static atomic_bool TLSServerThreadShouldDie;

static void *TLSServerThreadFunc(void *const Server_)
{
	QualiaTLSServer *const Server = Server_;

	QualiaLoopStatus LoopStatus = QUALIA_QLS_OK;

	while (!atomic_load(&TLSServerThreadShouldDie))
	{
		do
		{
			LoopStatus = QualiaTLSServer_EventLoop(Server, NULL, 0);
			
		} while (LoopStatus == QUALIA_QLS_RUNAGAIN);

		switch (LoopStatus)
		{
			case QUALIA_QLS_SHUTDOWN:
			case QUALIA_QLS_ERROR:
			{
				puts("Server error");
				goto ExitServerThread;
				break;
			}
			case QUALIA_QLS_OK:
			{
				usleep(10 * 1000); //Sleep 10 milliseconds before retrying.
				continue;
			}
			default:
				continue;
		}
	}
	
ExitServerThread:

	QualiaTLSServer_Shutdown(Server);

	return NULL;
}

static bool QualiaTLSTest(QualiaContext *const Ctx)
{

	char Err[1024] = "";
	
	QualiaTLSServerParams ServerParams =	{
												.Ctx = Ctx,
												.Snprintf = snprintf,
												.OnRecvStream = QualiaTLSTest_OnRecvClientStream,
												.OnClientConnect = QualiaTLSTest_OnClientConnect,
												.OnClientDisconnect = QualiaTLSTest_OnClientDisconnect,
												.CBUserdata = (void*)(uintptr_t)4444u,
												.ServerCertData = QualiaTest_ServerCert_Data,
												.ServerCertLen = sizeof QualiaTest_ServerCert_Data,
												.PrivateKeyData = QualiaTest_ServerPrivKey_Data,
												.PrivateKeyLen = sizeof QualiaTest_ServerPrivKey_Data,
												.PortNum = QUALIA_TLS_DEFAULT_PORT,
												
											};
											
	QualiaTLSServer *const Server = QualiaTLSServer_Init(&ServerParams, Err, sizeof Err);

	QUALIA_TEST_FAIL_IF(!Server, Err);

	//Server created.

	QualiaTLSConnectionParams ConnParams =	{
												.Ctx = Ctx,
												.Snprintf = snprintf,
												.OnRecvStream = QualiaTLSTest_OnRecvStream,
												.OnDisconnect = QualiaTLSTest_OnDisconnect,
												.OnConnect = QualiaTLSTest_OnConnect,
												.CBUserdata = (void*)(uintptr_t)2200u,
												.Hostname = "127.0.0.1",
												.PortNum = QUALIA_TLS_DEFAULT_PORT,
												.CACertData = QualiaTest_RootCert_Data,
												.CACertLen = sizeof QualiaTest_RootCert_Data,
											};

	pthread_t ServerThread = { 0 };

	pthread_create(&ServerThread, NULL, TLSServerThreadFunc, Server);

	QualiaTLSConnection *const Conn = QualiaTLSConnection_Init(&ConnParams, Err, sizeof Err);

	QUALIA_TEST_FAIL_IF(!Conn, Err);
	
	QualiaStream *Stream = Qualia_Stream_New(Ctx, 128);

	Qualia_Stream_Push_String(Stream, TLS_TEST_STRING);
	
	QualiaTLSConnection_SendStream(Conn, Stream);

	time_t Expire = time(NULL) + 5;
	
	while (time(NULL) < Expire)
	{
		QualiaTLSConnection_EventLoop(Conn, NULL, 0);
	}
	
	//Shut down thread.
	atomic_store(&TLSServerThreadShouldDie, true);

	pthread_join(ServerThread, NULL);
	
	return atomic_load(&TLSStringMatches);
}

#endif // !QUALIA_NO_TLS

static bool CoreProtocolTest(QualiaContext *const Ctx)
{	
	QualiaStream *Stream = Qualia_Stream_New(Ctx, 8);

	Qualia_Stream_Push_String(Stream, "BOOGERS!");
	Qualia_Stream_Push_String(Stream, "WARTS!");
	Qualia_Stream_Push_Uint32(Stream, 4444);
	Qualia_Stream_Push_Uint16(Stream, 2020);
	Qualia_Stream_Push_Blob(Stream, "DERP", sizeof "DERP");
	Qualia_Stream_Push_Uint64(Stream, 77777777777777);
	Qualia_Stream_Push_Byte(Stream, 44);
	Qualia_Stream_Push_Bool(Stream, false);
	Qualia_Stream_Push_Bool(Stream, true);
	Qualia_Stream_Push_Blob(Stream, "WEEBLE", sizeof "WEEBLE");

	Qualia_Stream_Push_Bool(Stream, true);
	Qualia_Stream_Push_Bool(Stream, false);

	if (!Qualia_Stream_Validate(Stream))
	{
		puts("Stream validation failed!");
		Qualia_Stream_Destroy(Stream);
		Qualia_DestroyContext(Ctx);
		return false;
	}
	
	assert(!strcmp(Qualia_Stream_Pop_String(Stream), "BOOGERS!"));
	assert(!strcmp(Qualia_Stream_Pop_String(Stream), "WARTS!"));
	assert(Qualia_Stream_Pop_Uint32(Stream) == 4444);
	assert(Qualia_Stream_Pop_Uint16(Stream) == 2020);

	uint32_t BlobLen = 0;
	const void *Blob = Qualia_Stream_Pop_Blob(Stream, &BlobLen);

	assert(memcmp(Blob, "DERP", BlobLen) == 0);
	
	assert(Qualia_Stream_Pop_Uint64(Stream) == 77777777777777);
	assert(Qualia_Stream_Pop_Byte(Stream) == 44);
	assert(Qualia_Stream_Pop_Bool(Stream) == false);
	assert(Qualia_Stream_Pop_Bool(Stream) == true);
	Blob = Qualia_Stream_Pop_Blob(Stream, &BlobLen);
	assert(memcmp(Blob, "WEEBLE", sizeof "WEEBLE") == 0);

	assert(Qualia_Stream_Pop_Bool(Stream) == true);
	assert(Qualia_Stream_Pop_Bool(Stream) == false);

	
	Qualia_Stream_Destroy(Stream);	
	return true;
}

int main(void)
{
	QualiaContext *Ctx = Qualia_InitContext(malloc, calloc, free, realloc);

	if (!Ctx)
	{
		fputs("Error allocating QualiaContext!\n", stderr);
		return -10;
	}

	bool AnyTestFailed = false;
	
	if (!CoreProtocolTest(Ctx))
	{
		fputs("Core protocol test failed!", stderr);
		AnyTestFailed = true;
	}

#ifndef QUALIA_NO_TLS
	if (!QualiaTLSTest(Ctx))
	{
		fputs("TLS networking stack test failed!", stderr);
		AnyTestFailed = true;
	}
#endif // !QUALIA_NO_TLS

	Qualia_DestroyContext(Ctx);

	return (int)AnyTestFailed;
}
