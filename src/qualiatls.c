///Qualia is copyright (c) 2024 Daniel Hopson.
///All rights reserved.

#include "../include/qualiatls.h"

#ifndef OPENSSL_EXTRA_X509_SMALL
#define OPENSSL_EXTRA_X509_SMALL
#endif //OPENSSL_EXTRA_X509_SMALL

#ifdef QUALIA_USE_WOLFSSL
#include <wolfssl/ssl.h>
#include <wolfssl/options.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/err.h>
#else
#include <openssl/ssl.h>
#include <openssl/opensslv.h>
#include <openssl/err.h>
#endif //QUALIA_USE_WOLFSSL

#if defined(WIN32) || defined(_MSC_VER) || defined(__MINGW32__) || defined(__MINGW64__)
#include <winsock2.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>            // struct addrinfo
#include <arpa/inet.h>
#endif //WIN32

#ifdef ESP_PLATFORM //Needs the POSIX headers, but also these.
#include <esp_netif.h>
#endif //ESP_PLATFORM

#define QUALIATLS_MAX_TX_PER_ITER 4

typedef struct QueuedStream
{
	QualiaStream *Stream;
	struct QueuedStream *Next; //Towards the back (tail) of the queue.
	struct QueuedStream *Prev; //Towards the front (head) of the queue.
	uint32_t Written;
} QueuedStream;

typedef struct QualiaStreamOutQueue
{
	QueuedStream *Front; //Always the newest stream in the queue.
	QueuedStream *Back; //Always the oldest, next-to-be-sent stream in the queue.
	size_t Size; //Number of outgoing streams.
} QualiaStreamOutQueue;

typedef struct PartialQualiaStream
{
	uint8_t *Data; //Incoming stream bytes.
	size_t Received; //Number of bytes received for this partial stream so far
	size_t TotalStreamSize; //Total stream size we got from reading the uint32_t at the start.
} PartialQualiaStream;

typedef struct TLSClient
{
	SSL *SSLObj;
	int Sock;
	//Most recent stream is at the head, currently transmitted stream is at the tail.
	QualiaStreamOutQueue OutQueue;
	PartialQualiaStream PartialData;
	char IP[48];
	bool Populated;
	bool NeedRXSelect;
} TLSClient;

typedef struct TLSServerInternal
{
	QualiaContext *Ctx;
	int (*Snprintf)(char *Buf, size_t Size, const char *, ...);
	int (*Vsnprintf)(char *Buf, size_t Size, const char *, va_list);
	void (*OnRecvStream)(QualiaTLSServer *const Server, const uint32_t ClientID, QualiaStream *const Stream, void *Userdata);
	void (*OnClientDisconnect)(QualiaTLSServer *const Server, const uint32_t ClientID, void *Userdata);
	void (*OnClientConnect)(QualiaTLSServer *const Server, const uint32_t ClientID, const char *IP, void *Userdata);
	void *CBUserdata;
	SSL_CTX *SSLCtx;
    TLSClient *Clients;
    size_t NumClients;
    size_t ClientsCapacity;
    int ServerSock;
    uint16_t PortNum;

} TLSServerInternal;

typedef struct TLSConnectionInternal
{
	QualiaContext *Ctx;
	QualiaStreamOutQueue OutQueue;
	PartialQualiaStream PartialData;
	int (*Snprintf)(char *Buf, size_t Size, const char *, ...);
	int (*Vsnprintf)(char *Buf, size_t Size, const char *, va_list);
	void (*OnRecvStream)(QualiaTLSConnection *const Conn, QualiaStream *const Stream, void *Userdata);
	void (*OnDisconnect)(QualiaTLSConnection *const Conn, void *Userdata);
	void (*OnConnect)(QualiaTLSConnection *const Conn, const char *IP, const uint16_t PortNum, void *Userdata);
	void *CBUserdata;
    SSL_CTX *SSLCtx;
    SSL *SSLObj;
    X509 *RCert;
    int Sock;
    bool NeedRXSelect;
} TLSConnectionInternal;

//Static helper functions
static TLSClient *NewServerClient(TLSServerInternal *I);
static QUALIA_FORCE_INLINE uint32_t GetServerClientID(TLSServerInternal *const I, TLSClient *const Client);
static int HandleClientEvents(	QualiaTLSServer *const Server,
								TLSClient *const Client,
								char *ErrOut, const size_t ErrOutCapacity);
static TLSClient *InitTLSClient(QualiaTLSServer *const Server,
								const int Sock,
								SSL *const SSLObj,
								const char *const IPAddr,
								char *const ErrOut,
								const size_t ErrOutCapacity);
static TLSClient *LookupClient(TLSServerInternal *const I, const uint32_t ID);
static int ProcessAccepts(	QualiaTLSServer *const Server,
							char *ErrOut, const size_t ErrOutCapacity);
static bool QualiaStreamOutQueue_PushFront(QualiaContext *const Ctx, QualiaStreamOutQueue *const OutQueue, QualiaStream *const Stream);
static bool QualiaStreamOutQueue_PopBack(QualiaContext *const Ctx, QualiaStreamOutQueue *const OutQueue);
static int QualiaStreamOutQueue_Tx(QualiaContext *const Ctx, QualiaStreamOutQueue *const OutQueue, SSL *SSLObj, int *const ErrorCodeOut);
static void QualiaStreamOutQueue_Destroy(QualiaContext *const Ctx, QualiaStreamOutQueue *const OutQueue);
static void PartialQualiaStream_AutoExtractStreamSize(PartialQualiaStream *const Partial);
static QualiaStream *PartialQualiaStream_Append(QualiaContext *const Ctx, PartialQualiaStream *Partial, const uint32_t ClientID, const void *const Data, const size_t Len);
static void PartialQualiaStream_Destroy(QualiaContext *const Ctx, PartialQualiaStream *const Partial);
static int BSDSock_Connect(TLSConnectionInternal *const I, const char *const InHost, const char *const PortText, char *const ErrOut, const size_t ErrOutCapacity);
static inline bool Qualia_CloseSocket(const int Descriptor);
static void FreeServerClient(TLSServerInternal *I, TLSClient *const Client);
static void SetDefaultSSLOpts(SSL_CTX *SSLCtx);

static inline bool SetNonblockingSock(const int Sock)
{
#if defined(WIN32) || defined(_MSC_VER) || defined(__MINGW32__) || defined(__MINGW64__)
	unsigned long Value = 1;
	
	return ioctlsocket(Sock, FIONBIO, &Value) == 0;
#else
	return fcntl(Sock, F_SETFL, O_NONBLOCK) == 0;
#endif //WIN32
}

QualiaLoopStatus QualiaTLSConnection_EventLoop(QualiaTLSConnection *const Conn, char *const ErrOut, const size_t ErrOutCapacity)
{
	TLSConnectionInternal *const I = Conn->Internal;

	bool DidAnything = false;

	int Err = 0;

	do
	{
		uint8_t Buffer[64] = { 0 };


		fd_set PollSet;
		FD_ZERO(&PollSet);
		FD_SET(I->Sock, &PollSet);

		struct timeval ZeroTime = { .tv_sec = 0, .tv_usec = 0 };
		
		if (I->NeedRXSelect && select(I->Sock + 1, &PollSet, NULL, NULL, &ZeroTime) == 0)
		{
			break;
		}

		I->NeedRXSelect = false;
		
		const int Read = SSL_read(I->SSLObj, Buffer, sizeof Buffer);

		if (Read <= 0)
		{
			Err = SSL_get_error(I->SSLObj, Read);

			if (Err == SSL_ERROR_WANT_READ || Err == SSL_ERROR_WANT_WRITE)
			{
				I->NeedRXSelect = true;
				break; //Nothing to read. Not an error. Skip reading this iteration.
			}

			//Actual error if we got here.
			if (ErrOut)
			{
				char ErrStr[128] = "";
				ERR_error_string_n(Err, ErrStr, sizeof(ErrStr) - 1);

				I->Snprintf(ErrOut, ErrOutCapacity, "Got SSL_read() error integer %i with strerror \"%s\"", Err, ErrStr);
			}

			//Disconnect the client.
			if (I->OnDisconnect != NULL)
			{
				I->OnDisconnect(Conn, I->CBUserdata);
			}

			return QUALIA_QLS_SHUTDOWN;
		}
		
		//We got data, so, we "did something".
		DidAnything = true;

		//Add the transmitted data to the current partial stream.
		QualiaStream *const NewStream = PartialQualiaStream_Append(I->Ctx, &I->PartialData, 0, Buffer, Read);

		if (NewStream)
		{ //Just now got enough data to call it a new stream.
			if (I->OnRecvStream != NULL)
			{
				I->OnRecvStream(Conn, NewStream, I->CBUserdata);
			}
			else
			{ //Nothing took the stream, get rid of it.
				Qualia_Stream_Destroy(NewStream);
			}
		}
	} while (Err > 0);


	int ErrorCode = 0;
	
	for (uint32_t NumTx = 0u;
		(Err = QualiaStreamOutQueue_Tx(I->Ctx, &I->OutQueue, I->SSLObj, &ErrorCode)) > 0 &&
		NumTx < QUALIATLS_MAX_TX_PER_ITER;
		++NumTx)
	{
		DidAnything = true;
	}

	if (Err == -1)
	{
		if (ErrOut)
		{
			char ErrStr[128] = "";
			ERR_error_string_n(ErrorCode, ErrStr, sizeof(ErrStr) - 1);

			I->Snprintf(ErrOut, ErrOutCapacity, "Got error from write, error integer %i with strerror %s", ErrorCode, ErrStr);
		}
		
		return QUALIA_QLS_ERROR;
	}

	return DidAnything ? QUALIA_QLS_RUNAGAIN : QUALIA_QLS_OK;
}

void QualiaTLSConnection_Destroy(QualiaTLSConnection *const Conn)
{
	TLSConnectionInternal *const I = Conn->Internal;

	if (!I) return;

	if (I->RCert)
	{
		X509_free(I->RCert);
	}
	
	if (I->SSLObj)
	{
		SSL_free(I->SSLObj);
	}
	
	if (I->SSLCtx)
	{
		SSL_CTX_free(I->SSLCtx);
	}

	void (*const Free)(void *) = I->Ctx->FreeFunc;

	Qualia_Memset(I, 0, sizeof(TLSConnectionInternal));

	Free(I);

	PartialQualiaStream_Destroy(I->Ctx, &I->PartialData);
	QualiaStreamOutQueue_Destroy(I->Ctx, &I->OutQueue);

	Qualia_Memset(Conn, 0, sizeof *Conn);

	Free(Conn);
}

static bool VerifyServerCert(TLSConnectionInternal *const I, SSL *SSLObj)
{ //Called to check that the server certificate is valid.
	X509 *const ServerCert = SSL_get_peer_certificate(SSLObj);

	if (!ServerCert)
	{
		return false;
	}
	
	EVP_PKEY *const RootPubKey = X509_get_pubkey(I->RCert);
	
	const bool Verified = X509_verify(ServerCert, RootPubKey) == 1;

	EVP_PKEY_free(RootPubKey);
	
	return Verified;
}

QualiaTLSConnection *QualiaTLSConnection_Init(const QualiaTLSConnectionParams *const Params, char *ErrOut, const size_t ErrOutCapacity)
{
	if (!Params->Snprintf)
	{
		const char ErrString[] = "An snprintf() implementation is required!";

		if (ErrOut && ErrOutCapacity >= sizeof ErrString)
		{
			Qualia_Memcpy(ErrOut, ErrString, sizeof ErrString);
		}

		return NULL;
	}
	
	QualiaContext *const Ctx = Params->Ctx;

	TLSConnectionInternal *const New = Ctx->CallocFunc(1, sizeof(TLSConnectionInternal));

	//Store QualiaContext
	New->Ctx = Ctx;

	//Unlike mbedtls wolfSSL doesn't seem to require snprintf(), but we sure fucking do.
	New->Snprintf = Params->Snprintf;
	
	//Set up user callbacks.
	New->OnRecvStream = Params->OnRecvStream;
	New->OnConnect = Params->OnConnect;
	New->OnDisconnect = Params->OnDisconnect;
	New->CBUserdata = Params->CBUserdata;

	//Fire up wolfSSL if it wasn't already.
#ifdef QUALIA_USE_WOLFSSL
	wolfSSL_Init();
#else
	SSL_library_init();
#endif
	
	//Load certificate we manually verify against
	BIO *const InBio = BIO_new_mem_buf((void*)Params->CACertData, Params->CACertLen);

	X509 *const RCert = PEM_read_bio_X509(InBio, NULL, NULL, NULL);

	if (!RCert)
	{
		BIO_free_all(InBio);
		goto Failure;
	}

	//Store root certificate for later verification.
	New->RCert = RCert;
	
	//Shouldn't need the bio now that we have the cert.
	BIO_free_all(InBio);

#ifdef QUALIA_USE_WOLFSSL
	New->SSLCtx = SSL_CTX_new(wolfTLSv1_3_client_method());
#else
	New->SSLCtx = SSL_CTX_new(TLS_client_method());
#endif //QUALIA_USE_WOLFSSL

	//Create SSL CTX
	if (!New->SSLCtx)
	{
		if (ErrOut)
		{
			Params->Snprintf(ErrOut, ErrOutCapacity, "Failed to create SSL CTX!");
		}

		goto Failure;
	}

	SetDefaultSSLOpts(New->SSLCtx);

	SSL_CTX_set_verify(New->SSLCtx, SSL_VERIFY_NONE, NULL);

	char PortText[16] = "";

	Params->Snprintf(PortText, sizeof PortText, "%u", (unsigned)Params->PortNum);

	const int Sock = BSDSock_Connect(New, Params->Hostname, PortText, ErrOut, ErrOutCapacity);

	if (Sock < 0)
	{
		goto Failure; //Already set its error code in ErrOut
	}

	SetNonblockingSock(Sock);
	
	SSL *SSLObj = SSL_new(New->SSLCtx);
	SSL_set_fd(SSLObj, Sock);
	New->SSLObj = SSLObj;
	New->Sock = Sock;
	
	int Err = 0;
	
RetryConnect:
	if ((Err = SSL_connect(SSLObj)) != 1)
	{
		Err = SSL_get_error(SSLObj, Err);

		if (Err == SSL_ERROR_WANT_CONNECT || Err == SSL_ERROR_WANT_READ || Err == SSL_ERROR_WANT_WRITE)
		{ //Spin until connected.
			goto RetryConnect;
		}
		
		if (ErrOut)
		{
			//Actual error if we got here.
			char ErrStr[128] = "";
			ERR_error_string_n(Err, ErrStr, sizeof(ErrStr) - 1);

			Params->Snprintf(ErrOut, ErrOutCapacity, "Got error integer %i from SSL_connect(), strerror %s", Err, ErrStr);
		}
		
		goto Failure;
	}
	
	
	if (!VerifyServerCert(New, SSLObj))
	{
		if (ErrOut)
		{
			Params->Snprintf(ErrOut, ErrOutCapacity, "Peer certificate validation failed!");
		}
		
		goto Failure;
	}

	QualiaTLSConnection *const RetVal = Ctx->CallocFunc(sizeof(QualiaTLSConnection), 1);

	if (!RetVal)
	{
		if (ErrOut)
		{
			Params->Snprintf(ErrOut, ErrOutCapacity, "Failed to allocate %u bytes for QualiaTLSConnection object", (unsigned)sizeof(QualiaTLSConnection));
		}

		goto Failure;

	}

	RetVal->Internal = New;

	if (New->OnConnect != NULL)
	{
		New->OnConnect(RetVal, Params->Hostname, Params->PortNum, New->CBUserdata);
	}

	return RetVal;

Failure:
	if (!New) return NULL;

	if (New->RCert)
	{
		X509_free(New->RCert);
	}
	
	if (New->SSLObj)
	{
		SSL_free(New->SSLObj);
	}
	
	if (New->SSLCtx)
	{
		SSL_CTX_free(New->SSLCtx);
	}
	
	Qualia_Memset(New, 0, sizeof(TLSConnectionInternal));

	Ctx->FreeFunc(New);

	return NULL;
}

bool QualiaTLSConnection_SendStream(QualiaTLSConnection *const Conn, QualiaStream *const Stream)
{
	if (!Conn || !Stream)
	{
		return false;
	}
	
	TLSConnectionInternal *const I = Conn->Internal;

	return QualiaStreamOutQueue_PushFront(I->Ctx, &I->OutQueue, Stream);
}

void QualiaTLSServer_Shutdown(QualiaTLSServer *const Server)
{
	if (!Server) return;
	
	TLSServerInternal *const I = Server->Internal;

	TLSClient *Worker = I->Clients;
	TLSClient *const Stopper = Worker + I->ClientsCapacity;

	for (; I->NumClients > 0 && Worker < Stopper; ++Worker)
	{
		FreeServerClient(I, Worker);
	}

	Qualia_CloseSocket(I->ServerSock);
	SSL_CTX_free(I->SSLCtx);

	I->Ctx->FreeFunc(Server); //Release our holder. We still have a valid pointer to the internal object.

	void (*const Free)(void *) = I->Ctx->FreeFunc;

	Qualia_Memset(I, 0, sizeof *I);

	Free(I); //The QualiaContext continues to exist after this.
}

//Function definitions
static QUALIA_FORCE_INLINE uint32_t GetServerClientID(TLSServerInternal *const I, TLSClient *const Client)
{
	if (!Client || !I) return 0;

	return (uint32_t)(Client - I->Clients) + 1; //ID is computed from its distance to the start of the buffer.
}

static void QualiaStreamOutQueue_Destroy(QualiaContext *const Ctx, QualiaStreamOutQueue *const OutQueue)
{
	QueuedStream *Worker = OutQueue->Front;

	while (Worker != NULL)
	{
		Qualia_Stream_Destroy(Worker->Stream);

		QueuedStream *const Next = Worker->Next;

		Ctx->FreeFunc(Worker);

		Worker = Next;
	}
}

static bool QualiaStreamOutQueue_PopBack(QualiaContext *const Ctx, QualiaStreamOutQueue *const OutQueue)
{
	if (!OutQueue || !OutQueue->Back) return false;

	QueuedStream *Back = OutQueue->Back;
	QualiaStream *const Stream = Back->Stream;

	Qualia_Stream_Destroy(Stream);

	if (Back->Prev != NULL)
	{ //We have another stream to send after this one.
		Back->Prev->Next = NULL; //Tell the stream after us to forget about us.

		OutQueue->Back = Back->Prev;
	}
	else
	{		
		OutQueue->Back = NULL;
		OutQueue->Front = NULL;
	}

	Ctx->FreeFunc(Back);

	--OutQueue->Size;
	return true;
}

static bool QualiaStreamOutQueue_PushFront(QualiaContext *const Ctx, QualiaStreamOutQueue *const OutQueue, QualiaStream *const Stream)
{
	if (!OutQueue->Front)
	{
		OutQueue->Front = OutQueue->Back = Ctx->CallocFunc(1, sizeof(QueuedStream));

		if (!OutQueue->Front) return false;

		OutQueue->Front->Stream = Stream;
		OutQueue->Size = 1;
		return true;
	}

	QueuedStream *const NewFront = Ctx->CallocFunc(1, sizeof(QueuedStream));

	if (!NewFront) return false;

	NewFront->Stream = Stream;

	QueuedStream *OldFront = OutQueue->Front;

	NewFront->Next = OldFront;
	OldFront->Prev = NewFront;

	OutQueue->Front = NewFront;

	++OutQueue->Size;

	return true;
}

static int QualiaStreamOutQueue_Tx(QualiaContext *const Ctx, QualiaStreamOutQueue *const OutQueue, SSL *SSLObj, int *const ErrorCodeOut)
{
	if (!OutQueue->Back) return 0;

	QueuedStream *const Queued = OutQueue->Back;
	QualiaStream *const Stream = Queued->Stream;

	const uint32_t StreamSize = Qualia_Stream_GetSize(Stream);
	const int Written = SSL_write(SSLObj, Stream->Bytes + Queued->Written, StreamSize - Queued->Written);

	if (Written <= 0)
	{
		const int Err = SSL_get_error(SSLObj, Written);

		if (Err == SSL_ERROR_WANT_WRITE || Err == SSL_ERROR_WANT_READ)
		{
			return 0; //Not an error, just not ready to write.
		}

		if (ErrorCodeOut)
		{
			*ErrorCodeOut = Err;
		}
		
		return -1;
	}

	Queued->Written += Written;
	
	if (Queued->Written >= StreamSize)
	{
		QualiaStreamOutQueue_PopBack(Ctx, OutQueue);
	}

	return Written;
}

static inline bool Qualia_CloseSocket(const int Descriptor)
{ //Winsock has a fucky close()
#if defined(WIN32) || defined(_MSC_VER) || defined(__MINGW32__) || defined(__MINGW64__)
	return !closesocket(Descriptor);
#else
	return !close(Descriptor);
#endif
}

static int BSDSock_Connect(TLSConnectionInternal *const I, const char *const InHost, const char *const PortText, char *const ErrOut, const size_t ErrOutCapacity)
{
	struct addrinfo Hints = { 0 }, *Res = NULL;
	
	Hints.ai_family = AF_UNSPEC;
	Hints.ai_socktype = SOCK_STREAM;
	
	if (getaddrinfo(InHost, PortText, &Hints, &Res) != 0)
	{
		if (ErrOut)
		{
			I->Snprintf(ErrOut, ErrOutCapacity, "Failed to resolve hostname \"%s\".", InHost);
		}
		
		return -1;
	}

	const int Desc = socket(Res->ai_family, Res->ai_socktype, Res->ai_protocol);

	if (Desc <= 0)
	{
		if (ErrOut)
		{
			I->Snprintf(ErrOut, ErrOutCapacity, "Failed to create socket, got error integer %i", Desc);
		}

		return -1;
	}

	int Err = 0;
	
	if ((Err = connect(Desc, Res->ai_addr, Res->ai_addrlen)) != 0)
	{
		if (ErrOut)
		{
			I->Snprintf(ErrOut, ErrOutCapacity, "Failed to connect to host at %s:%s, got error integer %i", InHost, PortText, Err);
		}

		Qualia_CloseSocket(Desc);
		
		return -1;
	}

	return Desc;
}

static int BSDSockServer_Init(TLSServerInternal *const I, char *const ErrOut, const size_t ErrOutCapacity)
{
	struct addrinfo BStruct = { 0 }, *Res = NULL;
	char AsciiPort[16] = "";
	static int True = true, False = false;
	int Err = 0;

	I->Snprintf(AsciiPort, sizeof AsciiPort, "%u", (unsigned)I->PortNum); //Cast to an unsigned in case of brain-dead snprintf() implementation.

	BStruct.ai_family = AF_INET6;
	BStruct.ai_socktype = SOCK_STREAM;
	BStruct.ai_flags = AI_PASSIVE;

	if ((Err = getaddrinfo(NULL, AsciiPort, &BStruct, &Res)) != 0)
	{
		if (ErrOut)
		{
			I->Snprintf(ErrOut, ErrOutCapacity, "Failed to getaddrinfo(): %s", (const char*)gai_strerror(Err));
		}

		return -1;
	}

	const int Desc = (int)socket(Res->ai_family, Res->ai_socktype, Res->ai_protocol);

	SetNonblockingSock(Desc);

	if (Desc <= 0)
	{
		if (ErrOut)
		{
			I->Snprintf(ErrOut, ErrOutCapacity, "Failed to open a socket on port %s", AsciiPort);
		}

		return -1;
	}

	setsockopt(Desc, SOL_SOCKET, SO_REUSEADDR, (const char*)&True, sizeof(int)); //The cast shuts up Windows compilation.
	setsockopt(Desc, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&False, sizeof(int)); //The cast shuts up Windows compilation.

	if (bind(Desc, Res->ai_addr, Res->ai_addrlen) == -1)
	{
		if (ErrOut)
		{
			I->Snprintf(ErrOut, ErrOutCapacity, "Failed to bind() on port %s, errno is %d", AsciiPort, (int)errno);
		}

		Qualia_CloseSocket(Desc);
		return -1;
	}

	//As soon as we don't need it, free it.
	freeaddrinfo(Res);
	
	if (listen(Desc, INT_MAX) == -1)
	{
		if (ErrOut)
		{
			I->Snprintf(ErrOut, ErrOutCapacity, "Failed to listen() on port %s, errno is %d", AsciiPort, (int)errno);
		}
		
		Qualia_CloseSocket(Desc);
		return -1;
	}

	return Desc;
}

static bool BSDSockServer_Accept(TLSServerInternal *const I, int *const ClientDescOut, SSL **const SSLOut, char *const OutIPAddr, const size_t IPAddrMaxLen, char *const ErrOut, const size_t ErrOutCapacity)
{
	struct sockaddr_storage ClientInfo = { 0 };
	struct sockaddr_storage Addr = { 0 };

	socklen_t SockaddrSize = sizeof ClientInfo;
	socklen_t AddrSize = sizeof Addr;
	
	const int ClientDesc = accept(I->ServerSock, (struct sockaddr*)&ClientInfo, &SockaddrSize);
	
	if (ClientDesc == -1) //Accept error.
	{
		return false;
	}
	
	//Get client IP.
	getpeername(ClientDesc, (struct sockaddr*)&Addr, &AddrSize);
	
#ifdef WIN32
	DWORD IPLen = (DWORD)IPAddrMaxLen;
	WSAAddressToString((struct sockaddr*)&ClientInfo, sizeof ClientInfo, nullptr, OutIPAddr, &IPLen);
#else
	switch (ClientInfo.ss_family)
	{
		default:
		case AF_INET:
		{
			inet_ntop(ClientInfo.ss_family, &((const struct sockaddr_in*)&ClientInfo)->sin_addr, OutIPAddr, IPAddrMaxLen);
			break;
		}
		case AF_INET6:
		{
			inet_ntop(ClientInfo.ss_family, &((const struct sockaddr_in6*)&ClientInfo)->sin6_addr, OutIPAddr, IPAddrMaxLen);
			break;
		}
	}

#endif //WIN32

	SSL *const New = SSL_new(I->SSLCtx);
	SSL_set_fd(New, ClientDesc);

	if (SSL_accept(New) < 1)
	{
		Qualia_CloseSocket(ClientDesc);
		return false;
	}

	//After we've accepted the socket, we set it to nonblocking.
	SetNonblockingSock(ClientDesc); //Switch the socket itself to nonblocking
#ifdef QUALIA_USE_WOLFSSL
	wolfSSL_set_using_nonblock(New, 1); //And now tell WolfSSL we're doing that.
#endif //QUALIA_USE_WOLFSSL
	*SSLOut = New;
	*ClientDescOut = ClientDesc; //Give them their descriptor.

	return true;
}

static void SetDefaultSSLOpts(SSL_CTX *SSLCtx)
{

	SSL_CTX_set_options(SSLCtx, SSL_OP_NO_COMPRESSION |
									SSL_OP_NO_SSLv2 |
									SSL_OP_NO_SSLv3 |
									SSL_OP_NO_TLSv1_1 |
									SSL_OP_NO_TLSv1_2);

	//Force TLS 1.3 100% of the time.
	SSL_CTX_set_min_proto_version(SSLCtx, TLS1_3_VERSION);
	SSL_CTX_set_num_tickets(SSLCtx, 0);
}

QualiaTLSServer *QualiaTLSServer_Init(const QualiaTLSServerParams *const Params, char *const ErrOut, const size_t ErrOutCapacity)
{
	QualiaContext *const Ctx = Params->Ctx;

	TLSServerInternal *const New = Ctx->CallocFunc(1, sizeof(TLSServerInternal));

	if (!New)
	{
		if (ErrOut)
		{
			Params->Snprintf(ErrOut, ErrOutCapacity, "Unable to allocate %u bytes for internal structure!", (unsigned)sizeof(TLSServerInternal));
		}

		return NULL;
	}

	//Store context
	New->Ctx = Ctx;

	//Set up required functions.
	New->Snprintf = Params->Snprintf;

#ifdef QUALIA_USE_WOLFSSL //OpenSSL doesn't work on embedded anyways.
	wolfSSL_SetAllocators(Ctx->MallocFunc, Ctx->FreeFunc, Ctx->ReallocFunc);
#endif //QUALIA_USE_WOLFSSL

	//Set up user callbacks.
	New->OnRecvStream = Params->OnRecvStream;
	New->OnClientConnect = Params->OnClientConnect;
	New->OnClientDisconnect = Params->OnClientDisconnect;
	New->CBUserdata = Params->CBUserdata;
	New->PortNum = Params->PortNum;


#if QUALIA_USE_WOLFSSL
	wolfSSL_Init();
	
	New->SSLCtx = SSL_CTX_new(wolfTLSv1_3_server_method());
#else
#if !OPENSSL_VERSION_PREREQ(3, 0)
	ERR_load_BIO_strings();
#endif // !OPENSSL_VERSION_PREREQ(3, 0)
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_digests();
    OpenSSL_add_ssl_algorithms();
	SSL_library_init();
	
	New->SSLCtx = SSL_CTX_new(TLS_server_method());
#endif //QUALIA_USE_WOLFSSL

	SetDefaultSSLOpts(New->SSLCtx);
	
	if (!New->SSLCtx)
	{
		if (ErrOut)
		{
			Params->Snprintf(ErrOut, ErrOutCapacity, "Failed to create SSLCtx!");
		}

		goto Failure;
	}

	//Disable verification for server-side.
	SSL_CTX_set_verify(New->SSLCtx, SSL_VERIFY_NONE, NULL);

	int Err = 0;

	//SSL library independent loading from memory buffers, even though wolfssl has nicer functions.

	//Load server certificate
	BIO *const RCertBio = BIO_new_mem_buf((void*)Params->ServerCertData, Params->ServerCertLen);
	X509 *const RCert = PEM_read_bio_X509(RCertBio, NULL, 0, NULL);

	BIO_free_all(RCertBio);
	
    if ((Err = SSL_CTX_use_certificate(New->SSLCtx, RCert)) != 1)
    {
		if (ErrOut)
		{
			const int SSLErr = ERR_get_error();

			Params->Snprintf(ErrOut, ErrOutCapacity, "Failed on SSL_CTX_use_certificate ServerCert, got error integer %i", SSLErr);
		}

		X509_free(RCert);

		goto Failure;
	}
	
	X509_free(RCert);

	//Load private key.
	BIO *const PKBio = BIO_new_mem_buf((void*)Params->PrivateKeyData, Params->PrivateKeyLen);

	EVP_PKEY *PrivateKey = NULL;
	
	PEM_read_bio_PrivateKey(PKBio, &PrivateKey, 0, NULL);

	BIO_free_all(PKBio);

	//Load server certificate
    if ((Err = SSL_CTX_use_PrivateKey(New->SSLCtx, PrivateKey)) != 1)
    {
		if (ErrOut)
		{
			Params->Snprintf(ErrOut, ErrOutCapacity, "Failed on wolfSSL_CTX_use_PrivateKey, got error integer %i", Err);
		}

		goto Failure;
	}
	
	EVP_PKEY_free(PrivateKey);

	char PortText[16] = "";

	Params->Snprintf(PortText, sizeof PortText, "%u", (unsigned)New->PortNum);

	//Fire up networking
	if ((New->ServerSock = BSDSockServer_Init(New, ErrOut, ErrOutCapacity)) == -1)
	{ //Already fills ErrOut on error.
		goto Failure;
	}
	
	QualiaTLSServer *const RetVal = Ctx->CallocFunc(1, sizeof(QualiaTLSServer));

	RetVal->Internal = New;

	return RetVal;

Failure:

	if (New->SSLCtx)
	{
		SSL_CTX_free(New->SSLCtx);
	}
	
	Qualia_Memset(New, 0, sizeof *New); //Erase any sensitive data.

	Ctx->FreeFunc(New);

	return NULL;
}

static TLSClient *InitTLSClient(QualiaTLSServer *const Server,
								const int Sock,
								SSL *const SSLObj,
								const char *const IPAddr,
								char *const ErrOut,
								const size_t ErrOutCapacity)
{
	TLSServerInternal *const I = Server->Internal;

	TLSClient *const NewClient = NewServerClient(I);

	if (!NewClient) return NULL;

	//Add the client's structure to bookkeeping.
	NewClient->Sock = Sock;
	NewClient->SSLObj = SSLObj;
	
	const uint32_t IPLen = Qualia_Strlen(IPAddr);
	
	Qualia_Memcpy(NewClient->IP, IPAddr, QUALIA_NMIN(IPLen + 1, sizeof NewClient->IP)); //Copy null terminator too.

	return NewClient;
}

static void PartialQualiaStream_AutoExtractStreamSize(PartialQualiaStream *const Partial)
{
	if (!Partial->TotalStreamSize && Partial->Received >= sizeof(uint32_t))
	{
		uint32_t Size = 0;

		Qualia_Memcpy(&Size, Partial->Data, sizeof(uint32_t));
		Size = Qualia_Ntohl(Size);

		Partial->TotalStreamSize = Size + sizeof(uint32_t);
	}
}
static void PartialQualiaStream_Destroy(QualiaContext *const Ctx, PartialQualiaStream *const Partial)
{
	if (Partial->Data == NULL) return;

	Ctx->FreeFunc(Partial->Data);

	Qualia_Memset(Partial, 0, sizeof *Partial);
}

static QualiaStream *PartialQualiaStream_Append(QualiaContext *const Ctx, PartialQualiaStream *Partial, const uint32_t ClientID, const void *const Data, const size_t Len)
{ //Returns a new stream if there's enough data, rolls over the rest for later.
	uint8_t *const NewPtr = Partial->Data == NULL ?
							Ctx->CallocFunc(1, Len) :
							Qualia_Realloc(	Ctx,
											Partial->Data,
											Partial->Received,
											Partial->Received + Len);

	if (!NewPtr) return NULL;

	Qualia_Memcpy(NewPtr + Partial->Received, Data, Len);

	Partial->Data = NewPtr;
	Partial->Received += Len;

	PartialQualiaStream_AutoExtractStreamSize(Partial);

	QualiaStream *RetVal = NULL;

	if (Partial->TotalStreamSize > 0 && Partial->Received >= Partial->TotalStreamSize)
	{ //Stream ready? Graduate it if so.
		RetVal = Ctx->CallocFunc(1, sizeof(QualiaStream));

		RetVal->Bytes = Partial->Data; //Move directly into the new stream structure.
		RetVal->Head = RetVal->Bytes + sizeof(uint32_t);
		RetVal->Capacity = Partial->TotalStreamSize;
		RetVal->Ctx = Ctx;

		const uint32_t Leftovers = Partial->Received - Partial->TotalStreamSize;

		if (Leftovers > 0)
		{ //A little more data in the stream
			uint8_t *PartialStream = Ctx->CallocFunc(1, Leftovers);

			Qualia_Memcpy(PartialStream, RetVal->Bytes + Partial->TotalStreamSize, Leftovers);
			Qualia_Memset(RetVal->Bytes + Partial->TotalStreamSize, 0, Leftovers); //Erase any sensitive leftovers before handing off the new stream.
			Partial->Data = PartialStream;
			Partial->Received = Leftovers;
			Partial->TotalStreamSize = 0; //Set to zero and then re-detect size, if possible.

			//If there's not enough data (4 bytes or more), this does nothing and it will be detected again when more data is received.
			PartialQualiaStream_AutoExtractStreamSize(Partial);
		}
		else
		{ //That was all of it. Set to null.
			Partial->Data = NULL;
			Partial->Received = 0;
			Partial->TotalStreamSize = 0;
		}
	}

	if (!Qualia_Stream_Validate(RetVal))
	{
		Qualia_Stream_Destroy(RetVal);
		return NULL; //Corrupted stream.
	}

	return RetVal;
}

static int HandleClientEvents(	QualiaTLSServer *const Server,
								TLSClient *const Client,
								char *ErrOut, const size_t ErrOutCapacity)
{
	TLSServerInternal *const I = Server->Internal;

	const uint32_t ClientID = GetServerClientID(I, Client);

	uint8_t Buffer[64] = { 0 };
	int Err = 0;

	bool DidAnything = false;
	
	do
	{
		fd_set PollSet;
		FD_ZERO(&PollSet);
		FD_SET(Client->Sock, &PollSet);

		struct timeval ZeroTime = { .tv_sec = 0, .tv_usec = 0 };
		
		if (Client->NeedRXSelect && select(Client->Sock + 1, &PollSet, NULL, NULL, &ZeroTime) == 0)
		{
			break;
		}

		Client->NeedRXSelect = false;
		
		const int Read = SSL_read(Client->SSLObj, Buffer, sizeof Buffer);

		if (Read > 0)
		{
			DidAnything = true;
			
			QualiaStream *const NewStream = PartialQualiaStream_Append(I->Ctx, &Client->PartialData, ClientID, Buffer, Read);

			if (NewStream)
			{ //Just now got enough data to call it a new stream.
				if (I->OnRecvStream != NULL)
				{
					I->OnRecvStream(Server, ClientID, NewStream, I->CBUserdata);
				}
				else
				{ //Nothing took the stream, get rid of it.
					Qualia_Stream_Destroy(NewStream);
				}
			}

			//Zealously clear buffer on stack right after we're done with it, just in case of an exploit.
			Qualia_Memset(Buffer, 0, sizeof Buffer);
		}
		else
		{ //Actual error.
			Err = SSL_get_error(Client->SSLObj, Err);

			if (Err == SSL_ERROR_WANT_READ || Err == SSL_ERROR_WANT_WRITE)
			{
				Client->NeedRXSelect = true;
				break; //Nothing to read. Not an error. Skip reading this iteration.
			}

			//Actual error if we got here.
			if (ErrOut)
			{
				char ErrStr[128] = "";
				ERR_error_string_n(Err, ErrStr, sizeof(ErrStr) - 1);

				I->Snprintf(ErrOut, ErrOutCapacity, "Got SSL_read() error integer %i with strerror \"%s\"", Err, ErrStr);
			}
			return Err < 0 ? Err : -Err; //Ensure negative.
		}
	} while (Err > 0);

	int SSLErr = 0;
	
	for (uint32_t NumTx = 0u;
		(Err = QualiaStreamOutQueue_Tx(I->Ctx, &Client->OutQueue, Client->SSLObj, &SSLErr)) > 0 &&
		NumTx < QUALIATLS_MAX_TX_PER_ITER;
		++NumTx)
	{
		DidAnything = true;
	}

	if (Err < 0)
	{
		I->Snprintf(ErrOut, ErrOutCapacity, "Got error from write for client ID %u, SSL error integer %i or 0x%x",
					(unsigned)ClientID, Err, SSLErr, SSLErr);
		return Err;
	}

	return !!DidAnything;
}

bool QualiaTLSServer_SendStream(QualiaTLSServer *const Server, const uint32_t ClientID, QualiaStream *const Stream)
{
	if (!Server) return false;
	
	TLSServerInternal *const I = Server->Internal;

	TLSClient *const Client = LookupClient(I, ClientID);

	if (!Client) return false;

	return QualiaStreamOutQueue_PushFront(I->Ctx, &Client->OutQueue, Stream);
}

QualiaLoopStatus QualiaTLSServer_EventLoop(QualiaTLSServer *Server,	char *ErrOut, const size_t ErrOutCapacity)
{
	if (!Server)
	{ //Prevent segfault with unchecked initialization failure
		return QUALIA_QLS_ERROR;
	}
	
	TLSServerInternal *const I = Server->Internal;

	bool DidAnything = false;

	int E = 0;
	while ((E = ProcessAccepts(Server, ErrOut, ErrOutCapacity)) == 1)
	{
		DidAnything = true;
	}

	if (E < 0) //We don't care if there's no clients, only if there was an issue.
	{
		return QUALIA_QLS_ERROR; //Error in accept, abort the event loop iteration. It will have already written to ErrOut.
	}

	if (!I->Clients || !I->ClientsCapacity)
	{
		goto End;
	}

	TLSClient *CurClient = I->Clients;	
	TLSClient *const Stopper = CurClient + I->ClientsCapacity;

	for (; CurClient < Stopper; ++CurClient)
	{
		if (!CurClient->Populated)
		{
			continue;
		} //We will encounter holes in the buffer that will be populated again on new connects.

		int Err = 0;

		while ((Err = HandleClientEvents(Server, CurClient, ErrOut, ErrOutCapacity)) > 0)
		{
			DidAnything = true;
		}

		if (Err < 0) //if we had any error, we destroy the client. This doesn't invalidate iteration, it just memsets.
		{
			const uint32_t ClientID = GetServerClientID(I, CurClient);

			//Call user disconnect callback.
			if (I->OnClientDisconnect != NULL)
			{
				I->OnClientDisconnect(Server, ClientID, I->CBUserdata);
			}

			FreeServerClient(I, CurClient);
		}
	}

End:
	return DidAnything ? QUALIA_QLS_RUNAGAIN : QUALIA_QLS_OK;
}

static TLSClient *NewServerClient(TLSServerInternal *I)
{
	if (!I->Clients || !I->ClientsCapacity)
	{
		//Only allocate one at a time, memory constraints are more important than performance for our purposes.
		if (I->Clients != NULL) I->Ctx->FreeFunc(I->Clients); //A little self-correcting behavior

		I->Clients = I->Ctx->CallocFunc(sizeof(TLSClient), 1);
		I->ClientsCapacity = 1;
		I->NumClients = 1;
		I->Clients->Populated = true;
		
		return I->Clients;
	}

	//Search in both directions to halve the lookup time.
	TLSClient *Worker = I->Clients;
	TLSClient *const Stopper = Worker + I->ClientsCapacity;

	for (; Worker < Stopper; ++Worker)
	{
		if (!Worker->Populated)
		{
			++I->NumClients;
			Worker->Populated = true;
			return Worker;
		}
	}
	
	//If we made it here, we need to allocate more space. Just allocate one more at a time, be conservative. This is for embedded too.
	TLSClient *const NewClients = Qualia_Realloc(I->Ctx, I->Clients, sizeof(TLSClient) * I->ClientsCapacity, sizeof(TLSClient) * (I->ClientsCapacity + 1));

	if (!NewClients) return NULL; //Allocation failed.

	I->Clients = NewClients;
	++I->ClientsCapacity;
	++I->NumClients;

	TLSClient *const RetVal = I->Clients + I->ClientsCapacity - 1;
	
	Qualia_Memset(RetVal, 0, sizeof *RetVal);
	
	RetVal->Populated = true;

	return RetVal; //Return new freshly zeroed slot at the end.
}

static void FreeServerClient(TLSServerInternal *I, TLSClient *const Client)
{
	if (!I || !Client || !I->Clients || !I->NumClients) return; //Wtf?

	if (Client->SSLObj)
	{
		SSL_shutdown(Client->SSLObj);
		Qualia_CloseSocket(Client->Sock);
		SSL_free(Client->SSLObj);
	}

	void (*const Free)(void *) = I->Ctx->FreeFunc;

	//Destroy any unsent outgoing streams for this client.
	PartialQualiaStream_Destroy(I->Ctx, &Client->PartialData);
	QualiaStreamOutQueue_Destroy(I->Ctx, &Client->OutQueue);

	Qualia_Memset(Client, 0, sizeof(TLSClient)); //Also sets Populated to false.
	--I->NumClients;

	if (!I->NumClients)
	{ //Just us. Release everything.
		Free(I->Clients);
		I->Clients = NULL;
		I->NumClients = 0;
		I->ClientsCapacity = 0;
	}
}

static TLSClient *LookupClient(TLSServerInternal *const I, const uint32_t ID)
{
	if (!I || !ID) return NULL; //IDs are always >= 1

	if (ID > I->ClientsCapacity) return NULL;

	TLSClient *const Lookup = I->Clients + (ID - 1);

	if (!Lookup->Populated) return NULL; //Client they refer to is zeroed out or doesn't exist anymore.

	return Lookup;
}

static int ProcessAccepts(	QualiaTLSServer *const Server,
							char *ErrOut, const size_t ErrOutCapacity)
{
	TLSServerInternal *const I = Server->Internal;
	char IP[48] = "";

	int ClientDesc = 0;

	int NumNewClients = 0;

	SSL *ClientSSL = NULL;
	
	while (BSDSockServer_Accept(I, &ClientDesc, &ClientSSL, IP, sizeof IP, ErrOut, ErrOutCapacity))
	{
		TLSClient *Client = NULL;
	
		//Adds the client to our bookkeeping.
		if (!(Client = InitTLSClient(Server, ClientDesc, ClientSSL, IP, ErrOut, ErrOutCapacity)))
		{
			Qualia_CloseSocket(ClientDesc);
			SSL_free(ClientSSL);
			break;
		}

		++NumNewClients;

		if (I->OnClientConnect != NULL)
		{
			I->OnClientConnect(Server, GetServerClientID(I, Client), Client->IP, I->CBUserdata);
		}

	}

	return NumNewClients;
}
