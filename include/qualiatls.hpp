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

#ifndef __LIBQUALIA_QUALIATLS_HPP__
#define __LIBQUALIA_QUALIATLS_HPP__

#include "qualiatls.h"
#include "qualia.hpp"
#include <iostream>

namespace Qualia
{
	typedef ::QualiaLoopStatus LoopStatus;

	class TLSConnection
	{
	public:
		typedef void OnRecvStreamType(TLSConnection &Conn, Stream S, void *Userdata);
		typedef void OnDisconnectType(TLSConnection &Conn, void *Userdata);
		typedef void OnConnectType(TLSConnection &Conn, const std::string &Hostname, const uint16_t PortNum, void *Userdata);

		//No copies or moves, they invalidate pointers passed into the C layer.
		TLSConnection(const TLSConnection&) = delete;
		TLSConnection &operator=(const TLSConnection&) = delete;
		TLSConnection &operator=(TLSConnection&&) = delete;
		TLSConnection(TLSConnection &&Other) = delete;
			
	private:
		QualiaContext *Ctx;
		void *CBUserdata;
		std::optional<std::function<OnRecvStreamType>> OnRecvStream;
		std::optional<std::function<OnDisconnectType>> OnDisconnect;
		std::optional<std::function<OnConnectType>> OnConnect;
		
		QualiaTLSConnection *Internal;
		char ErrBuf[256];

		static void COnRecvStreamCB(QualiaTLSConnection *const Connection, QualiaStream *const RecvStream, void *Userdata)
		{
			TLSConnection *const Us = static_cast<TLSConnection*>(Userdata);

			if (!Us) return;

			if (Us->OnRecvStream)
			{
				(*Us->OnRecvStream)(*Us, Stream{ RecvStream }, Us->CBUserdata);
			}
		}
		
		static void COnDisconnectCB(QualiaTLSConnection *const Connection, void *Userdata)
		{
			TLSConnection *const Us = static_cast<TLSConnection*>(Userdata);

			if (!Us) return;

			if (Us->OnDisconnect)
			{
				(*Us->OnDisconnect)(*Us, Us->CBUserdata);
			}
		}
		
		static void COnConnectCB(QualiaTLSConnection *const Connection, const char *const Hostname, const uint16_t PortNum, void *const Userdata)
		{
			TLSConnection *const Us = static_cast<TLSConnection*>(Userdata);

			if (!Us) return;

			if (Us->OnConnect)
			{
				(*Us->OnConnect)(*Us, Hostname, PortNum, Us->CBUserdata);
			}
		}
		
	public:

		QUALIA_FORCE_INLINE bool SendStream(const Qualia::Stream &Stream)
		{
			return QualiaTLSConnection_SendStream(this->Internal, Stream.Clone().Forget());
		}
		
		QUALIA_FORCE_INLINE bool SendStream(Qualia::Stream &&Stream)
		{
			return QualiaTLSConnection_SendStream(this->Internal, Stream.Forget());
		}

		QUALIA_FORCE_INLINE LoopStatus EventLoop(void)
		{
			return QualiaTLSConnection_EventLoop(this->Internal, this->ErrBuf, sizeof this->ErrBuf);
		}

		QUALIA_FORCE_INLINE const char *GetLastError(void) const { return this->ErrBuf; }

		QUALIA_FORCE_INLINE QualiaTLSConnection *GetPtr(void) const { return this->Internal; }
		
		inline TLSConnection(Qualia::Context &Ctx,
							std::optional<std::function<OnRecvStreamType>> OnRecvStream,
							std::optional<std::function<OnDisconnectType>> OnDisconnect,
							std::optional<std::function<OnConnectType>> OnConnect,
							const char *CACert,
							const char *Hostname,
							const uint16_t PortNum = QUALIA_TLS_DEFAULT_PORT,
							void *CBUserdata = nullptr)
			: Ctx{ Ctx.GetPtr() },
			CBUserdata{ CBUserdata },
			OnRecvStream{ std::move(OnRecvStream) },
			OnDisconnect{ std::move(OnDisconnect) },
			OnConnect{ std::move(OnConnect) },
			ErrBuf{}
		{
			QualiaTLSConnectionParams Params{};
			
			Params.Ctx = this->Ctx;

			Params.CACertData = CACert;
			Params.CACertLen = Qualia_Strlen(CACert);
			Params.Hostname = Hostname;
			Params.PortNum = PortNum;
			
			Params.CBUserdata = this; //We give it a pointer to ourselves, which we then translate back to a this pointer.
			Params.OnConnect = COnConnectCB;
			Params.OnDisconnect = COnDisconnectCB;
			Params.OnRecvStream = COnRecvStreamCB;

			Params.Snprintf = snprintf;
			
			this->Internal = QualiaTLSConnection_Init(&Params, this->ErrBuf, sizeof this->ErrBuf);

		}

		virtual QUALIA_FORCE_INLINE ~TLSConnection(void)
		{
			if (!this->Internal) return;
			
			QualiaTLSConnection_Destroy(this->Internal);
		}
		
	};
	
	class TLSServer
	{
	public:
		typedef void OnRecvStreamType(TLSServer&, const uint32_t, Stream, void *Userdata);
		typedef void OnClientDisconnectType(TLSServer&, const uint32_t, void *Userdata);
		typedef void OnClientConnectType(TLSServer&, const uint32_t, const char *IP, void *Userdata);

		//No copies or moves, it invalidates pointers fed into the C layer.
		TLSServer(const TLSServer&) = delete;
		TLSServer &operator=(const TLSServer&) = delete;
		TLSServer(TLSServer &&) = delete;
		TLSServer &operator=(TLSServer&&) = delete;
	private:
		QualiaContext *Ctx;
		void *CBUserdata;
		std::optional<std::function<OnRecvStreamType>> OnRecvStream;
		std::optional<std::function<OnClientDisconnectType>> OnClientDisconnect;
		std::optional<std::function<OnClientConnectType>> OnClientConnect;
		
		QualiaTLSServer *Internal;
		char ErrBuf[256];

		static void COnRecvStreamCB(QualiaTLSServer *const Server, const uint32_t ClientID, QualiaStream *const RecvStream, void *Userdata)
		{
			TLSServer *const Us = static_cast<TLSServer*>(Userdata);

			if (!Us) return;

			if (Us->OnRecvStream)
			{
				(*Us->OnRecvStream)(*Us, ClientID, Stream{ RecvStream }, Us->CBUserdata);
			}
		}
		
		static void COnClientDisconnectCB(QualiaTLSServer *const Server, const uint32_t ClientID,  void *Userdata)
		{
			TLSServer *const Us = static_cast<TLSServer*>(Userdata);

			if (!Us) return;
			
			if (Us->OnClientDisconnect)
			{
				(*Us->OnClientDisconnect)(*Us, ClientID, Us->CBUserdata);
			}
		}
		
		static void COnClientConnectCB(QualiaTLSServer *const Server, const uint32_t ClientID, const char *IP, void *Userdata)
		{
			TLSServer *const Us = static_cast<TLSServer*>(Userdata);

			if (!Us) return;

			if (Us->OnClientConnect)
			{
				(*Us->OnClientConnect)(*Us, ClientID, IP, Us->CBUserdata);
			}
		}
		
	public:

		QUALIA_FORCE_INLINE bool SendStream(const uint32_t ClientID, const Qualia::Stream &Stream)
		{
			return QualiaTLSServer_SendStream(this->Internal, ClientID, Stream.Clone().Forget());
		}
		
		QUALIA_FORCE_INLINE bool SendStream(const uint32_t ClientID, Qualia::Stream &&Stream)
		{
			return QualiaTLSServer_SendStream(this->Internal, ClientID, Stream.Forget());
		}

		QUALIA_FORCE_INLINE LoopStatus EventLoop(void)
		{
			return QualiaTLSServer_EventLoop(this->Internal, this->ErrBuf, sizeof this->ErrBuf);
		}

		QUALIA_FORCE_INLINE const char *GetLastError(void) const { return this->ErrBuf; }

		QUALIA_FORCE_INLINE QualiaTLSServer *GetPtr(void) const { return this->Internal; }
		
		inline TLSServer(Qualia::Context &Ctx,
						std::optional<std::function<OnRecvStreamType>> OnRecvStream,
						std::optional<std::function<OnClientDisconnectType>> OnClientDisconnect,
						std::optional<std::function<OnClientConnectType>> OnClientConnect,
						const char *const ServerCert,
						const char *const PrivateKey,
						const uint16_t PortNum = QUALIA_TLS_DEFAULT_PORT,
						void *const CBUserdata = nullptr)
			: Ctx{ Ctx.GetPtr() },
			CBUserdata{ CBUserdata },
			OnRecvStream{ std::move(OnRecvStream) },
			OnClientDisconnect{ std::move(OnClientDisconnect) },
			OnClientConnect{ std::move(OnClientConnect) },
			ErrBuf{}
		{
			QualiaTLSServerParams Params{};
			
			Params.Ctx = this->Ctx;

			Params.ServerCertData = ServerCert;
			Params.ServerCertLen = Qualia_Strlen(ServerCert);
			
			Params.PrivateKeyData = PrivateKey;
			Params.PrivateKeyLen = Qualia_Strlen(PrivateKey);
			Params.PortNum = PortNum;
			
			Params.CBUserdata = this; //We give it a pointer to ourselves, which we then translate back to a this pointer.
			Params.OnClientConnect = COnClientConnectCB;
			Params.OnClientDisconnect = COnClientDisconnectCB;
			Params.OnRecvStream = COnRecvStreamCB;

			Params.Snprintf = snprintf;
			
			this->Internal = QualiaTLSServer_Init(&Params, this->ErrBuf, sizeof this->ErrBuf);

			if (!this->Internal)
			{
				std::cerr << "Failed to QualiaTLSServer_Init, got error string \"" << (const char*)this->ErrBuf << "\"." << std::endl;
			}

		}

		virtual QUALIA_FORCE_INLINE ~TLSServer(void)
		{
			if (!this->Internal) return;
			
			QualiaTLSServer_Shutdown(this->Internal);
		}
		
	};
}
#endif // __LIBQUALIA_QUALIATLS_HPP__
