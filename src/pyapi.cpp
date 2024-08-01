///Qualia is copyright (c) 2024 Daniel Hopson.
///All rights reserved.

#include <vector>
#include <string>
#include <Python.h>

#include "../include/qualia.hpp"
#include "../include/qualiatls.hpp"
#include "../3rdparty/pybind11/include/pybind11/pybind11.h"
#include "../3rdparty/pybind11/include/pybind11/stl.h"
#include "../3rdparty/pybind11/include/pybind11/complex.h"
#include "../3rdparty/pybind11/include/pybind11/stl_bind.h"
#include "../3rdparty/pybind11/include/pybind11/functional.h"

namespace py = pybind11;
//If we have Python, we have malloc.
static Qualia::Context PyQualiaCtx{ malloc, calloc, free, realloc };

#define QUALIA_PY_ENUM(a) .value(#a, a)
#define QUALIA_PY_MFUNC(a, b) .def(#b, &Qualia::a::b)

PYBIND11_MODULE(libqualia, ModObj)
{
	py::enum_<Qualia::LoopStatus>(ModObj, "LoopStatus")
	QUALIA_PY_ENUM(QUALIA_QLS_ERROR)
	QUALIA_PY_ENUM(QUALIA_QLS_RUNAGAIN)
	QUALIA_PY_ENUM(QUALIA_QLS_OK)
	QUALIA_PY_ENUM(QUALIA_QLS_SHUTDOWN)
	QUALIA_PY_ENUM(QUALIA_QLS_MAX)
	.export_values();

	ModObj.def("GetRevision", Qualia::GetRevision);
	
	py::class_<Qualia::Stream>(ModObj, "Stream")
	.def(py::init([](void) -> Qualia::Stream
		{
			return Qualia::Stream{ PyQualiaCtx };
		}))
	.def(py::init([](const uint32_t Preallocate) -> Qualia::Stream
		{
			return Qualia::Stream{ PyQualiaCtx, Preallocate };
		}))
	.def(py::init([](const py::bytes &Bytes) -> Qualia::Stream
		{
			py::buffer_info BufInfo(py::buffer(Bytes).request());
			
			const char *const Data = reinterpret_cast<const char*>(BufInfo.ptr);
			const uint32_t Len = static_cast<uint32_t>(BufInfo.size);
                
			return Qualia::Stream{ PyQualiaCtx, Data, Len };
		}))
	.def("GetData", [](Qualia::Stream &Us) -> py::bytes
		{
			uint32_t Len = 0;
			const char *Data = static_cast<const char*>(Us.GetData(Len));
			return py::bytes{ Data, static_cast<size_t>(Len) };
		})
	.def("GetArgsData", [](Qualia::Stream &Us) -> py::bytes
		{
			return py::bytes{ reinterpret_cast<const char*>(Us.GetArgsData()), Us.GetArgsSize() };
		})
	QUALIA_PY_MFUNC(Stream, ChangeCapacity)
	QUALIA_PY_MFUNC(Stream, Rewind)
	.def("GetArgTypes", [] (Qualia::Stream &Us) -> std::vector<Qualia::ArgType>
		{
			Qualia::QualiaVec<Qualia::ArgType> Vals{ Us.GetArgTypes() };
			
			std::vector<Qualia::ArgType> RetVal;
			RetVal.resize(Vals.size());

			memcpy(RetVal.data(), Vals.data(), Vals.size() * sizeof(Qualia::ArgType));

			return RetVal;
		})
	.def("Push_Byte", [](Qualia::Stream &Us, const unsigned Value) -> bool { return Us.Push_Byte(Value); })
	QUALIA_PY_MFUNC(Stream, Push_Bool)
	QUALIA_PY_MFUNC(Stream, Push_Uint16)
	QUALIA_PY_MFUNC(Stream, Push_Uint32)
	QUALIA_PY_MFUNC(Stream, Push_Uint64)
	QUALIA_PY_MFUNC(Stream, Push_Int16)
	QUALIA_PY_MFUNC(Stream, Push_Int32)
	QUALIA_PY_MFUNC(Stream, Push_Int64)
	.def("Push_String", [](Qualia::Stream &Us, const std::string &String) -> bool { return Us.Push_String(String.c_str()); })
	.def("Push_Blob", [](Qualia::Stream &Us, const py::bytes &Blob) -> bool
		{
			py::buffer_info BufInfo(py::buffer(Blob).request());
			
			const char *const Data = reinterpret_cast<const char*>(BufInfo.ptr);
			const uint32_t Len = static_cast<uint32_t>(BufInfo.size);

			return Us.Push_Blob(Data, Len);
		})
	QUALIA_PY_MFUNC(Stream, Pop_Byte)
	QUALIA_PY_MFUNC(Stream, Pop_Bool)
	.def("Pop_String", [](Qualia::Stream &Us) -> py::str { return std::string{ Us.Pop_String() }; })
	.def("Pop_Blob", [](Qualia::Stream &Us) -> std::vector<uint8_t>
		{
			uint32_t Len = 0;
			const void *Data = Us.Pop_Blob(Len);

			if (!Data) return {};

			std::vector<uint8_t> RetVal;
			RetVal.resize(Len);

			memcpy(RetVal.data(), Data, Len);
			
			return RetVal;
		})
	QUALIA_PY_MFUNC(Stream, Pop_Int16)
	QUALIA_PY_MFUNC(Stream, Pop_Int32)
	QUALIA_PY_MFUNC(Stream, Pop_Int64)
	QUALIA_PY_MFUNC(Stream, Pop_Uint16)
	QUALIA_PY_MFUNC(Stream, Pop_Uint32)
	QUALIA_PY_MFUNC(Stream, Pop_Uint64)
	QUALIA_PY_MFUNC(Stream, Validate)
	.def("Clone", [] (const Qualia::Stream &Us) -> Qualia::Stream { return Us.Clone(); });

	py::enum_<Qualia::ArgType>(ModObj, "ArgType")
	QUALIA_PY_ENUM(QUALIA_ARG_INVALID)
	QUALIA_PY_ENUM(QUALIA_ARG_BOOL)
	QUALIA_PY_ENUM(QUALIA_ARG_BYTE)
	QUALIA_PY_ENUM(QUALIA_ARG_STRING)
	QUALIA_PY_ENUM(QUALIA_ARG_BLOB)
	QUALIA_PY_ENUM(QUALIA_ARG_UINT16)
	QUALIA_PY_ENUM(QUALIA_ARG_INT16)
	QUALIA_PY_ENUM(QUALIA_ARG_UINT32)
	QUALIA_PY_ENUM(QUALIA_ARG_INT32)
#ifndef QUALIA_NO_64
	QUALIA_PY_ENUM(QUALIA_ARG_UINT64)
	QUALIA_PY_ENUM(QUALIA_ARG_INT64)
#endif //QUALIA_NO_64)
	QUALIA_PY_ENUM(QUALIA_ARG_MAX)
	.export_values();
	
#ifndef QUALIA_NO_TLS
	py::class_<Qualia::TLSServer>(ModObj, "TLSServer")
		.def(py::init([](std::optional<std::function<void(Qualia::TLSServer &Conn, const uint32_t ClientID, Qualia::Stream S)>> OnRecvStream,
						std::optional<std::function<void(Qualia::TLSServer &Conn, const uint32_t ClientID)>> OnClientDisconnect,
						std::optional<std::function<void(Qualia::TLSServer &Conn, const uint32_t ClientID, const std::string &IP)>> OnClientConnect,
						const std::string &ServerCert,
						const std::string &PrivateKey,
						const uint16_t PortNum) -> Qualia::TLSServer
		{
			return	Qualia::TLSServer
					{
						PyQualiaCtx,
						[OnRecvStream = std::move(OnRecvStream)](Qualia::TLSServer &C, const uint32_t ClientID, Qualia::Stream S, void *)
						{
							if (OnRecvStream) (*OnRecvStream)(C, ClientID, std::move(S));
						},
						[OnClientDisconnect = std::move(OnClientDisconnect)](Qualia::TLSServer &C, const uint32_t ClientID, void*)
						{
							if (OnClientDisconnect) (*OnClientDisconnect)(C, ClientID);
						},
						[OnClientConnect = std::move(OnClientConnect)](Qualia::TLSServer &Conn, const uint32_t ClientID, const std::string &IP, void*)
						{
							if (OnClientConnect) (*OnClientConnect)(Conn, ClientID, IP);
						},
						ServerCert.c_str(),
						PrivateKey.c_str(),
						PortNum,
						nullptr
					};
		}))
		.def("SendStream", [](Qualia::TLSServer &Us, const uint32_t ClientID, Qualia::Stream &Out) -> bool
		{
			return Us.SendStream(ClientID, std::move(Out));
		})
		QUALIA_PY_MFUNC(TLSServer, GetLastError)
		QUALIA_PY_MFUNC(TLSServer, EventLoop);

	py::class_<Qualia::TLSConnection>(ModObj, "TLSConnection")
		.def(py::init([](std::optional<std::function<void(Qualia::TLSConnection &Conn, Qualia::Stream S)>> OnRecvStream,
						std::optional<std::function<void(Qualia::TLSConnection &Conn)>> OnDisconnect,
						std::optional<std::function<void(Qualia::TLSConnection &Conn, const std::string &Hostname, const uint16_t PortNum)>> OnConnect,
						const std::string &CACert,
						const std::string &Hostname,
						const uint16_t PortNum) -> Qualia::TLSConnection
		{
			return	Qualia::TLSConnection
					{
						PyQualiaCtx,
						[OnRecvStream = std::move(OnRecvStream)](Qualia::TLSConnection &C, Qualia::Stream S, void *)
						{
							if (OnRecvStream) (*OnRecvStream)(C, std::move(S));
						},
						[OnDisconnect = std::move(OnDisconnect)](Qualia::TLSConnection &C, void*)
						{
							if (OnDisconnect) (*OnDisconnect)(C);
						},
						[OnConnect = std::move(OnConnect)](Qualia::TLSConnection &Conn, const std::string &Hostname, const uint16_t PortNum, void*)
						{
							if (OnConnect) (*OnConnect)(Conn, Hostname, PortNum);
						},
						CACert.c_str(),
						Hostname.c_str(),
						PortNum,
						nullptr
					};
		}))
		.def("SendStream", [](Qualia::TLSConnection &Us, Qualia::Stream &Out) -> bool
		{
			return Us.SendStream(std::move(Out));
		})
		QUALIA_PY_MFUNC(TLSConnection, GetLastError)
		QUALIA_PY_MFUNC(TLSConnection, EventLoop);
#endif // !QUALIA_NO_TLS
}
	

