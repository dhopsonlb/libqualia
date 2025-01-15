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
#ifndef __LIBQUALIA_QUALIA_HPP__
#define __LIBQUALIA_QUALIA_HPP__

#ifndef __cplusplus
#error "This header requires C++! Use qualia.h if you want a C api, it's the original anyways. This is a wrapper."
#endif //__cplusplus

#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <optional>
#include <functional>
#include "qualia.h"

namespace Qualia
{
	typedef ::QualiaArgType ArgType;
	typedef void *MallocFuncType(size_t);
	typedef void *CallocFuncType(size_t, size_t);
	typedef void FreeFuncType(void*);
	typedef void *ReallocFuncType(void*, size_t);
	
	class Stream;
	
	class Context
	{
	private:
		QualiaContext *Internal;
	public:
		QUALIA_FORCE_INLINE Context(QualiaContext *Ctx)
			: Internal{ Ctx }
		{
		}

#ifndef QUALIA_EMBEDDED
		QUALIA_FORCE_INLINE Context(void)
			: Internal{ Qualia_InitContext(malloc, calloc, free, realloc) }
		{
		}
#endif //QUALIA_EMBEDDED
		QUALIA_FORCE_INLINE Context(MallocFuncType *MallocFunc, CallocFuncType *CallocFunc, FreeFuncType *FreeFunc, ReallocFuncType *ReallocFunc = nullptr)
			: Internal{ Qualia_InitContext(MallocFunc, CallocFunc, FreeFunc, ReallocFunc) }
		{
		}
		
		QUALIA_FORCE_INLINE ~Context(void)
		{
			if (this->Internal) Qualia_DestroyContext(this->Internal);
		}

		//No copies
		Context(const Context &) = delete;
		Context &operator=(const Context &) = delete;

		//But moves are okay
		QUALIA_FORCE_INLINE Context(Context &&Other) : Internal{ Other.Internal }
		{
			Other.Internal = nullptr;
		}
		
		QUALIA_FORCE_INLINE Context &operator=(Context &&Other)
		{
			this->Internal = Other.Internal;
			Other.Internal = nullptr;

			return *this;
		}

		QUALIA_FORCE_INLINE QualiaContext *GetPtr(void) const { return this->Internal; }
		
		QUALIA_FORCE_INLINE QualiaContext *Forget(void)
		{
			QualiaContext *const Ctx = this->Internal;

			this->Internal = nullptr;
			
			return Ctx;
		}

		friend class Stream;
	};

	template <typename T>
	class QualiaVec
	{
	private:
		FreeFuncType *FreeFunc;
		T *Data;
		uint32_t DataLen; //numbytes / sizeof(T)

	public:
	
		QUALIA_FORCE_INLINE QualiaVec(T *const Data = nullptr, const uint32_t DataLen = 0, FreeFuncType *const FreeFunc = nullptr)
			: FreeFunc{ FreeFunc }, Data{ Data }, DataLen{ DataLen }
		{
		}
		
		QUALIA_FORCE_INLINE QualiaVec(Qualia::Context &Ctx, T *const Data = nullptr, const uint32_t DataLen = 0)
			: FreeFunc{ Ctx.GetPtr()->FreeFunc }, Data{ Data }, DataLen{ DataLen }
		{
		}

		QualiaVec(QualiaVec &&Other) : FreeFunc{ Other.FreeFunc }, Data{ Other.Data }, DataLen{ Other.DataLen }
		{
			Other.FreeFunc = 0;
			Other.Data = nullptr;
			Other.DataLen = 0;
		}
		
		QualiaVec &operator=(QualiaVec &&Other)
		{
			if (&Other == this) return *this;
			
			this->FreeFunc = Other.FreeFunc;
			this->Data = Other.Data;
			this->DataLen = Other.DataLen;
			
			Other.FreeFunc = 0;
			Other.Data = nullptr;
			Other.DataLen = 0;

			return *this;
		}

		QUALIA_FORCE_INLINE ~QualiaVec(void)
		{
			if (this->Data && this->FreeFunc)
			{
				this->FreeFunc(this->Data);
			}
		}
		
		QualiaVec(const QualiaVec&) = delete;
		QualiaVec &operator=(const QualiaVec&) = delete;

		QUALIA_FORCE_INLINE operator bool(void) const { return this->Data && this->DataLen; }
		QUALIA_FORCE_INLINE const T *operator->(void) const { return this->Data; }
		QUALIA_FORCE_INLINE T *operator->(void) { return this->Data; }
		QUALIA_FORCE_INLINE T &operator*(void) { return *this->Data; }
		QUALIA_FORCE_INLINE const T &operator*(void) const { return *this->Data; }
		QUALIA_FORCE_INLINE const T &operator[](const size_t Index) const { return this->Data[Index]; }
		QUALIA_FORCE_INLINE T &operator[](const size_t Index) { return this->Data[Index]; }
		QUALIA_FORCE_INLINE size_t Len(void) const { return this->DataLen; }
		QUALIA_FORCE_INLINE size_t size(void) const { return this->DataLen; }
		QUALIA_FORCE_INLINE const T *data(void) const { return this->Data; }
		QUALIA_FORCE_INLINE T *data(void) { return this->Data; }
		QUALIA_FORCE_INLINE const T *GetData(void) const { return this->Data; }
		QUALIA_FORCE_INLINE T *GetData(void) { return this->Data; }
		QUALIA_FORCE_INLINE T *begin(void) { return this->Data; }
		QUALIA_FORCE_INLINE T *end(void) { return this->Data + this->DataLen; }
	};
	
	class Stream
	{
	private:
		QualiaStream *Internal;
	public:
		QUALIA_FORCE_INLINE Stream(Context &Ctx, const uint32_t Preallocate)
			: Internal{ Qualia_Stream_New(Ctx.Internal, Preallocate) }
		{
		}

		QUALIA_FORCE_INLINE Stream(QualiaStream *Stream)
			: Internal{ Stream }
		{
		}
		
		QUALIA_FORCE_INLINE Stream(Context &Ctx)
			: Internal{ Qualia_Stream_New(Ctx.Internal, sizeof(uint32_t)) }
		{
		}
		
		QUALIA_FORCE_INLINE Stream(QualiaContext *Ctx)
			: Internal{ Qualia_Stream_New(Ctx, sizeof(uint32_t)) }
		{
		}
		
		QUALIA_FORCE_INLINE Stream(Context &Ctx, const void *Data, const uint32_t Len)
			: Internal{ Qualia_Stream_New_With_Buffer(Ctx.Internal, Data, Len) }
		{
		}
		
		QUALIA_FORCE_INLINE Stream(QualiaContext *Ctx, const void *Data, const uint32_t Len)
			: Internal{ Qualia_Stream_New_With_Buffer(Ctx, Data, Len) }
		{
		}
		
		QUALIA_FORCE_INLINE ~Stream(void)
		{
			if (this->Internal) Qualia_Stream_Destroy(this->Internal);
		}


		QUALIA_FORCE_INLINE Stream(Stream &&Other) : Internal{ Other.Internal }
		{
			Other.Internal = nullptr;
		}
		
		QUALIA_FORCE_INLINE Stream &operator=(Stream &&Other)
		{
			this->Internal = Other.Internal;
			Other.Internal = nullptr;

			return *this;
		}
		
		QUALIA_FORCE_INLINE Stream(const Stream &Other) : Internal{ Qualia_Stream_Clone(Other.Internal) }
		{
		}
		
		QUALIA_FORCE_INLINE Stream &operator=(const Stream &Other)
		{
			if (&Other == this) return *this;

			this->Internal = Qualia_Stream_Clone(Other.Internal);

			return *this;
		}


		QUALIA_FORCE_INLINE void Rewind(void) {	Qualia_Stream_Rewind(this->Internal); }
		
		QualiaVec<ArgType> GetArgTypes(void) const
		{
			uint32_t NumArgs = 0;
			QualiaArgType *Args = Qualia_Stream_GetArgTypes(this->Internal, &NumArgs);
	
			return QualiaVec<ArgType>{ Args, NumArgs, this->Internal->Ctx->FreeFunc };
		}

		QUALIA_FORCE_INLINE uint32_t ChangeCapacity(const uint32_t NewCapacity) { return Qualia_Stream_ChangeCapacity(this->Internal, NewCapacity); }

		QUALIA_FORCE_INLINE uint32_t GetSize(void) const { return Qualia_Stream_GetSize(this->Internal);}
		QUALIA_FORCE_INLINE uint32_t GetArgsSize(void) const {return Qualia_Stream_GetArgsSize(this->Internal); }

		QUALIA_FORCE_INLINE const void *GetData(uint32_t &SizeOut) const
		{
			SizeOut = Qualia_Stream_GetSize(this->Internal);
			
			return this->Internal->Bytes;
		}
		
		QUALIA_FORCE_INLINE void *GetData(uint32_t &SizeOut)
		{
			SizeOut = Qualia_Stream_GetSize(this->Internal);
			
			return this->Internal->Bytes;
		}

		QUALIA_FORCE_INLINE QualiaStream *Forget(void)
		{
			QualiaStream *const RetVal = this->Internal;
			this->Internal = nullptr;
			return RetVal;
		}
		
		QUALIA_FORCE_INLINE QualiaStream *GetPtr(void) const { return this->Internal; }
		QUALIA_FORCE_INLINE Stream Clone(void) const { return Stream{ Qualia_Stream_Clone(this->Internal) }; }
		QUALIA_FORCE_INLINE uint8_t *GetArgsData(void) { return Qualia_Stream_GetArgsData(this->Internal); }
		QUALIA_FORCE_INLINE const uint8_t *GetArgsData(void) const { return Qualia_Stream_GetArgsData(this->Internal); }
		QUALIA_FORCE_INLINE const void *Pop_Blob(uint32_t &LenOut) { return Qualia_Stream_Pop_Blob(this->Internal, &LenOut); }
		QUALIA_FORCE_INLINE const char *Pop_String(uint32_t &LenOut) { return Qualia_Stream_Pop_String_Len(this->Internal, &LenOut); }
		QUALIA_FORCE_INLINE const char *Pop_String(void) { return Qualia_Stream_Pop_String(this->Internal); }
		QUALIA_FORCE_INLINE bool Validate(void) const { return Qualia_Stream_Validate(this->Internal); }
		QUALIA_FORCE_INLINE uint8_t Pop_Byte(void) { return Qualia_Stream_Pop_Byte(this->Internal); }
		QUALIA_FORCE_INLINE bool Pop_Bool(void) { return Qualia_Stream_Pop_Bool(this->Internal); }
		QUALIA_FORCE_INLINE uint16_t Pop_Uint16(void) { return Qualia_Stream_Pop_Uint16(this->Internal); }
		QUALIA_FORCE_INLINE int16_t Pop_Int16(void) { return Qualia_Stream_Pop_Int16(this->Internal); }
		QUALIA_FORCE_INLINE uint32_t Pop_Uint32(void) { return Qualia_Stream_Pop_Uint32(this->Internal); }
		QUALIA_FORCE_INLINE int32_t Pop_Int32(void) { return Qualia_Stream_Pop_Int32(this->Internal); }
#ifndef QUALIA_NO_64
		QUALIA_FORCE_INLINE uint64_t Pop_Uint64(void) { return Qualia_Stream_Pop_Uint64(this->Internal); }
		QUALIA_FORCE_INLINE int64_t Pop_Int64(void) { return Qualia_Stream_Pop_Int64(this->Internal); }
#endif //QUALIA_NO_64
		QUALIA_FORCE_INLINE bool Push_Blob(const void *Data, const uint32_t Len) { return Qualia_Stream_Push_Blob(this->Internal, Data, Len); }
		QUALIA_FORCE_INLINE bool Push_String(const char *String) { return Qualia_Stream_Push_String(this->Internal, String); }
		QUALIA_FORCE_INLINE bool Push_String(const char *String, const uint32_t Len) { return Qualia_Stream_Push_String_Len(this->Internal, String, Len); }
		QUALIA_FORCE_INLINE bool Push_Byte(const uint8_t Byte) { return Qualia_Stream_Push_Byte(this->Internal, Byte); }
		QUALIA_FORCE_INLINE bool Push_Bool(const bool Value) { return Qualia_Stream_Push_Bool(this->Internal, Value); }
		QUALIA_FORCE_INLINE bool Push_Uint16(const uint16_t Value) { return Qualia_Stream_Push_Uint16(this->Internal, Value); }
		QUALIA_FORCE_INLINE bool Push_Int16(const int16_t Value) { return Qualia_Stream_Push_Int16(this->Internal, Value); }
		QUALIA_FORCE_INLINE bool Push_Uint32(const uint32_t Value) { return Qualia_Stream_Push_Uint32(this->Internal, Value); }
		QUALIA_FORCE_INLINE bool Push_Int32(const int32_t Value) { return Qualia_Stream_Push_Int32(this->Internal, Value); }
#ifndef QUALIA_NO_64
		QUALIA_FORCE_INLINE bool Push_Uint64(const uint64_t Value) { return Qualia_Stream_Push_Uint64(this->Internal, Value); }
		QUALIA_FORCE_INLINE bool Push_Int64(const int64_t Value) { return Qualia_Stream_Push_Int64(this->Internal, Value); }
#endif //QUALIA_NO_64
		
	};

	constexpr decltype(&Qualia_GetRevision) GetRevision = &Qualia_GetRevision;
}

#endif //__LIBQUALIA_QUALIA_HPP__
