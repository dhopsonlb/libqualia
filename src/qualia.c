///Qualia is copyright (c) 2024 Daniel Hopson.
///All rights reserved.

/*Qualia is the sister protocol to Conation, intended for tiny, embedded devices, such as:
* ESP32, STM32, nRF52840, Cortex M0, RP2040, etc, as well as miscellanious out-of-Volition use-cases.
* Qualia requires more setup than Conation, partly because it's designed for at least the base Qualia protocol to work
* in freestanding, embedded environments, requiring only some forms of malloc, and free (realloc recommended, but can be NULL).
* Conation and Qualia are deliberately very similar in design and share a lot of design decisions and design patterns,
* and Qualia contains a small amount of code ripped directly from Conation V4.
*
* Qualia is, overall, designed for code size, memory usage, and portability.
* Some functionality is not as fast as it could be as a result of these design choices, but should still be very fast indeed.*/

#include "../include/qualia.h"

#define QUALIA_U8_SIGN_BIT 0x80

const char *Qualia_GetRevision(void)
{
#ifdef QUALIA_REVISION
	return QUALIA_REVISION;
#else
	return "unknown";
#endif //QUALIA_REVISION
}

static QUALIA_HOT uint32_t GetUnsizedTypeSize(const QualiaArgType ArgType)
{
	switch (ArgType)
	{
		case QUALIA_ARG_BOOL:
		case QUALIA_ARG_BYTE:
			return sizeof(uint8_t);
		case QUALIA_ARG_INT16:
		case QUALIA_ARG_UINT16:
			return sizeof(uint16_t);
		case QUALIA_ARG_INT32:
		case QUALIA_ARG_UINT32:
			return sizeof(uint32_t);
#ifndef QUALIA_NO_64
		case QUALIA_ARG_INT64:
		case QUALIA_ARG_UINT64:
			return sizeof(uint64_t);
#endif //QUALIA_NO_64
		default:
			return 0;
	}
}

void *Qualia_Realloc(QualiaContext *const Ctx, const void *const Data_, const size_t OldSize, const size_t NewSize)
{
	if (!Data_) return NULL;

	void *Data = (void*)Data_;

	if (Ctx->ReallocFunc)
	{
		void *RetVal = Ctx->ReallocFunc(Data, NewSize);

		//Zero out new space. Calloc does this, realloc does not.
		Qualia_Memset((uint8_t*)RetVal + OldSize, 0, NewSize - OldSize);

		return RetVal;
	}

	//No realloc func set, do things the shit way.
	void *const NewData = Ctx->CallocFunc(1, NewSize);

	if (!NewData) return NULL; //Reallocation failed.

	Qualia_Memcpy(NewData, Data, OldSize); //Copy old to new

	Ctx->FreeFunc(Data); //Release old.

	return NewData; //Return new.
}

#ifndef QUALIA_NO_64
static uint64_t Swap64Bits(uint64_t Original)
{ //Unoptimized implementation that will be used on weird compilers etc. Still works.
#if defined(__GNUC__) || defined(__clang__)
	return __builtin_bswap64(Original);
#else
	uint64_t Edited = 0;

	uint8_t *In = (uint8_t*)&Original;
	uint8_t *Out = (uint8_t*)&Edited;

	Out[0] = In[7];
	Out[1] = In[6];
	Out[2] = In[5];
	Out[3] = In[4];
	Out[4] = In[3];
	Out[5] = In[2];
	Out[6] = In[1];
	Out[7] = In[0];

	return Edited;
#endif //__GNUC__ __clang__
}
#endif //QUALIA_NO_64

static QUALIA_HOT uint32_t Swap32Bits(const uint32_t Original)
{ //Unoptimized implementation that will be used on weird compilers etc. Still works.
#if defined(__GNUC__) || defined(__clang__)
	return __builtin_bswap32(Original);
#else
	uint32_t Edited = 0;

	const uint8_t *In = (const uint8_t*)&Original;
	uint8_t *Out = (uint8_t*)&Edited;

	Out[0] = In[3];
	Out[1] = In[2];
	Out[2] = In[1];
	Out[3] = In[0];

	return Edited;
#endif //__GNUC__ __clang__
}

static uint16_t Swap16Bits(const uint16_t Original)
{ //Unoptimized implementation that will be used on weird compilers etc. Still works.
#if defined(__GNUC__) || defined(__clang__)
	return __builtin_bswap16(Original);
#else
	uint8_t *Worker = (uint8_t*)&Original;

	return (Worker[0] << 8) | (Worker[1] >> 8);
#endif //__GNUC__ __clang__
}

uint16_t Qualia_Htons(const uint16_t Int) { return ArchIsBigEndian() ? Int : Swap16Bits(Int); }
uint32_t Qualia_Htonl(const uint32_t Int) { return ArchIsBigEndian() ? Int : Swap32Bits(Int); }
#ifndef QUALIA_NO_64
uint64_t Qualia_Htonll(const uint64_t Int) { return ArchIsBigEndian() ? Int : Swap64Bits(Int); }
#endif //QUALIA_NO_64

uint16_t Qualia_Ntohs(const uint16_t Int) { return ArchIsBigEndian() ? Int : Swap16Bits(Int); }
uint32_t Qualia_Ntohl(const uint32_t Int) { return ArchIsBigEndian() ? Int : Swap32Bits(Int); }
#ifndef QUALIA_NO_64
uint64_t Qualia_Ntohll(const uint64_t Int) { return ArchIsBigEndian() ? Int : Swap64Bits(Int); }
#endif //QUALIA_NO_64


static uint8_t PredictMetasize(const uint32_t Size)
{
	if (Size <= INT8_MAX) return 0;
	else if (Size <= UINT16_MAX) return (uint8_t)sizeof(uint16_t);
	else return (uint8_t)sizeof(uint32_t);
}

static QUALIA_HOT uint32_t DecodeSize(QualiaStream *const Stream, const uint8_t **Worker, bool *Error)
{
	if ((*Worker - Stream->Bytes) + sizeof(uint8_t) > Stream->Capacity)
	{ //Check that we have space for a byte.
		*Error = true;
		return 0;
	}

	if ((**Worker & QUALIA_U8_SIGN_BIT) == 0)
	{
		const uint32_t RetVal = (uint32_t)**Worker;

		++*Worker;

		return RetVal;
	}

	const uint8_t Metasize = (uint8_t)(**Worker & ~QUALIA_U8_SIGN_BIT);

	++*Worker;

	if ((*Worker - Stream->Bytes) + sizeof(uint8_t) + Metasize > Stream->Capacity)
	{ //Check that we have space for the byte and the metasize.
		*Error = true;
		return 0;
	}

	switch (Metasize)
	{
		case sizeof(uint16_t):
		{
			uint16_t Decoded = 0;
			Qualia_Memcpy(&Decoded, *Worker, sizeof Decoded);

			Decoded = Qualia_Ntohs(Decoded);

			*Worker += sizeof Decoded;
			return Decoded;
		}
		case sizeof(uint32_t):
		{
			uint32_t Decoded = 0;
			Qualia_Memcpy(&Decoded, *Worker, sizeof Decoded);

			Decoded = Qualia_Ntohl(Decoded);

			*Worker += sizeof Decoded;
			return Decoded;
		}
		default:
			*Error = true;
			return 0;
	}
}

uint8_t QUALIA_HOT *Qualia_Stream_GetArgsData(QualiaStream *const Stream)
{
	return Stream->Bytes + sizeof(uint32_t);
}

void Qualia_Stream_Rewind(QualiaStream *const Stream)
{
	Stream->Head = Stream->Bytes + sizeof(uint32_t);
}

uint32_t Qualia_Stream_GetSize(QualiaStream *const Stream)
{
	return Qualia_Ntohl(*(const uint32_t*)Stream->Bytes) + sizeof(uint32_t); //Assumes CallocFunc returns correctly allocated data.
}

uint32_t QUALIA_HOT Qualia_Stream_GetArgsSize(QualiaStream *const Stream)
{
	return Qualia_Ntohl(*(const uint32_t*)Stream->Bytes);
}

static QUALIA_HOT void SetArgsSize(QualiaStream *const Stream, uint32_t NewStreamSize)
{
	NewStreamSize = Qualia_Htonl(NewStreamSize);

	Qualia_Memcpy(Stream->Bytes, &NewStreamSize, sizeof NewStreamSize);
}

static inline void IncreaseArgsSize(QualiaStream *const Stream, const uint32_t AddedSize)
{
	SetArgsSize(Stream, Qualia_Stream_GetArgsSize(Stream) + AddedSize);
}

QUALIA_HOT uint32_t Qualia_Stream_ChangeCapacity(QualiaStream *const Stream, const uint32_t NeededCapacity)
{ //Returns the new capacity, or the old one if unchanged.
	if (Stream->Capacity >= NeededCapacity) return Stream->Capacity;

	const ptrdiff_t BufDistance = Stream->Head - Stream->Bytes;

	Stream->Bytes = Qualia_Realloc(Stream->Ctx, Stream->Bytes, Stream->Capacity, NeededCapacity);

	if (!Stream->Bytes)
	{
		return 0;
	}

	Stream->Head = Stream->Bytes + BufDistance;

	//Zero out new space.
	Qualia_Memset(Stream->Bytes + Stream->Capacity, 0, NeededCapacity - Stream->Capacity);
	Stream->Capacity = NeededCapacity;

	return NeededCapacity;
}

static inline uint32_t EnsureStreamHasSpace(QualiaStream *const Stream, const uint32_t AdditionalSpace)
{
	const uint32_t OldSize = Qualia_Stream_GetSize(Stream);

	if (OldSize + AdditionalSpace <= Stream->Capacity) return OldSize;

	return Qualia_Stream_ChangeCapacity(Stream, Qualia_Stream_GetSize(Stream) + AdditionalSpace);
}

static QUALIA_HOT bool EncodeSize(QualiaStream *const Stream, const uint32_t Size)
{
	const uint8_t PredictedMetasize = PredictMetasize(Size);

	EnsureStreamHasSpace(Stream, sizeof(uint8_t) + PredictedMetasize);

	uint8_t *Worker = Qualia_Stream_GetArgsData(Stream) + Qualia_Stream_GetArgsSize(Stream);

	switch (PredictedMetasize)
	{
		case 0:
		{
			*Worker = (uint8_t)Size;

			break;
		}
		case sizeof(uint16_t):
		{
			*Worker = (uint8_t)(PredictedMetasize | QUALIA_U8_SIGN_BIT);

			const uint16_t Encoded = Qualia_Htons((uint16_t)Size);

			Qualia_Memcpy(Worker + 1, &Encoded, sizeof Encoded);
			break;
		}
		case sizeof(uint32_t):
		{
			*Worker = (uint8_t)(PredictedMetasize | QUALIA_U8_SIGN_BIT);

			const uint32_t Encoded = Qualia_Htonl((uint32_t)Size);

			Qualia_Memcpy(Worker + 1, &Encoded, sizeof Encoded);
			break;
		}
		default:
			break;
	}

	IncreaseArgsSize(Stream, sizeof(uint8_t) + PredictedMetasize);

	return true;
}

static QUALIA_HOT bool EncodeStreamArgType(QualiaStream *const Stream, const QualiaArgType ArgType)
{
	if (EnsureStreamHasSpace(Stream, sizeof(uint8_t)) == 0) return false;

	uint8_t *Worker = Qualia_Stream_GetArgsData(Stream) + Qualia_Stream_GetArgsSize(Stream);

	*Worker = (uint8_t)ArgType;

	IncreaseArgsSize(Stream, sizeof(uint8_t));

	return true;
}

static QUALIA_HOT QualiaArgType DecodeStreamArgType(QualiaStream *const Stream, const uint8_t **Worker)
{
	if ((*Worker - Stream->Bytes) + sizeof(uint8_t) > Stream->Capacity)
	{
		return QUALIA_ARG_INVALID;
	}

	const QualiaArgType ArgType = (QualiaArgType)**Worker;

	++*Worker;

	if (ArgType >= QUALIA_ARG_MAX)
	{
		return QUALIA_ARG_INVALID;
	}

	return ArgType;
}

static QUALIA_HOT QualiaArgType PeekStreamArgType(QualiaStream *const Stream, const uint8_t *Worker)
{
	if ((Worker - Stream->Bytes) + sizeof(uint8_t) > Stream->Capacity)
	{
		return QUALIA_ARG_INVALID;
	}

	const QualiaArgType ArgType = (QualiaArgType)*Worker;

	if (ArgType >= QUALIA_ARG_MAX)
	{
		return QUALIA_ARG_INVALID;
	}

	return ArgType;
}

static QUALIA_HOT QualiaArgType DecodeStreamArgHeader(QualiaStream *const Stream, const uint8_t **Worker, uint32_t *SizeOut)
{
	const QualiaArgType ArgType = DecodeStreamArgType(Stream, Worker);

	bool SizeError = false;

	const uint32_t Size = Qualia_IsUnsizedArgType(ArgType) ? GetUnsizedTypeSize(ArgType) : DecodeSize(Stream, Worker, &SizeError);

	if (SizeOut != NULL)
	{
		*SizeOut = Size;
	}

	return ArgType;
}


static QUALIA_HOT bool EncodeStreamArgHeader(QualiaStream *const Stream, const QualiaArgType ArgType, const uint32_t ArgSize)
{ //If ArgSize is specified for an unsized argument type, it is ignored. So put 0xb00b if you want, whatever.

	const uint32_t Metasize = PredictMetasize(ArgSize);

	const bool IsUnsized = Qualia_IsUnsizedArgType(ArgType);

	if (EnsureStreamHasSpace(Stream, sizeof(ArgType) + (IsUnsized ? 0 : sizeof(uint8_t) + Metasize)) == 0) return false;

	if (!EncodeStreamArgType(Stream, ArgType)) return false;

	if (!IsUnsized)
	{
		if (!EncodeSize(Stream, ArgSize)) return false;
	}

	return true;
}

static bool DecodeBool(QualiaStream *const Stream, const uint8_t **Worker)
{
	if ((*Worker - Stream->Bytes) + sizeof(bool) > Stream->Capacity)
	{
		return false;
	}

	const bool Value = **Worker;

	++*Worker;

	return Value;
}



static uint8_t DecodeByte(QualiaStream *const Stream, const uint8_t **Worker)
{
	if ((*Worker - Stream->Bytes) + sizeof(uint8_t) > Stream->Capacity)
	{
		return 0;
	}

	const uint8_t Byte = **Worker;

	++*Worker;

	return Byte;
}

#ifndef QUALIA_NO_64
static uint64_t DecodeU64(QualiaStream *const Stream, const uint8_t **Worker)
{
	if ((*Worker - Stream->Bytes) + sizeof(uint64_t) > Stream->Capacity)
	{
		return 0;
	}

	uint64_t Integer = 0;

	Qualia_Memcpy(&Integer, *Worker, sizeof Integer);

	Integer = Qualia_Ntohll(Integer);

	*Worker += sizeof(uint64_t);

	return Integer;
}

static inline int64_t DecodeI64(QualiaStream *const Stream, const uint8_t **Worker)
{
	const uint64_t Value = DecodeU64(Stream, Worker);

	return *(int64_t*)&Value;
}
#endif //QUALIA_NO_64

static uint16_t DecodeU16(QualiaStream *const Stream, const uint8_t **Worker)
{
	if ((*Worker - Stream->Bytes) + sizeof(uint16_t) > Stream->Capacity)
	{
		return 0;
	}

	uint16_t Integer;

	Qualia_Memcpy(&Integer, *Worker, sizeof Integer);

	Integer = Qualia_Ntohs(Integer);

	*Worker += sizeof(uint16_t);

	return Integer;
}

static inline int16_t DecodeI16(QualiaStream *const Stream, const uint8_t **Worker)
{
	const uint16_t Value = DecodeU16(Stream, Worker);

	return *(int16_t*)&Value;
}

static uint32_t DecodeU32(QualiaStream *const Stream, const uint8_t **Worker)
{
	if ((*Worker - Stream->Bytes) + sizeof(uint32_t) > Stream->Capacity)
	{
		return 0;
	}

	uint32_t Integer;

	Qualia_Memcpy(&Integer, *Worker, sizeof Integer);

	Integer = Qualia_Ntohl(Integer);

	*Worker += sizeof(uint32_t);

	return Integer;
}

static inline int32_t DecodeI32(QualiaStream *const Stream, const uint8_t **Worker)
{
	const uint32_t Value = DecodeU32(Stream, Worker);

	return *(int32_t*)&Value;
}

#ifndef QUALIA_NO_64
static bool EncodeU64(QualiaStream *const Stream, uint64_t Integer)
{
	if (EnsureStreamHasSpace(Stream, sizeof Integer) == 0) return false;

	const uint32_t OldSize = Qualia_Stream_GetArgsSize(Stream);
	uint8_t *Worker = Qualia_Stream_GetArgsData(Stream) + OldSize;

	Integer = Qualia_Htonll(Integer);

	Qualia_Memcpy(Worker, &Integer, sizeof Integer);

	IncreaseArgsSize(Stream, sizeof Integer);

	return true;
}

static bool EncodeI64(QualiaStream *const Stream, int64_t Integer)
{
	if (EnsureStreamHasSpace(Stream, sizeof Integer) == 0) return false;

	const uint32_t OldSize = Qualia_Stream_GetArgsSize(Stream);
	uint8_t *Worker = Qualia_Stream_GetArgsData(Stream) + OldSize;

	Integer = Qualia_Htonll(*(uint64_t*)&Integer);

	Qualia_Memcpy(Worker, &Integer, sizeof Integer);

	IncreaseArgsSize(Stream, sizeof Integer);

	return true;
}
#endif //QUALIA_NO_64

static bool EncodeU16(QualiaStream *const Stream, uint16_t Integer)
{
	if (EnsureStreamHasSpace(Stream, sizeof Integer) == 0) return false;

	const uint32_t OldSize = Qualia_Stream_GetArgsSize(Stream);
	uint8_t *Worker = Qualia_Stream_GetArgsData(Stream) + OldSize;

	Integer = Qualia_Htons(Integer);

	Qualia_Memcpy(Worker, &Integer, sizeof Integer);

	IncreaseArgsSize(Stream, sizeof Integer);

	return true;
}

static bool EncodeI16(QualiaStream *const Stream, int16_t Integer)
{
	if (EnsureStreamHasSpace(Stream, sizeof Integer) == 0) return false;

	const uint32_t OldSize = Qualia_Stream_GetArgsSize(Stream);
	uint8_t *Worker = Qualia_Stream_GetArgsData(Stream) + OldSize;

	Integer = Qualia_Htons(*(uint16_t*)&Integer);

	Qualia_Memcpy(Worker, &Integer, sizeof Integer);

	IncreaseArgsSize(Stream, sizeof Integer);

	return true;
}

static bool EncodeU32(QualiaStream *const Stream, uint32_t Integer)
{
	if (EnsureStreamHasSpace(Stream, sizeof Integer) == 0) return false;

	const uint32_t OldSize = Qualia_Stream_GetArgsSize(Stream);
	uint8_t *Worker = Qualia_Stream_GetArgsData(Stream) + OldSize;

	Integer = Qualia_Htonl(Integer);

	Qualia_Memcpy(Worker, &Integer, sizeof Integer);

	IncreaseArgsSize(Stream, sizeof Integer);

	return true;
}

static bool EncodeI32(QualiaStream *const Stream, int32_t Integer)
{
	if (EnsureStreamHasSpace(Stream, sizeof Integer) == 0) return false;

	const uint32_t OldSize = Qualia_Stream_GetArgsSize(Stream);
	uint8_t *Worker = Qualia_Stream_GetArgsData(Stream) + OldSize;

	Integer = Qualia_Htonl(*(uint32_t*)&Integer);

	Qualia_Memcpy(Worker, &Integer, sizeof Integer);

	SetArgsSize(Stream, OldSize + sizeof Integer);

	return true;
}

static bool EncodeByte(QualiaStream *const Stream, const uint8_t Integer)
{
	if (EnsureStreamHasSpace(Stream, sizeof Integer) == 0) return false;

	const uint32_t OldSize = Qualia_Stream_GetArgsSize(Stream);
	uint8_t *Worker = Qualia_Stream_GetArgsData(Stream) + OldSize;

	*Worker = Integer;

	SetArgsSize(Stream, OldSize + sizeof Integer);

	return true;
}


static bool EncodeString(QualiaStream *const Stream, const char *const String, const uint32_t Len)
{
	if (EnsureStreamHasSpace(Stream, Len + 1) == 0) return false;

	const uint32_t OldSize = Qualia_Stream_GetArgsSize(Stream);
	uint8_t *Worker = Qualia_Stream_GetArgsData(Stream) + OldSize;

	Qualia_Memcpy(Worker, String, Len);

	Worker[Len] = '\0'; //Null terminate.

	IncreaseArgsSize(Stream, Len + 1);

	return true;
}

static bool EncodeBlob(QualiaStream *const Stream, const void *const Data, const uint32_t Len)
{
	if (EnsureStreamHasSpace(Stream, Len) == 0) return false;

	const uint32_t OldSize = Qualia_Stream_GetArgsSize(Stream);
	uint8_t *Worker = Qualia_Stream_GetArgsData(Stream) + OldSize;

	Qualia_Memcpy(Worker, Data, Len);

	IncreaseArgsSize(Stream, Len);

	return true;
}

static bool EncodeBool(QualiaStream *const Stream, const bool Value)
{
	if (EnsureStreamHasSpace(Stream, sizeof Value) == 0) return false;

	const uint32_t OldSize = Qualia_Stream_GetArgsSize(Stream);
	uint8_t *Worker = Qualia_Stream_GetArgsData(Stream) + OldSize;

	*Worker = (uint8_t)Value;

	IncreaseArgsSize(Stream, sizeof Value);

	return true;
}

bool Qualia_IsUnsizedArgType(const QualiaArgType ArgType)
{
	switch (ArgType)
	{
		case QUALIA_ARG_BLOB:
		case QUALIA_ARG_STRING:
			return false;
			break;
		default:
			return true;
			break;
	}
}

QualiaContext *Qualia_InitContext(QualiaMallocFuncType *const MallocFunc,
								QualiaCallocFuncType *const CallocFunc,
								QualiaFreeFuncType *const FreeFunc,
								QualiaReallocFuncType *const ReallocFunc)
{
	QualiaContext *const Ctx = CallocFunc(1, sizeof(QualiaContext));

	Qualia_Memset(Ctx, 0, sizeof(QualiaContext));

	Ctx->MallocFunc = MallocFunc;
	Ctx->CallocFunc = CallocFunc;
	Ctx->FreeFunc = FreeFunc;
	Ctx->ReallocFunc = ReallocFunc;

	return Ctx;
}

void Qualia_DestroyContext(QualiaContext *const Ctx)
{
	QualiaFreeFuncType *const Free = Ctx->FreeFunc;

	Free(Ctx);
}

QualiaArgType *Qualia_Stream_GetArgTypes(QualiaStream *const Stream, uint32_t *NumArgsOut)
{
	const uint8_t *Worker = Qualia_Stream_GetArgsData(Stream);

	const uint8_t *const Stopper = Worker + Qualia_Stream_GetArgsSize(Stream);

	uint32_t NumArgs = 0;

	//Walk once to get number of arguments.
	while (Worker < Stopper)
	{
		uint32_t ArgSize = 0;

		DecodeStreamArgHeader(Stream, &Worker, &ArgSize);

		Worker += ArgSize;

		++NumArgs;
	}

	QualiaArgType *RetVal = Stream->Ctx->CallocFunc(1, sizeof(QualiaArgType) * NumArgs);
	QualiaArgType *Out = RetVal;

	if (!RetVal) return NULL;

	//Walk again to save them.
	Worker = Qualia_Stream_GetArgsData(Stream);

	while (Worker < Stopper)
	{
		uint32_t ArgSize = 0;

		const QualiaArgType ArgType = DecodeStreamArgHeader(Stream, &Worker, &ArgSize);

		*Out++ = ArgType;

		Worker += ArgSize;
	}

	if (NumArgsOut)
	{
		*NumArgsOut = Out - RetVal;
	}

	return RetVal;
}

void Qualia_Stream_Destroy(QualiaStream *const Stream)
{
	Stream->Ctx->FreeFunc(Stream->Bytes);
	Stream->Ctx->FreeFunc(Stream);
}

QualiaStream *Qualia_Stream_New(QualiaContext *const Ctx, uint32_t Preallocate)
{
	if (Preallocate < sizeof(uint32_t))
	{
		Preallocate = sizeof(uint32_t);
	}

	QualiaStream *const Stream = Ctx->CallocFunc(1, sizeof(QualiaStream));

	if (!Stream) return NULL;

	uint8_t *Buffer = Ctx->CallocFunc(1, Preallocate);

	if (!Buffer)
	{
		Ctx->FreeFunc(Stream);
		return NULL;
	}

	Qualia_Memset(Buffer, 0, Preallocate);

	Stream->Capacity = Preallocate;
	Stream->Bytes = Buffer;
	Stream->Head = Buffer + sizeof(uint32_t); //Skip past argsize uint32.
	Stream->Ctx = Ctx;

	return Stream;
}

QualiaStream *Qualia_Stream_New_With_Buffer(QualiaContext *const Ctx, const void *Data, const uint32_t Len)
{
	if (!Data) return NULL;

	if (Len < sizeof(uint32_t)) return NULL;

	QualiaStream *const Stream = Ctx->CallocFunc(1, sizeof(QualiaStream));

	if (!Stream) return NULL;

	uint8_t *Buffer = Ctx->CallocFunc(1, Len);

	if (!Buffer)
	{
		Ctx->FreeFunc(Stream);
		return NULL;
	}

	Qualia_Memcpy(Buffer, Data, Len);

	Stream->Capacity = Len;
	Stream->Bytes = Buffer;
	Stream->Head = Buffer + sizeof(uint32_t); //Skip past argsize uint32.
	Stream->Ctx = Ctx;

	if (!Qualia_Stream_Validate(Stream))
	{ //Check that the stream is well-formed.
		Ctx->FreeFunc(Stream->Bytes);
		Ctx->FreeFunc(Stream);
		return NULL;
	}

	return Stream;
}

bool Qualia_Stream_Push_String(QualiaStream *const Stream, const char *const String)
{
	const uint32_t Len = Qualia_Strlen(String);

	return 	EncodeStreamArgHeader(Stream, QUALIA_ARG_STRING, Len + 1) &&
			EncodeString(Stream, String, Len);
}

bool Qualia_Stream_Push_String_Len(QualiaStream *const Stream, const char *const String, const uint32_t Len)
{
	return 	EncodeStreamArgHeader(Stream, QUALIA_ARG_STRING, Len + 1) &&
			EncodeString(Stream, String, Len);
}

bool Qualia_Stream_Push_Blob(QualiaStream *const Stream, const void *const Data, const uint32_t Len)
{
	return 	EncodeStreamArgHeader(Stream, QUALIA_ARG_BLOB, Len) &&
			EncodeBlob(Stream, Data, Len);
}

bool Qualia_Stream_Push_Bool(QualiaStream *const Stream, const bool Value)
{
	return	EncodeStreamArgHeader(Stream, QUALIA_ARG_BOOL, sizeof(bool)) &&
			EncodeBool(Stream, Value);
}

bool Qualia_Stream_Push_Byte(QualiaStream *const Stream, const uint8_t Value)
{
	return	EncodeStreamArgHeader(Stream, QUALIA_ARG_BYTE, sizeof(uint8_t)) &&
			EncodeByte(Stream, Value);
}
bool Qualia_Stream_Push_Int16(QualiaStream *const Stream, const int16_t Value)
{
	return	EncodeStreamArgHeader(Stream, QUALIA_ARG_INT16, sizeof(int16_t)) &&
			EncodeI16(Stream, Value);
}
bool Qualia_Stream_Push_Uint16(QualiaStream *const Stream, const uint16_t Value)
{
	return	EncodeStreamArgHeader(Stream, QUALIA_ARG_UINT16, sizeof(uint16_t)) &&
			EncodeU16(Stream, Value);
}
bool Qualia_Stream_Push_Int32(QualiaStream *const Stream, const int32_t Value)
{
	return	EncodeStreamArgHeader(Stream, QUALIA_ARG_INT32, sizeof(int32_t)) &&
			EncodeI32(Stream, Value);
}
bool Qualia_Stream_Push_Uint32(QualiaStream *const Stream, const uint32_t Value)
{
	return	EncodeStreamArgHeader(Stream, QUALIA_ARG_UINT32, sizeof(uint32_t)) &&
			EncodeU32(Stream, Value);
}

#ifndef QUALIA_NO_64
bool Qualia_Stream_Push_Int64(QualiaStream *const Stream, const int64_t Value)
{
	return	EncodeStreamArgHeader(Stream, QUALIA_ARG_INT64, sizeof(int64_t)) &&
			EncodeI64(Stream, Value);
}

bool Qualia_Stream_Push_Uint64(QualiaStream *const Stream, const uint64_t Value)
{
	return	EncodeStreamArgHeader(Stream, QUALIA_ARG_UINT64, sizeof(uint64_t)) &&
			EncodeU64(Stream, Value);
}
#endif //QUALIA_NO_64

const char *Qualia_Stream_Pop_String(QualiaStream *const Stream) //Refers to data inside the stream, need not be freed.
{
	if (PeekStreamArgType(Stream, Stream->Head) != QUALIA_ARG_STRING) return NULL;

	uint32_t TerminatedLen = 0;

	if (DecodeStreamArgHeader(Stream, &Stream->Head, &TerminatedLen) != QUALIA_ARG_STRING)
	{
		return NULL;
	}

	const char *const RetVal = (const char*)Stream->Head;

	Stream->Head += TerminatedLen;

	return RetVal;
}

const char *Qualia_Stream_Pop_String_Len(QualiaStream *const Stream, uint32_t *LenOut) //Refers to data inside the stream, need not be freed.
{
	if (PeekStreamArgType(Stream, Stream->Head) != QUALIA_ARG_STRING) return NULL;

	uint32_t TerminatedLen = 0;

	if (DecodeStreamArgHeader(Stream, &Stream->Head, &TerminatedLen) != QUALIA_ARG_STRING)
	{
		return NULL;
	}

	if (LenOut)
	{
		*LenOut = TerminatedLen - 1; //Should always be one or more because of the null terminator.
	}

	const char *const RetVal = (const char*)Stream->Head;

	Stream->Head += TerminatedLen;

	return RetVal;
}


const void *Qualia_Stream_Pop_Blob(QualiaStream *const Stream, uint32_t *BlobLenOut) //Refers to data inside the stream, need not be freed.
{
	if (PeekStreamArgType(Stream, Stream->Head) != QUALIA_ARG_BLOB) return NULL;

	uint32_t Len = 0;

	if (DecodeStreamArgHeader(Stream, &Stream->Head, &Len) != QUALIA_ARG_BLOB)
	{
		return NULL;
	}

	if (BlobLenOut)
	{
		*BlobLenOut = Len;
	}

	const void *const RetVal = Stream->Head;

	Stream->Head += Len;

	return RetVal;
}

bool Qualia_Stream_Pop_Bool(QualiaStream *const Stream)
{
	if (PeekStreamArgType(Stream, Stream->Head) != QUALIA_ARG_BOOL) return 0;

	DecodeStreamArgHeader(Stream, &Stream->Head, NULL);
	return DecodeBool(Stream, &Stream->Head);
}

uint8_t Qualia_Stream_Pop_Byte(QualiaStream *const Stream)
{
	if (PeekStreamArgType(Stream, Stream->Head) != QUALIA_ARG_BYTE) return 0;

	DecodeStreamArgHeader(Stream, &Stream->Head, NULL);
	return DecodeByte(Stream, &Stream->Head);
}

uint16_t Qualia_Stream_Pop_Uint16(QualiaStream *const Stream)
{
	if (PeekStreamArgType(Stream, Stream->Head) != QUALIA_ARG_UINT16) return 0;

	DecodeStreamArgHeader(Stream, &Stream->Head, NULL);
	return DecodeU16(Stream, &Stream->Head);
}
int16_t Qualia_Stream_Pop_Int16(QualiaStream *const Stream)
{
	if (PeekStreamArgType(Stream, Stream->Head) != QUALIA_ARG_INT16) return 0;

	DecodeStreamArgHeader(Stream, &Stream->Head, NULL);
	return DecodeI16(Stream, &Stream->Head);
}

uint32_t Qualia_Stream_Pop_Uint32(QualiaStream *const Stream)
{
	if (PeekStreamArgType(Stream, Stream->Head) != QUALIA_ARG_UINT32) return 0;

	DecodeStreamArgHeader(Stream, &Stream->Head, NULL);
	return DecodeU32(Stream, &Stream->Head);
}
int32_t Qualia_Stream_Pop_Int32(QualiaStream *const Stream)
{
	if (PeekStreamArgType(Stream, Stream->Head) != QUALIA_ARG_INT32) return 0;

	DecodeStreamArgHeader(Stream, &Stream->Head, NULL);
	return DecodeI32(Stream, &Stream->Head);
}
#ifndef QUALIA_NO_64
uint64_t Qualia_Stream_Pop_Uint64(QualiaStream *const Stream)
{
	if (PeekStreamArgType(Stream, Stream->Head) != QUALIA_ARG_UINT64) return 0;

	DecodeStreamArgHeader(Stream, &Stream->Head, NULL);
	return DecodeU64(Stream, &Stream->Head);
}

int64_t Qualia_Stream_Pop_Int64(QualiaStream *const Stream)
{
	if (PeekStreamArgType(Stream, Stream->Head) != QUALIA_ARG_INT64) return 0;

	DecodeStreamArgHeader(Stream, &Stream->Head, NULL);
	return DecodeI64(Stream, &Stream->Head);
}

#endif //QUALIA_NO_64
bool Qualia_Stream_Validate(QualiaStream *const Stream)
{
	if (Stream->Capacity < sizeof(uint32_t))
	{
		return false;
	}

	if (!Stream->Bytes)
	{
		return false;
	}

	if (!Stream->Head ||
		((uintptr_t)Stream->Head > (uintptr_t)(Stream->Bytes + Stream->Capacity)) ||
		((uintptr_t)Stream->Head < (uintptr_t)(Stream->Bytes)))
	{
		return false;
	}

	const uint32_t StreamSize = Qualia_Stream_GetSize(Stream);

	//Validate size is sane.
	if (StreamSize > Stream->Capacity)
	{
		return false;
	}
	else if (StreamSize == Stream->Capacity) return true; //Empty stream, technically valid.

	const uint8_t *Worker = Qualia_Stream_GetArgsData(Stream);
	const uint8_t *const Stopper = Qualia_Stream_GetArgsData(Stream) + Qualia_Stream_GetArgsSize(Stream);

	while (Worker < Stopper)
	{
		const QualiaArgType ArgType = (QualiaArgType)*Worker++;

		if (Worker == Stopper)
		{
			return false;
		}

		bool SizeError = false;
		const size_t Size = Qualia_IsUnsizedArgType(ArgType) ? GetUnsizedTypeSize(ArgType) : DecodeSize(Stream, &Worker, &SizeError);

		if (SizeError)
		{
			return false;
		}

		if (ArgType == QUALIA_ARG_STRING && !Size)
		{
			return false; //Even a zero length string has a null terminator.
		}

		if ((Worker - Stream->Bytes) + Size > Stream->Capacity)
		{
			return false;
		}

		Worker += Size;
	}

	return true;
}

QualiaStream *Qualia_Stream_Clone(QualiaStream *const Stream)
{
	if (!Stream || !Stream->Bytes) return false;

	QualiaStream *New = Stream->Ctx->CallocFunc(1, sizeof(QualiaStream));

	Qualia_Memset(New, 0, sizeof(QualiaStream));

	New->Bytes = Stream->Ctx->CallocFunc(1, Stream->Capacity);

	const uint32_t StreamSize = Qualia_Stream_GetSize(Stream);

	Qualia_Memcpy(New->Bytes, Stream->Bytes, StreamSize);
	Qualia_Memset(New->Bytes + StreamSize, 0, Stream->Capacity - StreamSize);

	New->Head = New->Bytes + (Stream->Head - Stream->Bytes);
	New->Capacity = Stream->Capacity;
	New->Ctx = Stream->Ctx;

	return New;
}
