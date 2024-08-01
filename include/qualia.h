///Qualia is copyright (c) 2024 Daniel Hopson.
///All rights reserved.

#ifndef __LIBQUALIA_HEADER_H__
#define __LIBQUALIA_HEADER_H__

/*
 * Gentle storm, thundering silence
 * Inferior force, uncontrolled calm
 * Vital unlife, logic, chaos, logic
 * The tone of which his birth ascend
 * The beat that of a heart descend
 * Repeating in the infinite
 * An insight made it clear
 * Order stormed the surface
 * Where chaos set the norm
 * Had there always been balance?
 * ...Surely not
 * Therein lies the beauty
 * It was solid
 * Yet everchanging
 * It was different
 * Yet the same
 * So I starve myself for energy
 * It was solid
 * Yet everchanging
 * It was different
 * Yet the same
 * So I starve myself for energy
 * I starve myself for energy
 * The song around his soul will bend
 * The notes that in this hole will melt
 * Crawl out of science
 * A dreamland if you dare
 * Disorder clawed the boundaries
 * We're ordered to stand clear
 * Was it always different
 * ...Never the same?
 * Therein lies the beauty
 * It was solid
 * Yet everchanging
 * It was different
 * Yet the same
 * So I starve myself for Energy
 * It was solid
 * Yet everchanging
 * It was different
 * Yet the same
 * So I starve myself for energy
 * I starve myself for energy
 * As there were no witnesses
 * There was nothing to be told
 * As nothing could be grasped
 * The story could unfold
 * Superimposed on the elements of anger
 * Fear, anxiety, hate, despair, remorse
 * So break from all that fear hold fast
 * Exposed, now turn to all you lack
 * Let echoes be the answers
 * Return from all the screams
 * Wordless now the last attack
 * So silent it hurts to listen
 * Was it always solid
 * To never change?
 * Therein lies the beauty
 * It was solid
 * Yet everchanging
 * It was different
 * Yet the same
 * So I starve myself for energy
 * It was solid
 * Yet everchanging
 * It was different
 * Yet the same
 * So I starve myself for energy
 * I starve myself for energy
 *
 * -Dark Tranquillity - Therein, on the album "Projector"
 */

//Qualia requires a C99 compiler. That's it.
//You set allocation functions yourself. Realloc is optional, but recommended if available.

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <limits.h>


#ifdef _MSC_VER
#define QUALIA_FORCE_INLINE __forceinline
#else
#define QUALIA_FORCE_INLINE inline __attribute__((always_inline))
#endif //_MSC_VER

#ifdef _MSC_VER
#define QUALIA_HOT
#else
#define QUALIA_HOT __attribute__((hot))
#endif //_MSC_VER

#define QUALIA_NMIN(x, y) (x > y ? y : x)
#define QUALIA_NMAX(x, y) (x > y ? x : y)

#ifdef __cplusplus
extern "C"
{
#endif //__cplusplus

typedef enum QualiaArgType
{
	QUALIA_ARG_INVALID = 0,
	QUALIA_ARG_BOOL = 1,
	QUALIA_ARG_BYTE = 2,
	QUALIA_ARG_STRING = 3,
	QUALIA_ARG_BLOB = 4,
	QUALIA_ARG_UINT16 = 5,
	QUALIA_ARG_INT16 = 6,
	QUALIA_ARG_UINT32 = 7,
	QUALIA_ARG_INT32 = 8,
#ifndef QUALIA_NO_64
	QUALIA_ARG_UINT64 = 9,
	QUALIA_ARG_INT64 = 10,
#endif //QUALIA_NO_64
	QUALIA_ARG_MAX,
} QualiaArgType;

bool Qualia_IsUnsizedArgType(const QualiaArgType ArgType);

static QUALIA_FORCE_INLINE bool ArchIsBigEndian(void)
{ //Not ideal (preprocessor stuff isn't super portable for endianness),
	//but the optimizer seems to kill it with dead-code elimination.
	const uint16_t Test = 1;
	return *(const uint8_t*)&Test == 0;
}

static QUALIA_FORCE_INLINE size_t Qualia_Strlen(const char *const String)
{
#if defined(__GNUC__) || defined(__clang__)
	return __builtin_strlen(String);
#else
	const char *Worker = String;

	for (; *Worker; ++Worker);

	return (size_t)(Worker - String);
#endif //__GNUC__ __clang__
}

QUALIA_FORCE_INLINE void *Qualia_Memcpy(void *const Out, const void *const In_, const size_t Len)
{
#if defined(__GNUC__) || defined(__clang__)
	return __builtin_memcpy(Out, In_, Len);
#else

	if (!Len) return Out;

	const uint8_t *In = In_;

	uint8_t *Worker = Out;

	const uint8_t *const Stopper = Worker + Len;

	while (Worker < Stopper)
	{
		*Worker++ = *In++;
	}

	return Out;
#endif //__GNUC__ __clang__
}


QUALIA_FORCE_INLINE void *Qualia_Memset(void *const Out, const int Byte, const size_t Len)
{
#if defined(__GNUC__) || defined(__clang__)
	return __builtin_memset(Out, Byte, Len);
#else
	uint8_t *Worker = Out;
	const uint8_t *const Stopper = Worker + Len;

	while (Worker < Stopper)
	{
		*Worker++ = 0;
	}

	return Out;
#endif //__GNUC__ __clang__
}

typedef void *QualiaMallocFuncType(size_t);
typedef void *QualiaCallocFuncType(size_t, size_t);
typedef void QualiaFreeFuncType(void*);
typedef void *QualiaReallocFuncType(void*, size_t);

typedef struct QualiaContext
{
	QualiaMallocFuncType *MallocFunc;
	QualiaCallocFuncType *CallocFunc;
	QualiaFreeFuncType *FreeFunc;
	QualiaReallocFuncType *ReallocFunc;
} QualiaContext;


//You should be calling this function exactly ONCE per address-space/per application!
//Do not be creating and destroying contexts for no reason.
//Mostly, because some QualiaTLS stuff won't like it and you might get a segfault.
QualiaContext *Qualia_InitContext(	QualiaMallocFuncType *const MallocFunc,
									QualiaCallocFuncType *const CallocFunc,
									QualiaFreeFuncType *const FreeFunc,
									QualiaReallocFuncType *const ReallocFunc);

void Qualia_DestroyContext(QualiaContext *Ctx);

typedef struct QualiaStream
{
	QualiaContext *Ctx;
	uint8_t *Bytes;
	const uint8_t *Head;
	uint32_t Capacity;
} QualiaStream;

QualiaStream *Qualia_Stream_New(QualiaContext *const Ctx, uint32_t Preallocate);
QualiaStream *Qualia_Stream_New_With_Buffer(QualiaContext *const Ctx, const void *Data, const uint32_t Len);
uint32_t Qualia_Stream_ChangeCapacity(QualiaStream *const Stream, uint32_t NewCapacity);
void Qualia_Stream_Destroy(QualiaStream *const Stream);
uint32_t Qualia_Stream_GetSize(QualiaStream *const Stream);
uint32_t Qualia_Stream_GetArgsSize(QualiaStream *const Stream);
QualiaArgType *Qualia_Stream_GetArgTypes(QualiaStream *const Stream, uint32_t *NumArgsOut);
uint8_t *Qualia_Stream_GetArgsData(QualiaStream *const Stream);
void Qualia_Stream_Rewind(QualiaStream *const Stream);
const void *Qualia_Stream_Pop_Blob(QualiaStream *const Stream, uint32_t *BlobLenOut); //Refers to data inside the stream, need not be freed.
const char *Qualia_Stream_Pop_String(QualiaStream *const Stream); //Refers to data inside the stream, need not be freed.
const char *Qualia_Stream_Pop_String_Len(QualiaStream *const Stream, uint32_t *LenOut); //Refers to data inside the stream, need not be freed.
bool Qualia_Stream_Pop_Bool(QualiaStream *const Stream);
uint8_t Qualia_Stream_Pop_Byte(QualiaStream *const Stream);
uint16_t Qualia_Stream_Pop_Uint16(QualiaStream *const Stream);
int16_t Qualia_Stream_Pop_Int16(QualiaStream *const Stream);
uint32_t Qualia_Stream_Pop_Uint32(QualiaStream *const Stream);
int32_t Qualia_Stream_Pop_Int32(QualiaStream *const Stream);
#ifndef QUALIA_NO_64
uint64_t Qualia_Stream_Pop_Uint64(QualiaStream *const Stream);
int64_t Qualia_Stream_Pop_Int64(QualiaStream *const Stream);
#endif //QUALIA_NO_64
bool Qualia_Stream_Push_String(QualiaStream *const Stream, const char *const String);
bool Qualia_Stream_Push_String_Len(QualiaStream *const Stream, const char *const String, const uint32_t Len);
bool Qualia_Stream_Push_Blob(QualiaStream *const Stream, const void *const Data, const uint32_t Len);
bool Qualia_Stream_Push_Bool(QualiaStream *const Stream, const bool Value);
bool Qualia_Stream_Push_Byte(QualiaStream *const Stream, const uint8_t Value);
bool Qualia_Stream_Push_Int16(QualiaStream *const Stream, const int16_t Value);
bool Qualia_Stream_Push_Uint16(QualiaStream *const Stream, const uint16_t Value);
bool Qualia_Stream_Push_Int32(QualiaStream *const Stream, const int32_t Value);
bool Qualia_Stream_Push_Uint32(QualiaStream *const Stream, const uint32_t Value);
#ifndef QUALIA_NO_64
bool Qualia_Stream_Push_Int64(QualiaStream *const Stream, const int64_t Value);
bool Qualia_Stream_Push_Uint64(QualiaStream *const Stream, const uint64_t Value);
#endif //QUALIA_NO_64
bool Qualia_Stream_Validate(QualiaStream *const Stream);
QualiaStream *Qualia_Stream_Clone(QualiaStream *const Stream);

//Memory manipulation helpers
void *Qualia_Realloc(QualiaContext *const Ctx, const void *const Data_, const size_t OldSize, const size_t NewSize);
const char *Qualia_GetRevision(void);

//Byte ordering helpers
uint16_t Qualia_Htons(const uint16_t Int);
uint32_t Qualia_Htonl(const uint32_t Int);
#ifndef QUALIA_NO_64
uint64_t Qualia_Htonll(const uint64_t Int);
#endif //QUALIA_NO_64
uint16_t Qualia_Ntohs(const uint16_t Int);
uint32_t Qualia_Ntohl(const uint32_t Int);
#ifndef QUALIA_NO_64
uint64_t Qualia_Ntohll(const uint64_t Int);
#endif //QUALIA_NO_64

#ifdef __cplusplus
}
#endif //__cplusplus

#endif //__LIBQUALIA_HEADER_H__
