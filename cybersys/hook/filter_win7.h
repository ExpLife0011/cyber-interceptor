
/********************************************************************

	filename: 	e:\dev\CyberInterceptor\sys\udptraffic\udpTraffic.c
	file path:	e:\dev\CyberInterceptor\sys\udptraffic
	file base:	udpTraffic
	file ext:	c
	author:		kindof
	
	purpose:	
*********************************************************************/
#ifndef __filter_win7__
#define __filter_win7__


//////////////////////////////////////////////////////////////////////////
// typedef union _SLIST_HEADER {
// 	ULONGLONG Alignment;
// 	struct {
// 		SLIST_ENTRY Next;
// 		USHORT Depth;
// 		USHORT Sequence;
// 	} DUMMYSTRUCTNAME;
// } SLIST_HEADER, *PSLIST_HEADER;

typedef struct _NET_BUFFER_KK NET_BUFFER_KK, *PNET_BUFFER_KK;
typedef struct _NET_BUFFER_LIST_CONTEXT_KK NET_BUFFER_LIST_CONTEXT_KK, *PNET_BUFFER_LIST_CONTEXT_KK;
typedef struct _NET_BUFFER_LIST_KK NET_BUFFER_LIST_KK, *PNET_BUFFER_LIST_KK;

#include "miniport_hookWin7.h"

typedef struct _NET_BUFFER_DATA_KK
{
	PNET_BUFFER_KK Next;
	PMDL        CurrentMdl;
	ULONG       CurrentMdlOffset;
	union
	{
		DWORD	DataLength;
		DWORD	stDataLength;
	};
	PMDL        MdlChain;
	ULONG       DataOffset;
} NET_BUFFER_DATA_KK, *PNET_BUFFER_DATA_KK;


typedef union _NET_BUFFER_HEADER_KK
{
#ifdef __cplusplus
	NET_BUFFER_DATA_KK NetBufferData;
#else
	NET_BUFFER_DATA_KK;
#endif
	SLIST_HEADER    Link;

} NET_BUFFER_HEADER_KK, *PNET_BUFFER_HEADER_KK;


typedef struct _NET_BUFFER_KK
{

#ifdef __cplusplus
	NET_BUFFER_HEADER_KK NetBufferHeader;
#else
	NET_BUFFER_HEADER_KK;
#endif

	USHORT          ChecksumBias;
	USHORT          Reserved;
	NDIS_HANDLE     NdisPoolHandle;
	DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT)PVOID NdisReserved[2];
	DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT)PVOID ProtocolReserved[6];
	DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT)PVOID MiniportReserved[4];
	NDIS_PHYSICAL_ADDRESS   DataPhysicalAddress;

	union
	{
		/*PNET_BUFFER_SHARED_MEMORY*/PVOID   SharedMemoryInfo;
		/*PSCATTER_GATHER_LIST*/PVOID        ScatterGatherList;
	};

}NET_BUFFER_KK, *PNET_BUFFER_KK;



typedef struct _NET_BUFFER_LIST_KK_DATA
{
	PNET_BUFFER_LIST_KK    Next;           // Next NetBufferList in the chain
	PNET_BUFFER_KK         FirstNetBuffer; // First NetBuffer on this NetBufferList
} NET_BUFFER_LIST_KK_DATA, *PNET_BUFFER_LIST_KK_DATA;

typedef union _NET_BUFFER_LIST_HEADER_KK
{
#ifdef __cplusplus
	NET_BUFFER_LIST_KK_DATA NetBufferListData;
#else
	NET_BUFFER_LIST_KK_DATA;
#endif
	SLIST_HEADER            Link;           // used in SLIST of free NetBuffers in the block
} NET_BUFFER_LIST_HEADER_KK, *PNET_BUFFER_LIST_HEADER_KK;


typedef struct _NET_BUFFER_LIST_CONTEXT_KK
{
	PNET_BUFFER_LIST_CONTEXT_KK    Next;
	USHORT                      Size;
	USHORT                      Offset;
	DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT)     UCHAR      ContextData[];
} NET_BUFFER_LIST_CONTEXT_KK, *PNET_BUFFER_LIST_CONTEXT_KK;



typedef struct _NET_BUFFER_LIST_KK
{

#ifdef __cplusplus
	NET_BUFFER_LIST_HEADER_KK      NetBufferListHeader;
#else
	NET_BUFFER_LIST_HEADER_KK;
#endif

	PNET_BUFFER_LIST_CONTEXT_KK    Context;
	PNET_BUFFER_LIST_KK            ParentNetBufferList;
	NDIS_HANDLE                 NdisPoolHandle;
	DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT)PVOID NdisReserved[2];
	DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT)PVOID ProtocolReserved[4];
	DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT)PVOID MiniportReserved[2];
	PVOID                       Scratch;
	NDIS_HANDLE                 SourceHandle;
	ULONG                       NblFlags;   // public flags
	LONG                        ChildRefCount;
	ULONG                       Flags;      // private flags used by NDIs, protocols, miniport, etc.
	NDIS_STATUS                 Status;

	PVOID                       NetBufferListInfo/*[MaxNetBufferListInfo]*/;
} NET_BUFFER_LIST_KK, *PNET_BUFFER_LIST_KK;

typedef struct _NET_BUFFER_LIST_POOL_PARAMETERSWin7
{
	//
	// Set ObjectHeader.Type to NDIS_OBJECT_TYPE_DEFAULT
	//
	NDIS_OBJECT_HEADERWIN7      Header;
	UCHAR                   ProtocolId;
	BOOLEAN                 fAllocateNetBuffer;
	USHORT                  ContextSize;
	ULONG                   PoolTag;
	ULONG                   DataSize;
}NET_BUFFER_LIST_POOL_PARAMETERSWin7, *PNET_BUFFER_LIST_POOL_PARAMETERSWin7;

//////////////////////////////////////////////////////////////////////////

void KKNdisMIndicateReceiveNetBufferListsInternal_vista_later(
	DWORD MiniportAdapterHandle,
	PNET_BUFFER_LIST_KK NetBufferLists,
	DWORD PortNumber,
	DWORD NumberOfNetBufferLists,
	DWORD ReceiveFlags
	);

VOID
KKMPSendNetBufferLists(
					   NDIS_HANDLE             MiniportAdapterContext,
					   PNET_BUFFER_LIST_KK        NetBufferLists,
					   PVOID					PortNumber,
					   DWORD                   SendFlags);

NDIS_STATUS
CopyBytesFromNetBuffer(  PNET_BUFFER_KK        NetBuffer,  PULONG             cbDest, PVOID Dest);

NDIS_STATUS copy_buffer_to_netbuffer(PNET_BUFFER_KK pNet_Buffer, PUCHAR pbuffer, ULONG buffer_len);


PNET_BUFFER_LIST_KK
AllocateNetBufferList(
					  IN DWORD                          DataLength,
					  OUT PUCHAR *                     ppDataBuffer
					  );

VOID FreeNetBufferList(PNET_BUFFER_LIST_KK pNetList);

VOID	ReleaseNetBufferListPool();

#endif