/********************************************************************

	filename: 	e:\dev\CyberInterceptor\sys\udptraffic\udpTraffic.c
	file path:	e:\dev\CyberInterceptor\sys\udptraffic
	file base:	udpTraffic
	file ext:	c
	author:		kindof
	
	purpose:	
*********************************************************************/

#ifndef ALL__
#define ALL__

#define NDIS_LEGACY_MINIPORT 1


#include <ndis.h>

#include <ntddk.h>

#include <ntimage.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <ntstrsafe.h>

#include <tdikrnl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <ntimage.h>



#include "utils.h"
#include "tcpip_struct.h"

#include "hook/filter_xp.h"
#include "hook/miniport_hook.h"
#include "hook/filter_win7.h"
#include "hook/miniport_hookWin7.h"
#include "hook/miniport_hookXp.h"

#include "redirect/my_packet_redir.h"
#include "redirect/RedirectWin7.h"

#include "udptraffic/udpTraffic.h"

#include "netcards/NetcardsInfo.h"

#include "patchws/patchws.h"
#include "patchws/wscatcher.h"
#include "patchws/patchwsWin7.h"
#include "patchws/WScatcherWin7.h"

#include "patchws/PatchSinffer.h"

#include "network/connectionstatus.h"
#include "network/firewall.h"



#define NET_BUFFER_CURRENT_MDL(_NB)                 ((_NB)->CurrentMdl)
#define NET_BUFFER_CURRENT_MDL_OFFSET(_NB) ((_NB)->CurrentMdlOffset)
#define NDIS_MDL_LINKAGE(_Mdl) ((_Mdl)->Next)
#define NET_BUFFER_LIST_FIRST_NB(_NBL) ((_NBL)->FirstNetBuffer)
#define NET_BUFFER_FIRST_MDL(_NB) ((_NB)->MdlChain)
#define NET_BUFFER_DATA_LENGTH(_NB) ((_NB)->DataLength)
#define NET_BUFFER_NEXT_NB(_NB) ((_NB)->Next)
#define NET_BUFFER_LIST_NEXT_NBL(_NBL) ((_NBL)->Next)

#define NdisQueryMdl(_Mdl, _VirtualAddress, _Length, _Priority)             \
{                                                                           \
	if (ARGUMENT_PRESENT(_VirtualAddress))                                  \
	{                                                                       \
	*(PVOID *)(_VirtualAddress) = MmGetSystemAddressForMdlSafe(_Mdl, _Priority); \
	}                                                                       \
	*(_Length) = MmGetMdlByteCount(_Mdl);                                   \
}


//////////////////////////////////////////////////////////////////////////
typedef long LONG;
typedef unsigned char  BYTE, *PBYTE;
typedef unsigned long  DWORD, *PDWORD;
typedef unsigned short WORD, *PWORD;

//////////////////////////////////////////////////////////////////////////

//#define VMPROTECT

#ifdef VMPROTECT
#include "VMProtectDDK.h"
#endif

// #define MYVMPROTECTSTART \
// #ifdef VMPROTECT\
// VMProtectBeginVirtualization("VMPRO");\
// #endif
// 
// #define MYVMPROTECTEND\
// #ifdef VMPROTECT\
// VMProtectEnd();\
// #endif
//////////////////////////////////////////////////////////////////////////


#include "inc\tdi_fw\tdi_fw_lib.h"
#include "..\public\public.h"



#define STARTLOCK(lock,WriteOrRead)	\
	if(1)\
{\
	PLOCK_STATE	pLockState1=NULL;\
	pLockState1	=	kmalloc(sizeof(LOCK_STATE));\
	NdisAcquireReadWriteLock((lock), (WriteOrRead), pLockState1);

#define ENDLOCK(lock)	\
	if (pLockState1)\
	{\
	NdisReleaseReadWriteLock((lock), pLockState1);\
	kfree(pLockState1);\
	}\
}

#define	KKRWLOCK_FOR_WRITE	(TRUE)
#define KKRWLOCK_FOR_READ		(FALSE)
#define ExAllocatePool(a,b)	ExAllocatePoolWithTag((a),(b),'0')


typedef struct _DEVICE_EXTENSION
{
	ULONG  StateVariable;

} DEVICE_EXTENSION, *PDEVICE_EXTENSION;



//hook 信息模块
//导出是为了给UDP模块使用
extern NDIS_HOOK_INFO	g_pHookInfoHeader;
extern	NDIS_RW_LOCK	g_HookInfoLock2;	


//重定向模块
extern REDIRECT_INFO	g_RedirectInfo;
//extern KSPIN_LOCK		g_RedirectInfoLock;
extern NDIS_RW_LOCK		g_RedirectInfoLock2;


extern PDEVICE_OBJECT	g_CtlDevice;

extern PDRIVER_OBJECT	g_pDriverObject	;

//物理网卡信息链表，可用来发UDP表

extern NETCARDS_INFO	g_NetCardsInfoHeader;
extern KSPIN_LOCK		g_NetCardsInfoLock;

extern BOOLEAN	g_ChangingRedirectInfo	;

extern	LIST_ENTRY	g_SendPacketListHeader;
extern	KSPIN_LOCK	g_SendPacketListLock;
extern	KEVENT		g_SendPacketListEvent;
extern	BOOLEAN		g_TerminateUdpWorkThread;

extern	struct my_NDIS_PROTOCOL_BLOCK	*g_pNpfProtocolBlock;
extern	ULONG	g_NPFReceiveHandler;
extern	ULONG	g_NPFReceivePacketHandler;

PNDIS_PROTOCOL_BLOCKWin7 g_pNpfProtocolBlockWin7;
extern DWORD			g_PatchwsVersion;

extern KSPIN_LOCK	g_WSPacketListLock;
extern WSPacketList	g_WSPacketList;
extern KEVENT			g_WSPacketListEvent;
extern BOOLEAN	g_bAlreadyPatchWS;


//fw模块
extern AcceptedPort	g_AcceptedPortListHeader;
extern NDIS_RW_LOCK	g_AcceptedPortListLock2;


extern LIST_ENTRY		g_AskUserConnectListHeader;
extern KSPIN_LOCK		g_AskUserConnectListLock;


extern NDIS_HOOK_INFO	g_HookTcpipFireWallList;
extern NDIS_RW_LOCK		g_HookTcpipFireWallLock;

extern ULONG			g_InterceptTCPIPRcv;
extern ULONG			g_AlreadyHookTCPIP;

//handler for win7
extern PVOID		g_pfnNdisAllocateNetBufferListPool;
extern PVOID		g_pfnNdisAllocateNetBufferAndNetBufferList;
extern PVOID		g_pfnNdisFreeNetBufferListPool;
extern PVOID		g_pfnNdisCopyFromNetBufferToNetBuffer;
extern PVOID		g_pfnNdisFreeNetBufferList;

//////////////////////////////////////////////////////////////////////////
#define MYPACKETFLAG	('kkof')

#endif