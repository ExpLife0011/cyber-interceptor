#ifndef __miniport_hookWin7__
#define __miniport_hookWin7__


//////////////////////////////////////////////////////////////////////////
typedef struct _NDIS_OBJECT_HEADERWIN7
{
	UCHAR   Type;
	UCHAR   Revision;
	USHORT  Size;
} NDIS_OBJECT_HEADERWIN7, *PNDIS_OBJECT_HEADERWIN7;




typedef	struct	_NDIS_PROTOCOL_BLOCKWin7
{

	NDIS_OBJECT_HEADERWIN7	Header;
	ULONG_PTR	ProtocolDriverContext;
	ULONG_PTR	NextProtocol;
	ULONG_PTR	OpenQueue;
	REFERENCE	ref;
	UCHAR	MajorNdisVersion;
	UCHAR	MinorNdisVersion;
	UCHAR	MajorDriverVersion;
	UCHAR	MinorDriverVersion;
	DWORD	Reserved;
	DWORD	Flags;
	UNICODE_STRING	Name;
}NDIS_PROTOCOL_BLOCKWin7,*PNDIS_PROTOCOL_BLOCKWin7;

typedef	struct	_NDIS_OPEN_BLOCKWIN7
{
	PVOID                        MacHandle;          // needed for backward compatibility	+0
	NDIS_HANDLE                  BindingHandle;      // Miniport's open context				+4
	PNDIS_MINIPORT_BLOCK         MiniportHandle;     // pointer to the miniport				+8
	PNDIS_PROTOCOL_BLOCKWin7     ProtocolHandle;     // pointer to our protocol			+c
	PVOID						ProtocolBindingContext;	//+10
	PVOID						NextSendHandler;	//+14				
	PVOID						NextSendContext;	//+18
	PVOID						MiniportAdapterContext;//+1c
	
}NDIS_OPEN_BLOCKWIN7, *PNDIS_OPEN_BLOCKWIN7;


typedef struct _NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_WIN7
{
	NDIS_OBJECT_HEADERWIN7                      Header;
	UCHAR                                   MajorNdisVersion;
	UCHAR                                   MinorNdisVersion;
	UCHAR                                   MajorDriverVersion;
	UCHAR                                   MinorDriverVersion;
	ULONG                                   Flags;
	NDIS_STRING                             Name;
	DWORD                     SetOptionsHandler;
	DWORD                         BindAdapterHandlerEx;
	DWORD                       UnbindAdapterHandlerEx;
	DWORD        OpenAdapterCompleteHandlerEx;
	DWORD       CloseAdapterCompleteHandlerEx;
	DWORD                   NetPnPEventHandler;
	DWORD              UninstallHandler;
	DWORD            OidRequestCompleteHandler;
	DWORD                       StatusHandlerEx;
	DWORD        ReceiveNetBufferListsHandler;
	DWORD  SendNetBufferListsCompleteHandler;
#if (NDIS_SUPPORT_NDIS61)
	DWORD     DirectOidRequestCompleteHandler;
#endif // (NDIS_SUPPORT_NDIS61)
} NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_WIN7, *PNDIS_PROTOCOL_DRIVER_CHARACTERISTICS_WIN7;


typedef struct _NDIS50_PROTOCOL_CHARACTERISTICS_WIN7
{

	NDIS40_PROTOCOL_CHARACTERISTICS Ndis40Chars;


	//
	// Placeholders for protocol extensions for PnP/PM etc.
	//
	PVOID                           ReservedHandlers[4];

	//
	// Start of NDIS 5.0 extensions.
	//

	PVOID        CoSendCompleteHandler;
	PVOID               CoStatusHandler;
	PVOID       CoReceivePacketHandler;
	PVOID   CoAfRegisterNotifyHandler;

} NDIS50_PROTOCOL_CHARACTERISTICS_WIN7;

//////////////////////////////////////////////////////////////////////////

NTSTATUS	DoHookExWin7(DWORD uProtocolHeader);


DWORD	GetProtocolHeaderWin7();






#endif