#ifndef __miniport_hookXp__
#define __miniport_hookXp__

//////////////////////////////////////////////////////////////////////////



typedef struct _NDIS_COMMON_OPEN_BLOCK_2k3_early
{
	PVOID                        MacHandle;          // needed for backward compatibility
	NDIS_HANDLE                  BindingHandle;      // Miniport's open context
	PNDIS_MINIPORT_BLOCK         MiniportHandle;     // pointer to the miniport
	PNDIS_PROTOCOL_BLOCK         ProtocolHandle;     // pointer to our protocol
	NDIS_HANDLE                  ProtocolBindingContext;// context when calling ProtXX funcs
	struct _NDIS_COMMON_OPEN_BLOCK_2k3_early *             MiniportNextOpen;   // used by adapter's OpenQueue
	PNDIS_OPEN_BLOCK             ProtocolNextOpen;   // used by protocol's OpenQueue
	NDIS_HANDLE                  MiniportAdapterContext; // context for miniport
	BOOLEAN                      Reserved1;
	BOOLEAN                      Reserved2;
	BOOLEAN                      Reserved3;
	BOOLEAN                      Reserved4;
	PNDIS_STRING                 BindDeviceName;
	KSPIN_LOCK                   Reserved5;
	PNDIS_STRING                 RootDeviceName;

	//
	// These are referenced by the macros used by protocols to call.
	// All of the ones referenced by the macros are internal NDIS handlers for the miniports
	//
	union
	{
		SEND_HANDLER             SendHandler;
		WAN_SEND_HANDLER         WanSendHandler;
	};
	TRANSFER_DATA_HANDLER        TransferDataHandler;

	//
	// These are referenced internally by NDIS
	//
	union
	{
		SEND_COMPLETE_HANDLER        SendCompleteHandler;
		PVOID						 send_handler_for_2k;
	};

	TRANSFER_DATA_COMPLETE_HANDLER TransferDataCompleteHandler;
	RECEIVE_HANDLER              ReceiveHandler;
	RECEIVE_COMPLETE_HANDLER     ReceiveCompleteHandler;
	WAN_RECEIVE_HANDLER          WanReceiveHandler;
	REQUEST_COMPLETE_HANDLER     RequestCompleteHandler;

	//
	// NDIS 4.0 extensions
	//
	RECEIVE_PACKET_HANDLER       ReceivePacketHandler;
	SEND_PACKETS_HANDLER         SendPacketsHandler;

	//
	// More Cached Handlers
	//
	RESET_HANDLER                ResetHandler;
	REQUEST_HANDLER              RequestHandler;
	RESET_COMPLETE_HANDLER       ResetCompleteHandler;
	STATUS_HANDLER               StatusHandler;
	STATUS_COMPLETE_HANDLER      StatusCompleteHandler;

	//#if defined(NDIS_WRAPPER)
	ULONG                        Flags;
	ULONG                        References;
	KSPIN_LOCK                   SpinLock;           // guards Closing
	NDIS_HANDLE                  FilterHandle;
	ULONG                        ProtocolOptions;
	USHORT                       CurrentLookahead;
	USHORT                       ConnectDampTicks;
	USHORT                       DisconnectDampTicks;

	//
	// These are optimizations for getting to driver routines. They are not
	// necessary, but are here to save a dereference through the Driver block.
	//
	NDIS_HANDLE               WSendHandler;
	NDIS_HANDLE      WTransferDataHandler;

	//
	//   NDIS 4.0 miniport entry-points
	//
	NDIS_HANDLE       WSendPacketsHandler;

	NDIS_HANDLE    CancelSendPacketsHandler;

	//
	//   Contains the wake-up events that are enabled for the open.
	//
	ULONG                        WakeUpEnable;
	//
	// event to be signalled when close complets
	//
	PKEVENT                      CloseCompleteEvent;

	ULONG							QC[5];//QUEUED_CLOSE声明不出来，用这个代替
	//QUEUED_CLOSE                 QC;	//0x14字节大小

	ULONG                        AfReferences;

	struct _NDIS_COMMON_OPEN_BLOCK_2k3_early *             NextGlobalOpen;

	//#endif

} NDIS_COMMON_OPEN_BLOCK_2k3_early, *PNDIS_COMMON_OPEN_BLOCK_2k3_early;

typedef struct _MYNDIS50_PROTOCOL_CHARACTERISTICS
{

	NDIS40_PROTOCOL_CHARACTERISTICS Ndis40Chars;


	//
	// Placeholders for protocol extensions for PnP/PM etc.
	//
	PVOID                           ReservedHandlers[4];

	//
	// Start of NDIS 5.0 extensions.
	//

	// 	CO_SEND_COMPLETE_HANDLER        CoSendCompleteHandler;
	// 	CO_STATUS_HANDLER               CoStatusHandler;
	// 	CO_RECEIVE_PACKET_HANDLER       CoReceivePacketHandler;
	// 	CO_AF_REGISTER_NOTIFY_HANDLER   CoAfRegisterNotifyHandler;

} MYNDIS50_PROTOCOL_CHARACTERISTICS;

/*
XP：
kd> dt ndis!_NDIS_PROTOCOL_BLOCK 
+0x000 OpenQueue        : Ptr32 _NDIS_OPEN_BLOCK
+0x004 Ref              : _REFERENCE
+0x00c DeregEvent       : Ptr32 _KEVENT
+0x010 NextProtocol     : Ptr32 _NDIS_PROTOCOL_BLOCK
+0x014 ProtocolCharacteristics : _NDIS50_PROTOCOL_CHARACTERISTICS
+0x080 WorkItem         : _WORK_QUEUE_ITEM
+0x090 Mutex            : _KMUTANT
+0x0b0 MutexOwner       : Uint4B
+0x0b4 BindDeviceName   : Ptr32 _UNICODE_STRING
+0x0b8 RootDeviceName   : Ptr32 _UNICODE_STRING
*/

typedef struct my_NDIS_PROTOCOL_BLOCK
{
	PNDIS_COMMON_OPEN_BLOCK_2k3_early OpenQueue;
	REFERENCE Ref;
	KEVENT *DeregEvent;
	struct my_NDIS_PROTOCOL_BLOCK *NextProtocol;
	MYNDIS50_PROTOCOL_CHARACTERISTICS ProtocolCharacteristics;
	//.. there should be more member followed
}KK_NDIS_PROTOCOL_BLOCK,*PKK_NDIS_PROTOCOL_BLOCK;

//////////////////////////////////////////////////////////////////////////


BOOLEAN	HookRecvXP(PNDIS_MINIPORT_BLOCK p_mini_block);

BOOLEAN	HookSendXP(PNDIS_COMMON_OPEN_BLOCK p_open_block);

NTSTATUS	DoHookExXP(DWORD uProtocolHeader);

DWORD	GetProtocolHeaderXP();

#endif