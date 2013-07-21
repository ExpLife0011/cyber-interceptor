#ifndef _filter_xp
#define _filter_xp





typedef	enum	__FilterType__
{
	Drop,
	Bypass
}FilterType;




BOOLEAN	HookRecv(PNDIS_MINIPORT_BLOCK p_mini_block);

BOOLEAN	HookSend(PNDIS_COMMON_OPEN_BLOCK p_open_block);

FilterType	PacketRecvCallback(PPNDIS_PACKET packet_arrays, ULONG num_of_packets,  ULONG uReserved);

VOID	PacketSendCallback(PPNDIS_PACKET packet_arrays, ULONG num_of_packets);
////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////

typedef	ULONG	DWORD;
NDIS_STATUS my_WSendPacketsHandler(PVOID MiniportAdapterContext, PPNDIS_PACKET packet_arrays, ULONG num_of_packets);

NDIS_STATUS my_WSendHandler(PVOID MiniportAdapterContext, PNDIS_PACKET pPacket, ULONG flag);


NDIS_STATUS my_NdisSendComplete(PNDIS_MINIPORT_BLOCK pMiniblock, PNDIS_PACKET pPacket, ULONG Status);

NDIS_STATUS my_WSendPacketsHandlerComplete(PVOID ProtocolBindingContext, PNDIS_PACKET pPacket, NDIS_STATUS Status);

NDIS_STATUS my_ethFilterDprIndicateReceivePacket(PNDIS_MINIPORT_BLOCK pMiniblock, PPNDIS_PACKET packet_arrays, ULONG num_of_packets);

//just free the first mdl
VOID	FreePacket(PVOID pPacket1);
VOID	FreePacket2(PVOID pPacket1);

typedef NDIS_STATUS (*PNdis_ethFilterDprIndicateReceivePacket)(PNDIS_MINIPORT_BLOCK pMiniblock, PPNDIS_PACKET packets_arrays, ULONG num_of_packets);
typedef NDIS_STATUS (*PNdis_WSendPacketsHandler)(PVOID MiniportAdapterContext, PPNDIS_PACKET packets_arrays, ULONG num_of_packets);


//////////////////////////////////////////////////////////////////////////


//ndis info
typedef struct _myNDIS51_MINIPORT_CHARACTERISTICS
{
    NDIS50_MINIPORT_CHARACTERISTICS Ndis50Chars;

    //
    // Extensions for NDIS 5.1
    //
	//     W_CANCEL_SEND_PACKETS_HANDLER   CancelSendPacketsHandler;
	//     W_PNP_EVENT_NOTIFY_HANDLER      PnPEventNotifyHandler;
//     W_MINIPORT_SHUTDOWN_HANDLER     AdapterShutdownHandler;
    PVOID   CancelSendPacketsHandler;
    PVOID      PnPEventNotifyHandler;
    PVOID     AdapterShutdownHandler;
    PVOID                           Reserved1;
    PVOID                           Reserved2;
    PVOID                           Reserved3;
    PVOID                           Reserved4;
} myNDIS51_MINIPORT_CHARACTERISTICS;


// struct _NDIS_M_DRIVER_BLOCK
// {
// 	UCHAR	padd[0x20];
// 	_NDIS51_MINIPORT_CHARACTERISTICS MiniportCharacteristics;
// 
// };




typedef struct struct_NDIS_M_DRIVER_BLOCK_2k3_early
{
    struct struct_NDIS_M_DRIVER_BLOCK_2k3_early * NextDriver;
    NDIS_MINIPORT_BLOCK* miniportblock;
    DWORD NdisDriverInfo; 
    DWORD AssociatedProtocol ;
    DWORD DeviceList[2] ;      
    DWORD PendingDeviceList ;
    DWORD UnloadHandler ; 
	//这下面还有很多，不过我只需要使用第一个字段来遍历，所以不需要全部定义出来
}_NDIS_M_DRIVER_BLOCK_2k3_early, *P_NDIS_M_DRIVER_BLOCK_2k3_early;




#endif