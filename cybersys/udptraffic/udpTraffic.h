#ifndef __udpTraffic__
#define __udpTraffic__

#include <wdm.h>




#define MAX_PACKET_POOL_SIZE 0x0000FFFF
#define MIN_PACKET_POOL_SIZE 0x000000FF
#define	RESERVERUDPPORT	(55555)


#define SetPacketSign(p1,f1) (   ((NDIS_PACKET*)(p1))->Reserved[0]=(f1)     )
PVOID	MakePacketByMem(PVOID pBuffer,int len);
NTSTATUS	MiniportSendUdp(PVOID pSendInfo, ULONG uLen);

BOOLEAN	AllocatePacketPools();
VOID	MPFreeAllPacketPools();



PMDL
NdisAllocateMdl(
				__in  NDIS_HANDLE             NdisHandle,
				__in_bcount(Length)
				PVOID                   VirtualAddress,
				__in  UINT                    Length
				);



VOID	UdpRecvCallback(PVOID packet);
PVOID	MakeUdpBuffer(PVOID pSendInfo, PULONG pUdpPacket, PULONG uReserve);

VOID	TerminateUdpWorkItemThread();

VOID	UdpWorkItemThread(PVOID par);
//////////////////////////////////////////////////////////////////////////



#endif