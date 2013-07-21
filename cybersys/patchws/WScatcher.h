#ifndef __wscatcher__
#define __wscatcher__


#include <ndis.h>

typedef	struct __WSPacketList__ 
{
	LIST_ENTRY	Next;
	union
	{
		PUCHAR		pBuffer;
		PNDIS_PACKET	pPacket;
	};

	BOOLEAN		bIsBuffer;
}WSPacketList, *PWSPacketList;


VOID	WSCatcherPacketCallback(PVOID pb);

VOID	WSWorkThread(PDEVICE_OBJECT  DeviceObject, PVOID	pContext);




#endif