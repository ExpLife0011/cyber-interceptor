
/********************************************************************

	filename: 	e:\dev\CyberInterceptor\sys\udptraffic\udpTraffic.c
	file path:	e:\dev\CyberInterceptor\sys\udptraffic
	file base:	udpTraffic
	file ext:	c
	author:		kindof
	
	purpose:	
*********************************************************************/
#include "precomp.h"
#include "..\all_header.h"


////////////////////////////////////////////////////////////////////////////////
//����ȫ�ֱ���
ULONG	g_u2k_sendoffset	=	0x38;
// PNdis_ethFilterDprIndicateReceivePacket	Ori_ethFilterDprIndicateReceivePacket;
// PNdis_WSendPacketsHandler				ori_WSendPacketsHandler;




////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////
//
//�Զ������ݰ��������������ݣ�Complete�ص�Ӧ�ò������
NDIS_STATUS my_WSendPacketsHandlerComplete(PVOID ProtocolBindingContext, PNDIS_PACKET pPacket, NDIS_STATUS Status)
{

	//��ʹ��static�ˣ�����ж���ټ��صĻ������²�����
	/*static*/ PVOID pOldHandler =NULL;
	ULONG	uRet =0;
	PMDL	pmdl=NULL;

//	kprintf("notice================== ,here im\n");
	if (pPacket&&(pPacket->Reserved[0]==MYPACKETFLAG))
	{
		
		kprintf("Enter my_WSendPacketsHandlerComplete()==============,and Free Mypacket %x\n", pPacket);
		//free the packet from me
		//free the packet from me
		FreePacket(pPacket);
		return STATUS_SUCCESS;
	}

	if (pOldHandler==NULL)
	{

		pOldHandler	=	GetOldHandler(ProtocolBindingContext, my_WSendPacketsHandlerComplete);

	}
	if (pOldHandler==NULL)
	{
		kprintf("my_WSendPacketsHandlerComplete fail....oh god, crash me!!\n");
		DbgBreakPoint();
	}


	_asm
	{
			push Status
			push pPacket
			push ProtocolBindingContext
			call pOldHandler
			mov uRet,eax
	}
	return uRet;
}
//////////////////////////////////////////////////////////////////////////
//just free the first mdl
VOID	FreePacket(PVOID pPacket1)
{
	PMDL	pmdl=NULL;
	PNDIS_PACKET pPacket	=	(PNDIS_PACKET)pPacket1;
	PMDL	pmdl2=NULL;
	if (pPacket1==NULL)
	{
		return ;
	}
	NdisUnchainBufferAtFront(pPacket, &pmdl);
	while(pmdl)
	{
		UINT upMemBufferLen;
		PVOID pMemBuffer = NULL;

		NdisQueryBufferSafe(pmdl, 
			(PVOID *)&pMemBuffer, 
			&upMemBufferLen, 
			HighPagePriority );
		if (pMemBuffer)
		{
			kfree(pMemBuffer);
		}

		pmdl2	=	pmdl->Next;
		IoFreeMdl(pmdl);
		pmdl	=	pmdl2;
	}
	SetPacketSign(pPacket, '0000');	//���ԭ���ı�־
	NdisFreePacket(pPacket);
	return ;
}

//just free the first mdl
VOID	FreePacket2(PVOID pPacket1)
{
	PMDL	pmdl=NULL;
	PNDIS_PACKET pPacket	=	(PNDIS_PACKET)pPacket1;
	PMDL	pmdl2=NULL;
	if (pPacket1==NULL)
	{
		return ;
	}
	pmdl	=	pPacket->Private.Head;
	while(pmdl)
	{


		if (pmdl->MappedSystemVa==NULL)
		{
			break;
		}
		kprintf("%x\n", pmdl->MappedSystemVa);
		pmdl	=	pmdl->Next;
	}

//	NdisFreePacket(pPacket);
	return ;
}

//////////////////////////////////////////////////////////////////////////
NDIS_STATUS my_NdisSendComplete(PNDIS_MINIPORT_BLOCK pMiniblock, PNDIS_PACKET pPacket, ULONG Status)
{

	//��ʹ��static�ˣ�����ж���ټ��صĻ������²�����
	/*static*/ PVOID pOldHandler =NULL;
	ULONG	uRet =0;
	PMDL	pmdl=NULL;

	if (pPacket && (pPacket->Reserved[0]==MYPACKETFLAG))
	{
		//__asm int 3
		kprintf("Enter my_NdisSendComplete(),and Free Mypacket %x\n", pPacket);
		//free the packet from me
		FreePacket(pPacket);
		return STATUS_SUCCESS;
	}
	if (pOldHandler==NULL)
	{

		pOldHandler	=	GetOldHandler(pMiniblock, my_NdisSendComplete);

	}
	if (pOldHandler==NULL)
	{
		kprintf("my_WSendPacketsHandlerComplete fail....oh god, crash me!!\n");
		DbgBreakPoint();
	}

	_asm
	{
			push Status
			push pPacket
			push pMiniblock
			call pOldHandler
			mov uRet,eax
	}
	return uRet;

}
//////////////////////////////////////////////////////////////////////////
NDIS_STATUS my_WSendHandler(PVOID MiniportAdapterContext, PNDIS_PACKET pPacket, ULONG flag)
{
	ULONG	uRet =0;
	//��ʹ��static�ˣ�����ж���ټ��صĻ������²�����
	/*static*/ PVOID	pOldHandler	=	NULL;

	//���ûص�����
	PacketSendCallback(&pPacket, 1);
	if (pOldHandler==NULL)
	{

		pOldHandler	=	GetOldHandler(MiniportAdapterContext, my_WSendHandler);

	}

	if (pOldHandler==NULL)
	{
		kprintf("oh god, crash me!!\n");
		DbgBreakPoint();
	}
	//uRet	=	asmCallFun(pOldHandler, MiniportAdapterContext, packet_arrays, num_of_packets);
	_asm
	{
			push flag
			push pPacket
			push MiniportAdapterContext
			call pOldHandler
			mov uRet,eax
	}
	return uRet;


}
//////////////////////////////////////////////////////////////////////////


NDIS_STATUS my_WSendPacketsHandler(PVOID MiniportAdapterContext, PPNDIS_PACKET packet_arrays, ULONG num_of_packets)
{

	//��ʹ��static�ˣ�����ж���ټ��صĻ������²�����
	/*static*/ PVOID	pOldHandler	=	NULL;
	ULONG	uRet =0;
	if (num_of_packets==0)
	{

		kprintf("my_WSendPacketsHandler num_of_packets==0\r\n");
	
	}
	//���ûص�����
	PacketSendCallback(packet_arrays, num_of_packets);

	if (pOldHandler==NULL)
	{
		
		pOldHandler	=	GetOldHandler(MiniportAdapterContext, my_WSendPacketsHandler);

	}

	if (pOldHandler==NULL)
	{
		kprintf("oh god, crash me!!\n");
		DbgBreakPoint();
	}
	//uRet	=	asmCallFun(pOldHandler, MiniportAdapterContext, packet_arrays, num_of_packets);
	_asm
	{
			push num_of_packets
			push packet_arrays
			push MiniportAdapterContext
			call pOldHandler
			mov uRet,eax
	}
	return uRet;
	

}

//////////////////////////////////////////////////////////////////////////
NDIS_STATUS my_ethFilterDprIndicateReceivePacket(PNDIS_MINIPORT_BLOCK pMiniblock, PPNDIS_PACKET packet_arrays, ULONG num_of_packets)
{

	//��ʹ��static�ˣ�����ж���ټ��صĻ������²�����
	/*static*/	PVOID pOldHandler=NULL;
	ULONG	uRet =0;
	FilterType	BypassOrNot;
	if (num_of_packets==0)
	{
		kprintf(" my_ethFilterDprIndicateReceivePacket num_of_packets==0\r\n");
		
	}
	//���ûص�
	//Ҫ��drop packet_arrays��Щpacket,ʹ��miniportblock��Ӧ��ReturnPacketHandler��return
	//������ndis!ndisReturnpacket�⺯������Ϊ����һЩ�����������������ص����ﻹû���ú�
	//����ndis!ndisReturnpacket�Ļ��ͻ�ʧ��
	BypassOrNot = PacketRecvCallback(packet_arrays, num_of_packets, (ULONG)pMiniblock);
	if (BypassOrNot==Drop)
	{
		return STATUS_SUCCESS;
	}

	if (pOldHandler==NULL)
	{
		pOldHandler	=	GetOldHandler(pMiniblock, (PVOID)my_ethFilterDprIndicateReceivePacket);

	}
	if (pOldHandler==NULL)
	{
		kprintf("oh god, crash me!!\n");
		DbgBreakPoint();
	}
	_asm
	{
		push num_of_packets
		push packet_arrays
		push pMiniblock
		call pOldHandler
		mov uRet,eax
	}
	return uRet;
}
//////////////////////////////////////////////////////////////////////////

VOID	PacketSendCallback(PPNDIS_PACKET packet_arrays, ULONG num_of_packets)
{

	ULONG	idx;

	for (idx=0; idx<num_of_packets; idx++)
	{
		RedirectSendCallback(packet_arrays[idx]);
		WSCatcherPacketCallback(packet_arrays[idx]);

	}

}
//////////////////////////////////////////////////////////////////////////


FilterType	PacketRecvCallback(PPNDIS_PACKET packet_arrays, ULONG num_of_packets, ULONG uReserved)
{

	ULONG	idx;
	PNDIS_MINIPORT_BLOCK pMiniBlock=NULL;
	ULONG	pAdaptContext=0;
	ULONG	miniportReturnPacket=0;
	ULONG	utmp=0;
	pMiniBlock	=	(PNDIS_MINIPORT_BLOCK)uReserved;
	pAdaptContext	=	(ULONG)pMiniBlock->MiniportAdapterContext;
	miniportReturnPacket	=	0xf897b802;


	for (idx=0; idx<num_of_packets; idx++)
	{

// 		_asm
// 		{
// 			push utmp
// 			push pAdaptContext
// 			call miniportReturnPacket
// 		}
// 		continue;
		UdpRecvCallback(packet_arrays[idx]);
		RedirectRecvCallback(packet_arrays[idx]);
		WSCatcherPacketCallback(packet_arrays[idx]);

	}
	return Bypass;


}