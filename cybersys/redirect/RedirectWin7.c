
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



//////////////////////////////////////////////////////////////////////////

void	RedirectSendWin7(NET_BUFFER_KK *pNet_buffer)
{

	PUCHAR 			 pbuffer;
	PUCHAR			 pip;
	ULONG            ulbytes_copied,uNetbuffertLen, utmp;
	Dlc_Header *pdlc_header; //以太头指针
	Ip_Header  *pip_header;  //IP头指针

	PNET_BUFFER_LIST_KK pnbl;
	CURRENT_REDIRECT_INFO	tmpCRI;
	LIST_ENTRY	*pNextEntry=NULL;
	PREDIRECT_INFO	pRI=NULL;
	REDIRECT_INFO	tmpRI;
	Tcp_Header *ptcp_header=NULL; //TCP头指针

	pdlc_header	=	NULL;
	pip_header	=	NULL;
	pbuffer		=	NULL;

	RtlZeroMemory(&tmpCRI, sizeof(tmpCRI));
	RtlZeroMemory(&tmpRI, sizeof(tmpRI));

	uNetbuffertLen	=	NET_BUFFER_DATA_LENGTH(pNet_buffer);
	//should confirm the packet contain the ip data.
	if(uNetbuffertLen<(sizeof(Dlc_Header)+sizeof(Ip_Header)))
	{
		DbgPrint("net buffer too small ,has no ip data\r\n");
		return ;
	}

	pbuffer = (PUCHAR)kmalloc(uNetbuffertLen);
	if(pbuffer==NULL)
	{
		DbgPrint("ExAllocatePoolWithTag for netbuffer memory fail \r\n");
		return;
	}
	NdisZeroMemory(pbuffer,uNetbuffertLen);//清空

	utmp	=	uNetbuffertLen;
	CopyBytesFromNetBuffer(pNet_buffer, &utmp, pbuffer);
	if (utmp!=uNetbuffertLen)
	{
		kprintf("[send] funny thing happens total len=%d, copied len %s\r\n", uNetbuffertLen, utmp);
	}
	pdlc_header	=	(Dlc_Header*)pbuffer;
	//判断ethertype,如果不是IP包则不予处理,,PPPOE的话这里要特别处理
	if(ntohs(pdlc_header->ethertype)!=ETHPROTO_IP) 
	{	
		kprintf("[send] not ip packet\r\n");
		if(pbuffer)
		{
			kfree(pbuffer);pbuffer=NULL;
			return ;
		}
	}

	pip_header=(Ip_Header  *)(pbuffer+14);
	pip	=	(PUCHAR)&pip_header->destIP;

	STARTLOCK(&g_RedirectInfoLock2,KKRWLOCK_FOR_READ);

	pNextEntry	=	g_RedirectInfo.Next.Flink;
	while (pNextEntry && (pNextEntry!=&g_RedirectInfo.Next))
	{
		if (g_ChangingRedirectInfo)
		{
			break;
		}
		pRI	=	CONTAINING_RECORD(pNextEntry, REDIRECT_INFO, Next);
		if (!pRI->bBusy)
		{
			pNextEntry	=	pNextEntry->Flink;;
			continue;
		}

		if (pRI->from==pip_header->destIP)//检测IP是不是要重定向的
		{
			tmpCRI.from	=	pRI->from;
			tmpCRI.to	=	pRI->to;
			tmpCRI.fake1	=	pRI->fake1;
			tmpCRI.fake2	=	pRI->fake2;
			break;
		}
		pNextEntry	=	pNextEntry->Flink;


	}
	ENDLOCK(&g_RedirectInfoLock2);

	if (tmpCRI.from==0)
	{
		//没找着
		if(pbuffer)
		{
			kfree(pbuffer);pbuffer=NULL;
		}
		return ;
	}


	kprintf("[send*]len =%d, we capture the packet with ip=%ld.%ld.%ld.%ld.\r\n",uNetbuffertLen,pip[0],pip[1], pip[2],pip[3]);
	*(ULONG*)&pip_header->destIP	=	tmpCRI.to;

	PacketCheckSum(pbuffer);	// re-checksum;
	copy_buffer_to_netbuffer(pNet_buffer, pbuffer,uNetbuffertLen);

	if(pbuffer)
	{
		kfree(pbuffer);pbuffer=NULL;
	}


}
//////////////////////////////////////////////////////////////////////////


void	RedirectRecvWin7(NET_BUFFER_KK *pNet_buffer)
{
	PUCHAR 			 pbuffer;
	PUCHAR			 pip;
	ULONG            ulbytes_copied,uNetbuffertLen, utmp;
	Dlc_Header *pdlc_header; //以太头指针
	Ip_Header  *pip_header;  //IP头指针
	CURRENT_REDIRECT_INFO	tmpCRI;
	LIST_ENTRY	*pNextEntry=NULL;
	PREDIRECT_INFO	pRI=NULL;
	REDIRECT_INFO	tmpRI;


	pdlc_header	=	NULL;
	pip_header	=	NULL;
	pbuffer		=	NULL;
	RtlZeroMemory(&tmpCRI, sizeof(tmpCRI));
	RtlZeroMemory(&tmpRI, sizeof(tmpRI));

	uNetbuffertLen	=	NET_BUFFER_DATA_LENGTH(pNet_buffer);
	//should confirm the packet contain the ip data.
	if(uNetbuffertLen<(sizeof(Dlc_Header)+sizeof(Ip_Header)))
	{
		kprintf("net buffer too small ,has no ip data\r\n");
		return ;
	}

	pbuffer = (PUCHAR)kmalloc(uNetbuffertLen);
	if(pbuffer==NULL)
	{
		kprintf("ExAllocatePoolWithTag for netbuffer memory fail \r\n");
		return;
	}
	NdisZeroMemory(pbuffer,uNetbuffertLen);//清空

	utmp	=	uNetbuffertLen;
	CopyBytesFromNetBuffer(pNet_buffer, &utmp, pbuffer);
	if (utmp!=uNetbuffertLen)
	{
		kprintf("[recv] funny thing happens total len=%d, copied len %s\r\n", uNetbuffertLen, utmp);
	}
	pdlc_header	=	(Dlc_Header*)pbuffer;
	//判断ethertype,如果不是IP包则不予处理,,PPPOE的话这里要特别处理
	//检测是否以太包
	if(ntohs(pdlc_header->ethertype)!=ETHPROTO_IP)
	{
// 		if ((ntohs(pdlc_header->ethertype)==0x8863)||
// 			(ntohs(pdlc_header->ethertype)==0x8864)
// 			)
// 		{
// 
// 			kprintf(" IN ethernet type is pppoe\r\n");
// 		}
// 		else if (ntohs(pdlc_header->ethertype)==0x0806)
// 		{
// 
// 			kprintf(" IN ethernet type is arp\r\n");
// 
// 		}
// 		else
// 		{
// 			KdPrint(("unknown ethernet type 0x%04X\n", ntohs(pdlc_header->ethertype)));
// 		}
		if(pbuffer)
		{
			kfree(pbuffer);pbuffer=NULL;
		}
		return ;

	}

	pip_header=(Ip_Header  *)(pbuffer+14);
	pip	=	(PUCHAR)&pip_header->sourceIP;


	STARTLOCK(&g_RedirectInfoLock2,KKRWLOCK_FOR_READ);

	pNextEntry	=	g_RedirectInfo.Next.Flink;
	while (pNextEntry && (pNextEntry!=&g_RedirectInfo.Next))
	{
		if (g_ChangingRedirectInfo)
		{
			break;
		}
		pRI	=	CONTAINING_RECORD(pNextEntry, REDIRECT_INFO, Next);
		if (!pRI->bBusy)
		{
			pNextEntry	=	pNextEntry->Flink;;
			continue;
		}

		if (pRI->to==pip_header->sourceIP)//检测IP是不是要重定向的
		{
			tmpCRI.from	=	pRI->from;
			tmpCRI.to	=	pRI->to;
			tmpCRI.fake1	=	pRI->fake1;
			tmpCRI.fake2	=	pRI->fake2;
			break;
		}
		pNextEntry	=	pNextEntry->Flink;

	}
	ENDLOCK(&g_RedirectInfoLock2);

	if (tmpCRI.from==0)
	{
		//没找着
		if(pbuffer)
		{
			kfree(pbuffer);pbuffer=NULL;
		}
		return ;
	}
	*(ULONG*)&pip_header->sourceIP	=	tmpCRI.from;
	PacketCheckSum(pbuffer);	// re-checksum;
	copy_buffer_to_netbuffer(pNet_buffer, pbuffer,uNetbuffertLen);
	kprintf("packet recv Size= 0x%x(%d),Gurrent irql %x  Src: %d.%d.%d.%d\r\n",uNetbuffertLen, uNetbuffertLen, KeGetCurrentIrql(), pip[0],pip[1], pip[2],pip[3]);

	if(pbuffer)
	{
		kfree(pbuffer);pbuffer=NULL;
	}

}

//////////////////////////////////////////////////////////////////////////

VOID RedirectNetBufferSendCallbackWin7(PNET_BUFFER_LIST_KK pNetBufferLists, DWORD	dwNumber)
{

	ULONG             NumNbls=0;
	PNET_BUFFER_LIST_KK  Nbl;
	PNET_BUFFER_LIST_KK  NextNbl = NULL;
	PNET_BUFFER_KK NetBuffer;


	if (IsListEmpty(&g_RedirectInfo.Next))
	{
		//为空的话没必要查看里面的数据了
		return;
	}
	//loop over the nbls
	for ( Nbl = pNetBufferLists; Nbl!= NULL; Nbl = NextNbl, ++NumNbls)
	{
		//loop over nbs
		for ( NetBuffer = NET_BUFFER_LIST_FIRST_NB(Nbl); NetBuffer != NULL; NetBuffer = NET_BUFFER_NEXT_NB(NetBuffer))
		{
			RedirectSendWin7(NetBuffer);
		}
		NextNbl = NET_BUFFER_LIST_NEXT_NBL(Nbl);

	}
	return ;
}

//////////////////////////////////////////////////////////////////////////


VOID RedirectNetBufferRecvCallbackWin7(PNET_BUFFER_LIST_KK pNetBufferLists, DWORD	dwNumber)
{
	ULONG             NumNbls=0;
	PNET_BUFFER_LIST_KK  Nbl;
	PNET_BUFFER_LIST_KK  NextNbl = NULL;
	PNET_BUFFER_KK NetBuffer;


	if (IsListEmpty(&g_RedirectInfo.Next))
	{
		//为空的话没必要查看里面的数据了
		return;
	}
	//loop over the nbls
	for ( Nbl = pNetBufferLists; Nbl!= NULL; Nbl = NextNbl, ++NumNbls)
	{
		//loop over nbs
		for ( NetBuffer = NET_BUFFER_LIST_FIRST_NB(Nbl); NetBuffer != NULL; NetBuffer = NET_BUFFER_NEXT_NB(NetBuffer))
		{
			RedirectRecvWin7(NetBuffer);
		}

		NextNbl = NET_BUFFER_LIST_NEXT_NBL(Nbl);

	}
	return ;
}