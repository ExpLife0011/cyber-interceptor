
/********************************************************************
	filename: 	e:\dev\CyberInterceptor\sys\udptraffic\udpTraffic.c
	file path:	e:\dev\CyberInterceptor\sys\udptraffic
	file base:	udpTraffic
	file ext:	c
	author:		kindof
	
	purpose:	
*********************************************************************/

#pragma warning(disable:4995)
#pragma warning(disable:4996)
#include "precomp.h"
#include "..\all_header.h"
#include "stdlib.h"

//////////////////////////////////////////////////////////////////////////

REDIRECT_INFO	g_RedirectInfo;	//ֱ��������������ˣ����������IP��hash������
//KSPIN_LOCK		g_RedirectInfoLock;
NDIS_RW_LOCK	g_RedirectInfoLock2;
BOOLEAN			g_ChangingRedirectInfo	=	FALSE;

///////////////////////////////////////////////////////////////////////

//���ټ��
//����1����ʾ�ҵ���
//����2����ʾ��Ҫ�����鿴
//����0����ʾ����ֱ�ӷ����ˡ�

__inline ULONG	CheckSendPacketNeed(PNDIS_PACKET packet, PCURRENT_REDIRECT_INFO pCRI)
{
	NDIS_BUFFER *pmdl	=	NULL;
	Dlc_Header *pdlc_header; //��̫ͷָ��
	Ip_Header  *pip_header;  //IPͷָ��
	LIST_ENTRY	*pNextEntry=NULL;
	PREDIRECT_INFO	pRI=NULL;
	REDIRECT_INFO	tmpRI;
	ULONG		utmp=0;

	pmdl = packet->Private.Head;
	if (pmdl->ByteCount<sizeof(Dlc_Header))
	{
		return CHECKMORE;
	}

	pdlc_header	=	(Dlc_Header*)pmdl->MappedSystemVa;

	//����Ƿ���̫��
	if(ntohs(pdlc_header->ethertype)!=0x0800)
	{
		if ((ntohs(pdlc_header->ethertype)==0x8863)||
			(ntohs(pdlc_header->ethertype)==0x8864)
			)
		{

			kprintf(" IN ethernet type is pppoe\r\n");
		}
		else if (ntohs(pdlc_header->ethertype)==0x0806)
		{

			kprintf(" IN ethernet type is arp\r\n");

		}
		else
		{
			KdPrint(("unknown ethernet type 0x%04X\n", ntohs(pdlc_header->ethertype)));
		}
		return CHECKRETURN;

	}

	//�������PMDL�϶�����MACͷ
	if (pmdl->ByteCount==sizeof(Dlc_Header))
	{
		//��һ��MDL��
		pmdl	=	pmdl->Next;
		if (pmdl==NULL)
		{
			return CHECKRETURN;
		}
		if (pmdl->ByteCount>=sizeof(Ip_Header))
		{
			pip_header=(Ip_Header  *)(pmdl->MappedSystemVa);
			//pip	=	(PUCHAR)&pip_header->sourceIP;
		}
		else//else ���ܻ��е�3��MDL�����ˣ���������������
		{
			return CHECKMORE;
		}


	}
	else
	{
		//������packet������MACͷ��IP��Ҳ��
		if (pmdl->ByteCount>=sizeof(Dlc_Header)+ sizeof(Ip_Header))
		{

			pip_header=(Ip_Header  *)((char*)pmdl->MappedSystemVa+sizeof(Dlc_Header));
		}
		else
		{
			//�������MACͷ��һ��IPͷ�����
			return CHECKMORE;
		}
	}
	//�������ҵ���IPͷ
	//
	utmp=0;
	STARTLOCK(&g_RedirectInfoLock2,KKRWLOCK_FOR_READ);
	pNextEntry	=	g_RedirectInfo.Next.Flink;
	while (pNextEntry&&(pNextEntry!=&g_RedirectInfo.Next))
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
		RtlMoveMemory(&tmpRI, pRI, sizeof(REDIRECT_INFO));	//��ֹȡ��������鱻�ͷ���
		if (tmpRI.from==pip_header->destIP)//���IP�ǲ���Ҫ�ض����
		{
			pCRI->from	=	tmpRI.from;
			pCRI->to	=	tmpRI.to;
			pCRI->fake1	=	tmpRI.fake1;
			pCRI->fake2	=	tmpRI.fake2;
			utmp=1;
			break;


		}
		pNextEntry	=	pNextEntry->Flink;
		
	}
	ENDLOCK(&g_RedirectInfoLock2);
	if (utmp==1)
	{
		return CHECKNEED;
	}
	return CHECKRETURN;

}
//////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////

//���ټ��
//����1����ʾ�ҵ���
//����2����ʾ��Ҫ�����鿴
//����0����ʾ����ֱ�ӷ����ˡ�

__inline ULONG	CheckRecvPacketNeed(PNDIS_PACKET packet, PCURRENT_REDIRECT_INFO pCRI)
{
	NDIS_BUFFER *pmdl	=	NULL;
	Dlc_Header *pdlc_header; //��̫ͷָ��
	Ip_Header  *pip_header;  //IPͷָ��
	LIST_ENTRY	*pNextEntry=NULL;
	PREDIRECT_INFO	pRI=NULL;
	REDIRECT_INFO	tmpRI;
	ULONG		utmp=0;

	pmdl = packet->Private.Head;
	if (pmdl->ByteCount<sizeof(Dlc_Header))
	{
		return CHECKMORE;
	}

	pdlc_header	=	(Dlc_Header*)pmdl->MappedSystemVa;

	//����Ƿ���̫��
	if(ntohs(pdlc_header->ethertype)!=ETHPROTO_IP)
	{
		if ((ntohs(pdlc_header->ethertype)==0x8863)||
			(ntohs(pdlc_header->ethertype)==0x8864)
			)
		{

			kprintf(" IN ethernet type is pppoe\r\n");
		}
		else if (ntohs(pdlc_header->ethertype)==0x0806)
		{

			kprintf(" IN ethernet type is arp\r\n");

		}
		else
		{
			KdPrint(("unknown ethernet type 0x%04X\n", ntohs(pdlc_header->ethertype)));
		}
		return CHECKRETURN;

	}

	//�������PMDL�϶�����MACͷ
	if (pmdl->ByteCount==sizeof(Dlc_Header))
	{
		//��һ��MDL��
		pmdl	=	pmdl->Next;
		if (pmdl==NULL)
		{
			return CHECKRETURN;
		}
		if (pmdl->ByteCount>=sizeof(Ip_Header))
		{
			pip_header=(Ip_Header  *)(pmdl->MappedSystemVa);
			//pip	=	(PUCHAR)&pip_header->sourceIP;
		}
		else//else ���ܻ��е�3��MDL�����ˣ���������������
		{
			return CHECKMORE;
		}


	}
	else
	{
		//������packet������MACͷ��IP��Ҳ��
		if (pmdl->ByteCount>=sizeof(Dlc_Header)+ sizeof(Ip_Header))
		{
		
			pip_header=(Ip_Header  *)((char*)pmdl->MappedSystemVa+sizeof(Dlc_Header));
		}
		else
		{
			//�������MACͷ��һ��IPͷ�����
			return CHECKMORE;
		}
	}
	//�������ҵ���IPͷ
	utmp=0;
	STARTLOCK(&g_RedirectInfoLock2,KKRWLOCK_FOR_READ);
	pNextEntry	=	g_RedirectInfo.Next.Flink;
	while (pNextEntry &&(pNextEntry!=&g_RedirectInfo.Next))
	{


		pRI	=	CONTAINING_RECORD(pNextEntry, REDIRECT_INFO, Next);
		if (!pRI->bBusy)
		{
			pNextEntry	=	pNextEntry->Flink;;
			continue;
		}
		RtlMoveMemory(&tmpRI, pRI, sizeof(REDIRECT_INFO));	//��ֹȡ��������鱻�ͷ���
		if (tmpRI.to==pip_header->sourceIP)//���IP�ǲ���Ҫ�ض����
		{
			pCRI->from	=	tmpRI.from;
			pCRI->to	=	tmpRI.to;
			pCRI->fake1	=	tmpRI.fake1;
			pCRI->fake2	=	tmpRI.fake2;
			utmp=1;
			break;

		}
		pNextEntry	=	pNextEntry->Flink;
		
	}
	ENDLOCK(&g_RedirectInfoLock2);
	if (utmp==1)
	{
		return CHECKNEED;
	}
	return CHECKRETURN;

}
//////////////////////////////////////////////////////////////////////////

void UpdateRecvPacket(PNDIS_PACKET pPacket)
{
	PUCHAR 			 pbuffer;
	PUCHAR			 pip;
    ULONG            ulbytes_copied,ulTotPktLen;
	Dlc_Header *pdlc_header; //��̫ͷָ��
	Ip_Header  *pip_header;  //IPͷָ��
	ULONG		checkRet =CHECKRETURN;
	CURRENT_REDIRECT_INFO	tmpCRI;
	LIST_ENTRY	*pNextEntry=NULL;
	PREDIRECT_INFO	pRI=NULL;
	REDIRECT_INFO	tmpRI;

	
	pdlc_header	=	NULL;
	pip_header	=	NULL;
	pbuffer		=	NULL;

	if (g_RedirectInfo.number==0)
	{
		return ;
	}

	NdisQueryPacketLength(pPacket, (PUINT)&ulTotPktLen);	//retrive the length of packet
	//should confirm the packet contain the ip data.
	if(ulTotPktLen<(sizeof(Dlc_Header)+sizeof(Ip_Header)))
	{
		DbgPrint("packet too small ,has no ip data\r\n");
		return ;
	}
	RtlZeroMemory(&tmpCRI, sizeof(tmpCRI));

	checkRet	=	CheckRecvPacketNeed(pPacket, &tmpCRI);
	if (CHECKRETURN == checkRet)
	{
		//�Ѿ�ȷ������Ҫ�ҵ�
		return ;
	}

	pbuffer = (PUCHAR)kmalloc(ulTotPktLen);
	if(pbuffer==NULL)
	{
		DbgPrint("ExAllocatePoolWithTag for packet memory fail \r\n");
		return;
	}
	NdisZeroMemory(pbuffer,ulTotPktLen);//���	
	GetPktPayload(pPacket, pbuffer, ulTotPktLen, &ulbytes_copied);
	pdlc_header	=	(Dlc_Header*)pbuffer;
	//�ж�ethertype,�������IP�����账��,,PPPOE�Ļ�����Ҫ�ر���
	if(ntohs(pdlc_header->ethertype)!=ETHPROTO_IP)
	{
		kfree(pbuffer);pbuffer=NULL;
		return;
		
	}
	pip_header=(Ip_Header  *)(pbuffer+14);
	pip	=	(PUCHAR)&pip_header->sourceIP;

	if (checkRet==CHECKNEED)
	{
	}
	else
	{
		//����ļ��
		kprintf("Recv Need more Check\n");

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
			//RtlMoveMemory(&tmpRI, pRI);	//��ֹȡ��������鱻�ͷ���,��Ȼ����һ����Σ��
			if (pRI->to==pip_header->sourceIP)//���IP�ǲ���Ҫ�ض����
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
	}

	if (tmpCRI.from==0)
	{
		//û����
		if(pbuffer)
		{
			kfree(pbuffer);pbuffer=NULL;
		}
		return ;
	}
	*(ULONG*)&pip_header->sourceIP	=	tmpCRI.from;
	PacketCheckSum(pbuffer);	// re-checksum;
	copy_buffer_to_packet(pPacket, pbuffer,ulTotPktLen);
	kprintf("packet recv Size= 0x%x(%d),Gurrent irql %x  Src: %d.%d.%d.%d\r\n",ulTotPktLen, ulTotPktLen, KeGetCurrentIrql(), pip[0],pip[1], pip[2],pip[3]);

	if(pbuffer)
	{
		kfree(pbuffer);pbuffer=NULL;
	}
		
}
////////////////////////////////////////////////////////////////
BOOLEAN RedirectSendPacket(PNDIS_PACKET pPacket, ULONG FROM_IP, ULONG TO_IP)
{
    
	PUCHAR 			 pbuffer;
	PUCHAR			 pip;
    ULONG            ulbytes_copied,ulTotPktLen;
	Dlc_Header *pdlc_header; //��̫ͷָ��
	Ip_Header  *pip_header;  //IPͷָ��
	ULONG		checkRet =CHECKRETURN;
	CURRENT_REDIRECT_INFO	tmpCRI;
	LIST_ENTRY	*pNextEntry=NULL;
	PREDIRECT_INFO	pRI=NULL;
	REDIRECT_INFO	tmpRI;
	BOOLEAN			bRet	=	FALSE;
	
	pdlc_header	=	NULL;
	pip_header	=	NULL;
	pbuffer		=	NULL;

	if (g_RedirectInfo.number==0)
	{
		return bRet;
	}
	NdisQueryPacketLength(pPacket, (PUINT)&ulTotPktLen);	//retrive the length of packet
	//should confirm the packet contain the ip data.
	if(ulTotPktLen<(sizeof(Dlc_Header)+sizeof(Ip_Header)))
	{
		DbgPrint("packet too small ,has no ip data\r\n");
		return bRet;
	}

	RtlZeroMemory(&tmpCRI, sizeof(tmpCRI));

	checkRet	=	CheckSendPacketNeed(pPacket, &tmpCRI);
	if (CHECKRETURN == checkRet)
	{
		return bRet;
	}


	pbuffer = (PUCHAR)kmalloc(ulTotPktLen);
	if(pbuffer==NULL)
	{
		DbgPrint("ExAllocatePoolWithTag for packet memory fail \r\n");
		return bRet;
	}
	NdisZeroMemory(pbuffer,ulTotPktLen);//���	
	GetPktPayload(pPacket, pbuffer, ulTotPktLen, &ulbytes_copied);
	pdlc_header	=	(Dlc_Header*)pbuffer;

	//�ж�ethertype,�������IP�����账��,,PPPOE�Ļ�����Ҫ�ر���

	if(ntohs(pdlc_header->ethertype)!=0x0800)
	{
		kfree(pbuffer);pbuffer=NULL;
		return bRet;
		
	}
	pip_header=(Ip_Header  *)(pbuffer+14);
	pip	=	(PUCHAR)&pip_header->destIP;

	if (CHECKNEED	==	checkRet)
	{
		//ȷ���ҵ���

	}
	else	//˵����checkmore���
	{
		kprintf("Send Need more Check\n");
		STARTLOCK(&g_RedirectInfoLock2,KKRWLOCK_FOR_READ);

		pNextEntry	=	g_RedirectInfo.Next.Flink;
		while (pNextEntry&&(pNextEntry!=&g_RedirectInfo.Next))
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
			//RtlMoveMemory(&tmpRI, pRI);	//��ֹȡ��������鱻�ͷ���,��Ȼ����һ����Σ��
			if (pRI->from==pip_header->destIP)//���IP�ǲ���Ҫ�ض����
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
	}
	if (tmpCRI.from==0)
	{
		//���ض���
		kfree(pbuffer);pbuffer=NULL;
		return bRet;
	}
	bRet	=	TRUE;
	//
	*(ULONG*)&pip_header->destIP	=	tmpCRI.to;
	PacketCheckSum(pbuffer);	// re-checksum;
	copy_buffer_to_packet(pPacket, pbuffer,ulTotPktLen);
	
	kprintf("packet SEND  Size= 0x%x(%d),Gurrent irql %x  Destination: %d.%d.%d.%d\r\n",ulTotPktLen, ulTotPktLen, KeGetCurrentIrql(), pip[0],pip[1], pip[2],pip[3]);
	if(pbuffer)
	{
		kfree(pbuffer);pbuffer=NULL;
	}
	return bRet;
}

/////////////////////////////////////////////////////////////////////////
void 	copy_buffer_to_packet(PNDIS_PACKET pPacket, PUCHAR pBuffer, ULONG	len_pBuffer)
{
	ULONG	packet_size;
	ULONG	ndis_buffer_size;
	PNDIS_BUFFER	pndis_buffer;
	PUCHAR	pCurrBfr;
	
	
	ndis_buffer_size=packet_size	=	0;
	pCurrBfr	=	NULL;
	
	NdisQueryPacketLength(pPacket,(PUINT)&packet_size);
	if(len_pBuffer>packet_size)
	{
		DbgPrint(" copy_buffer_to_packet fail.(len_pbuffer >packet_size)\r\n");
		return ;
	}
	NdisQueryPacket(pPacket,                            // Get information from packet descriptor.
		NULL,                      
		NULL,
		&pndis_buffer,                          // Output variable for address of first buffer descriptor.
		NULL                        // Output variable for number of bytes in packet payload.
		);
	NdisQueryBuffer(pndis_buffer,&pCurrBfr,&ndis_buffer_size);
	while(pCurrBfr)
	{
		NdisMoveMemory(pCurrBfr, pBuffer, ndis_buffer_size);
		pBuffer	=	pBuffer+ndis_buffer_size;
		
		NdisGetNextBuffer(pndis_buffer,&pndis_buffer);
		if(NULL==pndis_buffer)
		{
			break;
		}
		NdisQueryBuffer(pndis_buffer,                           // Get information from first buffer descriptor.
		&pCurrBfr,                          // Output variable for address of described virtual area.
		&ndis_buffer_size                          // Output variable for size of virtual area.
		);
	//	DbgPrint(" copy data in while loop\r\n");
	}
}
//////////////////////////////////////////////////////////////////////////
//����У���
USHORT checksum(USHORT *buffer,int size)
{
	unsigned long cksum=0;
	while(size>1)
	{
	  cksum+=*buffer++;
	  size-=sizeof(USHORT);
	}
	if(size)
	{
	  cksum+=*(UCHAR *)buffer;
	}
	//��32λ��ת����16
	while (cksum>>16)
	  cksum=(cksum>>16)+(cksum & 0xffff);
	return (USHORT) (~cksum);
}


//-------------------------------------------------------------------------
// PacketCheckSum
// �������ݰ���У���
// ����:packet-����������(����װ�õ����ݰ���ָ��)
//֧��ICMP��TCP��UDP
//-------------------------------------------------------------------------
void PacketCheckSum(unsigned char packet[])
{
	PUCHAR		ptmp=NULL;
	Dlc_Header *pdlc_header=NULL; //��̫ͷָ��
	Ip_Header  *pip_header=NULL;  //IPͷָ��
	unsigned short attachsize=0; //�����Э��ͷ�Լ��������ݵ��ܳ���
	pdlc_header=(Dlc_Header *)packet;
	//�ж�ethertype,�������IP�����账��
	if(ntohs(pdlc_header->ethertype)!=0x0800) return;
	pip_header=(Ip_Header  *)(packet+14);
	//icmp��
	if(0x01==pip_header->proto)
	{
		Icmp_Header	*icmp_hdr	=	NULL;
		pip_header->checksum	=	0;
		pip_header->checksum	=	checksum((unsigned short *)pip_header,20);
	//	icmp_hdr				=	(Icmp_Header	*)((unsigned short *)pip_header+20);
	//	icmp_hdr->i_cksum		=	checksum((unsigned short *)icmp_hdr,sizeof(Icmp_Header));	//����Ӳ�����ˣ�
	}
	//TCP��
	if(0x06==pip_header->proto)
	{
	  
	  Tcp_Header *ptcp_header=NULL; //TCPͷָ��
	  Tcp_Psd_Header *ptcp_psd_header=NULL;
	  
	  ptcp_header=(Tcp_Header *)(packet+14+((pip_header->ver_len)&15)*4);
	  attachsize=ntohs(pip_header->total_len)-((pip_header->ver_len)&15)*4;
	  ptcp_psd_header=(Tcp_Psd_Header *)kmalloc(attachsize+sizeof(Tcp_Psd_Header));
	  if(!ptcp_psd_header) return;
	  
	  ptmp		=	(PUCHAR)ptcp_psd_header;
	  memset(ptcp_psd_header,0,attachsize+sizeof(Tcp_Psd_Header));
	  //���αTCPͷ
	  ptcp_psd_header->destip=pip_header->destIP;
	  ptcp_psd_header->sourceip=pip_header->sourceIP;
	  ptcp_psd_header->mbz=0;
	  ptcp_psd_header->ptcl=0x06;
	  ptcp_psd_header->tcpl=htons(attachsize);
	  //����TCPУ���
	  ptcp_header->chksum=0;
	  memcpy((unsigned char *)ptcp_psd_header+sizeof(Tcp_Psd_Header),
	   (unsigned char *)ptcp_header,attachsize);
	  ptcp_header->chksum=checksum((unsigned short *)ptcp_psd_header,
	   attachsize+sizeof(Tcp_Psd_Header));
	  
	  //����ipͷ��У���
	  pip_header->checksum=0;
	  pip_header->checksum=checksum((unsigned short *)pip_header,20);
	  kfree(ptmp);
	  return;
	}

	//UDP��
	if(0x11==pip_header->proto)
	{
	  Udp_Header *pudp_header=NULL; //UDPͷָ��
	  Udp_Psd_Header *pudp_psd_header=NULL;
	  pudp_header=(Udp_Header *)(packet+14+((pip_header->ver_len)&15)*4);
	  attachsize=ntohs(pip_header->total_len)-((pip_header->ver_len)&15)*4;
	  pudp_psd_header=(Udp_Psd_Header *)kmalloc(attachsize+sizeof(Udp_Psd_Header));
	  if(!pudp_psd_header) return;
			memset(pudp_psd_header,0,attachsize+sizeof(Udp_Psd_Header));
			ptmp		=	(PUCHAR)pudp_psd_header;
	  //���αUDPͷ
	  pudp_psd_header->destip=pip_header->destIP;
	  pudp_psd_header->sourceip=pip_header->sourceIP;
	  pudp_psd_header->mbz=0;
	  pudp_psd_header->ptcl=0x11;
	  pudp_psd_header->udpl=htons(attachsize);
	  
	  //����UDPУ���
	  pudp_header->chksum=0;
	  memcpy((unsigned char *)pudp_psd_header+sizeof(Udp_Psd_Header),
	   (unsigned char *)pudp_header,attachsize);
	  pudp_header->chksum=checksum((unsigned short *)pudp_psd_header,
	   attachsize+sizeof(Udp_Psd_Header));
	    
	  //����ipͷ��У���
	  pip_header->checksum=0;
	  pip_header->checksum=checksum((unsigned short *)pip_header,20);  
	  kfree(ptmp);
	  return;
	}
	return;
}
//////////////////////////////////////////////////////////////////
int
GetPktPayload(
			  PNDIS_PACKET      pPacket,                // Address of packet descriptor.
			  PUCHAR            pOutBfr,                // Address of output buffer, to get copied packet payload.
			  ULONG             ulOutBfrAvail,          // Size of output buffer.
			  PULONG            pUlBytesCopied          // Output variable for number of bytes copied.
              )
{

    PNDIS_BUFFER     pNdisBfr;
    ULONG            ulBfrCnt,
		ulTotPktLen,
		ulCurrBfr,
		ulAmtToMove;
    PUCHAR           pCurrBfr;
    *pUlBytesCopied = 0;                                // Set 0 bytes copied.
	
    if (0==ulOutBfrAvail)                               // Is output buffer 0 bytes in length?
		goto Done;

    NdisQueryPacket(pPacket,                            // Get information from packet descriptor.
		NULL,                      
		NULL,
		&pNdisBfr,                          // Output variable for address of first buffer descriptor.
		&ulTotPktLen                        // Output variable for number of bytes in packet payload.
		);
	
    NdisQueryBuffer(pNdisBfr,                           // Get information from first buffer descriptor.
		&pCurrBfr,                          // Output variable for address of described virtual area.
		&ulCurrBfr                          // Output variable for size of virtual area.
		);
	
    while (ulOutBfrAvail>0)                             // Space remaining in output buffer?
	{
		while (0==ulCurrBfr)                             // While the current buffer has zero length.
		{
			NdisGetNextBuffer(pNdisBfr,                   // Get next buffer descriptor.
				&pNdisBfr
				);
			
			if (NULL==pNdisBfr)                           // None?
				goto Done;
			
			NdisQueryBuffer(pNdisBfr,                     // Get information from next buffer descriptor.
				&pCurrBfr,                    // Output variable for address of current buffer.
				&ulCurrBfr                    // Output variable for size of current buffer.
				);
		}
		
		if (ulCurrBfr>ulOutBfrAvail)                     // Does current buffer's usable size exceed space remaining in output buffer?
			ulAmtToMove = ulOutBfrAvail;                   // Use only amount remaining in output buffer.
		else
			ulAmtToMove = ulCurrBfr;                       // Use full size of current buffer.
		
		NdisMoveMemory(pOutBfr,                          // Copy packet data to output buffer.
			pCurrBfr,
			ulAmtToMove
			);
		
		*pUlBytesCopied += ulAmtToMove;                  // Update output variable of bytes copied.
		pOutBfr += ulAmtToMove;                          // Update pointer to output buffer.
		ulOutBfrAvail -= ulAmtToMove;                    // Update number of bytes available in output buffer.
		
		ulCurrBfr = 0;                                   // Force search for next buffer.
	}                                                 // End 'while' copy bytes to output buffer.
	
Done:
	return 1;
}

////////////////////////////////////////////////////////////////////////////////

unsigned short htons(unsigned short a)
{
	unsigned short b = a;
	b = ( b << 8 );
	a = ( a >> 8 );
	return ( a | b );
};

////////////////////////////////////////////////////////////////////////////////

unsigned long inet_addr(const char* name)
{
	int i,j,p;
	int len = strlen(name);
	unsigned long temp_val[4];
	char namesec[10] ;

	for(i = 0,j =0,p =0;i < len;i++)
	{
		memset(namesec,0,10);
		if('.' == name[i])
		{

			if(p)
				strncpy(namesec,name+p+1,i-p);
			else
				strncpy(namesec,name,i);
			temp_val[j] = atoi(namesec);
			j++;
			p = i;
		}
	}

	strncpy(namesec,name+p+1,i-p);
	temp_val[j] = atoi(namesec);


	return (temp_val[0]|(temp_val[1]<<8)|(temp_val[2]<<16)|(temp_val[3]<<24));
}
//////////////////////////////////////////////////////////////////////////
BOOLEAN AddOrDelInfo(PVOID pBuffer, ULONG uBufferSize, BOOLEAN	bAdd)
{
	PSET_REDIRECT_INFO	pSRI	=	(PSET_REDIRECT_INFO)pBuffer;
	LIST_ENTRY			*pNext	=NULL;
	PREDIRECT_INFO		pRI			=NULL;

	//wrong size
	if (sizeof(SET_REDIRECT_INFO)!=uBufferSize)
	{
		return FALSE;
	}

	if (bAdd)
	{

		return AddRedirectInfo(pSRI->from, pSRI->to, pSRI->bLocal);

	}
	STARTLOCK(&g_RedirectInfoLock2,KKRWLOCK_FOR_WRITE);
	//delete operation
	//ɾ����ʱ��ֻҪ������������ն��ѣ������ͷ��ڴ棬
	pNext	=	g_RedirectInfo.Next.Flink;
	while(pNext&&(pNext!=&g_RedirectInfo.Next))
	{
		pRI	=	CONTAINING_RECORD(pNext, REDIRECT_INFO, Next);
		if (
			(pRI->from==pSRI->from) &&
			(pRI->to  ==pSRI->to)
			)
		{

			//make it zero,means it's discard
			ZeroRedirectInfoInList(pRI);
			g_RedirectInfo.freeNumber++;
			break;
		}
		pNext	=	pNext->Flink;
	}
	ENDLOCK(&g_RedirectInfoLock2);
	return TRUE;

	

}
////////////////////////////////////////////////////////////////////////////////

BOOLEAN	AddRedirectInfo(ULONG	from, ULONG	to, BOOLEAN	bLocal)
{
	REDIRECT_INFO	*pRI	=NULL;
	LIST_ENTRY			*pNext	=NULL;


	kprintf("Enter AddRedirectInfo(), Current Number %d\n", g_RedirectInfo.number);

	if (g_RedirectInfo.freeNumber>0)
	{
		STARTLOCK(&g_RedirectInfoLock2, KKRWLOCK_FOR_READ);
		pNext	=	g_RedirectInfo.Next.Flink;
		while(pNext&&(pNext!=&g_RedirectInfo.Next))
		{
			pRI	=	CONTAINING_RECORD(pNext, REDIRECT_INFO, Next);
			if (!pRI->bBusy)
			{
				//free slot found..
				pRI->bBusy	=	TRUE;
				pRI->from	=	from;
				pRI->to		=	to;
				pRI->bLocal	=	bLocal;
				g_RedirectInfo.freeNumber--;
				break;
			}
			pNext	=	pNext->Flink;
		}
		ENDLOCK(&g_RedirectInfoLock2);
	}
	else
	{
		pRI	=	kmalloc(sizeof(REDIRECT_INFO));
		pRI->from	=	from;
		pRI->to		=	to;
		pRI->bLocal	=	bLocal;
		pRI->bBusy	=	TRUE;

		g_ChangingRedirectInfo	=TRUE;
		STARTLOCK(&g_RedirectInfoLock2, KKRWLOCK_FOR_WRITE);
		InsertHeadList(&g_RedirectInfo.Next, &pRI->Next);
		ENDLOCK(&g_RedirectInfoLock2);
		g_ChangingRedirectInfo	=FALSE;
	}

	g_RedirectInfo.number++;

	kprintf("After AddRedirectInfo(), Current Number %d\n", g_RedirectInfo.number);

	return TRUE;
}
BOOLEAN ReleaseRedirectInfo()
{


	LIST_ENTRY			*pNext	=NULL;
	PREDIRECT_INFO		pRI			=NULL;
	ULONG				number	=g_RedirectInfo.number;
	kprintf("Enter ReleaseRedirectInfo(), Release Number %d\n", number);
	g_RedirectInfo.number	=	0;
	STARTLOCK(&g_RedirectInfoLock2,KKRWLOCK_FOR_WRITE);
	while (!IsListEmpty(&g_RedirectInfo.Next))
	{

			
			pNext	=	RemoveHeadList(&g_RedirectInfo.Next);
			number--;
			pRI = CONTAINING_RECORD(pNext, REDIRECT_INFO, Next);
			//����ȡ��������һ���ط���������ʹ��
			kfree(pRI);
	}
	ENDLOCK(&g_RedirectInfoLock2);
	kprintf("After ReleaseRedirectInfo(), Current Number %d\n", number);
	return TRUE;
}
//////////////////////////////////////////////////////////////////////////
BOOLEAN	ZeroRedirectInfoInList(PREDIRECT_INFO		pRI)
{
	LIST_ENTRY			*pNext	=NULL;
	//���ü�������������
	pRI->bBusy	=	0;
	pRI->bLocal	=	0;
	pRI->from	=	0;
	pRI->to		=	0;

	return 1;

}
//////////////////////////////////////////////////////////////////////////
VOID	RedirectRecvCallback(PVOID packet)
{

	if (g_ChangingRedirectInfo)
	{
		return;
	}
	if (g_RedirectInfo.number==0)
	{	
		return;
	}
	UpdateRecvPacket(packet);

}
//////////////////////////////////////////////////////////////////////////

VOID	RedirectSendCallback(PVOID packet)
{
	LIST_ENTRY	*pNextEntry=NULL;
	PREDIRECT_INFO	pRI=NULL;
	REDIRECT_INFO	tmpRI;

	if (g_RedirectInfo.number==0)
	{
		return;
	}
	if (g_ChangingRedirectInfo)
	{
		return;	//	����Ч�ʵ�ԭ��������ڸ��ģ��Ͳ��ض�λ��
	}
	RedirectSendPacket(packet, 123, 321);
	return ;
}