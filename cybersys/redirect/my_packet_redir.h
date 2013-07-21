
#ifndef _my_packet_redir_
#define _my_packet_redir_



//////////////////////////////////////////////////////////////////////////
//CheckSendPacketNeed
//�ض���ʱԤ��CHECK�ķ���ֵ
#define		CHECKMORE	(2)	//��������

#define		CHECKNEED	(1)//�Ѿ��ҵ�������ʹ�ò���2��ֵ

#define		CHECKRETURN	(0)	//����ֱ�ӷ�����
//////////////////////////////////////////////////////////////////////////




typedef	struct __REDIRECT_INFO__
{
	LIST_ENTRY	Next;
	ULONG		from;
	ULONG		to;
	ULONG		fake1;	//��2�������������ض���ʱʹ�õ�
	ULONG		fake2;
	
	ULONG		number;
	ULONG		freeNumber;
	BOOLEAN		bLocal;	//�����ǲ��Ǳ����ض���
	BOOLEAN		bBusy;
}REDIRECT_INFO, *PREDIRECT_INFO;

typedef	struct __CURRENT_REDIRECT_INFO__
{

	ULONG		from;
	ULONG		to;
	ULONG		fake1;	//��2�������������ض���ʱʹ�õ�
	ULONG		fake2;
	BOOLEAN		bLocal;	//�����ǲ��Ǳ����ض���

}CURRENT_REDIRECT_INFO, *PCURRENT_REDIRECT_INFO;

//////////////////////////////////////////////////////////////////////////
//function definition

unsigned short htons(unsigned short hostshort);

unsigned long  inet_addr(const char *name);

void UpdateRecvPacket(PNDIS_PACKET pPacket);

BOOLEAN RedirectSendPacket(PNDIS_PACKET pPacket, ULONG FROM_IP, ULONG TO_IP);

USHORT checksum(USHORT *buffer,int size);

void PacketCheckSum(unsigned char pBuffer[]);

void 	copy_buffer_to_packet(PNDIS_PACKET pPacket, PUCHAR pBuffer, ULONG	len_pBuffer);

VOID	RedirectRecvCallback(PVOID packet);

VOID	RedirectSendCallback(PVOID packet);

int 
GetPktPayload(
			  PNDIS_PACKET      pPacket,                // Address of packet descriptor.
			  PUCHAR            pOutBfr,                // Address of output buffer, to get copied packet payload.
			  ULONG             ulOutBfrAvail,          // Size of output buffer.
			  PULONG            pUlUCHARsCopied          // Output variable for number of UCHARs copied.
			  );

BOOLEAN	AddRedirectInfo(ULONG	from, ULONG	to, BOOLEAN	bLocal);

BOOLEAN ReleaseRedirectInfo();

BOOLEAN AddOrDelInfo(PVOID pBuffer, ULONG uBufferSize, BOOLEAN	bAdd);

BOOLEAN	ZeroRedirectInfoInList(PREDIRECT_INFO		pRI);
#endif
