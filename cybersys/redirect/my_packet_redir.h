
#ifndef _my_packet_redir_
#define _my_packet_redir_



//////////////////////////////////////////////////////////////////////////
//CheckSendPacketNeed
//重定向时预先CHECK的返回值
#define		CHECKMORE	(2)	//继续分析

#define		CHECKNEED	(1)//已经找到，可以使用参数2的值

#define		CHECKRETURN	(0)	//可以直接返回了
//////////////////////////////////////////////////////////////////////////




typedef	struct __REDIRECT_INFO__
{
	LIST_ENTRY	Next;
	ULONG		from;
	ULONG		to;
	ULONG		fake1;	//这2个是用来本地重定向时使用的
	ULONG		fake2;
	
	ULONG		number;
	ULONG		freeNumber;
	BOOLEAN		bLocal;	//例如是不是本地重定向
	BOOLEAN		bBusy;
}REDIRECT_INFO, *PREDIRECT_INFO;

typedef	struct __CURRENT_REDIRECT_INFO__
{

	ULONG		from;
	ULONG		to;
	ULONG		fake1;	//这2个是用来本地重定向时使用的
	ULONG		fake2;
	BOOLEAN		bLocal;	//例如是不是本地重定向

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
