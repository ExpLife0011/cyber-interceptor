#ifndef __NetcardsInfo__
#define __NetcardsInfo__




//////////////////////////////////////////////////////////////////////////

#define MACADDRESSLEN	(6)


//value for flag in NETCARDS_INFO
#define	DHCPENABLE		(0x00000001)

#define	REGULARNETCARD	(0x00000002)

#define	WIRELESSNETCARD	(0x00000004)

#define	ISCONNECTED		(0x20000000)



//////////////////////////////////////////////////////////////////////////
typedef struct __ADAPTER_INFO__
{
	UNICODE_STRING	GUID;
	ULONG	status;
	UCHAR	macAddress[MACADDRESSLEN];

	ULONG			IPAddr;	//±¾»úIPµØÖ·
	ULONG			GatewayIpAddr;
	BOOLEAN			bDhcp;
}ADAPTER_INFO;



typedef struct __ADAPTER_INFOEX__
{
	ULONG		uNumber;
	ADAPTER_INFO pAI[1];
}ADAPTER_INFOEX;


//////////////////////////////////////////////////////////////////////////



BOOLEAN	EnumNetCards();
BOOLEAN	ReleaseNetCardsInfo();

NTSTATUS	GetNicNameByGUID(PUNICODE_STRING guid, __out PUNICODE_STRING pbuffer);

NTSTATUS GetAdapterInfo(ADAPTER_INFOEX *pAIEX,  PULONG Size2Take);

BOOLEAN GetAdapterInfoEx(ADAPTER_INFO *pAI, PUNICODE_STRING pRegistryPath);

BOOLEAN	GetGatewayMacByRecvPacket(PVOID packet, PUCHAR pBuffer, ULONG uBufferLen);

ULONG	IsPhysicalMiniport(PVOID pMiniportBlock);

NTSTATUS	FixGatewayMac(PVOID pb, ULONG ulen);
//////////////////////////////////////////////////////////////////////////




#endif