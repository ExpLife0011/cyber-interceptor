#ifndef __connectionstatus__
#define __connectionstatus__





#pragma pack (1)

typedef struct _UF_TCPROW_PID{  
	CHAR  State[128];  
	ULONG	LocalIP;
	USHORT	localPort;
	ULONG	RemoteIP;
	USHORT	RemotePort;
	ULONG dwPid;
}UF_TCPROW_PID, *PUF_TCPROW_PID;

typedef struct _UF_UDPROW_PID{  
	ULONG	LocalIP;
	USHORT	localPort;
	ULONG	RemoteIP;
	USHORT	RemotePort;
	ULONG  dwPid;
}UF_UDPROW_PID, *PUF_UDPROW_PID;

#pragma pack ()




typedef struct _INTERNAL_TCP_TABLE_SUBENTRY
{
	char bytesfill0[2];
	USHORT Port;
	ULONG dwIP;
	char bytesfill[20];

}INTERNAL_TCP_TABLE_SUBENTRY,*PINTERNAL_TCP_TABLE_SUBENTRY;

typedef struct _INTERNAL_TCP_TABLE_ENTRY
{
	INTERNAL_TCP_TABLE_SUBENTRY localEntry;
	INTERNAL_TCP_TABLE_SUBENTRY remoteEntry;

}INTERNAL_TCP_TABLE_ENTRY,*PINTERNAL_TCP_TABLE_ENTRY;

typedef struct _INTERNAL_UDP_TABLE_ENTRY
{
	char bytesfill0[2];
	USHORT Port;
	ULONG dwIP;
	char bytesfill[20];

}INTERNAL_UDP_TABLE_ENTRY,*PINTERNAL_UDP_TABLE_ENTRY;



typedef struct _NSI_STATUS_ENTRY
{   
	ULONG  dwState;
	char bytesfill[8]; 

}NSI_STATUS_ENTRY,*PNSI_STATUS_ENTRY;

typedef struct _NSI_PROCESSID_INFO
{

	ULONG dwUdpProId;
	ULONG UnknownParam2;
	ULONG UnknownParam3;
	ULONG dwProcessId;
	ULONG UnknownParam5;
	ULONG UnknownParam6;
	ULONG UnknownParam7;
	ULONG UnknownParam8;

}NSI_PROCESSID_INFO,*PNSI_PROCESSID_INFO;




typedef struct _NSI_PARAM
{

	ULONG_PTR UnknownParam1;
	SIZE_T UnknownParam2;
	PVOID UnknownParam3;
	SIZE_T UnknownParam4;
	ULONG UnknownParam5;
	ULONG UnknownParam6;
	PVOID UnknownParam7;
	SIZE_T UnknownParam8;
	PVOID UnknownParam9;
	SIZE_T UnknownParam10;
	PVOID UnknownParam11;
	SIZE_T UnknownParam12;
	PVOID UnknownParam13;
	SIZE_T UnknownParam14;
	SIZE_T ConnCount;      

}NSI_PARAM,*PNSI_PARAM;



#define IOCTL_NSI_GETALLPARAM (0x12001B)

#define IOCTL_TCP_QUERY_INFORMATION_EX (0x00120003)


typedef struct _MIB_TCPROW_OWNER_PID{  
	ULONG dwState;  
	ULONG dwLocalAddr;  
	ULONG dwLocalPort;  
	ULONG dwRemoteAddr;  
	ULONG dwRemotePort;  
	ULONG dwOwningPid;
} MIB_TCPROW_OWNER_PID, *PMIB_TCPROW_OWNER_PID;

typedef struct _MIB_UDPROW_OWNER_PID{  
	ULONG dwLocalAddr;  
	ULONG dwLocalPort;  
	ULONG dwOwningPid;
} MIB_UDPROW_OWNER_PID, *PMIB_UDPROW_OWNER_PID;

typedef struct _CONNINFO110 {
	ULONG	size;
	ULONG	status; 
	ULONG	src_addr; 
	USHORT	src_port; 
	USHORT	unk1; 
	ULONG	dst_addr; 
	USHORT	dst_port; 
	USHORT	unk2; 
	ULONG	pid;
	PVOID    unk3[35];
} CONNINFO110, *PCONNINFO110;

#define TCP_MIB_STATS_ID 1
#define TCP_MIB_ADDRTABLE_ENTRY_ID 0x101
#define TCP_MIB_ADDRTABLE_ENTRY_EX_ID 0x102
#define TCP_MIB_ADDRTABLE_ENTRY_XXX 0x110

#define MIB_TCP_STATE_CLOSED            1
#define MIB_TCP_STATE_LISTEN            2
#define MIB_TCP_STATE_SYN_SENT          3
#define MIB_TCP_STATE_SYN_RCVD          4
#define MIB_TCP_STATE_ESTAB             5
#define MIB_TCP_STATE_FIN_WAIT1         6
#define MIB_TCP_STATE_FIN_WAIT2         7
#define MIB_TCP_STATE_CLOSE_WAIT        8
#define MIB_TCP_STATE_CLOSING           9
#define MIB_TCP_STATE_LAST_ACK         10
#define MIB_TCP_STATE_TIME_WAIT        11
#define MIB_TCP_STATE_DELETE_TCB       12

#define	CO_TL_ENTITY				0x400
#define	CL_TL_ENTITY				0x401

#define INFO_CLASS_PROTOCOL 0x200
#define INFO_TYPE_PROVIDER 0x100
#define IP_MIB_STATS_ID                 1

typedef	struct _IP_MIB_STATS_
{
	UCHAR padding[0x38];
	ULONG	uConnectionNumber;
}IP_MIB_STATS;
typedef	struct _UDPStats
{
	UCHAR padding[0x10];
	ULONG	uNumber;
}UDPStats;
/*
Letters	Stand for	Comments
"AT"	Address Translation	Address resolution such as that provided by ARP (Address Resolution Protocol).
"NL"	Network Layer	As in the Open Systems Interconnection (OSI) reference model.
"TL"	Transport Layer	As in the OSI reference model.
"CL"	Connection-Less	A connectionless protocol based on broadcast packets.
"CO"	Connected	A connected protocol based on directed packets.
"ER"	Echo Request/Reply	Packet types used by Ping to test TCP/IP connectivity.
"IF"	Interface	An interface in the sense used in SNMP.
*/
#define CONTEXT_SIZE 16

//* Structure of an entity ID.
typedef struct TDIEntityID {
	ULONG		tei_entity;
	ULONG		tei_instance;
} TDIEntityID;

//* Structure of an object ID.
typedef struct TDIObjectID {
	TDIEntityID	toi_entity;
	ULONG		toi_class;
	ULONG		toi_type;
	ULONG		toi_id;
} TDIObjectID;

typedef struct tcp_request_query_information_ex_xp {
	TDIObjectID     ID;             // object ID to query.
	ULONG_PTR       Context[CONTEXT_SIZE/sizeof(ULONG_PTR)];  // multi-request
	// context. Zeroed for the first request.
} TCP_REQUEST_QUERY_INFORMATION_EX_XP, *PTCP_REQUEST_QUERY_INFORMATION_EX_XP;
typedef TCP_REQUEST_QUERY_INFORMATION_EX_XP TCP_REQUEST_QUERY_INFORMATION_EX;
typedef TCP_REQUEST_QUERY_INFORMATION_EX* PTCP_REQUEST_QUERY_INFORMATION_EX;

VOID
FormatTcpStruct(PMIB_TCPROW_OWNER_PID tcpTable,PVOID pBuf,ULONG_PTR num);

VOID
FormatUdpStruct(PMIB_UDPROW_OWNER_PID udpTable,PUF_UDPROW_PID  pUdpStruct, ULONG_PTR num);
NTSTATUS  
EnumUdpPortInformationWin7(
						   PMIB_UDPROW_OWNER_PID  *udpRow,
						   ULONG_PTR  *len
									);
NTSTATUS  
EnumTcpPortInformationWin7(
						   PMIB_TCPROW_OWNER_PID  *TcpRow,
						   ULONG_PTR  *len);

NTSTATUS  
EnumUdpPortInformationExWin7(
						   PMIB_UDPROW_OWNER_PID  *udpRow,
						   ULONG_PTR  *len
									);
NTSTATUS  
EnumTcpPortInformationExWin7(
						   PMIB_TCPROW_OWNER_PID  *TcpRow,
						   ULONG_PTR  *len);

NTSTATUS	GetNetworkInfoWin7(
						   IN PDEVICE_OBJECT		DeviceObject,
						   IN PIRP					Irp
						   );
NTSTATUS	GetNetworkInfoXP(
							   IN PDEVICE_OBJECT		DeviceObject,
							   IN PIRP					Irp
							   );

NTSTATUS    GetObjectByName(PHANDLE pFileHandle, PVOID *pFileObject, PCWSTR szObjectName);


NTSTATUS	EnumConnections(
						   IN PDEVICE_OBJECT		DeviceObject,
						   IN PIRP					Irp
						   );



#endif