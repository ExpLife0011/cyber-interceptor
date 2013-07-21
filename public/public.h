#ifndef __PUBLICCOMM__
#define __PUBLICCOMM__


//
// Define the various device type values.  Note that values used by Microsoft
// Corporation are in the range 0-0x7FFF(32767), and 0x8000(32768)-0xFFFF(65535)
// are reserved for use by customers.
//

#define FILE_DEVICE_CYBERSYS	0x8000

//
// Macro definition for defining IOCTL and FSCTL function control codes. Note
// that function codes 0-0x7FF(2047) are reserved for Microsoft Corporation,
// and 0x800(2048)-0xFFF(4095) are reserved for customers.
//

#define IOCTL_BASE	0x800

//
// The device driver IOCTLs
//

#define CTL_CODE_BASE(i) CTL_CODE(FILE_DEVICE_CYBERSYS, IOCTL_BASE+i, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_CYBERSYS_HELLO		CTL_CODE_BASE(0)
#define IOCTL_CYBERSYS_TEST			CTL_CODE_BASE(1)


#define IOCTL_ADD_RIDIRECTINFO		CTL_CODE_BASE(2)

#define IOCTL_DEL_RIDIRECTINFO		CTL_CODE_BASE(3)

#define IOCTL_SEND_UDP				CTL_CODE_BASE(4)

#define IOCTL_FIX_GATEWAYMAC		CTL_CODE_BASE(5)

#define IOCTL_PATCHWS				CTL_CODE_BASE(6)

#define IOCTL_CHECKNPFSYS			CTL_CODE_BASE(7)

#define IOCTL_UNPATCHWS				CTL_CODE_BASE(8)

#define	IOCTL_GET_TCPINFO			CTL_CODE_BASE(9)

#define	IOCTL_GET_UDPINFO			CTL_CODE_BASE(10)

#define	IOCTL_GPATHBYPID			CTL_CODE_BASE(11)

#define	IOCTL_PENDDINGCHECKPORT			CTL_CODE_BASE(12)

#define	IOCTL_SETUPFW			CTL_CODE_BASE(13)

#define	IOCTL_UNSETFW			CTL_CODE_BASE(14)

#define	IOCTL_GETPORTSTATUS			CTL_CODE_BASE(15)

#define	IOCTL_SETONEPORTSTATUS			CTL_CODE_BASE(16)

#define	IOCTL_RESPONSEPORTASK			CTL_CODE_BASE(17)

#define	IOCTL_ReleasePENDDINGCHECKPORT			CTL_CODE_BASE(18)

#define	IOCTL_PATCH_NOSENTLOOPBACK			CTL_CODE_BASE(19)

#define	IOCTL_PATCH_RESTORE_NOSENTLOOPBACK			CTL_CODE_BASE(20)

#define	IOCTL_GETPROTOCOLLIST			CTL_CODE_BASE(21)

//
// Name that Win32 front end will use to open the SuperCI2k3 device
//



//
// Name that Win32 front end will use to open the cybersys device
//

#define CYBERSYS_WIN32_DEVICE_NAME_A	"\\\\.\\cybersys"
#define CYBERSYS_WIN32_DEVICE_NAME_W	L"\\\\.\\cybersys"
#define CYBERSYS_DEVICE_NAME_A			"\\Device\\cybersys"
#define CYBERSYS_DEVICE_NAME_W			L"\\Device\\cybersys"
#define CYBERSYS_DOS_DEVICE_NAME_A		"\\DosDevices\\cybersys"
#define CYBERSYS_DOS_DEVICE_NAME_W		L"\\DosDevices\\cybersys"

#ifdef _UNICODE
#define CYBERSYS_WIN32_DEVICE_NAME	CYBERSYS_WIN32_DEVICE_NAME_W
#define CYBERSYS_DEVICE_NAME		CYBERSYS_DEVICE_NAME_W
#define CYBERSYS_DOS_DEVICE_NAME	CYBERSYS_DOS_DEVICE_NAME_W
#else
#define CYBERSYS_WIN32_DEVICE_NAME	CYBERSYS_WIN32_DEVICE_NAME_A
#define CYBERSYS_DEVICE_NAME		CYBERSYS_DEVICE_NAME_A
#define CYBERSYS_DOS_DEVICE_NAME	CYBERSYS_DOS_DEVICE_NAME_A
#endif


//这个是应用层传下来的重定向内容
typedef	struct __SET_REDIRECT_INFO__
{
	ULONG		from;
	ULONG		to;
	BOOLEAN		bLocal;	//例如是不是本地重定向
}SET_REDIRECT_INFO, *PSET_REDIRECT_INFO;

typedef	struct __SEND_UDP_INFO__
{

	ULONG		dstIP;
	ULONG		dstPort;
	ULONG		srcIP;//这个IP用在驱动中匹配使用哪个网卡
	ULONG		dwSize;		//size of pbuffer
	char		pbuffer[1];
}SEND_UDP_INFO, *PSEND_UDP_INFO;
typedef	enum	__PortStatus__
{
	PortUnknow,	//刚加入到链表中，未决，也就是一般会丢掉吧
	PortAccept,
	PortDeny

}PortStatus;

typedef	struct	__FIREWALL_ASKUSER__
{
	USHORT	uPort;
	PortStatus		PStatus;
	ULONG		SrcIP;
	ULONG		DstIP;

}FIREWALL_ASKUSER, *PFIREWALL_ASKUSER;

typedef	struct	__AcceptedPort__
{
	LIST_ENTRY	Next;
	USHORT		uPort;
	PortStatus		PStatus;
	ULONG_PTR		pProtocolBlcok;
	ULONG_PTR		ProtocolBindingContext;
	ULONG_PTR		MacReceiveContext;
	ULONG		SrcIP;
	ULONG		DstIP;
	UCHAR		cMacSrcDst[12];//目标和源MAC
	UCHAR              HeaderBuffer[20];
	UINT                HeaderBufferSize;
	UCHAR               LookAheadBuffer[70];
	UINT                LookAheadBufferSize;
}AcceptedPort, *PAcceptedPort;

#define		ProtocolNameSize	(128)
typedef	struct	_Protocol_Lists__
{
	char szName[ProtocolNameSize];

}Protocol_Lists, *PProtocol_Lists;


#define MACADDRESSLEN	(6)

typedef struct __NETCARDS_INFO__
{
	LIST_ENTRY		Next;
	ANSI_STRING	Name;	//网卡名字	使用rtlFreeAnistring释放,为了能打印中文，换回单字节
	UCHAR			MacAddr[MACADDRESSLEN];	//本机网卡mac地址
	UCHAR			GatewayMacAddr[MACADDRESSLEN];

	ULONG			IPAddr;	//本机IP地址
	ULONG			GatewayIpAddr;
	ULONG			flag;

	PVOID			pMiniBlock;

}NETCARDS_INFO,*PNETCARDS_INFO;


// typedef struct _MIB_TCPROW_OWNER_PID{  
// 	ULONG dwState;  
// 	ULONG dwLocalAddr;  
// 	ULONG dwLocalPort;  
// 	ULONG dwRemoteAddr;  
// 	ULONG dwRemotePort;  
// 	ULONG dwOwningPid;
// } MIB_TCPROW_OWNER_PID, *PMIB_TCPROW_OWNER_PID;
// 
// typedef struct _MIB_UDPROW_OWNER_PID{  
// 	ULONG dwLocalAddr;  
// 	ULONG dwLocalPort;  
// 	ULONG dwOwningPid;
// } MIB_UDPROW_OWNER_PID, *PMIB_UDPROW_OWNER_PID;
// 
// typedef	struct __MIBCONNECTINFO__
// {
// 	ULONG	uCount;
// 	union
// 	{
// 		MIB_TCPROW_OWNER_PID[0];
// 		MIB_UDPROW_OWNER_PID[0];
// 	}mib_row;
// 
// }MIBCONNECTINFO, *PMIBCONNECTINFO;

#endif