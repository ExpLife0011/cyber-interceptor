
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


NETCARDS_INFO	g_NetCardsInfoHeader;
KSPIN_LOCK		g_NetCardsInfoLock;

//////////////////////////////////////////////////////////////////////////

/*

禁用网卡时，会调用网卡的HaltHandler函数，调用的是Mdriver_block里面mchars字段中的回调

但是开启网卡时，没法做到HOOK 网卡的初始化回调函数，因为之前网卡驱动都还没加载，哪来的HOOK，

所以只能HOOK协议驱动的bind函数才行了。（注意，也许开启一个网卡后，会有很多的协议的bind函数被调用，基本我们HOOK TCPIP的就行了

驱动下完美获取网卡信息方法
http://hi.baidu.com/zhouws1011/blog/item/460e864adc40d4d5d1c86aec.html
*/

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
/*
kd> dt ndis!_NDIS_PROTOCOL_BLOCK
+0x000 Header           : _NDIS_OBJECT_HEADER
+0x004 ProtocolDriverContext : Ptr32 Void
+0x008 NextProtocol     : Ptr32 _NDIS_PROTOCOL_BLOCK
+0x00c OpenQueue        : Ptr32 _NDIS_OPEN_BLOCK
win7
*/
BOOLEAN	EnumNetCards()
{
	PNDIS_MINIPORT_BLOCK pMiniBlock=NULL;
	PNDIS_COMMON_OPEN_BLOCK_2k3_early	pOpenBlock=NULL;

	ULONG	MiniDriverBlockHeader	;
	ULONG	NetCardType	=	0;
	LIST_ENTRY		*pListEntry=NULL;
	NETCARDS_INFO		*pNI=NULL;
	NTSTATUS			status = STATUS_SUCCESS;
	ULONG			uTmp=0;
	ADAPTER_INFOEX	*pAdapterInfoEx	=	NULL;
	ADAPTER_INFO	AI;
	WCHAR			*p1,*p2;
	ULONG			index=0;
	UNICODE_STRING	uniTmp;
	DWORD		dwVersion=0;


	

	PKK_NDIS_PROTOCOL_BLOCK	pProtocol	=	(PKK_NDIS_PROTOCOL_BLOCK)GetProtocolHeader();

	dwVersion = GetWindowsVersion();
	p1=p2=NULL;

	//清空列表
	if (!IsListEmpty(&g_NetCardsInfoHeader.Next))
	{
		ExInterlockedRemoveHeadList(&g_NetCardsInfoHeader.Next, &g_NetCardsInfoLock);
// 		LockResource(&g_NetCardsInfoLock, TRUE);
// 		pListEntry = RemoveHeadList(&g_NetCardsInfoHeader.Next);
// 		UnlockResource(&g_NetCardsInfoLock);
		pNI	=	CONTAINING_RECORD(pListEntry, NETCARDS_INFO, Next);
		if (NULL==pNI)
		{

			DbgBreakPoint();

		}
		RtlFreeAnsiString(&pNI->Name);
		kfree(pNI);
	}
	status	=	GetAdapterInfo(NULL, &uTmp);
	if (status==STATUS_BUFFER_TOO_SMALL)
	{
		pAdapterInfoEx	=	kmalloc(uTmp);
		RtlZeroMemory(pAdapterInfoEx, uTmp);
		if (NULL== pAdapterInfoEx)
		{
			return FALSE;
		}
	}
	status = GetAdapterInfo(pAdapterInfoEx, &uTmp);
	if (pAdapterInfoEx->uNumber==0)
	{
		kprintf("GetAdapterInfo() return pAdapterInfoEx->uNumber==0");
		kfree(pAdapterInfoEx);
		return FALSE;
	}

	while (pProtocol)	
	{
		//search for  the nic driver block
		if (dwVersion==Windows_7||dwVersion==Windows_Vista)
		{
			if (((PNDIS_PROTOCOL_BLOCKWin7)pProtocol)->OpenQueue==0)
			{
				goto NextBlock;
			}
		}
		else
		{
			if (pProtocol->OpenQueue==NULL)
			{
				goto NextBlock;
			}
		}

		uTmp=0;
		//现在使用了protocol链表，所以要防止一个miniport多次使用的情况
		if (dwVersion==Windows_Vista||dwVersion==Windows_7)
		{
			PNDIS_OPEN_BLOCKWIN7 pOP7	=	(PNDIS_OPEN_BLOCKWIN7)((PNDIS_PROTOCOL_BLOCKWin7)pProtocol)->OpenQueue;
			pMiniBlock	=	pOP7->MiniportHandle;
		}
		else
		{
			pMiniBlock	=	pProtocol->OpenQueue->MiniportHandle;
		}

		pListEntry	=	g_NetCardsInfoHeader.Next.Flink;
		while(pListEntry&& (pListEntry!=&g_NetCardsInfoHeader.Next))
		{
			pNI	=	CONTAINING_RECORD(pListEntry, NETCARDS_INFO, Next);
			if (pNI==NULL)
			{
				kprintf("Crash......when checking pMiniBlock is in g_NetCardsInfoHeader already\n");
				return FALSE;
			//	DbgBreakPoint();
			}
			if (pNI->pMiniBlock==pMiniBlock)
			{
				uTmp	=	1;
				break;
			}
			pListEntry	=	pListEntry->Flink;
		}
		if (uTmp==1)
		{
			//这个miniport已经使用过了
			goto NextBlock;
		}
		NetCardType		=	IsPhysicalMiniport(pMiniBlock);	//只取物理网卡
		if (NetCardType==0)
		{
			goto NextBlock;
		}
		
		pNI	=	kmalloc(sizeof(NETCARDS_INFO));
		RtlZeroMemory(pNI, sizeof(NETCARDS_INFO));
		if (NetCardType==1)
		{
			SetFlag(pNI->flag, REGULARNETCARD);
			
		}
		if (NetCardType==2)
		{
			SetFlag(pNI->flag, WIRELESSNETCARD);
		}
		/*
		p_mini_block->SymbolicLinkName
		亦可直接Createfile (p_mini_block->SymbolicLinkName....)发OID_802_3_CURRENT_ADDRESS来查询
		*/
		pNI->pMiniBlock	=	pMiniBlock;
		uTmp =0;
		
		for (index=0; index<pAdapterInfoEx->uNumber; index++)
		{
			p1	=	kmalloc(pMiniBlock->SymbolicLinkName.Length+2);
			RtlZeroMemory(p1, pMiniBlock->SymbolicLinkName.Length+2);
			RtlCopyMemory(p1, pMiniBlock->SymbolicLinkName.Buffer, pMiniBlock->SymbolicLinkName.Length);

			AI	=	pAdapterInfoEx->pAI[index];
			p2	=	kmalloc(AI.GUID.Length+2);
			RtlZeroMemory(p2, AI.GUID.Length+2);
			RtlCopyMemory(p2, AI.GUID.Buffer, AI.GUID.Length);
			_wcsupr(p1);_wcsupr(p2);
			if (wcsstr(p1,p2))
			{
				kfree(p1);kfree(p2);
				uTmp	=	1;
				break;	//找到了，已经获取网卡MAC地址
			}
			kfree(p1);kfree(p2);

		}//end for (index=0; index<pAdapterInfoEx->uNumber; index++)
		
		if (uTmp==1)
		{
			RtlCopyMemory(pNI->MacAddr, AI.macAddress, sizeof(pNI->MacAddr));
			pNI->IPAddr	=	 AI.IPAddr;
			pNI->GatewayIpAddr	=	 AI.GatewayIpAddr;
			if (pAdapterInfoEx->pAI[index].bDhcp)
			{
				SetFlag(pNI->flag, DHCPENABLE);
	
			}
			ExInterlockedInsertHeadList(&g_NetCardsInfoHeader.Next, &pNI->Next, &g_NetCardsInfoLock);
// 			LockResource(&g_NetCardsInfoLock, TRUE);
// 			InsertHeadList(&g_NetCardsInfoHeader.Next, &pNI->Next);
// 			UnlockResource(&g_NetCardsInfoLock);
		}
		else
		{
			kfree(pNI);
			pNI	=	NULL;
			goto NextBlock;

		}

// 		if ((p_mini_block->Flags&ISCONNECTED))
// 		{
// 			SetFlag(pNI->flag, ISCONNECTED);
// 		}
		if (AI.status==NdisMediaStateConnected)
		{
			SetFlag(pNI->flag, ISCONNECTED);
		}
		//HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}

		GetNicNameByGUID(&AI.GUID, &uniTmp);
		RtlUnicodeStringToAnsiString(&pNI->Name, &uniTmp, TRUE);
		kprintf("\r\n 检举网卡信息如下：\r\nMAC : %02X:%02X:%02X:%02X:%02X:%02X   \nIP :0x%x   \nflag:0X%X  \n网关IP:0x%x   \nName: %Z \n\n", pNI->MacAddr[0], pNI->MacAddr[1], pNI->MacAddr[2], pNI->MacAddr[3], pNI->MacAddr[4], pNI->MacAddr[5], (pNI->IPAddr), pNI->flag, (pNI->GatewayIpAddr),&pNI->Name);


NextBlock:
		if (dwVersion==Windows_Vista||dwVersion==Windows_7)
		{
			pProtocol	=	(PKK_NDIS_PROTOCOL_BLOCK )((PNDIS_PROTOCOL_BLOCKWin7)pProtocol)->NextProtocol;
		}
		else
		pProtocol	=	pProtocol->NextProtocol;
	}	//end  while (p_driver_block->NextDriver)	
	

	//释放上面申请的内容
	for (index=0; index<pAdapterInfoEx->uNumber; index++)
	{
		kfree(pAdapterInfoEx->pAI[index].GUID.Buffer);

	}
	kfree(pAdapterInfoEx);

	return 1;
}
//////////////////////////////////////////////////////////////////////////
BOOLEAN	ReleaseNetCardsInfo()
{
	LIST_ENTRY		*pListEntry=NULL;
	NETCARDS_INFO		*pNI=NULL;

	if (!IsListEmpty(&g_NetCardsInfoHeader.Next))
	{
		pListEntry = ExInterlockedRemoveHeadList(&g_NetCardsInfoHeader.Next, &g_NetCardsInfoLock);
		// 		LockResource(&g_NetCardsInfoLock, TRUE);
		// 		pListEntry = RemoveHeadList(&g_NetCardsInfoHeader.Next);
		// 		UnlockResource(&g_NetCardsInfoLock);
		pNI	=	CONTAINING_RECORD(pListEntry, NETCARDS_INFO, Next);
		if (pNI==NULL)
		{
			kprintf("what the hell is going on\n");

		}
		RtlFreeAnsiString(&pNI->Name);
		kfree(pNI);
	}

	return TRUE;
}
//////////////////////////////////////////////////////////////////////////
//0表示不是
//1，是一般物理网卡
//2。USB无线网卡
/*
XP的
NDIS!_NDIS_MINIPORT_BLOCK

*/
ULONG	IsPhysicalMiniport(PVOID pMiniportBlock)
{

	PNDIS_MINIPORT_BLOCK	pMini	=	(PNDIS_MINIPORT_BLOCK)pMiniportBlock;
	UNICODE_STRING		ustrPrefix	;
	UNICODE_STRING		ustrPrefix2	;
	RtlInitUnicodeString(&ustrPrefix, L"\\??\\PCI");
	RtlInitUnicodeString(&ustrPrefix2, L"\\??\\USB");

	if (RtlPrefixUnicodeString(&ustrPrefix, &pMini->SymbolicLinkName, FALSE))
	{
		return 1;
	}
	if (RtlPrefixUnicodeString(&ustrPrefix2, &pMini->SymbolicLinkName, FALSE))
	{
		return 2;
	}
	return 0;
}
//////////////////////////////////////////////////////////////////////////



#define OID_802_3_PERMANENT_ADDRESS             0x01010101
#define OID_802_3_CURRENT_ADDRESS               0x01010102
#define        DEV_DOS_ROOT    L"\\??\\"

#define ANSI_STRING_CONST(x)        {sizeof(x)-1, sizeof(x), x}
#define UNICODE_STRING_CONST(x)        {sizeof(x)-2, sizeof(x), x}

//////////////////////////////////////////////////////////////////////////
//如果提供的缓存区不够大，返回STATUS_BUFFER_TOO_SMALL
NTSTATUS GetAdapterInfo(ADAPTER_INFOEX *pAIEX,  PULONG Size2Take)
{

	NTSTATUS                status;
	HANDLE                    hAdapter = NULL;
	PKEY_FULL_INFORMATION    pKeyFullInfo = NULL;
	ULONG					uTmp;
	ULONG					 uCounter=0;

	do
	{
		//        UNICODE_STRING            ustrAdapter = UNICODE_STRING_CONST(L";\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}";);
		UNICODE_STRING            ustrAdapter = UNICODE_STRING_CONST(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Adapters");
		OBJECT_ATTRIBUTES        ObjAttrib;
		ULONG                    nSize;
		ULONG                    nIndex;


		InitializeObjectAttributes(&ObjAttrib, &ustrAdapter, OBJ_CASE_INSENSITIVE, NULL, NULL);
		status = ZwOpenKey(&hAdapter, KEY_READ, &ObjAttrib);
		if (!NT_SUCCESS(status))
		{
			//DbgPrintEx(DPFLTR_IHVBUS_ID ,DPFLTR_ERROR_LEVEL,"ZwOpenKey Error: %x\n", status);
			break;
		}
		ZwQueryKey(hAdapter, KeyFullInformation, NULL, 0, &nSize);
		pKeyFullInfo = (PKEY_FULL_INFORMATION)kmalloc( nSize);
		if (!pKeyFullInfo)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		status  = ZwQueryKey(hAdapter, KeyFullInformation, pKeyFullInfo, nSize, &nSize);
		if (!NT_SUCCESS(status))
		{
			//DbgPrintEx(DPFLTR_IHVBUS_ID ,DPFLTR_ERROR_LEVEL,";ZwQueryKey Error: %x\n", status);
			break;
		}
		if (pAIEX==NULL)
		{
			status	=	STATUS_BUFFER_TOO_SMALL;
			*Size2Take	=	pKeyFullInfo->SubKeys*sizeof(ADAPTER_INFO)+sizeof(ULONG);
			break;
		}

		for (nIndex = 0; nIndex< pKeyFullInfo->SubKeys; nIndex ++)
		{
			PKEY_BASIC_INFORMATION        pKeyBasicInfo = NULL;
			HANDLE                        hDev = NULL;
			pKeyBasicInfo = NULL;

			do
			{
				UNICODE_STRING        strKeyName;
				UNICODE_STRING        ustrDev ;// UNICODE_STRING_CONST(DEV_DOS_ROOT L"{F6ACFAC2-D39E-4A43-A320-0CDB9E22B15B}");
				IO_STATUS_BLOCK        IoStatusBlock;
				ULONG                nOid;

				ZwEnumerateKey(hAdapter, nIndex, KeyBasicInformation, NULL, 0, &nSize);
				pKeyBasicInfo = (PKEY_BASIC_INFORMATION) kmalloc(nSize);
				if (NULL == pKeyBasicInfo)
				{
					status = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}
				status = ZwEnumerateKey(hAdapter, nIndex, KeyBasicInformation, pKeyBasicInfo, nSize, &nSize);
				if (!NT_SUCCESS(status))
				{
					kprintf("ZwEnumerateKey fail \n");
					break;
				}

				strKeyName.Buffer = pKeyBasicInfo->Name;
				strKeyName.MaximumLength = (USHORT)pKeyBasicInfo->NameLength;
				strKeyName.Length = (USHORT)pKeyBasicInfo->NameLength;

				ustrDev.Buffer	=	kmalloc(strKeyName.MaximumLength+sizeof(DEV_DOS_ROOT));
				ustrDev.MaximumLength	=	strKeyName.MaximumLength+sizeof(DEV_DOS_ROOT);
				ustrDev.Length = 0;

				if (NULL == ustrDev.Buffer)
				{
					status = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}
				RtlAppendUnicodeToString(&ustrDev, DEV_DOS_ROOT);
				status = RtlAppendUnicodeStringToString(&ustrDev, &strKeyName);
				if (STATUS_SUCCESS != status)
				{
					//DbgPrintEx(DPFLTR_IHVBUS_ID ,DPFLTR_ERROR_LEVEL,";RtlAppendUnicodeStringToString Error: %x\n", status);
					kfree(ustrDev.Buffer);
					break;
				}
				InitializeObjectAttributes(&ObjAttrib, &ustrDev, OBJ_CASE_INSENSITIVE, NULL, NULL);
				status = ZwOpenFile(&hDev,
					GENERIC_READ,
					&ObjAttrib,
					&IoStatusBlock,
					FILE_SHARE_READ,
					FILE_NON_DIRECTORY_FILE);
				if (STATUS_SUCCESS != status)
				{
					//DbgPrintEx(DPFLTR_IHVBUS_ID ,DPFLTR_ERROR_LEVEL,";ZwOpenFile %wZ,Error: %x\n", &ustrDev, status);
					kfree(ustrDev.Buffer);
					break;
				}
				

				//	nOid = OID_GEN_MEDIA_IN_USE;
// 				nOid	=	OID_GEN_PHYSICAL_MEDIUM; //网卡类型
// 				uTmp	=	sizeof(uTmp);
// 				status = ZwDeviceIoControlFile(hDev,
// 					NULL,
// 					NULL,
// 					NULL,
// 					&IoStatusBlock,
// 					IOCTL_NDIS_QUERY_GLOBAL_STATS,
// 					&nOid,
// 					sizeof(nOid),
// 					&uTmp,
// 					uTmp);
// 				if (STATUS_SUCCESS != status)
// 				{
// 					DbgPrintEx(DPFLTR_IHVBUS_ID ,DPFLTR_ERROR_LEVEL,";ZwDeviceIoControlFile OID_GEN_PHYSICAL_MEDIUM Error: 0X%x\n", status);
// 					uTmp	=	-1;
// 					if (status==STATUS_INVALID_PARAMETER)
// 					{
// 						// NdisPhysicalMediumUnspecified
// 					}
// 					//	break;
// 				}
	//其实这里应该先发OID_GEN_MEDIA_IN_USE获取下media类型

				nOid	=	OID_GEN_MEDIA_CONNECT_STATUS; //网卡类型
				uTmp	=	sizeof(uTmp);
				status = ZwDeviceIoControlFile(hDev,
					NULL,
					NULL,
					NULL,
					&IoStatusBlock,
					IOCTL_NDIS_QUERY_GLOBAL_STATS,
					&nOid,
					sizeof(nOid),
					&uTmp,
					uTmp);
				if (STATUS_SUCCESS != status)
				{
					//DbgPrintEx(DPFLTR_IHVBUS_ID ,DPFLTR_ERROR_LEVEL,";ZwDeviceIoControlFile OID_GEN_MEDIA_CONNECT_STATUS Error: 0X%x\n", status);
					uTmp	=	NdisMediaStateDisconnected;
					//	break;
				}
				pAIEX->pAI[uCounter].status	=	uTmp;
				kprintf(" %wZ, OID_GEN_MEDIA_CONNECT_STATUS %s \n", &ustrDev, uTmp == NdisMediaStateConnected ? "Connected" : "Disconnected");
				kfree(ustrDev.Buffer);
				uTmp	=	sizeof(pAIEX->pAI[uCounter].macAddress);
				nOid = OID_802_3_CURRENT_ADDRESS;
				status = ZwDeviceIoControlFile(hDev,
					NULL,
					NULL,
					NULL,
					&IoStatusBlock,
					IOCTL_NDIS_QUERY_GLOBAL_STATS,
					&nOid,
					sizeof(nOid),
					pAIEX->pAI[uCounter].macAddress,
					uTmp);
				if (STATUS_SUCCESS != status)
				{
					//DbgPrintEx(DPFLTR_IHVBUS_ID ,DPFLTR_ERROR_LEVEL,";ZwDeviceIoControlFile OID_802_3_PERMANENT_ADDRESS Error: 0x%x\n", status);
					break;
				}
				//DbgPrintEx(DPFLTR_IHVBUS_ID ,DPFLTR_ERROR_LEVEL,"Mac: %02X:%02X:%02X:%02X:%02X:%02X\n", pAIEX->pAI[uCounter].macAddress[0], pAIEX->pAI[uCounter].macAddress[1], pAIEX->pAI[uCounter].macAddress[2], pAIEX->pAI[uCounter].macAddress[3], pAIEX->pAI[uCounter].macAddress[4], pAIEX->pAI[uCounter].macAddress[5]);


				pAIEX->pAI[uCounter].GUID.Buffer	=	kmalloc(pKeyBasicInfo->NameLength);

				pAIEX->pAI[uCounter].GUID.Length = pAIEX->pAI[uCounter].GUID.MaximumLength	=	(USHORT)pKeyBasicInfo->NameLength;
				RtlCopyMemory(pAIEX->pAI[uCounter].GUID.Buffer, pKeyBasicInfo->Name, pKeyBasicInfo->NameLength);
				if (1)
				{
					CHAR	IPAddress[48];
					ANSI_STRING	aniString;
					UNICODE_STRING	uniString;
					char *pTmp=NULL;
					UNICODE_STRING   ustrAdapterInfo = UNICODE_STRING_CONST(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\");
					WCHAR	*pPath	=kmalloc(ustrAdapterInfo.Length+pKeyBasicInfo->NameLength+2);
					RtlZeroMemory(pPath, ustrAdapterInfo.Length+pKeyBasicInfo->NameLength+2);
					RtlCopyMemory(pPath, ustrAdapterInfo.Buffer, ustrAdapterInfo.Length);
					pTmp	=	(char*)pPath;
					RtlCopyMemory(&pTmp[ustrAdapterInfo.Length], pKeyBasicInfo->Name, pKeyBasicInfo->NameLength);

					uTmp=0;
					uTmp	= sizeof(ULONG);
					status	=	KKGetKeyValue(pPath, L"EnableDHCP", &uTmp, &uTmp);
					if (NT_SUCCESS(status))
					{
						RtlZeroMemory(IPAddress, sizeof(IPAddress));
						//开启了DHCP情况
						if (uTmp==1)
						{
							pAIEX->pAI[uCounter].bDhcp	=	TRUE;

							//够长了，应该会自动截断
							RtlZeroMemory(IPAddress, sizeof(IPAddress));

							uTmp	=	sizeof(IPAddress);

							status = KKGetKeyValue(pPath, L"DhcpIPAddress", IPAddress, &uTmp);
							if (NT_SUCCESS(status))
							{

								RtlInitUnicodeString(&uniString, (WCHAR*)IPAddress);
								RtlUnicodeStringToAnsiString(&aniString, &uniString, TRUE);
								RtlZeroMemory(IPAddress, sizeof(IPAddress));
								RtlCopyMemory(IPAddress, aniString.Buffer, aniString.Length);
								pAIEX->pAI[uCounter].IPAddr	=	inet_addr(IPAddress);
								RtlFreeAnsiString(&aniString);
							}
							else
							{
								kprintf("fail 2 get DhcpIPAddress\n");
							}
							RtlZeroMemory(IPAddress, sizeof(IPAddress));

							uTmp	=	sizeof(IPAddress);

							status = KKGetKeyValue(pPath, L"DhcpDefaultGateway", IPAddress, &uTmp);
							if (NT_SUCCESS(status))
							{

								RtlInitUnicodeString(&uniString, (WCHAR*)IPAddress);
								RtlUnicodeStringToAnsiString(&aniString, &uniString, TRUE);
								RtlZeroMemory(IPAddress, sizeof(IPAddress));
								RtlCopyMemory(IPAddress, aniString.Buffer, aniString.Length);
								pAIEX->pAI[uCounter].GatewayIpAddr	=	inet_addr(IPAddress);
								RtlFreeAnsiString(&aniString);
							}
							else
							{
								kprintf("fail 2 get DhcpDefaultGateway\n");
							}
						}//if (uTmp==1)
						else
						{

							pAIEX->pAI[uCounter].bDhcp	=	FALSE;

							//够长了，应该会自动截断
							RtlZeroMemory(IPAddress, sizeof(IPAddress));
							uTmp	=	sizeof(IPAddress);

							status = KKGetKeyValue(pPath, L"IPAddress", IPAddress, &uTmp);
							if (NT_SUCCESS(status))
							{

								RtlInitUnicodeString(&uniString, (WCHAR*)IPAddress);
								RtlUnicodeStringToAnsiString(&aniString, &uniString, TRUE);
								RtlZeroMemory(IPAddress, sizeof(IPAddress));
								RtlCopyMemory(IPAddress, aniString.Buffer, aniString.Length);
								pAIEX->pAI[uCounter].IPAddr	=	inet_addr(IPAddress);
								RtlFreeAnsiString(&aniString);
							}
							else
							{
								kprintf("fail 2 get IPAddress\n");
							}
							RtlZeroMemory(IPAddress, sizeof(IPAddress));
							uTmp	=	sizeof(IPAddress);

							status = KKGetKeyValue(pPath, L"DefaultGateway", IPAddress, &uTmp);
							if (NT_SUCCESS(status))
							{

								RtlInitUnicodeString(&uniString, (WCHAR*)IPAddress);
								RtlUnicodeStringToAnsiString(&aniString, &uniString, TRUE);
								RtlZeroMemory(IPAddress, sizeof(IPAddress));
								RtlCopyMemory(IPAddress, aniString.Buffer, aniString.Length);
								pAIEX->pAI[uCounter].GatewayIpAddr	=	inet_addr(IPAddress);
								RtlFreeAnsiString(&aniString);
							}
							else
							{
								kprintf("fail 2 get DefaultGateway\n");
							}
						}
					}// end status = QueryRegistryValue(pPath, L"EnableDHCP

					if (pPath)
					{
						kfree(pPath);pPath=NULL;
					}


				}


				uCounter++;
				pAIEX->uNumber	=	uCounter;

			}while(0);
			if (hDev)
			{
				ZwClose(hDev);
			}

			if (pKeyBasicInfo)
			{
				kfree(pKeyBasicInfo);
			}
			if (STATUS_SUCCESS == status)
			{

				//                break;
			}
		}
	}while(0);

	if (pKeyFullInfo)
	{
		kfree(pKeyFullInfo);
	}
	if (hAdapter)
	{
		ZwClose(hAdapter);
	}


	return status;
}
//////////////////////////////////////////////////////////////////////////
//函数返回成功的话，需要调用者使用kfree把pbuffer.buffer释放掉
//返回的pbuffer， 是一个WCHAR *字符串

NTSTATUS	GetNicNameByGUID(PUNICODE_STRING guid, __out PUNICODE_STRING pbuffer)
{
	CHAR	IPAddress[48];
	ANSI_STRING	aniString;
	UNICODE_STRING	uniString;
	UNICODE_STRING	uniString2	=	UNICODE_STRING_CONST(L"\\Connection");
	UNICODE_STRING   ustrAdapterInfo = UNICODE_STRING_CONST(L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\");

	NTSTATUS	status=STATUS_SUCCESS;
	ULONG	utmp	=	0;
	char *pTmp=NULL;
	WCHAR	*pPath=NULL;


	pbuffer->Buffer=NULL;
	pbuffer->Length=pbuffer->MaximumLength=0;

	do 
	{
		utmp	=	ustrAdapterInfo.Length+guid->Length+2+ uniString2.Length;
		pPath	=kmalloc(utmp);
		RtlZeroMemory(pPath, utmp);
		RtlCopyMemory(pPath, ustrAdapterInfo.Buffer, ustrAdapterInfo.Length);
		pTmp	=	(char*)pPath;
		RtlCopyMemory(&pTmp[ustrAdapterInfo.Length], guid->Buffer, guid->Length);

		RtlCopyMemory(&pTmp[ustrAdapterInfo.Length+ guid->Length], uniString2.Buffer, uniString2.Length);

		utmp=0;
		status	=	KKGetKeyValue(pPath, L"Name", 0, &utmp);
		if (status!=STATUS_BUFFER_TOO_SMALL)
		{
			break; 
		}
		pbuffer->Buffer	=	kmalloc(utmp);
		if (pbuffer==NULL)
		{
			kprintf("crash me\n");
			DbgBreakPoint();
		}
		status	=	KKGetKeyValue(pPath, L"Name", pbuffer->Buffer, &utmp);
		if (status!=STATUS_SUCCESS)
		{
			kfree(pbuffer->Buffer);
			break; 
		}

		pbuffer->Length=pbuffer->MaximumLength=(USHORT)utmp;


	} while (0);

	if (pPath)
	{
		kfree(pPath);pPath=NULL;
	}

	return status;

}
//////////////////////////////////////////////////////////////////////////

NTSTATUS	FixGatewayMac(PVOID pb, ULONG ulen)
{
	NTSTATUS status = STATUS_SUCCESS; 
	ULONG	uidx=0;
	ULONG	uNumber=0;
	LIST_ENTRY		*pListEntry=NULL;
	NETCARDS_INFO		*pNI=NULL;
	NETCARDS_INFO		*pNIBuffer=	(NETCARDS_INFO*)pb;

	kprintf("Enter FixGatewayMac()\n");

	do 
	{
		if (ulen<sizeof(NETCARDS_INFO))
		{
			status	=	STATUS_BUFFER_TOO_SMALL;
			break;
		}
		//先使用内容方式取得所有对应的miniport
		EnumNetCards();
		pListEntry =	g_NetCardsInfoHeader.Next.Flink;
		while (pListEntry != &g_NetCardsInfoHeader.Next)
		{
			if (pListEntry)
			{
				pNI = CONTAINING_RECORD(pListEntry, NETCARDS_INFO, Next);
				
				//find  ipaddress for the correspond GatewayMac
				uNumber	=	ulen/sizeof(NETCARDS_INFO);
				for (uidx=0; uidx<uNumber; uidx++)
				{
					if (pNI->IPAddr==pNIBuffer->IPAddr)
					{
						//found
						kprintf("find GatewayMacAddr for gateway IP 0x%x\n", pNI->GatewayIpAddr);
						RtlCopyMemory(pNI->GatewayMacAddr, pNIBuffer->GatewayMacAddr, sizeof(pNI->GatewayMacAddr));
						kprintf("\r\n after fix：\r\nLocalMAC : %02X:%02X:%02X:%02X:%02X:%02X   \nlocalIP :0x%x   \nflag:0X%X  \ngatewayIP:0x%x   GatewayMac : %02X:%02X:%02X:%02X:%02X:%02X\n \n\n", pNI->MacAddr[0], pNI->MacAddr[1], pNI->MacAddr[2], pNI->MacAddr[3], pNI->MacAddr[4], pNI->MacAddr[5], (pNI->IPAddr), pNI->flag, (pNI->GatewayIpAddr), pNI->GatewayMacAddr[0], pNI->GatewayMacAddr[1], pNI->GatewayMacAddr[2], pNI->GatewayMacAddr[3], pNI->GatewayMacAddr[4], pNI->GatewayMacAddr[5]);

					}

				}
				

			}
			pListEntry	=	pListEntry->Flink;
		}

	} while (0);


	return status;
}
BOOLEAN	GetGatewayMacByRecvPacket(PVOID packet, PUCHAR pBuffer, ULONG uBufferLen)
{
	BOOLEAN		bRet	=FALSE;


	return bRet;

}
//////////////////////////////////////////////////////////////////////////
//在注册表HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip下查找网卡信息

BOOLEAN GetAdapterInfoEx(ADAPTER_INFO *pAI, PUNICODE_STRING pRegistryPath)
{
	/*
	OBJECT_ATTRIBUTES        ObjAttrib;
	ULONG                    nSize;
	ULONG                    nIndex;
	NTSTATUS                status;
	HANDLE                    hAdapter = NULL;
	PKEY_FULL_INFORMATION    pKeyFullInfo = NULL;
	ULONG					uTmp;

	InitializeObjectAttributes(&ObjAttrib, &ustrAdapter, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwOpenKey(&hAdapter, KEY_READ, &ObjAttrib);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVBUS_ID ,DPFLTR_ERROR_LEVEL,"ZwOpenKey Error: %x\n", status);
		break;
	}
	ZwQueryKey(hAdapter, KeyFullInformation, NULL, 0, &nSize);
	pKeyFullInfo = (PKEY_FULL_INFORMATION)kmalloc( nSize);
	if (!pKeyFullInfo)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		return status;
	}
	status  = ZwQueryKey(hAdapter, KeyFullInformation, pKeyFullInfo, nSize, &nSize);

	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVBUS_ID ,DPFLTR_ERROR_LEVEL,";ZwQueryKey Error: %x\n", status);
		kfree(pKeyFullInfo);
		return status;
	}

	for (nIndex = 0; nIndex< pKeyFullInfo->Values; nIndex ++)
	{
		PKEY_VALUE_BASIC_INFORMATION        pKeyValueBasicInfo = NULL;
		HANDLE                        hDev = NULL;
		pKeyValueBasicInfo = NULL;

		do
		{
			UNICODE_STRING        strKeyName;
			UNICODE_STRING        ustrtmp ;
			IO_STATUS_BLOCK        IoStatusBlock;
			ULONG                nOid;

			ZwEnumerateValueKey(hAdapter, nIndex, KeyValueBasicInformation, NULL, 0, &nSize);
			pKeyValueBasicInfo = (PKEY_BASIC_INFORMATION) kmalloc(nSize);
			if (NULL == pKeyValueBasicInfo)
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			status = ZwEnumerateValueKey(hAdapter, nIndex, KeyValueBasicInformation, pKeyValueBasicInfo, nSize, &nSize);
			if (!NT_SUCCESS(status))
			{
				kprintf("ZwEnumerateValueKey fail \n");
				
				break;
			}
			strKeyName.Buffer = pKeyValueBasicInfo->Name;
			strKeyName.MaximumLength = (USHORT)pKeyValueBasicInfo->NameLength;
			strKeyName.Length = (USHORT)pKeyValueBasicInfo->NameLength;

			RtlInitUnicodeString(&ustrtmp, L"DefaultGateway");
			if (RtlEqualUnicodeString(&strKeyName, &ustrtmp, FALSE))
			{
				
			}

		}while(0);

		if (pKeyValueBasicInfo)
		{
			kfree(pKeyValueBasicInfo);
		}
	}

	if (hAdapter)
	{
		ZwClose(hAdapter);
	}

	*/
	return TRUE;

}
//////////////////////////////////////////////////////////////////////////