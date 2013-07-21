#include "comhdr.h"




//////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////

PVOID CUdpTrafficControl::makeSendInfoByBuffer(PVOID pBuffer, int len)
{

	return NULL;
}
//////////////////////////////////////////////////////////////////////////

bool CUdpTrafficControl::SendUdpPacket(PVOID pBuffer, int len,ULONG dstIP, USHORT dstPort)
{


	OVERLAPPED	varOverLapped;  
	HANDLE		hNotifyEvent=0;

	DWORD	dwBufferSize	=	sizeof(SEND_UDP_INFO)+ len;
	PSEND_UDP_INFO	pSendInfo	=	(PSEND_UDP_INFO)new char[dwBufferSize];
	ZeroMemory(pSendInfo, dwBufferSize);
	
	hNotifyEvent	=	CreateEvent(NULL, FALSE, FALSE, "");
	memset(&varOverLapped,0,sizeof(OVERLAPPED));  
	varOverLapped.hEvent = hNotifyEvent;  
	varOverLapped.Offset = 0;  
	varOverLapped.OffsetHigh = 0;

	pSendInfo->dstIP	=	dstIP;
	pSendInfo->dwSize	=	len;
	pSendInfo->dstPort	=	dstPort;
	pSendInfo->srcIP	=	0;	//如果是0，说明随意
	memcpy(pSendInfo->pbuffer, pBuffer, len);

	//异步都搞烦了
	DWORD	dwRet=0;
	bool bret = DeviceIoControl(g_SuperCIHandle, IOCTL_SEND_UDP, pSendInfo, dwBufferSize, NULL, NULL,&dwRet, &varOverLapped);
	DWORD dwLastError	=	GetLastError();
	char 	strOutput[512];
	sprintf(strOutput, "DeviceIoControl IOCTL_SEND_UDP return %d, Lasterror %d\r\n", bret , GetLastError());
	OutputDebugString(strOutput);
	
	delete	pSendInfo;
	if (!bret)
	{
		if (dwLastError!=ERROR_IO_PENDING)
		{
			return false;
		}
		
	}
	DWORD varEventResult = WaitForSingleObject(hNotifyEvent,2*1000);// wait for 2s
	CloseHandle(hNotifyEvent);
	if (varEventResult!=WAIT_OBJECT_0)
	{
		return false;
	}
	DWORD dwBytes=0;
	if (!GetOverlappedResult(g_SuperCIHandle, &varOverLapped, &dwBytes, FALSE))
	{
		return false;
	}
	return true;
}

