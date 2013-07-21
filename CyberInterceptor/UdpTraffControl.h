

#pragma once


class CUdpTrafficControl
{
public:

	
protected:
private:
public:

	bool SendUdpPacket(PVOID pp, int iLen,ULONG dstIP, USHORT dstPort);
	PVOID makeSendInfoByBuffer(PVOID pBuffer, int len);

};
