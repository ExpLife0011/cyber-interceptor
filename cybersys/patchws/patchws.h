#ifndef __patchws__
#define __patchws__




NTSTATUS	DoPatchWS();
NTSTATUS	CheckProtocolExist(char *DrvName, DWORD dwLen);
NTSTATUS	DoPatchWS2(char *DrvName, DWORD dwLen);
NTSTATUS	UnDoPatchWS2(char *DrvName, DWORD dwLen);
ULONG	GetProtocolBlockXP(char *ProName, DWORD dwlen);

VOID	NewNPFReceiveHandler();
VOID	NewNPFReceivePacketHandler();

/*

npf+0x4300:
aa801300 8bff            mov     edi,edi
aa801302 55              push    ebp
aa801303 8bec            mov     ebp,esp
aa801305 83ec20          sub     esp,20h
lkd> db aa801300
aa801300  8b ff 55 8b ec 

*/

//////////////////////////////////////////////////////////////////////////

extern ULONG_PTR	g_NPFReceiveHandler;
extern ULONG_PTR	g_NPFReceivePacketHandler;

#endif