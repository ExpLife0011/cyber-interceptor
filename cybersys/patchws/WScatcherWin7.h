#ifndef __WScatcherWin7__
#define __WScatcherWin7__


VOID	NetBufferListSinfferCallback(PNET_BUFFER_LIST_KK NetBufferLists, DWORD NumberOfNetBufferLists);

VOID	WSWorkThreadWin7(PDEVICE_OBJECT  DeviceObject, PVOID	pContext);

VOID	WSWorkThreadWin7ForNdis5(PDEVICE_OBJECT  DeviceObject, PVOID	pContext);

VOID	NetBufferListSinfferCallbackWin7(PNET_BUFFER_LIST_KK NetBufferLists, DWORD NumberOfNetBufferLists);


#endif