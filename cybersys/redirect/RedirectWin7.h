#ifndef __RedirectNetBufferWin7__
#define	__RedirectNetBufferWin7__




VOID RedirectNetBufferRecvCallbackWin7(PNET_BUFFER_LIST_KK pNetBufferLists, DWORD	dwNumber);

VOID RedirectNetBufferSendCallbackWin7(PNET_BUFFER_LIST_KK pNetBufferLists, DWORD	dwNumber);

void	RedirectRecvWin7(NET_BUFFER_KK *pNet_buffer);

void	RedirectSendWin7(NET_BUFFER_KK *pNet_buffer);


#endif