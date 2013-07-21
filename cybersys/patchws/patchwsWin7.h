#ifndef __patchwsWin7__
#define __patchwsWin7__

//Ê§°Ü·µ»Ø0
DWORD GetTargetProtocolBlockWin7(char *ProName, DWORD dwLen);



NTSTATUS	UndoPatchwsWin7();

NTSTATUS	doPatchwsWin7(char *ProName, DWORD dwLen);

VOID	NewReceiveNetBufferListsHandler(
										 ULONG                  ProtocolBindingContext,
										ULONG             pNetBufferLists,
										ULONG             PortNumber,
										IN ULONG                        NumberOfNetBufferLists,
										IN ULONG                        ReceiveFlags
										);

#endif