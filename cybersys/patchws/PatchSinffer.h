#ifndef __PatchSinffer__
#define __PatchSinffer__




NTSTATUS
PatchDispatch(IN PDEVICE_OBJECT		DeviceObject, IN PIRP	Irp);

NTSTATUS	PatchDontLoopbackForXp();
NTSTATUS	PatchRestoreDontLoopbackForXp();

NTSTATUS	UnInitPatch();

NTSTATUS	GetProtocolList(char *pbuffer, DWORD *dwlen);

#endif