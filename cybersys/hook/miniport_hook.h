

#ifndef _MINIPORT_HOOK_H
#define _MINIPORT_HOOK_H


//hook info
typedef struct __NDIS_HOOK_INFO__
{

	LIST_ENTRY	Next;
	PVOID		Address2Restore;
	PVOID		OldHandler;
	PVOID		NewHandler;
	PVOID		pSignContext;//为了区分多个网卡的情况
	DWORD		HandlerSign;	//send or Recv,or.....
	DWORD		Count;
	PVOID		pReserveContext1;
	CHAR		*szFuncname;
	DWORD		uHandlerType;
	ULONG_PTR		pMiniBlock;
	ULONG_PTR		pOpenblock;
	ULONG_PTR		pProtocolBlock;
	ULONG_PTR		pProtocolBindingContext;
	ULONG_PTR		pMiniportAdaptContext;

}NDIS_HOOK_INFO,*PNDIS_HOOK_INFO;



ULONG	GetMDriverBlockHeader();

/*__inline*/ PVOID	GetOldHandler(PVOID pSgin,PVOID pNewHandler);


BOOLEAN	UnHook(void);

BOOLEAN	ReleaseHookInfo(void);

NTSTATUS	StartMiniportHookEx();

//如果失败，则返回0

DWORD	GetProtocolHeader();


extern BOOLEAN tdifw_register_user_device(PDEVICE_OBJECT dev);

NTSTATUS InitMiniPortHook();




VOID
PtBindAdapter(
			  OUT PNDIS_STATUS              Status,
			  IN  NDIS_HANDLE               BindContext,
			  IN  PNDIS_STRING              DeviceName,
			  IN  PVOID                     SystemSpecific1,
			  IN  PVOID                     SystemSpecific2
			  );


VOID
PtUnbindAdapter(
				OUT PNDIS_STATUS              Status,
				IN  NDIS_HANDLE               ProtocolBindingContext,
				IN  NDIS_HANDLE               UnbindContext
				);


VOID
MPAdapterShutdown(
				  IN NDIS_HANDLE                MiniportAdapterContext
				  );
NTSTATUS
DriverEntry(
			IN PDRIVER_OBJECT		DriverObject,
			IN PUNICODE_STRING		RegistryPath
			);

NTSTATUS
Miniport_hookDispatchCreate(
							IN PDEVICE_OBJECT		DeviceObject,
							IN PIRP					Irp
							);

NTSTATUS
Miniport_hookDispatchClose(
						   IN PDEVICE_OBJECT		DeviceObject,
						   IN PIRP					Irp
						   );

NTSTATUS
Miniport_hookDispatchDeviceControl(
								   IN PDEVICE_OBJECT		DeviceObject,
								   IN PIRP					Irp
								   );
VOID
MPDevicePnPEvent(
				 IN NDIS_HANDLE              MiniportAdapterContext,
				 IN NDIS_DEVICE_PNP_EVENT    DevicePnPEvent,
				 IN PVOID                    InformationBuffer,
				 IN ULONG                    InformationBufferLength
				 );
VOID
Miniport_hookUnload(
					IN PDRIVER_OBJECT		DriverObject
);




#endif