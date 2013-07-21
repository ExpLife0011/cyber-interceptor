
/********************************************************************

	filename: 	e:\dev\CyberInterceptor\sys\udptraffic\udpTraffic.c
	file path:	e:\dev\CyberInterceptor\sys\udptraffic
	file base:	udpTraffic
	file ext:	c
	author:		kindof
	
	purpose:	
*********************************************************************/
#ifndef __FIREWALL__
#define __FIREWALL__







typedef	struct	__ASKUserWorkItemContext__
{
	PIO_WORKITEM	pWorkItem;
	PVOID			pContext;
}ASKUserWorkItemContext, *PASKUserWorkItemContext;

NTSTATUS	InitFW();

NTSTATUS	UninitFW();

NTSTATUS	FWHookTcpipRecvHandler();

NTSTATUS	FWUnhookTcpipRecvHandler();

NTSTATUS	FWReleasePortRuleList();
NTSTATUS FWDispatch(
					IN PDEVICE_OBJECT		DeviceObject,
					IN PIRP					Irp
					);
NDIS_STATUS
KKNewTcpipArpRcv(
				 IN  NDIS_HANDLE         ProtocolBindingContext,
				 IN  NDIS_HANDLE         MacReceiveContext,
				 IN  PVOID               HeaderBuffer,
				 IN  UINT                HeaderBufferSize,
				 IN  PVOID               LookAheadBuffer,
				 IN  UINT                LookAheadBufferSize,
				 IN  UINT                PacketSize
				 );
#endif