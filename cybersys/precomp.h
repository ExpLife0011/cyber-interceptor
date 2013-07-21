/*++

Copyright (c) 2008  Chunhua Liu.

Module Name:

    precomp.h

Abstract:

    This framework is generated by QuickSYS 0.4

Environment:

	Kernel mode only.

Notes:


Revision History:

--*/

#ifndef _PRECOMP_H
#define _PRECOMP_H 1

//#include <ntddk.h>
#include <ntifs.h>
#pragma warning( push )
#pragma warning( disable : 6011 )

#include <ntstrsafe.h>
#pragma warning( pop )
#pragma warning( disable : 4995 )


#define dprintf if (DBG) DbgPrint
#define nprintf DbgPrint

#define kmalloc(_s)	ExAllocatePoolWithTag(NonPagedPool, _s, 'cybe')
//#define kfree(_p)	ExFreePoolWithTag(_p, 'SYSQ')
#define kfree(_p)	ExFreePool(_p)

#endif
