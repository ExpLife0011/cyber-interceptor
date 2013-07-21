#pragma once

class CPatchWS
{
public:
	CPatchWS(void);
	~CPatchWS(void);
	bool doPatch(char *name);
	bool UndoPatch(char *name);

	BOOL PatchDontLoopback(void);
	BOOL PatchRestoreDontLoopback(void);
};
