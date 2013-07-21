#pragma once
#include <string>

class CDriverLoader
{
public:
	CDriverLoader(void);
	~CDriverLoader(void);

	bool MyZwLoadDriver(char * szDrvName, char * szDrvPath);
	bool MyZwUnloadDriver(char * szDrvName, char * szDrvPath);
	std::string	m_szDrvName;
	std::string	m_szDrvPath;
	bool	bDriverLoaded;

};
