/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#ifndef _MXLIBHLP_SERVICE_MANAGER_H
#define _MXLIBHLP_SERVICE_MANAGER_H

#include <Defines.h>
#include <Windows.h>

//-----------------------------------------------------------

namespace MX {

class CServiceManager : public virtual CBaseMemObj
{
public:
  typedef enum {
    ServiceTypeLocalSystem,
    ServiceTypeKernelDriver,
    ServiceTypeNetworkService
  } eServiceType;

  CServiceManager();
  ~CServiceManager();

  HRESULT OpenManager(_In_ BOOL bFullAccess, _In_opt_z_ LPCWSTR szServerW=NULL);
  VOID CloseManager();

  //NOTE: If service already exists, it's configuration will be updated
  HRESULT Create(_In_ eServiceType nServiceType, _In_z_ LPCWSTR szServiceNameW, _In_z_ LPCWSTR szServiceDisplayNameW,
                 _In_z_ LPCWSTR szFileNameW, _In_ BOOL bAutoStart, _In_opt_z_ LPCWSTR szDependenciesW=NULL,
                 _In_opt_z_ LPCWSTR szRequiredPrivilegesW=NULL, _In_opt_ DWORD dwRestartOnFailureTimeMs=0);
  HRESULT Open(_In_z_ LPCWSTR szServiceNameW, _In_ DWORD dwDesiredAccess);
  VOID Close();

  HRESULT Start(_In_ DWORD dwTimeoutMs);
  HRESULT Stop(_In_opt_ DWORD dwTimeoutMs=INFINITE);

  HRESULT Delete(_In_opt_ BOOL bDoStop=TRUE, _In_opt_ DWORD dwStopTimeoutMs=INFINITE);

  HRESULT QueryStatus(_Out_ SERVICE_STATUS &sSvcStatus);

  SC_HANDLE Get() const
    {
    return hServ;
    };

private:
  SC_HANDLE hServMgr, hServ;
};

}; //namespace MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_SERVICE_MANAGER_H
