/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#include "ServiceManager.h"
#include "HelperRoutines.h"
#include <Debug.h>
#include <Strings\Strings.h>

//-----------------------------------------------------------

CServiceManager::CServiceManager() : MX::CBaseMemObj()
{
  hServMgr = hServ = NULL;
  return;
}

CServiceManager::~CServiceManager()
{
  CloseManager();
  return;
}

HRESULT CServiceManager::OpenManager(_In_ BOOL bFullAccess, _In_opt_z_ LPCWSTR szServerW)
{
  MX::CStringW cStrTempW;
  HRESULT hRes;

  CloseManager();
  if (szServerW != NULL && szServerW[0] != 0 && (szServerW[0] != L'.' || szServerW[1] != 0))
  {
    if (cStrTempW.Format(L"\\\\%s", szServerW) == FALSE)
      return E_OUTOFMEMORY;
    szServerW = (LPCWSTR)cStrTempW;
  }
  hServMgr = ::OpenSCManagerW(szServerW, NULL, (bFullAccess != FALSE) ? SC_MANAGER_ALL_ACCESS : SC_MANAGER_CONNECT);
  if (hServMgr == NULL)
  {
    hRes = MX_HRESULT_FROM_LASTERROR();
    return hRes;
  }
  return S_OK;
}

VOID CServiceManager::CloseManager()
{
  Close();
  if (hServMgr != NULL)
  {
    ::CloseServiceHandle(hServMgr);
    hServMgr = NULL;
  }
  return;
}

HRESULT CServiceManager::Create(_In_ eServiceType nServiceType, _In_z_ LPCWSTR szServiceNameW,
                                _In_z_ LPCWSTR szServiceDisplayNameW, _In_z_ LPCWSTR szFileNameW, _In_ BOOL bAutoStart,
                                _In_opt_z_ LPCWSTR szDependenciesW, _In_opt_z_ LPCWSTR szRequiredPrivilegesW,
                                _In_opt_ DWORD dwRestartOnFailureTimeMs)
{
  //Reference:
  //  CC – SERVICE_QUERY_CONFIG – ask the SCM for the service’s current configuration
  //  LC – SERVICE_QUERY_STATUS – ask the SCM for the service’s current status
  //  SW – SERVICE_ENUMERATE_DEPENDENTS – list dependent services
  //  LO – SERVICE_INTERROGATE – ask the service its current status
  //  CR – SERVICE_USER_DEFINED_CONTROL – send a service control defined by the service’s authors
  //  RC – READ_CONTROL – read the security descriptor on this service.
  //  RP – SERVICE_START – start the service
  //  WP – SERVICE_STOP – stop the service
  //  DT – SERVICE_PAUSE_CONTINUE – pause / continue the service
  //  SD - DELETE
  //  DC - SERVICE_CHANGE_CONFIG - the right to reconfigure the service
  //  SD - DELETE - the right to delete the service
  //  WD - WRITE_DAC - permission to change the permissions
  //  WO - WRITE_OWNER - permission to take ownership

  //D:(A;;GA;;;SY)
  //  (A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)
  //  (A;;CCLCSWRPLOCRRC;;;IU)
  //  (A;;CCLCSWRPLOCRRC;;;SU)
  //  (A;;CCLCSWRPLOCRRC;;;AU)
  //S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD) -Enable auditing for anyone
  static const BYTE aSecDescr[] = {
    0x01, 0x00, 0x14, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
    0x30, 0x00, 0x00, 0x00, 0x02, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x80, 0x14, 0x00,
    0xFF, 0x01, 0x0F, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x70, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0xFD, 0x01, 0x02, 0x00,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00,
    0xFF, 0x01, 0x0F, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00,
    0x20, 0x02, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x9D, 0x01, 0x02, 0x00, 0x01, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x05, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x9D, 0x01, 0x02, 0x00,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00,
    0x9D, 0x01, 0x02, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x0B, 0x00, 0x00, 0x00
  };
  static const LPCWSTR szNetworkServiceAccountW = L"NT AUTHORITY\\NetworkService";
  SERVICE_REQUIRED_PRIVILEGES_INFOW sReqPrivInfoW;
  BOOL bIsWindowsVistaOrLater;
  HRESULT hRes;

  if (szServiceNameW == NULL || szServiceDisplayNameW == NULL || szFileNameW == NULL)
    return E_POINTER;
  if (*szServiceNameW == 0 || *szServiceDisplayNameW == 0 || *szFileNameW == 0)
    return E_INVALIDARG;
  if (nServiceType != ServiceTypeLocalSystem && nServiceType != ServiceTypeKernelDriver &&
      nServiceType != ServiceTypeNetworkService)
    return E_INVALIDARG;
  if (hServMgr == NULL)
    return MX_E_NotReady;
  if (szDependenciesW != NULL && *szDependenciesW == 0)
    szDependenciesW = NULL;
  bIsWindowsVistaOrLater = HelperRoutines::IsWindowsVistaOrLater();
  //create service
  Close();
  hServ = ::CreateServiceW(hServMgr, szServiceNameW, szServiceDisplayNameW, SERVICE_ALL_ACCESS,
                           (nServiceType != ServiceTypeKernelDriver) ? SERVICE_WIN32_OWN_PROCESS
                                                                     : SERVICE_KERNEL_DRIVER,
                           (bAutoStart != FALSE) ? SERVICE_AUTO_START : SERVICE_DEMAND_START,
                           SERVICE_ERROR_NORMAL, szFileNameW, NULL, NULL, szDependenciesW,
                           (nServiceType != ServiceTypeNetworkService) ? NULL : szNetworkServiceAccountW, NULL);
  if (hServ == NULL)
  {
    hRes = MX_HRESULT_FROM_LASTERROR();
    if (hRes != HRESULT_FROM_WIN32(ERROR_SERVICE_EXISTS) && hRes != HRESULT_FROM_WIN32(ERROR_DUPLICATE_SERVICE_NAME))
      return hRes;
    //if service already exists, open it and update
    hServ = ::OpenServiceW(hServMgr, szServiceNameW, SERVICE_ALL_ACCESS);
    if (hServ == NULL)
      return MX_HRESULT_FROM_LASTERROR();
    if (::ChangeServiceConfigW(hServ, (nServiceType != ServiceTypeKernelDriver) ? SERVICE_WIN32_OWN_PROCESS
                                                                                : SERVICE_KERNEL_DRIVER,
                               (bAutoStart != FALSE) ? SERVICE_AUTO_START : SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                               szFileNameW, NULL, NULL, szDependenciesW,
                               (nServiceType != ServiceTypeNetworkService) ? NULL : szNetworkServiceAccountW, NULL,
                               szServiceDisplayNameW) == FALSE)
    {
      hRes = MX_HRESULT_FROM_LASTERROR();
      ::CloseServiceHandle(hServ);
      hServ = NULL;
      return hRes;
    }
 }
  //change security
  hRes = S_OK;
  if (::SetServiceObjectSecurity(hServ, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)aSecDescr) == FALSE)
  {
    hRes = MX_HRESULT_FROM_LASTERROR();
  }
  //setup required privileges
  if (SUCCEEDED(hRes) && bIsWindowsVistaOrLater != FALSE && nServiceType != ServiceTypeKernelDriver &&
      szRequiredPrivilegesW != NULL && *szRequiredPrivilegesW != 0)
  {
    sReqPrivInfoW.pmszRequiredPrivileges = (LPWSTR)szRequiredPrivilegesW;
    if (::ChangeServiceConfig2W(hServ, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, &sReqPrivInfoW) == FALSE)
    {
      hRes = MX_HRESULT_FROM_LASTERROR();
    }
  }
  //setup sid info
  if (SUCCEEDED(hRes) && bIsWindowsVistaOrLater != FALSE && nServiceType != ServiceTypeKernelDriver)
  {
    SERVICE_SID_INFO sServSidInfo;

    sServSidInfo.dwServiceSidType = SERVICE_SID_TYPE_UNRESTRICTED;
    if (::ChangeServiceConfig2W(hServ, SERVICE_CONFIG_SERVICE_SID_INFO, &sServSidInfo) == FALSE)
    {
      hRes = MX_HRESULT_FROM_LASTERROR();
    }
  }
  //setup restart time
  if (SUCCEEDED(hRes) && nServiceType != ServiceTypeKernelDriver && dwRestartOnFailureTimeMs > 0)
  {
    SERVICE_FAILURE_ACTIONSW sSfaW;
    SC_ACTION sSfaActions[1];
    SERVICE_FAILURE_ACTIONS_FLAG sSfaf;

    sSfaf.fFailureActionsOnNonCrashFailures = FALSE;
    MX::MemSet(&sSfaW, 0, sizeof(sSfaW));
    sSfaW.dwResetPeriod = INFINITE;
    sSfaW.cActions = 1;
    sSfaW.lpsaActions = sSfaActions;
    sSfaActions[0].Type = SC_ACTION_RESTART;
    sSfaActions[0].Delay = dwRestartOnFailureTimeMs;
    if (::ChangeServiceConfig2W(hServ, SERVICE_CONFIG_FAILURE_ACTIONS, &sSfaW) != FALSE)
    {
      if (bIsWindowsVistaOrLater != FALSE)
      {
        if (::ChangeServiceConfig2W(hServ, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &sSfaf) == FALSE)
        {
          hRes = MX_HRESULT_FROM_LASTERROR();
        }
      }
    }
    else
    {
      hRes = MX_HRESULT_FROM_LASTERROR();
    }
  }
  //done
  if (FAILED(hRes))
  {
    ::DeleteService(hServ);
    ::CloseServiceHandle(hServ);
    hServ = NULL;
  }
  return hRes;
}

HRESULT CServiceManager::Open(_In_z_ LPCWSTR szServiceNameW, _In_ DWORD dwDesiredAccess)
{
  if (szServiceNameW == NULL)
    return E_POINTER;
  if (*szServiceNameW == 0)
    return E_INVALIDARG;
  if (hServMgr == NULL)
    return MX_E_NotReady;
  //open service
  Close();
  hServ = ::OpenServiceW(hServMgr, szServiceNameW, dwDesiredAccess);
  return (hServ != NULL) ? S_OK : MX_HRESULT_FROM_LASTERROR();
}

VOID CServiceManager::Close()
{
  if (hServ != NULL)
  {
    ::CloseServiceHandle(hServ);
    hServ = NULL;
  }
  return;
}

HRESULT CServiceManager::Start(_In_ DWORD dwTimeoutMs)
{
  SERVICE_STATUS sSvcStatus;
  DWORD dwOldCheckPoint, dwOrigTimeoutMs;
  HRESULT hRes;

  if (hServ == NULL)
    return MX_E_NotReady;
  //start service
  if (::StartServiceW(hServ, 0, NULL) == FALSE)
  {
    hRes = MX_HRESULT_FROM_LASTERROR();
    if (hRes != HRESULT_FROM_WIN32(ERROR_SERVICE_ALREADY_RUNNING))
      return hRes;
  }
  //wait until operation is complete
  dwOrigTimeoutMs = dwTimeoutMs;
  dwOldCheckPoint = 0;
  while (1)
  {
    MX::MemSet(&sSvcStatus, 0, sizeof(sSvcStatus));
    if (::QueryServiceStatus(hServ, &sSvcStatus) == FALSE)
      return MX_HRESULT_FROM_LASTERROR();
    if (sSvcStatus.dwCurrentState == SERVICE_RUNNING)
      break;
    if (sSvcStatus.dwCurrentState != SERVICE_START_PENDING)
      return (sSvcStatus.dwWin32ExitCode != 0) ? HRESULT_FROM_WIN32(sSvcStatus.dwWin32ExitCode) : E_FAIL;
    if (dwTimeoutMs == 0)
      return MX_E_Timeout;
    if (sSvcStatus.dwWaitHint > 1000)
      sSvcStatus.dwWaitHint = 1000;
    else if (sSvcStatus.dwWaitHint < 10)
      sSvcStatus.dwWaitHint = 10;
    if (sSvcStatus.dwCheckPoint > dwOldCheckPoint)
    {
      dwTimeoutMs = dwOrigTimeoutMs;
      dwOldCheckPoint = sSvcStatus.dwCheckPoint;
    }
    if (dwTimeoutMs != INFINITE && sSvcStatus.dwWaitHint > dwTimeoutMs)
      sSvcStatus.dwWaitHint = dwTimeoutMs;
    ::Sleep(sSvcStatus.dwWaitHint);
    if (dwTimeoutMs != INFINITE)
      dwTimeoutMs = (dwTimeoutMs > sSvcStatus.dwWaitHint) ? (dwTimeoutMs-sSvcStatus.dwWaitHint) : 0;
  }
  //done
  return S_OK;
}

HRESULT CServiceManager::Stop(_In_opt_ DWORD dwTimeoutMs)
{
  SERVICE_STATUS sSvcStatus;

  if (hServ == NULL)
    return MX_E_NotReady;
  //check if service is already stopped
  MX::MemSet(&sSvcStatus, 0, sizeof(sSvcStatus));
  if (::QueryServiceStatus(hServ, &sSvcStatus) != FALSE)
  {
    if (sSvcStatus.dwCurrentState == SERVICE_STOPPED)
      return S_OK;
    if (sSvcStatus.dwCurrentState == SERVICE_STOP_PENDING)
      goto waitForStop;
  }
  //stop service
  if (::ControlService(hServ, SERVICE_CONTROL_STOP, &sSvcStatus) == FALSE)
    return MX_HRESULT_FROM_LASTERROR();
waitForStop:
  //wait until operation is complete
  MX::MemSet(&sSvcStatus, 0, sizeof(sSvcStatus));
  ::Sleep(100);
  while (::QueryServiceStatus(hServ, &sSvcStatus) != FALSE)
  {
    if (sSvcStatus.dwCurrentState != SERVICE_STOP_PENDING)
      break;
    if (dwTimeoutMs != INFINITE)
    {
      if (dwTimeoutMs == 0)
        return MX_E_Timeout;
      if (dwTimeoutMs >= 100)
      {
        ::Sleep(100);
        dwTimeoutMs -= 100;
      }
      else
      {
        ::Sleep(dwTimeoutMs);
        dwTimeoutMs = 0;
      }
    }
    else
    {
      ::Sleep(100);
    }
  }
  return (sSvcStatus.dwCurrentState == SERVICE_STOPPED) ? S_OK : E_FAIL;
}

HRESULT CServiceManager::Delete(_In_opt_ BOOL bDoStop, _In_opt_ DWORD dwStopTimeoutMs)
{
  HRESULT hRes;

  if (hServ == NULL)
    return MX_E_NotReady;
  //first stop service
  hRes = (bDoStop != FALSE) ? Stop(dwStopTimeoutMs) : S_OK;
  if (SUCCEEDED(hRes))
  {
    //delete service
    if (::DeleteService(hServ) == FALSE)
    {
      hRes = MX_HRESULT_FROM_LASTERROR();
      if (hRes == HRESULT_FROM_WIN32(ERROR_SERVICE_MARKED_FOR_DELETE))
        hRes = S_OK;
    }
  }
  return hRes;
}

HRESULT CServiceManager::QueryStatus(_Out_ SERVICE_STATUS &sSvcStatus)
{
  MX::MemSet(&sSvcStatus, 0, sizeof(sSvcStatus));
  if (hServ == NULL)
    return MX_E_NotReady;
  return (::QueryServiceStatus(hServ, &sSvcStatus) != FALSE) ? S_OK : MX_HRESULT_FROM_LASTERROR();
}
