/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#include "ServiceManager.h"
#include <Debug.h>
#include <Strings\Strings.h>
#include <VersionHelpers.h>

//-----------------------------------------------------------

static DWORD GetServiceStartType(_In_ MX::CServiceManager::eStartMode nStartMode);

//-----------------------------------------------------------

namespace MX {

CServiceManager::CServiceManager() : CBaseMemObj()
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
  CStringW cStrTempW;
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

HRESULT CServiceManager::Create(_In_z_ LPCWSTR szServiceNameW, _In_ LPCREATEINFO lpCreateInfo)
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
  BOOL bIsWindowsVistaOrLater;
  DWORD dwServiceType, dwStartType;
  HRESULT hRes;

  if (szServiceNameW == NULL || lpCreateInfo == NULL || lpCreateInfo->szServiceDisplayNameW == NULL ||
      lpCreateInfo->szFileNameW == NULL)
  {
    return E_POINTER;
  }
  if (*szServiceNameW == 0 || *(lpCreateInfo->szServiceDisplayNameW) == 0 || *(lpCreateInfo->szFileNameW) == 0)
    return E_INVALIDARG;
  dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  switch (lpCreateInfo->nServiceType)
  {
    case ServiceTypeLocalSystem:
    case ServiceTypeNetworkService:
      break;

    case ServiceTypeKernelDriver:
      dwServiceType = SERVICE_KERNEL_DRIVER;
      break;

    case ServiceTypeFileSystemDriver:
      dwServiceType = SERVICE_FILE_SYSTEM_DRIVER;
      break;

    default:
      return E_INVALIDARG;
  }
  dwStartType = GetServiceStartType(lpCreateInfo->nStartMode);
  if (dwStartType == 0xFFFFFFFFUL)
    return E_INVALIDARG;
  if (hServMgr == NULL)
    return MX_E_NotReady;
  bIsWindowsVistaOrLater = ::IsWindowsVistaOrGreater();
  //create service
  Close();
  hServ = ::CreateServiceW(hServMgr, szServiceNameW, lpCreateInfo->szServiceDisplayNameW, SERVICE_ALL_ACCESS,
                           dwServiceType, dwStartType, SERVICE_ERROR_NORMAL, lpCreateInfo->szFileNameW,
                           (lpCreateInfo->szLoadOrderGroupW != NULL &&
                            *(lpCreateInfo->szLoadOrderGroupW) != 0) ? lpCreateInfo->szLoadOrderGroupW : NULL,
                           NULL,
                           (lpCreateInfo->szDependenciesW != NULL &&
                            *(lpCreateInfo->szDependenciesW) != 0) ? lpCreateInfo->szDependenciesW : NULL,
                           (lpCreateInfo->nServiceType != ServiceTypeNetworkService) ? NULL : szNetworkServiceAccountW,
                           NULL);
  if (hServ == NULL)
  {
    hRes = MX_HRESULT_FROM_LASTERROR();
    if (hRes != HRESULT_FROM_WIN32(ERROR_SERVICE_EXISTS) && hRes != HRESULT_FROM_WIN32(ERROR_DUPLICATE_SERVICE_NAME))
    {
      //MX::DebugPrint("ServiceManager/CreateServiceW: %08X\n", hRes);
      return hRes;
    }
    //if service already exists, open it and update
    hServ = ::OpenServiceW(hServMgr, szServiceNameW, SERVICE_ALL_ACCESS);
    if (hServ == NULL)
      return MX_HRESULT_FROM_LASTERROR();
    if (::ChangeServiceConfigW(hServ, dwServiceType, dwStartType, SERVICE_ERROR_NORMAL, lpCreateInfo->szFileNameW,
                               (lpCreateInfo->szLoadOrderGroupW != NULL &&
                                *(lpCreateInfo->szLoadOrderGroupW) != 0) ? lpCreateInfo->szLoadOrderGroupW : NULL,
                               NULL,
                               (lpCreateInfo->szDependenciesW != NULL &&
                                *(lpCreateInfo->szDependenciesW) != 0) ? lpCreateInfo->szDependenciesW : L"\0",
                               (lpCreateInfo->nServiceType != ServiceTypeNetworkService) ? NULL
                                                                                         : szNetworkServiceAccountW,
                               NULL, lpCreateInfo->szServiceDisplayNameW) == FALSE)
    {
      hRes = MX_HRESULT_FROM_LASTERROR();
      ::CloseServiceHandle(hServ);
      hServ = NULL;
      //MX::DebugPrint("ServiceManager/ChangeServiceConfigW: %08X\n", hRes);
      return hRes;
    }
 }
  //change security
  hRes = S_OK;
  if (::SetServiceObjectSecurity(hServ, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)aSecDescr) == FALSE)
    hRes = MX_HRESULT_FROM_LASTERROR();
  //setup required privileges
  if (SUCCEEDED(hRes) && bIsWindowsVistaOrLater != FALSE &&
      (lpCreateInfo->nServiceType == ServiceTypeLocalSystem || lpCreateInfo->nServiceType == ServiceTypeNetworkService))
  {
    SERVICE_REQUIRED_PRIVILEGES_INFOW sReqPrivInfoW;

    sReqPrivInfoW.pmszRequiredPrivileges = (lpCreateInfo->szRequiredPrivilegesW != NULL &&
                                            *(lpCreateInfo->szRequiredPrivilegesW) != 0)
                                           ? (LPWSTR)(lpCreateInfo->szRequiredPrivilegesW) : L"";
    if (::ChangeServiceConfig2W(hServ, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, &sReqPrivInfoW) == FALSE)
    {
      hRes = MX_HRESULT_FROM_LASTERROR();
      //MX::DebugPrint("ServiceManager/ChangeServiceConfig2W(1): %08X\n", hRes);
    }
  }
  //setup sid info
  if (SUCCEEDED(hRes) && bIsWindowsVistaOrLater != FALSE &&
      (lpCreateInfo->nServiceType == ServiceTypeLocalSystem || lpCreateInfo->nServiceType == ServiceTypeNetworkService))
  {
    SERVICE_SID_INFO sServSidInfo;

    sServSidInfo.dwServiceSidType = SERVICE_SID_TYPE_UNRESTRICTED;
    if (::ChangeServiceConfig2W(hServ, SERVICE_CONFIG_SERVICE_SID_INFO, &sServSidInfo) == FALSE)
    {
      hRes = MX_HRESULT_FROM_LASTERROR();
      //MX::DebugPrint("ServiceManager/ChangeServiceConfig2W(2): %08X\n", hRes);
    }
  }
  //setup restart time
  if (SUCCEEDED(hRes) &&
      (lpCreateInfo->nServiceType == ServiceTypeLocalSystem || lpCreateInfo->nServiceType == ServiceTypeNetworkService))
  {
    SERVICE_FAILURE_ACTIONSW sServFailActW;
    SC_ACTION aServActions[1];

    MemSet(&sServFailActW, 0, sizeof(sServFailActW));
    sServFailActW.dwResetPeriod = INFINITE;
    sServFailActW.cActions = 1;
    sServFailActW.lpsaActions = aServActions;
    MemSet(aServActions, 0, sizeof(aServActions));
    if (lpCreateInfo->sFailureControl.bAutoRestart != FALSE)
    {
      aServActions[0].Type = SC_ACTION_RESTART;
      aServActions[0].Delay = lpCreateInfo->sFailureControl.dwRestartDelayMs;
    }
    if (::ChangeServiceConfig2W(hServ, SERVICE_CONFIG_FAILURE_ACTIONS, &sServFailActW) != FALSE)
    {
      if (lpCreateInfo->sFailureControl.bAutoRestart != FALSE && bIsWindowsVistaOrLater != FALSE)
      {
        SERVICE_FAILURE_ACTIONS_FLAG sServFailActFlagW;

        MemSet(&sServFailActFlagW, 0, sizeof(sServFailActFlagW));
        sServFailActFlagW.fFailureActionsOnNonCrashFailures = FALSE;
        if (::ChangeServiceConfig2W(hServ, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &sServFailActFlagW) == FALSE)
        {
          hRes = MX_HRESULT_FROM_LASTERROR();
          //MX::DebugPrint("ServiceManager/ChangeServiceConfig2W(3): %08X\n", hRes);
        }
      }
    }
    else
    {
      hRes = MX_HRESULT_FROM_LASTERROR();
      //MX::DebugPrint("ServiceManager/ChangeServiceConfig2W(4): %08X\n", hRes);
    }
  }
  if (SUCCEEDED(hRes) &&
      (lpCreateInfo->nServiceType == ServiceTypeLocalSystem || lpCreateInfo->nServiceType == ServiceTypeNetworkService))
  {
    SERVICE_DESCRIPTIONW sServDescW;

    MemSet(&sServDescW, 0, sizeof(sServDescW));
    sServDescW.lpDescription = (lpCreateInfo->szDescriptionW != NULL) ? lpCreateInfo->szDescriptionW : L"";
    if (::ChangeServiceConfig2W(hServ, SERVICE_CONFIG_DESCRIPTION, &sServDescW) == FALSE)
    {
      hRes = MX_HRESULT_FROM_LASTERROR();
      //MX::DebugPrint("ServiceManager/ChangeServiceConfig2W(5): %08X\n", hRes);
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
    MemSet(&sSvcStatus, 0, sizeof(sSvcStatus));
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
  MemSet(&sSvcStatus, 0, sizeof(sSvcStatus));
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
  MemSet(&sSvcStatus, 0, sizeof(sSvcStatus));
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
  MemSet(&sSvcStatus, 0, sizeof(sSvcStatus));
  if (hServ == NULL)
    return MX_E_NotReady;
  return (::QueryServiceStatus(hServ, &sSvcStatus) != FALSE) ? S_OK : MX_HRESULT_FROM_LASTERROR();
}

HRESULT CServiceManager::ChangeStartMode(_In_ eStartMode nStartMode)
{
  DWORD dwStartType;

  if (hServ == NULL)
    return MX_E_NotReady;
  dwStartType = GetServiceStartType(nStartMode);
  if (dwStartType == 0xFFFFFFFFUL)
    return E_INVALIDARG;
  if (::ChangeServiceConfigW(hServ, SERVICE_NO_CHANGE, dwStartType, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL,
                             NULL, NULL, NULL) == FALSE)
  {
    return MX_HRESULT_FROM_LASTERROR();;
  }
  //done
  return S_OK;
}

}; //namespace MX

//-----------------------------------------------------------

static DWORD GetServiceStartType(_In_ MX::CServiceManager::eStartMode nStartMode)
{
  switch (nStartMode)
  {
    case MX::CServiceManager::StartModeAuto:
      return SERVICE_AUTO_START;
    case MX::CServiceManager::StartModeBoot:
      return SERVICE_BOOT_START;
    case MX::CServiceManager::StartModeSystem:
      return SERVICE_SYSTEM_START;
    case MX::CServiceManager::StartModeManual:
      return SERVICE_DEMAND_START;
    case MX::CServiceManager::StartModeDisabled:
      return SERVICE_DISABLED;
  }
  return 0xFFFFFFFFUL;
}
