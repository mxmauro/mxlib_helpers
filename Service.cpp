/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#include "Service.h"
#include <AutoHandle.h>
#include <Strings\Strings.h>
#include <AutoPtr.h>
#include <AutoHandle.h>
#include <Debug.h>
#include "SingleInstance.h"

//-----------------------------------------------------------

static MX::CWindowsEvent cShutdownEv;
static SERVICE_STATUS_HANDLE hServiceStatus = NULL;
static SERVICE_STATUS sServiceStatus = {
  SERVICE_WIN32_OWN_PROCESS, SERVICE_STOPPED, SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN, NO_ERROR, 0, 0, 0
};
static MX::CStringW cStrServiceNameW;
static MXHelpers::Service::OnStartCallback cStartCallback = MX::NullCallback();
static MXHelpers::Service::OnStopCallback cStopCallback = MX::NullCallback();
static BOOL bRunningAsConsole = FALSE;
static int nArgumentsCount = 0;
static WCHAR** lpArguments = NULL;
static BOOL bDisableStop = FALSE;

//-----------------------------------------------------------

static BOOL WINAPI _ConsoleHandlerRoutine(_In_ DWORD dwCtrlType);
static VOID WINAPI _ServiceMain(_In_ DWORD dwArgc, _In_ LPWSTR *pszArgv);
static VOID WINAPI _ServiceCtrlHandler(_In_ DWORD dwCtrl);
static HRESULT _SetServiceStatus(_In_ DWORD dwCurrentState, _In_opt_ HRESULT hResExitCode=S_OK,
                                 _In_opt_ DWORD dwWaitHint=0, _In_opt_ HRESULT hResServiceSpecificExitCode=S_OK);
static HRESULT _UpdateServiceStatus();
static HRESULT IsInteractiveRunningApp();

//-----------------------------------------------------------

namespace MXHelpers {

namespace Service {

HRESULT Run(_In_opt_z_ LPCWSTR szServiceNameW, _In_ OnStartCallback _cStartCallback, _In_ OnStopCallback _cStopCallback,
            _In_ int argc, _In_ WCHAR* argv[])
{
  SERVICE_TABLE_ENTRYW aServiceTableW[2];
  HRESULT hRes;

  if ((!_cStartCallback) || (!_cStopCallback))
    return E_POINTER;

  if (szServiceNameW == NULL)
    szServiceNameW = L"";
  //check for single instance
  if (*szServiceNameW != NULL)
  {
    hRes = MXHelpers::SingleInstanceCheck(szServiceNameW);
    if (FAILED(hRes))
      return hRes;
    if (hRes == S_FALSE)
      return MX_E_AlreadyInitialized;
  }
  //check for interactive or service process
  hRes = IsInteractiveRunningApp();
  if (FAILED(hRes))
    return hRes;
  bRunningAsConsole = (hRes == S_OK) ? TRUE : FALSE;
  //setup internal info
  nArgumentsCount = argc;
  lpArguments = argv;
  if (cStrServiceNameW.Copy(szServiceNameW) == FALSE)
    return E_OUTOFMEMORY;
  //set callbacks
  cStartCallback = _cStartCallback;
  cStopCallback = _cStopCallback;
  //create shutdown event
  hRes = cShutdownEv.Create(TRUE, FALSE);
  if (FAILED(hRes))
    return hRes;
  //run
  if (bRunningAsConsole == FALSE)
  {
    MX::MemSet(&aServiceTableW, 0, sizeof(aServiceTableW));
    aServiceTableW[0].lpServiceName = (LPWSTR)cStrServiceNameW;
    aServiceTableW[0].lpServiceProc = &_ServiceMain;
    hRes = (::StartServiceCtrlDispatcherW(aServiceTableW) != FALSE) ? S_OK : MX_HRESULT_FROM_LASTERROR();
  }
  else
  {
    //setup console handler
    if (::SetConsoleCtrlHandler(_ConsoleHandlerRoutine, TRUE) == FALSE)
      return MX_HRESULT_FROM_LASTERROR();
    //send start callback
    hRes = cStartCallback(cShutdownEv.Get(), nArgumentsCount, lpArguments, TRUE);
    if (SUCCEEDED(hRes))
    {
      //wait until termination event
      cShutdownEv.Wait(INFINITE);
      //send stop callback
      hRes = cStopCallback();
    }
    //remove console handler
    ::SetConsoleCtrlHandler(_ConsoleHandlerRoutine, FALSE);
  }
  //done
  return hRes;
}

VOID SignalStarting()
{
  if (bRunningAsConsole == FALSE)
    _SetServiceStatus(SERVICE_START_PENDING, ERROR_SUCCESS, 5000);
  return;
}

VOID SignalStopping()
{
  if (bRunningAsConsole == FALSE)
    _SetServiceStatus(SERVICE_START_PENDING, ERROR_SUCCESS, 5000);
  return;
}

VOID EnableStop()
{
  bDisableStop = FALSE;
  if (bRunningAsConsole == FALSE && sServiceStatus.dwCurrentState != SERVICE_START_PENDING)
  {
    sServiceStatus.dwControlsAccepted |= SERVICE_ACCEPT_STOP;
    _UpdateServiceStatus();
  }
  return;
}

VOID DisableStop()
{
  bDisableStop = TRUE;
  if (bRunningAsConsole == FALSE && sServiceStatus.dwCurrentState != SERVICE_START_PENDING)
  {
    sServiceStatus.dwControlsAccepted &= ~SERVICE_ACCEPT_STOP;
    _UpdateServiceStatus();
  }
  return;
}

}; //namespace Service

}; //namespace MXHelpers

//-----------------------------------------------------------

static BOOL WINAPI _ConsoleHandlerRoutine(_In_ DWORD dwCtrlType)
{
  switch (dwCtrlType)
  {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
      cShutdownEv.Set();
      return TRUE;
  }
  return FALSE;
}

static VOID WINAPI _ServiceMain(_In_ DWORD dwArgc, _In_ LPWSTR *pszArgv)
{
  HRESULT hRes, hResServiceExitCode;

  hServiceStatus = ::RegisterServiceCtrlHandlerW((LPCWSTR)cStrServiceNameW, _ServiceCtrlHandler);
  if (hServiceStatus == NULL)
    return;
  sServiceStatus.dwControlsAccepted = 0;
  _SetServiceStatus(SERVICE_START_PENDING, ERROR_SUCCESS, 5000);
  //----
  hRes = cShutdownEv.Create(TRUE, FALSE);
  if (SUCCEEDED(hRes))
  {
    _SetServiceStatus(SERVICE_START_PENDING, ERROR_SUCCESS, 5000);
    //send start callback
    hRes = cStartCallback(cShutdownEv.Get(), nArgumentsCount, lpArguments, FALSE);
  }
  if (SUCCEEDED(hRes))
  {
    //wait until termination event
    sServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_SHUTDOWN;
    if (bDisableStop == FALSE)
      sServiceStatus.dwControlsAccepted |= SERVICE_ACCEPT_STOP;
    _SetServiceStatus(SERVICE_RUNNING);
    cShutdownEv.Wait(INFINITE);
    _SetServiceStatus(SERVICE_STOP_PENDING, ERROR_SUCCESS, 5000);
    //send top callback
    hResServiceExitCode = cStopCallback();
    hRes = S_OK;
  }
  else
  {
    hResServiceExitCode = hRes;
  }
  _SetServiceStatus(SERVICE_STOPPED, hRes, 0, hResServiceExitCode);
  return;
}

static VOID WINAPI _ServiceCtrlHandler(_In_ DWORD dwCtrl)
{
  switch (dwCtrl)
  {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
      cShutdownEv.Set();
      break;

    case SERVICE_CONTROL_INTERROGATE:
      ::SetServiceStatus(hServiceStatus, &sServiceStatus);
      break;
  }
  return;
}

static HRESULT _SetServiceStatus(_In_ DWORD dwCurrentState, _In_opt_ HRESULT hResExitCode, _In_opt_ DWORD dwWaitHint,
                                 _In_opt_ HRESULT hResServiceSpecificExitCode)
{
  static DWORD dwCheckPoint = 1;

  sServiceStatus.dwCurrentState = dwCurrentState;
  sServiceStatus.dwWin32ExitCode = (DWORD)hResExitCode;
  sServiceStatus.dwServiceSpecificExitCode = (DWORD)hResServiceSpecificExitCode;
  sServiceStatus.dwWaitHint = dwWaitHint;
  switch (dwCurrentState)
  {
    case SERVICE_START_PENDING:
    case SERVICE_STOP_PENDING:
    case SERVICE_CONTINUE_PENDING:
    case SERVICE_PAUSE_PENDING:
      sServiceStatus.dwCheckPoint = dwCheckPoint++;
      break;
    default:
      dwCheckPoint = 1;
      sServiceStatus.dwCheckPoint = 0;
      break;
  }
  return _UpdateServiceStatus();
}

static HRESULT _UpdateServiceStatus()
{
  HRESULT hRes;

  hRes = (::SetServiceStatus(hServiceStatus, &sServiceStatus) != FALSE) ? S_OK : MX_HRESULT_FROM_LASTERROR();
  MX_DEBUGPRINT(("Setting service status to %lu. [Error:0x%08X]", sServiceStatus.dwCurrentState, hRes));
  return hRes;
}

static HRESULT IsInteractiveRunningApp()
{
  MX::TAutoFreePtr<TOKEN_GROUPS> cTokenGroups;
  MX::CWindowsHandle cProcToken;
  DWORD dw, dwTokenGroupLength;
  SID_IDENTIFIER_AUTHORITY sSia = SECURITY_NT_AUTHORITY;
  PSID lpInteractiveSid, lpServiceSid;
  HRESULT hRes;

  dwTokenGroupLength = 128;
  cTokenGroups.Attach((PTOKEN_GROUPS)MX_MALLOC(dwTokenGroupLength));
  if (!cTokenGroups)
    return E_OUTOFMEMORY;
  if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &cProcToken) == FALSE)
    return MX_HRESULT_FROM_LASTERROR();
  if (::GetTokenInformation(cProcToken, TokenGroups, cTokenGroups.Get(), dwTokenGroupLength,
                            &dwTokenGroupLength) == FALSE)
  {
    hRes = MX_HRESULT_FROM_LASTERROR();
    if (hRes != HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER))
      return hRes;
    cTokenGroups.Attach((PTOKEN_GROUPS)MX_MALLOC(dwTokenGroupLength));
    if (!cTokenGroups)
      return E_OUTOFMEMORY;
    if (::GetTokenInformation(cProcToken, TokenGroups, cTokenGroups.Get(), dwTokenGroupLength,
                              &dwTokenGroupLength) == FALSE)
      return MX_HRESULT_FROM_LASTERROR();
  }
  if (::AllocateAndInitializeSid(&sSia, 1, SECURITY_INTERACTIVE_RID, 0, 0, 0, 0, 0, 0, 0, &lpInteractiveSid) == FALSE)
    return MX_HRESULT_FROM_LASTERROR();
  if (::AllocateAndInitializeSid(&sSia, 1, SECURITY_SERVICE_RID, 0, 0, 0, 0, 0, 0, 0, &lpServiceSid) == FALSE)
  {
    hRes = MX_HRESULT_FROM_LASTERROR();
    ::FreeSid(lpInteractiveSid);
    return hRes;
  }
  hRes = S_FALSE; //assume a service process by default
  for (dw=0; dw<cTokenGroups->GroupCount; dw++)
  {
    if (::EqualSid(cTokenGroups->Groups[dw].Sid, lpInteractiveSid) != FALSE)
    {
      hRes = S_OK; //interactive process
      break;
    }
    if (::EqualSid(cTokenGroups->Groups[dw].Sid, lpServiceSid) != FALSE)
      break;
  }
  ::FreeSid(lpInteractiveSid);
  ::FreeSid(lpServiceSid);
  return hRes;
}
