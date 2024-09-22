/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the LICENSE file distributed with
 * this work for additional information regarding copyright ownership.
 *
 * Also, if exists, check the Licenses directory for information about
 * third-party modules.
 *
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "Service.h"
#include <AutoHandle.h>
#include <Strings\Strings.h>
#include <AutoPtr.h>
#include <AutoHandle.h>
#include <Debug.h>
#include <Threads.h>
#include "SingleInstance.h"

//-----------------------------------------------------------

static MX::CWindowsEvent cShutdownEv;
static SERVICE_STATUS_HANDLE hServiceStatus = NULL;
static SERVICE_STATUS sServiceStatus = {
  SERVICE_WIN32_OWN_PROCESS, SERVICE_STOPPED, SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN, NO_ERROR, 0, 0, 0
};
static MX::CStringW cStrServiceNameW;
static MX::Service::OnStartCallback cStartCallback = MX::NullCallback();
static MX::Service::OnStopCallback cStopCallback = MX::NullCallback();
static MX::Service::OnDeviceChangeCallback cDeviceChangeCallback = MX::NullCallback();
static BOOL bRunningAsConsole = FALSE;
static int nArgumentsCount = 0;
static WCHAR** lpArguments = NULL;
static BOOL bDisableStop = FALSE;
static MX::CWorkerThread cConsoleDeviceChangeListenerThread;

//-----------------------------------------------------------

static BOOL WINAPI _ConsoleHandlerRoutine(_In_ DWORD dwCtrlType);
static VOID WINAPI _ServiceMain(_In_ DWORD dwArgc, _In_ LPWSTR *pszArgv);
static DWORD WINAPI _ServiceCtrlHandlerEx(_In_ DWORD dwControl, _In_ DWORD dwEventType, _In_ LPVOID lpEventData,
                                          _In_ LPVOID lpContext);
static HRESULT _SetServiceStatus(_In_ DWORD dwCurrentState, _In_opt_ HRESULT hResExitCode=S_OK,
                                 _In_opt_ DWORD dwWaitHint=0, _In_opt_ HRESULT hResServiceSpecificExitCode=S_OK);
static HRESULT _UpdateServiceStatus();
static HRESULT IsInteractiveRunningApp();

static HRESULT CreateConsoleDeviceChangeListener();
static VOID DestroyConsoleDeviceChangeListener();
static VOID ConsoleDeviceChangeListenerThreadProc(_In_ MX::CWorkerThread *lpWrkThread, _In_opt_ LPVOID lpParam);
static LRESULT WINAPI ConsoleDeviceChangeListenerWinProc(_In_ HWND hWnd, _In_ UINT message, _In_ WPARAM wParam,
                                                         _In_ LPARAM lParam);

//-----------------------------------------------------------

namespace MX {

namespace Service {

HRESULT Run(_In_opt_z_ LPCWSTR szServiceNameW, _In_ OnStartCallback _cStartCallback, _In_ OnStopCallback _cStopCallback,
            _In_opt_ OnDeviceChangeCallback _cDeviceChangeCallback, _In_ int argc, _In_ WCHAR* argv[])
{
  SERVICE_TABLE_ENTRYW aServiceTableW[2];
  HRESULT hRes;

  if ((!_cStartCallback) || (!_cStopCallback))
    return E_POINTER;

  if (szServiceNameW == NULL)
    szServiceNameW = L"";

  //check for single instance
  if (*szServiceNameW != 0)
  {
    hRes = MX::SingleInstanceCheck(szServiceNameW);
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
  cDeviceChangeCallback = _cDeviceChangeCallback;

  //create shutdown event
  hRes = cShutdownEv.Create(TRUE, FALSE);
  if (FAILED(hRes))
    return hRes;

  //run
  if (bRunningAsConsole == FALSE)
  {
    ::MxMemSet(&aServiceTableW, 0, sizeof(aServiceTableW));
    aServiceTableW[0].lpServiceName = (LPWSTR)cStrServiceNameW;
    aServiceTableW[0].lpServiceProc = &_ServiceMain;
    hRes = (::StartServiceCtrlDispatcherW(aServiceTableW) != FALSE) ? S_OK : MX_HRESULT_FROM_LASTERROR();
  }
  else
  {
    BOOL bCallStop = FALSE;

    //setup console handler
    if (::SetConsoleCtrlHandler(_ConsoleHandlerRoutine, TRUE) == FALSE)
      return MX_HRESULT_FROM_LASTERROR();

    //send start callback
    hRes = cStartCallback(nArgumentsCount, lpArguments);
    if (SUCCEEDED(hRes))
    {
      bCallStop = TRUE;

      if (cDeviceChangeCallback)
      {
        hRes = CreateConsoleDeviceChangeListener();
      }
    }

    //wait until termination event
    if (SUCCEEDED(hRes))
    {
      cShutdownEv.Wait(INFINITE);
    }

    //shutdown console device change listener if running
    DestroyConsoleDeviceChangeListener();

    //send stop callback
    if (bCallStop != FALSE)
    {
      if (SUCCEEDED(hRes))
      {
        hRes = cStopCallback();
      }
      else
      {
        cStopCallback();
      }
    }

    //remove console handler
    ::SetConsoleCtrlHandler(_ConsoleHandlerRoutine, FALSE);
  }
  //done
  return hRes;
}

VOID SignalShutdown()
{
  cShutdownEv.Set();
  return;
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
    _SetServiceStatus(SERVICE_STOP_PENDING, ERROR_SUCCESS, 5000);
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

BOOL IsInteractive()
{
  return bRunningAsConsole;
}

}; //namespace Service

}; //namespace MX

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

  hServiceStatus = ::RegisterServiceCtrlHandlerExW((LPCWSTR)cStrServiceNameW, &_ServiceCtrlHandlerEx, NULL);
  if (hServiceStatus == NULL)
    return;
  sServiceStatus.dwControlsAccepted = 0;
  _SetServiceStatus(SERVICE_START_PENDING, ERROR_SUCCESS, 5000);

  hRes = cShutdownEv.Create(TRUE, FALSE);
  if (SUCCEEDED(hRes))
  {
    _SetServiceStatus(SERVICE_START_PENDING, ERROR_SUCCESS, 5000);
    //send start callback
    hRes = cStartCallback(nArgumentsCount, lpArguments);
  }

  if (SUCCEEDED(hRes))
  {
    HDEVNOTIFY hDevNotify = NULL;

    if (cDeviceChangeCallback)
    {
      DEV_BROADCAST_DEVICEINTERFACE sNotificationFilter = { 0 };

      sNotificationFilter.dbcc_size = (DWORD)sizeof(sNotificationFilter);
      sNotificationFilter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
      hDevNotify = ::RegisterDeviceNotificationW(hServiceStatus, &sNotificationFilter, DEVICE_NOTIFY_SERVICE_HANDLE |
                                                 DEVICE_NOTIFY_ALL_INTERFACE_CLASSES);
      if (hDevNotify == NULL)
        hRes = MX_HRESULT_FROM_LASTERROR();
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

      if (hDevNotify != NULL)
      {
        ::UnregisterDeviceNotification(hDevNotify);
        hDevNotify = NULL;
      }
    }

    //send stop callback
    if (SUCCEEDED(hRes))
    {
      hResServiceExitCode = cStopCallback();
    }
    else
    {
      cStopCallback();
      hResServiceExitCode = hRes;
    }
  }
  else
  {
    hResServiceExitCode = hRes;
  }

  _SetServiceStatus(SERVICE_STOPPED, hRes, 0, hResServiceExitCode);
  return;
}

static DWORD WINAPI _ServiceCtrlHandlerEx(_In_ DWORD dwControl, _In_ DWORD dwEventType, _In_ LPVOID lpEventData,
                                          _In_ LPVOID lpContext)
{
  switch (dwControl)
  {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
      cShutdownEv.Set();
      return NO_ERROR;

    case SERVICE_CONTROL_INTERROGATE:
      ::SetServiceStatus(hServiceStatus, &sServiceStatus);
      return NO_ERROR;

    case SERVICE_CONTROL_DEVICEEVENT:
      if (dwEventType == DBT_DEVICEARRIVAL || dwEventType == DBT_DEVICEREMOVECOMPLETE)
      {
        cDeviceChangeCallback(dwEventType, (PDEV_BROADCAST_HDR)lpEventData);
      }
      return NO_ERROR;
  }
  return ERROR_CALL_NOT_IMPLEMENTED;
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

  if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &cProcToken) == FALSE)
    return MX_HRESULT_FROM_LASTERROR();

  dwTokenGroupLength = 128;
  cTokenGroups.Attach((PTOKEN_GROUPS)MX_MALLOC(dwTokenGroupLength));
  if (!cTokenGroups)
    return E_OUTOFMEMORY;
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

  //done
  ::FreeSid(lpInteractiveSid);
  ::FreeSid(lpServiceSid);
  return hRes;
}

static HRESULT CreateConsoleDeviceChangeListener()
{
  if (cConsoleDeviceChangeListenerThread.SetRoutine(&ConsoleDeviceChangeListenerThreadProc) == FALSE ||
      cConsoleDeviceChangeListenerThread.Start() == FALSE)
  {
    return E_OUTOFMEMORY;
  }

  //done
  return S_OK;
}

static VOID DestroyConsoleDeviceChangeListener()
{
  DWORD dwTid;

  dwTid = cConsoleDeviceChangeListenerThread.GetThreadId();
  if (dwTid != 0)
    ::PostThreadMessageW(dwTid, WM_QUIT, 0, 0);
  cConsoleDeviceChangeListenerThread.Stop();
  return;
}

static VOID ConsoleDeviceChangeListenerThreadProc(_In_ MX::CWorkerThread *lpWrkThread, _In_opt_ LPVOID lpParam)
{
  WNDCLASS sWndClassW = { 0 };
  DEV_BROADCAST_DEVICEINTERFACE_W sNotifyFilterW = { 0 };
  HWND hWnd;
  HDEVNOTIFY hDevNotify;
  MSG sMsg;

  sWndClassW.lpfnWndProc = &ConsoleDeviceChangeListenerWinProc;
  sWndClassW.hInstance = ::GetModuleHandleW(NULL);
  sWndClassW.lpszClassName = L"TrapmineDC";
  ::RegisterClassW(&sWndClassW);

  hWnd = ::CreateWindowExW(0, sWndClassW.lpszClassName, NULL, 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, NULL, NULL);
  if (hWnd != NULL)
  {
    sNotifyFilterW.dbcc_size = (DWORD)sizeof(sNotifyFilterW);
    sNotifyFilterW.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
    hDevNotify = ::RegisterDeviceNotificationW(hWnd, &sNotifyFilterW,
                                               DEVICE_NOTIFY_WINDOW_HANDLE | DEVICE_NOTIFY_ALL_INTERFACE_CLASSES);
    if (hDevNotify != NULL)
    {
      while (cConsoleDeviceChangeListenerThread.CheckForAbort() == FALSE && ::GetMessageW(&sMsg, NULL, 0, 0) != 0)
      {
        ::TranslateMessage(&sMsg);
        ::DispatchMessageW(&sMsg);
      }

      ::UnregisterDeviceNotification(hDevNotify);
    }
    ::DestroyWindow(hWnd);
  }

  //done
  return;
}

static LRESULT WINAPI ConsoleDeviceChangeListenerWinProc(_In_ HWND hWnd, _In_ UINT message, _In_ WPARAM wParam,
                                                         _In_ LPARAM lParam)
{
  if (message == WM_DEVICECHANGE && (wParam == DBT_DEVICEARRIVAL || wParam == DBT_DEVICEREMOVECOMPLETE))
  {
    if (cConsoleDeviceChangeListenerThread.CheckForAbort() == FALSE)
      cDeviceChangeCallback((DWORD)wParam, (PDEV_BROADCAST_HDR)lParam);
    return TRUE;
  }
  return ::DefWindowProcW(hWnd, message, wParam, lParam);
}
