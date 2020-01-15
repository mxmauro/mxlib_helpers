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
#include "RegistryChangeMonitor.h"

#define OPEN_KEY_RETRY_TIMEOUT_MS 10000

//-----------------------------------------------------------

namespace MX {

CRegistryChangeMonitor::CRegistryChangeMonitor() : CBaseMemObj(), CNonCopyableObj()
{
  hEvent = NULL;
  hRootKey = NULL;
  cStrSubKeyW.Empty();
  bWatchSubtree = FALSE;
  cCallback = NullCallback();
  lpUserParam = NULL;
  return;
}

CRegistryChangeMonitor::~CRegistryChangeMonitor()
{
  Stop();
  return;
}

HRESULT CRegistryChangeMonitor::Start(_In_ HKEY _hRootKey, _In_z_ LPCWSTR szSubkeyW, _In_ BOOL _bWatchSubtree,
                                      _In_ OnRegistryChangedCallback _cCallback, _In_opt_ LPVOID _lpUserParam)
{
  HRESULT hRes;

  if (_hRootKey == NULL || szSubkeyW == NULL || (!_cCallback))
    return E_POINTER;
  if (*szSubkeyW == 0)
    return E_INVALIDARG;

  Stop();

  hRootKey = _hRootKey;
  bWatchSubtree = _bWatchSubtree;
  cCallback = _cCallback;
  lpUserParam = _lpUserParam;
  hRes = (cStrSubKeyW.Copy(szSubkeyW) != FALSE) ? S_OK : E_OUTOFMEMORY;
  if (SUCCEEDED(hRes))
  {
    hEvent = ::CreateEventW(NULL, FALSE, FALSE, NULL);
    if (hEvent == NULL)
      hRes = E_OUTOFMEMORY;
  }
  if (SUCCEEDED(hRes))
  {
    if (cWorkerThread.Start(this, &CRegistryChangeMonitor::WorkerThread) == FALSE)
      hRes = E_OUTOFMEMORY;
  }
  //done
  if (FAILED(hRes))
    Stop();
  return hRes;
}

VOID CRegistryChangeMonitor::Stop()
{
  cWorkerThread.Stop();
  if (hEvent != NULL)
  {
    ::CloseHandle(hEvent);
    hEvent = NULL;
  }
  hRootKey = NULL;
  cStrSubKeyW.Empty();
  bWatchSubtree = FALSE;
  cCallback = NullCallback();
  lpUserParam = NULL;
  //done
  return;
}

VOID CRegistryChangeMonitor::WorkerThread()
{
  LSTATUS lRes;
  DWORD dwTimeoutMs, dwRet;
  HANDLE hEvents[2];
  HKEY hKey;

  hEvents[0] = cWorkerThread.GetKillEvent();
  hEvents[1] = hEvent;

  hKey = NULL;
  dwTimeoutMs = 0;
  while (cWorkerThread.CheckForAbort(dwTimeoutMs) == FALSE)
  {
    lRes = (hKey == NULL) ? ::RegOpenKeyExW(hRootKey, (LPCWSTR)cStrSubKeyW, 0, KEY_NOTIFY, &hKey) : ERROR_SUCCESS;
    if (lRes == ERROR_SUCCESS)
    {
      lRes = ::RegNotifyChangeKeyValue(hKey, bWatchSubtree, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                                       hEvent, TRUE);
      if (lRes != ERROR_SUCCESS)
      {
        ::RegCloseKey(hKey);
        hKey = NULL;
      }
    }
    else
    {
      hKey = NULL;
    }

    if (hKey != NULL)
    {
      dwRet = ::WaitForMultipleObjects(2, hEvents, FALSE, INFINITE);
      if (dwRet == WAIT_OBJECT_0)
        break;
      if (dwRet == WAIT_OBJECT_0 + 1)
      {
        cCallback(lpUserParam);
      }
      dwTimeoutMs = 0;
    }
    else
    {
      dwTimeoutMs = OPEN_KEY_RETRY_TIMEOUT_MS;
    }
  }
  if (hKey != NULL)
  {
    ::RegCloseKey(hKey);
  }
  return;
}

}; //namespace MX
