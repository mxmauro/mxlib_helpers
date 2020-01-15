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
#ifndef _MXLIBHLP_REGISTRY_CHANGE_MONITOR_H
#define _MXLIBHLP_REGISTRY_CHANGE_MONITOR_H

#include <Defines.h>
#include <Windows.h>
#include <Threads.h>
#include <Callbacks.h>
#include <Strings\Strings.h>

//-----------------------------------------------------------

namespace MX {

class CRegistryChangeMonitor : public CBaseMemObj, public CNonCopyableObj
{
public:
  typedef Callback<VOID(_In_ LPVOID lpUserParam)> OnRegistryChangedCallback;

public:
  CRegistryChangeMonitor();
  ~CRegistryChangeMonitor();

  HRESULT Start(_In_ HKEY hRootKey, _In_z_ LPCWSTR szSubkeyW, _In_ BOOL bWatchSubtree,
                _In_ OnRegistryChangedCallback cCallback, _In_opt_ LPVOID lpUserParam = NULL);
  VOID Stop();

private:
  VOID WorkerThread();

private:
  HKEY hRootKey;
  CStringW cStrSubKeyW;
  BOOL bWatchSubtree;
  HANDLE hEvent;
  OnRegistryChangedCallback cCallback;
  LPVOID lpUserParam;
  TClassWorkerThread<CRegistryChangeMonitor> cWorkerThread;
};

}; //namespace MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_REGISTRY_CHANGE_MONITOR_H
