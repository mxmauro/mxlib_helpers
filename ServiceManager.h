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
    ServiceTypeNetworkService,
    ServiceTypeKernelDriver,
    ServiceTypeFileSystemDriver
  } eServiceType;

  typedef enum {
    StartModeAuto,
    StartModeBoot,
    StartModeSystem,
    StartModeManual,
    StartModeDisabled
  } eStartMode;

public:
  typedef struct tagCREATEINFO {
    eServiceType nServiceType;
    LPCWSTR szServiceDisplayNameW;
    LPCWSTR szFileNameW;
    eStartMode nStartMode;
    LPCWSTR szLoadOrderGroupW;
    LPCWSTR szDependenciesW;
    LPCWSTR szRequiredPrivilegesW;
    LPCWSTR szDescriptionW;
    struct {
      BOOL bAutoRestart;
      DWORD dwRestartDelayMs;
    } sFailureControl;
  } CREATEINFO, *LPCREATEINFO;

public:
  CServiceManager();
  ~CServiceManager();

  HRESULT OpenManager(_In_ BOOL bFullAccess, _In_opt_z_ LPCWSTR szServerW=NULL);
  VOID CloseManager();

  //NOTE: If service already exists, it's configuration will be updated
  HRESULT Create(_In_z_ LPCWSTR szServiceNameW, _In_ LPCREATEINFO lpCreateInfo);
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

  HRESULT ChangeStartMode(_In_ eStartMode nStartMode);

private:
  SC_HANDLE hServMgr, hServ;
};

}; //namespace MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_SERVICE_MANAGER_H
