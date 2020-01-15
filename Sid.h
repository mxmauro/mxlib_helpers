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
#ifndef _MXLIBHLP_SID_H
#define _MXLIBHLP_SID_H

#include <Defines.h>
#include <Windows.h>
#include <sddl.h>
#include <AutoPtr.h>
#include <Strings\Strings.h>

//-----------------------------------------------------------

namespace MX {

class CSid : public virtual CBaseMemObj, public CNonCopyableObj
{
public:
  CSid();
  ~CSid();

  VOID Reset();

  HRESULT Set(_In_ PSID lpSid);
  HRESULT Set(_In_z_ LPCWSTR szAccountNameOrSidStringW);

  BOOL operator==(_In_ PSID lpSid) const;

  HRESULT FromToken(_In_ HANDLE hToken);
  HRESULT FromProcess(_In_ HANDLE hProc);
  HRESULT FromThread(_In_ HANDLE hThread);
  HRESULT FromProcessId(_In_ DWORD dwPid);
  HRESULT FromThreadId(_In_ DWORD dwTid);

  HRESULT SetCurrentUserSid();
  HRESULT SetWellKnownAccount(_In_ WELL_KNOWN_SID_TYPE nSidType);

  HRESULT GetStringSid(_Inout_ CStringW &cStrSidW);
  HRESULT GetAccountName(_Inout_ CStringW &cStrNameW, _In_opt_ CStringW *lpStrDomainW=NULL);

  HRESULT GetCompatibleSidString(_Inout_ CStringW &cStrNameOrSidW, _In_opt_ CStringW *lpStrDomainW)
    {
    if (lpStrDomainW != NULL)
      lpStrDomainW->Empty();
    return IsAnyWellKnownSid() ? GetStringSid(cStrNameOrSidW) : GetAccountName(cStrNameOrSidW, lpStrDomainW);
    };

  operator PSID() const
    {
    return (PSID)(const_cast<TAutoFreePtr<BYTE>&>(cSid).Get());
    };

  BOOL IsAnyWellKnownSid() const;

  BOOL IsWellKnownSid(_In_ WELL_KNOWN_SID_TYPE nSidType) const;

private:
  TAutoFreePtr<BYTE> cSid;
};

}; //MXHelpers

//-----------------------------------------------------------

#endif //_MXLIBHLP_SID_H
