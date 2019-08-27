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
#ifndef _MXLIBHLP_ADS_HELPER_H
#define _MXLIBHLP_ADS_HELPER_H

#include <Defines.h>
#include <Windows.h>
#include <objbase.h>
#include <Iads.h>
#include <ActiveDS.h>
#include "Sid.h"
#include <ArrayList.h>

//-----------------------------------------------------------

namespace MX {

class CAdsHelper : public CBaseMemObj
{
public:
  CAdsHelper();
  ~CAdsHelper();

  HRESULT Initialize(_In_opt_z_ LPCWSTR szServerAddressW=NULL, _In_opt_z_ LPCWSTR szUsernameW=NULL,
                     _In_opt_z_ LPCWSTR szPasswordW=NULL);

  VOID SetCancelEvent(_In_ HANDLE hEvent);
  VOID SetQueryTimeoutMs(_In_ DWORD dwTimeoutMs);

  HRESULT GetAllUsers(_Inout_ TArrayListWithFree<LPWSTR> &aUsersList);
  HRESULT GetAllGroups(_Inout_ TArrayListWithFree<LPWSTR> &aGroupsList);
  HRESULT GetAllComputers(_Inout_ TArrayListWithFree<LPWSTR> &aComputersList);

  HRESULT GetSidFromADsPath(_In_z_ LPCWSTR szADsPathW, _Inout_ CSid &cSid);
  HRESULT GetDomainFromUrl(_In_z_ LPCWSTR szUrlW, _Inout_ CStringW &cStrDomainW);
  HRESULT GetDomainFromDn(_In_z_ LPCWSTR szDistinguishedNameW, _Inout_ CStringW &cStrDomainW);

  HRESULT GetRootADSPath(_Inout_ CStringW &cStrRootPathW);

  HRESULT GetComputerSids(_Out_ CSid **lplpComputerSid, _Inout_ TArrayListWithDelete<CSid*> &aGroupSids);

  HRESULT EnumerateContainerFolders(_In_z_ LPCWSTR szParentW, _Inout_ TArrayListWithFree<LPWSTR> &aChildrenList);
  HRESULT GetContainerMembers(_In_z_ LPCWSTR szParentW, _Inout_ TArrayListWithFree<LPWSTR> &aMembersList);

  static HRESULT GetUrlFromDn(_In_ LPCWSTR szDnW, _Inout_ CStringW &cStrW);
  static HRESULT GetUrlFromDn(_Inout_ CStringW &cStrW);
  static LPCWSTR GetDnFromUrl(_In_ LPCWSTR szUrlW);

private:
  static BOOL EscapeSlashes(_Inout_ CStringW &cStrW);
  HRESULT AdsOpen(_In_z_ LPCWSTR szPathNameW, _In_ REFIID riid, __deref_out LPVOID *ppObject);
  BOOL IsCancelled();

private:
  CStringW cStrServerAddressW, cStrUserNameW, cStrPasswordW;
  HRESULT hResComInit;
  HANDLE hCancelEvent;
  DWORD dwQueryTimeoutMs;
};

}; //namespace MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_ADS_HELPER_H
