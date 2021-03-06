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
#include "Sid.h"

//-----------------------------------------------------------

namespace MX {

CSid::CSid() : CBaseMemObj(), CNonCopyableObj()
{
  return;
}

CSid::~CSid()
{
  return;
}

VOID CSid::Reset()
{
  cSid.Reset();
  return;
}

HRESULT CSid::Set(_In_ PSID lpSid)
{
  DWORD dwLength;

  if (lpSid == NULL)
    return E_POINTER;
  if (::IsValidSid(lpSid) == FALSE)
    return E_INVALIDARG;
  dwLength = ::GetLengthSid(lpSid);
  cSid.Attach((LPBYTE)::MxMemAlloc((SIZE_T)dwLength));
  if (!cSid)
    return E_OUTOFMEMORY;
  ::MxMemCopy(cSid.Get(), lpSid, (SIZE_T)dwLength);
  return S_OK;
}

HRESULT CSid::Set(_In_z_ LPCWSTR szAccountNameOrSidStringW)
{
  if (szAccountNameOrSidStringW == NULL)
    return E_POINTER;
  if (*szAccountNameOrSidStringW == 0)
    return E_INVALIDARG;

  if ((szAccountNameOrSidStringW[0] == L'S' || szAccountNameOrSidStringW[0] == L's') &&
       szAccountNameOrSidStringW[1] == L'-' &&
       szAccountNameOrSidStringW[2] >= L'0' && szAccountNameOrSidStringW[2] <= L'9')
  {
    PSID lpSid;
    DWORD dwLength;

    if (::ConvertStringSidToSidW(szAccountNameOrSidStringW, &lpSid) == FALSE)
      return MX_HRESULT_FROM_LASTERROR();
    dwLength = ::GetLengthSid(lpSid);
    cSid.Attach((LPBYTE)::MxMemAlloc((SIZE_T)dwLength));
    if (!cSid)
    {
      ::LocalFree(lpSid);
      return E_OUTOFMEMORY;
    }
    ::MxMemCopy(cSid.Get(), lpSid, (SIZE_T)dwLength);
    ::LocalFree(lpSid);
  }
  else
  {
    DWORD dwUserSidLen, dwReferencedDomainLen;
    SID_NAME_USE nSidNameUse;
    PSID lpUserSid;
    LPWSTR szReferencedDomainW;
    HRESULT hRes;

    dwUserSidLen = dwReferencedDomainLen = 0;
    ::LookupAccountNameW(NULL, szAccountNameOrSidStringW, NULL, &dwUserSidLen, NULL, &dwReferencedDomainLen,
                         &nSidNameUse);
    lpUserSid = (PSID)::MxMemAlloc((SIZE_T)dwUserSidLen);
    if (lpUserSid == NULL)
      return E_OUTOFMEMORY;
    szReferencedDomainW = (LPWSTR)::MxMemAlloc((SIZE_T)dwReferencedDomainLen * sizeof(WCHAR));
    if (szReferencedDomainW == NULL)
    {
      ::MxMemFree(lpUserSid);
      return E_OUTOFMEMORY;
    }
    if (::LookupAccountNameW(NULL, szAccountNameOrSidStringW, lpUserSid, &dwUserSidLen, szReferencedDomainW,
                             &dwReferencedDomainLen, &nSidNameUse) == FALSE)
    {
      hRes = MX_HRESULT_FROM_LASTERROR();
      ::MxMemFree(szReferencedDomainW);
      ::MxMemFree(lpUserSid);
      return hRes;
    }
    ::MxMemFree(szReferencedDomainW);
    cSid.Attach((LPBYTE)lpUserSid);
  }
  return S_OK;
}

BOOL CSid::operator==(_In_ PSID lpSid) const
{
  if (lpSid != NULL && cSid)
  {
    PSID _sid = (SID*)(const_cast<TAutoFreePtr<BYTE>&>(cSid).Get());
    DWORD dw;

    dw = ::GetLengthSid(lpSid);
    if (dw != ::GetLengthSid(_sid))
      return FALSE;
    return (::MxMemCompare(lpSid, _sid, (SIZE_T)dw) == 0) ? TRUE : FALSE;
  }
  return ((!lpSid) && (!cSid)) ? TRUE : FALSE;
}

HRESULT CSid::FromToken(_In_ HANDLE hToken)
{
  TAutoFreePtr<TOKEN_USER> cTokenInfo;
  DWORD dwLength;
  HRESULT hRes;

  if (hToken == NULL)
    return E_POINTER;
  dwLength = 0;
  if (::GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLength) == FALSE)
  {
    hRes = MX_HRESULT_FROM_LASTERROR();
    if (hRes != HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER))
      return hRes;
  }
  //----
  cTokenInfo.Attach((PTOKEN_USER)::MxMemAlloc((DWORD)dwLength));
  if (!cTokenInfo)
    return E_OUTOFMEMORY;
  if (::GetTokenInformation(hToken, TokenUser, cTokenInfo.Get(), dwLength, &dwLength) == FALSE)
    return MX_HRESULT_FROM_LASTERROR();
  //set
  return Set(cTokenInfo->User.Sid);
}

HRESULT CSid::FromProcess(_In_opt_ HANDLE hProc)
{
  HANDLE hToken;
  HRESULT hRes;

  if (::OpenProcessToken((hProc != NULL) ? hProc : (::GetCurrentProcess()), TOKEN_QUERY, &hToken) != FALSE)
  {
    hRes = FromToken(hToken);
    ::CloseHandle(hToken);
  }
  else
  {
    hRes = MX_HRESULT_FROM_LASTERROR();
  }
  //done
  return hRes;
}

HRESULT CSid::FromThread(_In_opt_ HANDLE hThread)
{
  HANDLE hToken;
  HRESULT hRes;

  if (hThread == NULL)
    hThread = ::GetCurrentThread();
  if (::OpenThreadToken(hThread, TOKEN_QUERY, TRUE, &hToken) != FALSE)
  {
    hRes = FromToken(hToken);
    ::CloseHandle(hToken);
  }
  else
  {
    MX_THREAD_BASIC_INFORMATION sBi;
    NTSTATUS nNtStatus;

    nNtStatus = ::MxNtQueryInformationThread(hThread, MxThreadBasicInformation, &sBi, (ULONG)sizeof(sBi), NULL);
    if (nNtStatus >= 0)
    {
      hRes = FromProcessId((DWORD)(sBi.ClientId.UniqueProcess));
    }
    else
    {
      hRes = MX_HRESULT_FROM_WIN32(::MxRtlNtStatusToDosError(nNtStatus));
    }
  }
  //done
  return hRes;
}

HRESULT CSid::FromProcessId(_In_ DWORD dwPid)
{
  HANDLE hProc;
  HRESULT hRes;

  if (dwPid == 0)
    return E_INVALIDARG;
  if (dwPid == ::GetCurrentProcessId())
  {
    hRes = FromProcess(NULL);
  }
  else
  {
    hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPid);
    if (hProc != NULL)
    {
      hRes = FromProcess(hProc);
      ::CloseHandle(hProc);
    }
    else
    {
      hRes = MX_HRESULT_FROM_LASTERROR();
    }
  }
  //done
  return hRes;
}

HRESULT CSid::FromThreadId(_In_ DWORD dwTid)
{
  HANDLE hProc;
  HRESULT hRes;

  if (dwTid == 0)
    return E_INVALIDARG;
  if (dwTid == ::GetCurrentThreadId())
  {
    hRes = FromThread(NULL);
  }
  else
  {
    hProc = OpenThread(THREAD_QUERY_INFORMATION, FALSE, dwTid);
    if (hProc != NULL)
    {
      hRes = FromThread(hProc);
      ::CloseHandle(hProc);
    }
    else
    {
      hRes = MX_HRESULT_FROM_LASTERROR();
    }
  }
  //done
  return hRes;
}

HRESULT CSid::SetCurrentUserSid()
{
  HANDLE hToken;
  TAutoFreePtr<TOKEN_USER> cTokenInfo;
  DWORD dwLength;
  HRESULT hRes;

  if (::OpenThreadToken(::GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken) == FALSE)
  {
    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &hToken) == FALSE)
      return MX_HRESULT_FROM_LASTERROR();
  }

  dwLength = 0;
  if (::GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLength) == FALSE)
  {
    hRes = MX_HRESULT_FROM_LASTERROR();
    if (hRes != HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER))
    {
      ::CloseHandle(hToken);
      return hRes;
    }
  }

  cTokenInfo.Attach((PTOKEN_USER)::MxMemAlloc((DWORD)dwLength));
  if (cTokenInfo)
  {
    if (::GetTokenInformation(hToken, TokenUser, cTokenInfo.Get(), dwLength, &dwLength) == FALSE)
      hRes = Set(cTokenInfo->User.Sid);
    else
      hRes = MX_HRESULT_FROM_LASTERROR();
  }
  else
  {
    hRes = E_OUTOFMEMORY;
  }
  ::CloseHandle(hToken);
  return hRes;
}

HRESULT CSid::SetWellKnownAccount(_In_ WELL_KNOWN_SID_TYPE nSidType)
{
  BYTE aLocalSid[SECURITY_MAX_SID_SIZE];
  DWORD dwSidBytes;

  dwSidBytes = SECURITY_MAX_SID_SIZE;
  if (::CreateWellKnownSid(nSidType, 0, (PSID)aLocalSid, &dwSidBytes) == FALSE)
    return MX_HRESULT_FROM_LASTERROR();
  return Set((PSID)aLocalSid);
}

HRESULT CSid::GetStringSid(_Inout_ CStringW &cStrSidW)
{
  cStrSidW.Empty();
  if (cSid)
  {
    LPWSTR szStringSidW;

    if (::ConvertSidToStringSidW((PSID)(cSid.Get()), &szStringSidW) == FALSE)
      return MX_HRESULT_FROM_LASTERROR();
    if (cStrSidW.Copy(szStringSidW) == FALSE)
    {
      ::LocalFree(szStringSidW);
      return E_OUTOFMEMORY;
    }
    ::LocalFree(szStringSidW);
  }
  return S_OK;
}

HRESULT CSid::GetAccountName(_Inout_ CStringW &cStrNameW, _In_opt_ CStringW *lpStrDomainW)
{
  CStringW cStrTempDomainW;
  DWORD dwNameLength, dwDomainLength;
  SID_NAME_USE nSidNameUse;
  HRESULT hRes;

  cStrNameW.Empty();
  if (lpStrDomainW != NULL)
    lpStrDomainW->Empty();
  else
    lpStrDomainW = &cStrTempDomainW;
  if (cSid)
  {
    dwNameLength = dwDomainLength = 0;
    if (::LookupAccountSidW(NULL, (PSID)(cSid.Get()), NULL, &dwNameLength, NULL, &dwDomainLength,
                            &nSidNameUse) == FALSE)
    {
      hRes = MX_HRESULT_FROM_LASTERROR();
      if (hRes != HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER))
        return hRes;
    }
    dwNameLength += 2;
    dwDomainLength += 2;
    if (cStrNameW.EnsureBuffer((SIZE_T)dwNameLength) == FALSE ||
        lpStrDomainW->EnsureBuffer((SIZE_T)dwDomainLength) == FALSE)
    {
      return E_OUTOFMEMORY;
    }
    if (::LookupAccountSidW(NULL, (PSID)(cSid.Get()), (LPWSTR)cStrNameW, &dwNameLength,
                            (lpStrDomainW != NULL) ? (LPWSTR)(*lpStrDomainW) : NULL,
                            &dwDomainLength, &nSidNameUse) == FALSE)
    {
      hRes = MX_HRESULT_FROM_LASTERROR();
      cStrNameW.Empty();
      lpStrDomainW->Empty();
      return hRes;
    }
    ((LPWSTR)cStrNameW)[dwNameLength] = 0;
    cStrNameW.Refresh();
    ((LPWSTR)(*lpStrDomainW))[dwDomainLength] = 0;
    lpStrDomainW->Refresh();
  }
  return S_OK;
}

BOOL CSid::IsAnyWellKnownSid() const
{
  SID *_sid;

  //instead of calling "IsWellKnownSid" api for each SID, we do the fast check as pointed here:
  //http://blogs.msdn.com/b/oldnewthing/archive/2014/12/12/10580256.aspx
  //and checked for values here: https://msdn.microsoft.com/en-us/library/cc980032.aspx
  if (!cSid)
    return FALSE;
  _sid = (SID*)(const_cast<TAutoFreePtr<BYTE>&>(cSid).Get());
  if (_sid->Revision != 1)
    return TRUE;
  if (MAKELONG(MAKEWORD(_sid->IdentifierAuthority.Value[5], _sid->IdentifierAuthority.Value[4]),
               MAKEWORD(_sid->IdentifierAuthority.Value[3], _sid->IdentifierAuthority.Value[2])) != 5)
  {
    return TRUE;
  }
  return (_sid->SubAuthorityCount == 0 || _sid->SubAuthority[0] != 21) ? TRUE : FALSE;
}

BOOL CSid::IsWellKnownSid(_In_ WELL_KNOWN_SID_TYPE nSidType) const
{
  if (!cSid)
    return FALSE;
  return ::IsWellKnownSid((PSID)(const_cast<TAutoFreePtr<BYTE>&>(cSid).Get()), nSidType) ? TRUE : FALSE;
}

}; //MX
