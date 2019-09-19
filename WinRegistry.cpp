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
#include "WinRegistry.h"
#include "Process.h"
#include <dpapi.h>

#pragma comment(lib, "crypt32.lib")

#define STATUS_PREDEFINED_HANDLE   0x40000016

//-----------------------------------------------------------

static const MX_UNICODE_STRING usEmpty = { 0, 0, L"" };

//-----------------------------------------------------------

static NTSTATUS OpenBaseKey(_In_ HKEY hKey, _In_ DWORD dwAccess, _Out_ PHANDLE lphBaseKey);
static HRESULT RecursiveDeleteKey(_In_ HKEY hKey, _In_opt_ PMX_UNICODE_STRING SubKey);

//-----------------------------------------------------------

namespace MX {

CWindowsRegistry::CWindowsRegistry() : CBaseMemObj()
{
  hKey = NULL;
  return;
}

CWindowsRegistry::~CWindowsRegistry()
{
  Close();
  return;
}

HRESULT CWindowsRegistry::Create(_In_ HKEY hParentKey, _In_z_ LPCWSTR szSubKeyW)
{
  Close();
  if (szSubKeyW == NULL)
    szSubKeyW = L"";
  //if we are opening a root key, then use NtXXX method to return a real handle to be able to call other
  //functions using NtXXX apis
  if (*szSubKeyW == 0 && (hParentKey == HKEY_LOCAL_MACHINE || hParentKey == HKEY_USERS))
  {
    NTSTATUS nNtStatus;

    nNtStatus = OpenBaseKey(hParentKey, KEY_ALL_ACCESS, (PHANDLE)&hKey);
    if (!NT_SUCCESS(nNtStatus))
      return MX_HRESULT_FROM_WIN32(::MxRtlNtStatusToDosError(nNtStatus));
  }
  else
  {
    DWORD dwOsErr;

    dwOsErr = (DWORD)::RegCreateKeyExW(hParentKey, szSubKeyW, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey, NULL);
    if (dwOsErr != 0)
      return MX_HRESULT_FROM_WIN32(dwOsErr);
  }
  //done
  return S_OK;
}

HRESULT CWindowsRegistry::Create(_In_ HKEY hParentKey, _In_ PUNICODE_STRING SubKey)
{
  MX_OBJECT_ATTRIBUTES sObjAttr;
  NTSTATUS nNtStatus;

  Close();
  if (SubKey != NULL && SubKey->Buffer == NULL && SubKey->Length > 0)
    return E_POINTER;
  //prepare
  MemSet(&sObjAttr, 0, sizeof(sObjAttr));
  sObjAttr.Length = (ULONG)sizeof(sObjAttr);
  sObjAttr.Attributes = OBJ_CASE_INSENSITIVE;
  //open base key if needed
  nNtStatus = OpenBaseKey(hParentKey, KEY_ALL_ACCESS, &(sObjAttr.RootDirectory));
  if (NT_SUCCESS(nNtStatus))
  {
    ULONG nDisposition;

    //create key
    sObjAttr.ObjectName = (SubKey != NULL) ? (PMX_UNICODE_STRING)SubKey : (PMX_UNICODE_STRING)&usEmpty;
    nNtStatus = ::MxNtCreateKey((PHANDLE)&hKey, KEY_ALL_ACCESS, &sObjAttr, 0, NULL, REG_OPTION_NON_VOLATILE,
                                &nDisposition);
    //cleanup
    if (sObjAttr.RootDirectory != NULL && sObjAttr.RootDirectory != (HANDLE)hParentKey)
      ::MxNtClose(sObjAttr.RootDirectory);
  }
  //done
  if (nNtStatus == STATUS_PREDEFINED_HANDLE)
  {
    if (hKey != NULL)
      ::MxNtClose(hKey);
    hKey = NULL;
    return HRESULT_FROM_WIN32(ERROR_PREDEFINED_HANDLE);
  }
  if (!NT_SUCCESS(nNtStatus))
    return HRESULT_FROM_WIN32(::MxRtlNtStatusToDosError(nNtStatus));
  return S_OK;
}

HRESULT CWindowsRegistry::Open(_In_ HKEY hParentKey, _In_opt_z_ LPCWSTR szSubKeyW, _In_opt_ BOOL bWriteAccess)
{
  Close();
  if (szSubKeyW == NULL)
    szSubKeyW = L"";
  //if we are opening a root key, then use NtXXX method to return a real handle to be able to call other
  //functions using NtXXX apis
  if (*szSubKeyW == 0 && (hParentKey == HKEY_LOCAL_MACHINE || hParentKey == HKEY_USERS))
  {
    NTSTATUS nNtStatus;

    nNtStatus = OpenBaseKey(hParentKey, (bWriteAccess != FALSE) ? KEY_ALL_ACCESS : KEY_READ, (PHANDLE)&hKey);
    if (!NT_SUCCESS(nNtStatus))
      return MX_HRESULT_FROM_WIN32(::MxRtlNtStatusToDosError(nNtStatus));
  }
  else
  {
    DWORD dwOsErr;

    dwOsErr = (DWORD)::RegOpenKeyExW(hParentKey, szSubKeyW, 0, (bWriteAccess != FALSE) ? KEY_ALL_ACCESS : KEY_READ,
                                     &hKey);
    if (dwOsErr != 0)
      return MX_HRESULT_FROM_WIN32(dwOsErr);
  }
  //done
  return S_OK;
}

HRESULT CWindowsRegistry::Open(_In_ HKEY hParentKey, _In_ PUNICODE_STRING SubKey, _In_opt_ BOOL bWriteAccess)
{
  MX_OBJECT_ATTRIBUTES sObjAttr;
  NTSTATUS nNtStatus;

  Close();
  if (SubKey != NULL && SubKey->Buffer == NULL && SubKey->Length > 0)
    return E_POINTER;
  //prepare
  MemSet(&sObjAttr, 0, sizeof(sObjAttr));
  sObjAttr.Length = (ULONG)sizeof(sObjAttr);
  sObjAttr.Attributes = OBJ_CASE_INSENSITIVE;
  //open base key if needed
  nNtStatus = OpenBaseKey(hParentKey, (bWriteAccess != FALSE) ? KEY_ALL_ACCESS : KEY_READ, &(sObjAttr.RootDirectory));
  if (NT_SUCCESS(nNtStatus))
  {
    //open key
    sObjAttr.ObjectName = (SubKey != NULL) ? (PMX_UNICODE_STRING)SubKey : (PMX_UNICODE_STRING)&usEmpty;
    nNtStatus = ::MxNtOpenKey((PHANDLE)&hKey, (bWriteAccess != FALSE) ? KEY_ALL_ACCESS : KEY_READ, &sObjAttr);
    //cleanup
    if (sObjAttr.RootDirectory != NULL && sObjAttr.RootDirectory != (HANDLE)hParentKey)
      ::MxNtClose(sObjAttr.RootDirectory);
  }
  //done
  if (nNtStatus == STATUS_PREDEFINED_HANDLE)
  {
    if (hKey != NULL)
      ::MxNtClose(hKey);
    hKey = NULL;
    return HRESULT_FROM_WIN32(ERROR_PREDEFINED_HANDLE);
  }
  if (!NT_SUCCESS(nNtStatus))
    return HRESULT_FROM_WIN32(::MxRtlNtStatusToDosError(nNtStatus));
  return S_OK;
}

VOID CWindowsRegistry::Close()
{
  if (hKey != NULL)
  {
    ::RegCloseKey(hKey);
    hKey = NULL;
  }
  return;
}

HRESULT CWindowsRegistry::ReadDWord(_In_z_ LPCWSTR szNameW, _Out_ DWORD &dwValue)
{
  DWORD dwType, dwDataSize, dwOsErr;

  dwValue = 0;
  if (hKey == NULL)
    return MX_E_NotReady;
  dwDataSize = (DWORD)sizeof(DWORD);
  dwOsErr = (DWORD)::RegQueryValueExW(hKey, szNameW, NULL, &dwType, (LPBYTE)&dwValue, &dwDataSize);
  if (dwOsErr != 0)
  {
    dwValue = 0;
    return (dwOsErr == ERROR_MORE_DATA) ? MX_E_InvalidData : MX_HRESULT_FROM_WIN32(dwOsErr);
  }
  if (dwType != REG_DWORD && dwType != REG_DWORD_BIG_ENDIAN)
  {
    dwValue = 0;
    return MX_E_InvalidData;
  }
  if (dwType == REG_DWORD_BIG_ENDIAN)
  {
    dwValue = ((dwValue & 0xFF000000) >> 24) | ((dwValue & 0x00FF0000) >> 8) |
              ((dwValue & 0x0000FF00) << 8) | ((dwValue & 0x000000FF) << 24);
  }
  //done
  return S_OK;
}

HRESULT CWindowsRegistry::ReadDWord(_In_ PUNICODE_STRING Name, _Out_ DWORD &dwValue)
{
  struct {
    MX_KEY_VALUE_PARTIAL_INFORMATION Info;
    BYTE aData[256];
  } s;
  ULONG RetLength;
  NTSTATUS nNtStatus;

  dwValue = 0;
  if (hKey == NULL)
    return MX_E_NotReady;

  if (Name == NULL)
    Name = (PUNICODE_STRING)&usEmpty;

  nNtStatus = ::MxNtQueryValueKey((HANDLE)hKey, (PMX_UNICODE_STRING)Name, MxKeyValuePartialInformation,
                                  &s, (ULONG)sizeof(s), &RetLength);
  if (!NT_SUCCESS(nNtStatus))
  {
    dwValue = 0;
    return (nNtStatus == STATUS_BUFFER_OVERFLOW ||
            nNtStatus == STATUS_BUFFER_TOO_SMALL) ? MX_E_InvalidData
                                                  : HRESULT_FROM_WIN32(::MxRtlNtStatusToDosError(nNtStatus));
  }
  if (s.Info.Type != REG_DWORD && s.Info.Type != REG_DWORD_BIG_ENDIAN)
  {
    dwValue = 0;
    return MX_E_InvalidData;
  }
  dwValue = *((DWORD MX_UNALIGNED*)(s.Info.Data));
  if (s.Info.Type == REG_DWORD_BIG_ENDIAN)
  {
    dwValue = ((dwValue & 0xFF000000) >> 24) | ((dwValue & 0x00FF0000) >> 8) |
              ((dwValue & 0x0000FF00) << 8) | ((dwValue & 0x000000FF) << 24);
  }
  //done
  return S_OK;
}

HRESULT CWindowsRegistry::ReadString(_In_z_ LPCWSTR szNameW, _Out_ CStringW &cStrValueW,
                                     _In_opt_ BOOL bAutoExpandRegSz)
{
  DWORD dwType, dwDataSize, dwOsErr;

  cStrValueW.Empty();
  if (hKey == NULL)
    return MX_E_NotReady;
  //get string size and type
  dwDataSize = 0;
  dwOsErr = (DWORD)::RegQueryValueExW(hKey, szNameW, NULL, &dwType, NULL, &dwDataSize);
  if (dwOsErr != 0)
    return MX_HRESULT_FROM_WIN32(dwOsErr);
  if (dwType != REG_SZ && dwType != REG_EXPAND_SZ)
    return MX_E_InvalidData;
  //prepare buffer
  if (cStrValueW.EnsureBuffer(((SIZE_T)dwDataSize/sizeof(WCHAR)) + 1) == FALSE)
    return E_OUTOFMEMORY;
  dwOsErr = (DWORD)::RegQueryValueExW(hKey, szNameW, NULL, &dwType, (LPBYTE)((LPWSTR)cStrValueW), &dwDataSize);
  if (dwOsErr != 0)
  {
    cStrValueW.Empty();
    return MX_HRESULT_FROM_WIN32(dwOsErr);
  }
  if (dwType != REG_SZ && dwType != REG_EXPAND_SZ)
  {
    cStrValueW.Empty();
    return MX_E_InvalidData;
  }
  ((LPWSTR)cStrValueW)[(SIZE_T)dwDataSize / sizeof(WCHAR)] = 0;
  cStrValueW.Refresh();
  //auto-expand REG_EXPAND_SZ?
  if (dwType == REG_EXPAND_SZ && bAutoExpandRegSz != FALSE && cStrValueW.IsEmpty() == FALSE)
  {
    HRESULT hRes;

    hRes = Process::_ExpandEnvironmentStrings(cStrValueW);
    if (FAILED(hRes) && hRes != MX_E_BufferOverflow)
    {
      cStrValueW.Empty();
      return hRes;
    }
  }
  //done
  return S_OK;
}

HRESULT CWindowsRegistry::ReadString(_In_ PUNICODE_STRING Name, _Out_ PUNICODE_STRING *pValue,
                                     _In_opt_ BOOL bAutoExpandRegSz)
{
  TAutoFreePtr<MX_KEY_VALUE_PARTIAL_INFORMATION> aBuffer;
  struct {
    MX_KEY_VALUE_PARTIAL_INFORMATION Info;
    BYTE aData[256];
  } s;
  PMX_KEY_VALUE_PARTIAL_INFORMATION lpInfo;
  ULONG RetLength;
  NTSTATUS nNtStatus;

  if (pValue == NULL)
    return E_POINTER;
  *pValue = NULL;
  if (hKey == NULL)
    return MX_E_NotReady;
  if (Name == NULL)
    Name = (PUNICODE_STRING)&usEmpty;
  //query
  lpInfo = &(s.Info);
  nNtStatus = ::MxNtQueryValueKey((HANDLE)hKey, (PMX_UNICODE_STRING)Name, MxKeyValuePartialInformation,
                                  lpInfo, (ULONG)sizeof(s), &RetLength);
  if (nNtStatus == STATUS_BUFFER_OVERFLOW || nNtStatus == STATUS_BUFFER_TOO_SMALL)
  {
    //check type
    if (lpInfo->Type != REG_SZ && lpInfo->Type != REG_EXPAND_SZ)
      return MX_E_InvalidData;
    //realloc and retry
    if (RetLength < 4096)
      RetLength = 4096;
    aBuffer.Attach((PMX_KEY_VALUE_PARTIAL_INFORMATION)MX_MALLOC((SIZE_T)RetLength));
    if (!aBuffer)
      return E_OUTOFMEMORY;
    lpInfo = aBuffer.Get();
    nNtStatus = ::MxNtQueryValueKey((HANDLE)hKey, (PMX_UNICODE_STRING)Name, MxKeyValuePartialInformation,
                                    lpInfo, RetLength, &RetLength);
  }
  if (!NT_SUCCESS(nNtStatus))
    return HRESULT_FROM_WIN32(::MxRtlNtStatusToDosError(nNtStatus));
  //check type
  if (lpInfo->Type != REG_SZ && lpInfo->Type != REG_EXPAND_SZ)
    return MX_E_InvalidData;
  //sanitize length (just in case)
  lpInfo->DataLength &= ~1;
  //crop nul chars at the end
  while (lpInfo->DataLength > 0 && ((LPWSTR)(lpInfo->Data))[lpInfo->DataLength / 2 - 1] == 0)
    lpInfo->DataLength -= 2;
  //auto-expand REG_EXPAND_SZ?
  if (lpInfo->Type == REG_EXPAND_SZ && bAutoExpandRegSz != FALSE)
  {
    TAutoFreePtr<UNICODE_STRING> aTempStr;
    CStringW cStrTempW;
    LPWSTR sW = (LPWSTR)(lpInfo->Data);
    ULONG Idx, StartIdx;
    USHORT Cap;
    HRESULT hRes;

    aTempStr.Attach((PUNICODE_STRING)MX_MALLOC(sizeof(UNICODE_STRING) + 65536));
    if (!aTempStr)
      return E_OUTOFMEMORY;

    aTempStr->Buffer = (PWSTR)(aTempStr.Get() + 1);
    aTempStr->Length = 0;
    aTempStr->MaximumLength = 65534;
    //Size = ((lpInfo->DataLength > 65534) ? 65534 : lpInfo->DataLength) & (~1);
    Idx = 0;
    while (Idx < lpInfo->DataLength && aTempStr->Length < aTempStr->MaximumLength)
    {
      //process non-nul characters
      StartIdx = Idx;
      while (Idx < lpInfo->DataLength && sW[Idx >> 1] != 0)
        Idx += 2;
      if (Idx > StartIdx)
      {
        if (cStrTempW.CopyN(sW + StartIdx / 2, (SIZE_T)(Idx - StartIdx) / 2) == FALSE)
          return E_OUTOFMEMORY;
        hRes = Process::_ExpandEnvironmentStrings(cStrTempW);
        if (FAILED(hRes) && hRes != MX_E_BufferOverflow)
          return hRes;

        Cap = aTempStr->MaximumLength - aTempStr->Length;
        if ((ULONG)Cap > cStrTempW.GetLength() * 2)
          Cap = (USHORT)(cStrTempW.GetLength() * 2);

        MemCopy(aTempStr->Buffer + (SIZE_T)(aTempStr->Length) / 2, (LPCWSTR)cStrTempW, (SIZE_T)Cap);
        aTempStr->Length += Cap;
      }
      //process nul characters
      StartIdx = Idx;
      while (Idx < lpInfo->DataLength && sW[Idx >> 1] == 0)
        Idx += 2;
      if (Idx > StartIdx)
      {
        Cap = aTempStr->MaximumLength - aTempStr->Length;
        if ((ULONG)Cap > Idx - StartIdx)
          Cap = (USHORT)(Idx - StartIdx);

        MemSet(aTempStr->Buffer + (SIZE_T)(aTempStr->Length) / 2, 0, (SIZE_T)Cap);
        aTempStr->Length += Cap;
      }
    }
    //copy only required bytes
    *pValue = (PUNICODE_STRING)MX_MALLOC(sizeof(UNICODE_STRING) + (SIZE_T)(aTempStr->Length) + 2);
    if ((*pValue) == NULL)
      return E_OUTOFMEMORY;
    //copy key name
    (*pValue)->Buffer = (PWSTR)((*pValue) + 1);
    (*pValue)->Length = (*pValue)->MaximumLength = aTempStr->Length;
    MemCopy((*pValue)->Buffer, aTempStr->Buffer, (SIZE_T)(aTempStr->Length));
    (*pValue)->Buffer[aTempStr->Length / 2] = 0;
  }
  else
  {
    ULONG Size = ((lpInfo->DataLength > 65534) ? 65534 : lpInfo->DataLength) & (~1);
    *pValue = (PUNICODE_STRING)MX_MALLOC(sizeof(UNICODE_STRING) + (SIZE_T)Size + 2);
    if ((*pValue) == NULL)
      return E_OUTOFMEMORY;
    //copy key name
    (*pValue)->Buffer = (PWSTR)((*pValue) + 1);
    (*pValue)->Length = (*pValue)->MaximumLength = (USHORT)Size;
    MemCopy((*pValue)->Buffer, lpInfo->Data, Size);
    (*pValue)->Buffer[Size / 2] = 0;
  }
  //done
  return S_OK;
}

HRESULT CWindowsRegistry::ReadPassword(_In_z_ LPCWSTR szNameW, _Out_ CStringW &cStrPasswordW)
{
  TAutoFreePtr<BYTE> cBlob;
  SIZE_T nBlobSize;
  DATA_BLOB sInput, sOutput;
  HRESULT hRes;

  cStrPasswordW.Empty();

  hRes = ReadBlob(szNameW, cBlob, nBlobSize);
  if (SUCCEEDED(hRes))
  {
    if (nBlobSize > 0)
    {
      MemSet(&sInput, 0, sizeof(sInput));
      MemSet(&sOutput, 0, sizeof(sOutput));
      sInput.pbData = cBlob.Get();
      sInput.cbData = (DWORD)nBlobSize;
      if (::CryptUnprotectData(&sInput, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &sOutput) != FALSE)
      {
        if ((sOutput.cbData & 1) == 0)
        {
          if (cStrPasswordW.CopyN((LPCWSTR)(sOutput.pbData), (SIZE_T)(sOutput.cbData) / 2) == FALSE)
            hRes = E_OUTOFMEMORY;
        }
        else
        {
          hRes = MX_E_InvalidData;
        }
        MemSet(sOutput.pbData, '*', (SIZE_T)(sOutput.cbData));
        ::LocalFree((HLOCAL)(sOutput.pbData));
      }
      else
      {
        hRes = MX_HRESULT_FROM_LASTERROR();
      }
    }
  }
  else if (hRes == MX_E_InvalidData)
  {
    hRes = ReadString(szNameW, cStrPasswordW);
  }
  //done
  return hRes;
}

HRESULT CWindowsRegistry::ReadMultiString(_In_z_ LPCWSTR szNameW, _Out_ TArrayListWithFree<LPWSTR> &aStrValuesList)
{
  TAutoFreePtr<WCHAR> cBuf;
  LPWSTR sW, szStartW;
  CStringW cStrTempW;
  DWORD dw, dwType, dwDataSize, dwOsErr;

  aStrValuesList.RemoveAllElements();
  if (hKey == NULL)
    return MX_E_NotReady;
  //get string size and type
  dwDataSize = 0;
  dwOsErr = (DWORD)::RegQueryValueExW(hKey, szNameW, NULL, &dwType, NULL, &dwDataSize);
  if (dwOsErr != 0)
    return MX_HRESULT_FROM_WIN32(dwOsErr);
  if (dwType != REG_MULTI_SZ)
    return MX_E_InvalidData;
  //prepare buffer
  cBuf.Attach((LPWSTR)MX_MALLOC((SIZE_T)dwDataSize));
  if (!cBuf)
    return E_OUTOFMEMORY;
  dwOsErr = (DWORD)::RegQueryValueExW(hKey, szNameW, NULL, &dwType, (LPBYTE)cBuf.Get(), &dwDataSize);
  if (dwOsErr != 0)
    return MX_HRESULT_FROM_WIN32(dwOsErr);
  if (dwType != REG_MULTI_SZ)
    return MX_E_InvalidData;
  dwDataSize /= (DWORD)sizeof(WCHAR);
  //extract strings
  sW = cBuf.Get();
  dw = 0;
  while (dw < dwDataSize)
  {
    while (dw < dwDataSize && sW[dw] == 0)
      dw++;
    if (dw < dwDataSize)
    {
      szStartW = &sW[dw];
      while (dw < dwDataSize && sW[dw] != 0)
        dw++;
      if (cStrTempW.CopyN(szStartW, (SIZE_T)(&sW[dw] - szStartW)) == FALSE)
      {
        aStrValuesList.RemoveAllElements();
        return E_OUTOFMEMORY;
      }
      if (aStrValuesList.AddElement((LPWSTR)cStrTempW) == FALSE)
      {
        aStrValuesList.RemoveAllElements();
        return E_OUTOFMEMORY;
      }
      cStrTempW.Detach();
    }
  }
  //done
  return S_OK;
}

HRESULT CWindowsRegistry::ReadMultiString(_In_ PUNICODE_STRING Name,
                                          _Out_ TArrayListWithFree<PUNICODE_STRING> &aStrValuesList)
{
  TAutoFreePtr<MX_KEY_VALUE_PARTIAL_INFORMATION> aBuffer;
  struct {
    MX_KEY_VALUE_PARTIAL_INFORMATION Info;
    BYTE aData[256];
  } s;
  PMX_KEY_VALUE_PARTIAL_INFORMATION lpInfo;
  ULONG RetLength;
  DWORD dw, dwDataSize;
  SIZE_T nSize;
  LPCWSTR sW, szStartW;
  PUNICODE_STRING TempStr;
  NTSTATUS nNtStatus;

  aStrValuesList.RemoveAllElements();
  if (hKey == NULL)
    return MX_E_NotReady;
  if (Name == NULL)
    Name = (PUNICODE_STRING)&usEmpty;
  //query
  lpInfo = &(s.Info);
  nNtStatus = ::MxNtQueryValueKey((HANDLE)hKey, (PMX_UNICODE_STRING)Name, MxKeyValuePartialInformation,
                                  lpInfo, (ULONG)sizeof(s), &RetLength);
  if (nNtStatus == STATUS_BUFFER_OVERFLOW || nNtStatus == STATUS_BUFFER_TOO_SMALL)
  {
    //check type
    if (lpInfo->Type != REG_MULTI_SZ)
      return MX_E_InvalidData;
    //realloc and retry
    if (RetLength < 4096)
      RetLength = 4096;
    aBuffer.Attach((PMX_KEY_VALUE_PARTIAL_INFORMATION)MX_MALLOC((SIZE_T)RetLength));
    if (!aBuffer)
      return E_OUTOFMEMORY;
    lpInfo = aBuffer.Get();
    nNtStatus = ::MxNtQueryValueKey((HANDLE)hKey, (PMX_UNICODE_STRING)Name, MxKeyValuePartialInformation,
                                    lpInfo, RetLength, &RetLength);
  }
  if (!NT_SUCCESS(nNtStatus))
    return HRESULT_FROM_WIN32(::MxRtlNtStatusToDosError(nNtStatus));
  //check type
  if (lpInfo->Type != REG_MULTI_SZ)
    return MX_E_InvalidData;
  //fill list
  dwDataSize = lpInfo->DataLength / (DWORD)sizeof(WCHAR);
  //extract strings
  sW = (LPCWSTR)(lpInfo->Data);
  dw = 0;
  while (dw < dwDataSize)
  {
    while (dw < dwDataSize && sW[dw] == 0)
      dw++;
    if (dw < dwDataSize)
    {
      szStartW = &sW[dw];
      while (dw < dwDataSize && sW[dw] != 0)
        dw++;

      nSize = (SIZE_T)(&sW[dw] - szStartW);
      if (nSize > 32767)
        nSize = 32767;
      //copy only required bytes
      TempStr = (PUNICODE_STRING)MX_MALLOC(sizeof(UNICODE_STRING) + nSize * 2 + 2);
      if (TempStr == NULL)
      {
        aStrValuesList.RemoveAllElements();
        return E_OUTOFMEMORY;
      }
      //copy value
      TempStr->Buffer = (PWSTR)(TempStr + 1);
      TempStr->Length = TempStr->MaximumLength = (USHORT)nSize * 2;
      MemCopy(TempStr->Buffer, szStartW, nSize * 2);
      TempStr->Buffer[TempStr->Length / 2] = 0;
      //add to list
      if (aStrValuesList.AddElement(TempStr) == FALSE)
      {
        MX_FREE(TempStr);
        aStrValuesList.RemoveAllElements();
        return E_OUTOFMEMORY;
      }
    }
  }
  //done
  return S_OK;
}

HRESULT CWindowsRegistry::ReadBlob(_In_z_ LPCWSTR szNameW, _Out_ TAutoFreePtr<BYTE> &cBlob, _Out_ SIZE_T &nBlobSize)
{
  DWORD dwOsErr, dwDataSize, dwType;

  cBlob.Reset();
  nBlobSize = 0;
  if (hKey == NULL)
    return MX_E_NotReady;
  //get blob size and type
  dwDataSize = 0;
  dwOsErr = (DWORD)::RegQueryValueExW(hKey, szNameW, NULL, &dwType, NULL, &dwDataSize);
  if (dwOsErr != 0)
    return MX_HRESULT_FROM_WIN32(dwOsErr);
  if (dwType != REG_BINARY)
    return MX_E_InvalidData;
  //prepare buffer
  if (dwDataSize > 0)
  {
    cBlob.Attach((LPBYTE)MX_MALLOC((SIZE_T)dwDataSize));
    if (!cBlob)
      return E_OUTOFMEMORY;
    dwOsErr = (DWORD)::RegQueryValueExW(hKey, szNameW, NULL, &dwType, cBlob.Get(), &dwDataSize);
    if (dwOsErr != 0)
    {
      cBlob.Reset();
      return MX_HRESULT_FROM_WIN32(dwOsErr);
    }
  }
  if (dwType != REG_BINARY)
  {
    cBlob.Reset();
    return MX_E_InvalidData;
  }
  nBlobSize = (SIZE_T)dwDataSize;
  //done
  return S_OK;
}

HRESULT CWindowsRegistry::ReadBlob(_In_ PUNICODE_STRING Name, _Out_ TAutoFreePtr<BYTE> &cBlob, _Out_ SIZE_T &nBlobSize)
{
  TAutoFreePtr<MX_KEY_VALUE_PARTIAL_INFORMATION> aBuffer;
  struct {
    MX_KEY_VALUE_PARTIAL_INFORMATION Info;
    BYTE aData[256];
  } s;
  PMX_KEY_VALUE_PARTIAL_INFORMATION lpInfo;
  ULONG RetLength;
  NTSTATUS nNtStatus;

  cBlob.Reset();
  nBlobSize = 0;
  if (hKey == NULL)
    return MX_E_NotReady;
  if (Name == NULL)
    Name = (PUNICODE_STRING)&usEmpty;
  //query
  lpInfo = &(s.Info);
  nNtStatus = ::MxNtQueryValueKey((HANDLE)hKey, (PMX_UNICODE_STRING)Name, MxKeyValuePartialInformation,
                                  lpInfo, (ULONG)sizeof(s), &RetLength);
  if (nNtStatus == STATUS_BUFFER_OVERFLOW || nNtStatus == STATUS_BUFFER_TOO_SMALL)
  {
    //check type
    if (lpInfo->Type != REG_BINARY)
      return MX_E_InvalidData;
    //realloc and retry
    if (RetLength < 4096)
      RetLength = 4096;
    aBuffer.Attach((PMX_KEY_VALUE_PARTIAL_INFORMATION)MX_MALLOC((SIZE_T)RetLength));
    if (!aBuffer)
      return E_OUTOFMEMORY;
    lpInfo = aBuffer.Get();
    nNtStatus = ::MxNtQueryValueKey((HANDLE)hKey, (PMX_UNICODE_STRING)Name, MxKeyValuePartialInformation,
                                    lpInfo, RetLength, &RetLength);
  }
  if (!NT_SUCCESS(nNtStatus))
    return HRESULT_FROM_WIN32(::MxRtlNtStatusToDosError(nNtStatus));
  //check type
  if (lpInfo->Type != REG_BINARY)
    return MX_E_InvalidData;
  //prepare buffer
  if (lpInfo->DataLength > 0)
  {
    cBlob.Attach((LPBYTE)MX_MALLOC((SIZE_T)(lpInfo->DataLength)));
    if (!cBlob)
      return E_OUTOFMEMORY;
    MemCopy(cBlob.Get(), lpInfo->Data, (SIZE_T)(lpInfo->DataLength));
  }
  nBlobSize = (SIZE_T)(lpInfo->DataLength);
  //done
  return S_OK;
}

HRESULT CWindowsRegistry::ReadAny(_In_z_ LPCWSTR szNameW, _Out_ DWORD &dwType, _Out_ TAutoFreePtr<BYTE> &cData,
                                  _Out_ SIZE_T &nDataSize)
{
  DWORD dwOsErr, dwDataSize;

  dwType = REG_NONE;
  cData.Reset();
  nDataSize = 0;
  if (hKey == NULL)
    return MX_E_NotReady;
  //get data size and type
  dwDataSize = 0;
  dwOsErr = (DWORD)::RegQueryValueExW(hKey, szNameW, NULL, &dwType, NULL, &dwDataSize);
  if (dwOsErr != 0)
  {
    dwType = REG_NONE;
    return MX_HRESULT_FROM_WIN32(dwOsErr);
  }
  //prepare buffer
  if (dwDataSize > 0)
  {
    cData.Attach((LPBYTE)MX_MALLOC((SIZE_T)dwDataSize));
    if (!cData)
    {
      dwType = REG_NONE;
      return E_OUTOFMEMORY;
    }
    dwOsErr = (DWORD)::RegQueryValueExW(hKey, szNameW, NULL, &dwType, cData.Get(), &dwDataSize);
    if (dwOsErr != 0)
    {
      dwType = REG_NONE;
      cData.Reset();
      return MX_HRESULT_FROM_WIN32(dwOsErr);
    }
  }
  nDataSize = (SIZE_T)dwDataSize;
  //done
  return S_OK;
}

HRESULT CWindowsRegistry::ReadAny(_In_ PUNICODE_STRING Name, _Out_ DWORD &dwType, _Out_ TAutoFreePtr<BYTE> &cData,
                                  _Out_ SIZE_T &nDataSize)
{
  TAutoFreePtr<MX_KEY_VALUE_PARTIAL_INFORMATION> aBuffer;
  struct {
    MX_KEY_VALUE_PARTIAL_INFORMATION Info;
    BYTE aData[256];
  } s;
  PMX_KEY_VALUE_PARTIAL_INFORMATION lpInfo;
  ULONG RetLength;
  NTSTATUS nNtStatus;

  dwType = REG_NONE;
  cData.Reset();
  nDataSize = 0;
  if (hKey == NULL)
    return MX_E_NotReady;
  if (Name == NULL)
    Name = (PUNICODE_STRING)&usEmpty;
  //query
  lpInfo = &(s.Info);
  nNtStatus = ::MxNtQueryValueKey((HANDLE)hKey, (PMX_UNICODE_STRING)Name, MxKeyValuePartialInformation,
                                  lpInfo, (ULONG)sizeof(s), &RetLength);
  if (nNtStatus == STATUS_BUFFER_OVERFLOW || nNtStatus == STATUS_BUFFER_TOO_SMALL)
  {
    //realloc and retry
    if (RetLength < 4096)
      RetLength = 4096;
    aBuffer.Attach((PMX_KEY_VALUE_PARTIAL_INFORMATION)MX_MALLOC((SIZE_T)RetLength));
    if (!aBuffer)
      return E_OUTOFMEMORY;
    lpInfo = aBuffer.Get();
    nNtStatus = ::MxNtQueryValueKey((HANDLE)hKey, (PMX_UNICODE_STRING)Name, MxKeyValuePartialInformation,
                                    lpInfo, RetLength, &RetLength);
  }
  if (!NT_SUCCESS(nNtStatus))
    return HRESULT_FROM_WIN32(::MxRtlNtStatusToDosError(nNtStatus));
  //prepare buffer
  if (lpInfo->DataLength > 0)
  {
    cData.Attach((LPBYTE)MX_MALLOC((SIZE_T)(lpInfo->DataLength)));
    if (!cData)
      return E_OUTOFMEMORY;
    MemCopy(cData.Get(), lpInfo->Data, (SIZE_T)(lpInfo->DataLength));
  }
  nDataSize = (SIZE_T)(lpInfo->DataLength);
  //done
  return S_OK;
}

HRESULT CWindowsRegistry::WriteDWord(_In_z_ LPCWSTR szNameW, _In_ DWORD dwValue)
{
  DWORD dwOsErr;

  if (hKey == NULL)
    return MX_E_NotReady;
  dwOsErr = ::RegSetValueExW(hKey, szNameW, 0, REG_DWORD, (const LPBYTE)&dwValue, (DWORD)sizeof(DWORD));
  if (dwOsErr != 0)
    return MX_HRESULT_FROM_WIN32(dwOsErr);
  //done
  return S_OK;
}

HRESULT CWindowsRegistry::WriteString(_In_z_ LPCWSTR szNameW, _In_z_ LPCWSTR szValueW)
{
  DWORD dwOsErr;
  SIZE_T nLen;

  if (hKey == NULL)
    return MX_E_NotReady;
  if (szValueW == NULL)
    szValueW = L"";
  nLen = (StrLenW(szValueW) + 1); //include NUL char
  if (nLen > 0x7FFFFFFF)
    return E_FAIL;
  dwOsErr = ::RegSetValueExW(hKey, szNameW, 0, REG_SZ, (const LPBYTE)szValueW, (DWORD)(nLen*sizeof(WCHAR)));
  if (dwOsErr != 0)
    return MX_HRESULT_FROM_WIN32(dwOsErr);
  //done
  return S_OK;
}

HRESULT CWindowsRegistry::WriteMultiString(_In_z_ LPCWSTR szNameW, _In_ SIZE_T nValuesCount, _In_ LPCWSTR *lpszValuesW)
{
  TAutoFreePtr<BYTE> cBuf;
  DWORD dwOsErr;
  SIZE_T i, nLen, nThisLen;

  if (hKey == NULL)
    return MX_E_NotReady;
  if (nValuesCount > 0 && lpszValuesW == NULL)
    return E_POINTER;
  for (i=nLen=0; i<nValuesCount; i++)
  {
    nLen += StrLenW(lpszValuesW[i]) + 1;
    if (nLen > 1048756 / 2)
      return MX_E_BadLength;
  }
  if (nLen + 1 > 1048756 / 2)
    return MX_E_BadLength;
  //allocate buffer
  cBuf.Attach((LPBYTE)MX_MALLOC((nLen+1)*sizeof(WCHAR)));
  if (!cBuf)
    return E_OUTOFMEMORY;
  for (i=nLen=0; i<nValuesCount; i++)
  {
    nThisLen = (StrLenW(lpszValuesW[i]) + 1) * sizeof(WCHAR);
    MemCopy(cBuf.Get()+nLen, lpszValuesW[i], nThisLen);
    nLen += nThisLen;
  }
  MemSet(cBuf.Get()+nLen, 0, 2);
  nLen += 2;
  //save value
  dwOsErr = ::RegSetValueExW(hKey, szNameW, 0, REG_MULTI_SZ, (const LPBYTE)cBuf.Get(), (DWORD)nLen);
  if (dwOsErr != 0)
    return MX_HRESULT_FROM_WIN32(dwOsErr);
  //done
  return S_OK;
}

HRESULT CWindowsRegistry::WriteBlob(_In_z_ LPCWSTR szNameW, _In_ LPCVOID lpValue, _In_ SIZE_T nValueLen)
{
  return WriteAny(szNameW, REG_BINARY, lpValue, nValueLen);
}

HRESULT CWindowsRegistry::WriteAny(_In_z_ LPCWSTR szNameW, _In_ DWORD dwType, _In_ LPCVOID lpValue,
                                   _In_ SIZE_T nValueLen)
{
  DWORD dwOsErr;

  if (hKey == NULL)
    return MX_E_NotReady;
  if (nValueLen > 0 && lpValue == NULL)
    return E_POINTER;
  if (nValueLen > 0x7FFFFFFFUL)
    return E_INVALIDARG;
  //save value
  dwOsErr = ::RegSetValueExW(hKey, szNameW, 0, dwType, (const BYTE*)lpValue, (DWORD)nValueLen);
  if (dwOsErr != 0)
    return MX_HRESULT_FROM_WIN32(dwOsErr);
  //done
  return S_OK;
}

HRESULT CWindowsRegistry::WritePassword(_In_z_ LPCWSTR szNameW, _In_z_ LPCWSTR szPasswordW)
{
  DATA_BLOB sInput, sOutput;
  HRESULT hRes;

  if (szPasswordW == NULL || *szPasswordW == 0)
    return WriteBlob(szNameW, NULL, 0);

  MemSet(&sInput, 0, sizeof(sInput));
  MemSet(&sOutput, 0, sizeof(sOutput));
  sInput.pbData = (LPBYTE)szPasswordW;
  sInput.cbData = (DWORD)StrLenW(szPasswordW) * 2;
  if (::CryptProtectData(&sInput, NULL, NULL, NULL, NULL, CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
                         &sOutput) == FALSE)
  {
    return MX_HRESULT_FROM_LASTERROR();
  }
  hRes = WriteBlob(szNameW, sOutput.pbData, (SIZE_T)(sOutput.cbData));
  //cleanup
  ::LocalFree((HLOCAL)(sOutput.pbData));
  //done
  return hRes;
}

HRESULT CWindowsRegistry::DeleteKey(_In_z_ LPCWSTR szNameW)
{
  MX_UNICODE_STRING usTemp;
  SIZE_T nLen;

  if (hKey == NULL)
    return MX_E_NotReady;
  if (szNameW == NULL)
    return E_POINTER;
  nLen = StrLenW(szNameW);
  if (nLen == 0 || nLen >= 32768)
    return E_INVALIDARG;
  usTemp.Buffer = (PWSTR)szNameW;
  usTemp.Length = usTemp.MaximumLength = (USHORT)nLen * 2;
  return RecursiveDeleteKey(hKey, &usTemp);
}

HRESULT CWindowsRegistry::DeleteKey(_In_ PUNICODE_STRING Name)
{
  if (Name == NULL || Name->Buffer == NULL)
    return E_POINTER;
  if (Name->Length == 0)
    return E_INVALIDARG;
  return RecursiveDeleteKey(hKey, (PMX_UNICODE_STRING)Name);
}

HRESULT CWindowsRegistry::DeleteValue(_In_opt_z_ LPCWSTR szNameW)
{
  DWORD dwOsErr;

  if (hKey == NULL)
    return MX_E_NotReady;
  dwOsErr = ::RegDeleteValueW(hKey, szNameW);
  if (dwOsErr != ERROR_PATH_NOT_FOUND && dwOsErr != ERROR_FILE_NOT_FOUND)
    return MX_HRESULT_FROM_WIN32(dwOsErr);
  //done
  return S_OK;
}

HRESULT CWindowsRegistry::DeleteValue(_In_opt_ PUNICODE_STRING Name)
{
  NTSTATUS nNtStatus;

  if (hKey == NULL)
    return MX_E_NotReady;
  if (Name == NULL)
    Name = (PUNICODE_STRING)&usEmpty;
  nNtStatus = ::MxNtDeleteValueKey(hKey, (PMX_UNICODE_STRING)Name);
  //done
  if (!NT_SUCCESS(nNtStatus))
  {
    HRESULT hRes = HRESULT_FROM_WIN32(::MxRtlNtStatusToDosError(nNtStatus));
    return (hRes == MX_E_PathNotFound || hRes == MX_E_FileNotFound) ? S_OK : hRes;
  }
  return S_OK;
}

HRESULT CWindowsRegistry::EnumerateKeys(_In_ DWORD dwIndex, _Inout_ CStringW &cStrKeyNameW)
{
  DWORD dwOsErr, dw, dwBufSize;

  if (hKey == NULL)
    return MX_E_NotReady;
  for (dwBufSize=256; dwBufSize<=32768; dwBufSize<<=1)
  {
    if (cStrKeyNameW.EnsureBuffer((SIZE_T)dwBufSize + 1) == FALSE)
      return E_OUTOFMEMORY;
    dw = dwBufSize;
    dwOsErr = ::RegEnumKeyExW(hKey, dwIndex, (LPWSTR)cStrKeyNameW, &dw, NULL, NULL, NULL, NULL);
    if (dwOsErr == NOERROR)
    {
      ((LPWSTR)cStrKeyNameW)[dw] = 0;
      cStrKeyNameW.Refresh();
      return S_OK;
    }
    if (dwOsErr == ERROR_NO_MORE_ITEMS)
    {
      cStrKeyNameW.Empty();
      return MX_E_EndOfFileReached;
    }
    if (dwOsErr != ERROR_MORE_DATA)
    {
      cStrKeyNameW.Empty();
      return MX_HRESULT_FROM_WIN32(dwOsErr);
    }
  }
  //done
  return E_OUTOFMEMORY;
}

HRESULT CWindowsRegistry::EnumerateKeys(_In_ DWORD dwIndex, _Out_ PUNICODE_STRING *pKeyName)
{
  TAutoFreePtr<MX_KEY_BASIC_INFORMATION> aBuffer;
  ULONG Size, RetLength;
  NTSTATUS nNtStatus;

  if (pKeyName == NULL)
    return E_POINTER;
  *pKeyName = NULL;

  if (hKey == NULL)
    return MX_E_NotReady;

  //allocate buffer
  aBuffer.Attach((PMX_KEY_BASIC_INFORMATION)MX_MALLOC(2048));
  if (!aBuffer)
    return E_OUTOFMEMORY;
  //get key info
  nNtStatus = ::MxNtEnumerateKey((HANDLE)hKey, dwIndex, MxKeyBasicInformation, aBuffer.Get(), 2048, &RetLength);
  if (nNtStatus == STATUS_BUFFER_OVERFLOW || nNtStatus == STATUS_BUFFER_TOO_SMALL)
  {
    if (RetLength < 4096)
      RetLength = 4096;
    aBuffer.Attach((PMX_KEY_BASIC_INFORMATION)MX_MALLOC((SIZE_T)RetLength));
    if (!aBuffer)
      return E_OUTOFMEMORY;
    nNtStatus = ::MxNtEnumerateKey((HANDLE)hKey, dwIndex, MxKeyBasicInformation, aBuffer.Get(), RetLength, &RetLength);
  }
  if (!NT_SUCCESS(nNtStatus))
    return HRESULT_FROM_WIN32(::MxRtlNtStatusToDosError(nNtStatus));
  //allocate target string
  Size = ((aBuffer.Get()->NameLength > 65534) ? 65534 : aBuffer.Get()->NameLength) & (~1);
  *pKeyName = (PUNICODE_STRING)MX_MALLOC(sizeof(UNICODE_STRING) + (SIZE_T)Size + 2);
  if ((*pKeyName) == NULL)
    return E_OUTOFMEMORY;
  //copy key name
  (*pKeyName)->Buffer = (PWSTR)((*pKeyName) + 1);
  (*pKeyName)->Length = (*pKeyName)->MaximumLength = (USHORT)Size;
  MemCopy((*pKeyName)->Buffer, aBuffer.Get()->Name, Size);
  (*pKeyName)->Buffer[Size / 2] = 0;
  //done
  return S_OK;
}

HRESULT CWindowsRegistry::EnumerateValues(_In_ DWORD dwIndex, _Inout_ CStringW &cStrValueNameW)
{
  DWORD dwOsErr, dw, dwBufSize;

  if (hKey == NULL)
    return MX_E_NotReady;
  for (dwBufSize=256; dwBufSize<=32768; dwBufSize<<=1)
  {
    if (cStrValueNameW.EnsureBuffer((SIZE_T)dwBufSize + 1) == FALSE)
      return E_OUTOFMEMORY;
    dw = dwBufSize;
    dwOsErr = ::RegEnumValueW(hKey, dwIndex, (LPWSTR)cStrValueNameW, &dw, NULL, NULL, NULL, NULL);
    if (dwOsErr == NOERROR)
    {
      ((LPWSTR)cStrValueNameW)[dw] = 0;
      cStrValueNameW.Refresh();
      return S_OK;
    }
    if (dwOsErr == ERROR_NO_MORE_ITEMS)
    {
      cStrValueNameW.Empty();
      return MX_E_EndOfFileReached;
    }
    if (dwOsErr != ERROR_MORE_DATA)
    {
      cStrValueNameW.Empty();
      return MX_HRESULT_FROM_WIN32(dwOsErr);
    }
  }
  //done
  return E_OUTOFMEMORY;
}

HRESULT CWindowsRegistry::EnumerateValues(_In_ DWORD dwIndex, _Out_ PUNICODE_STRING *pValueName)
{
  TAutoFreePtr<MX_KEY_VALUE_FULL_INFORMATION> aBuffer;
  ULONG Size, RetLength;
  NTSTATUS nNtStatus;

  if (pValueName == NULL)
    return E_POINTER;
  *pValueName = NULL;

  if (hKey == NULL)
    return MX_E_NotReady;

  //allocate buffer
  aBuffer.Attach((PMX_KEY_VALUE_FULL_INFORMATION)MX_MALLOC(2048));
  if (!aBuffer)
    return E_OUTOFMEMORY;
  //get key info
  nNtStatus = ::MxNtEnumerateValueKey((HANDLE)hKey, dwIndex, MxKeyValueFullInformation, aBuffer.Get(), 2048,
                                      &RetLength);
  if (nNtStatus == STATUS_BUFFER_OVERFLOW || nNtStatus == STATUS_BUFFER_TOO_SMALL)
  {
    if (RetLength < 4096)
      RetLength = 4096;
    aBuffer.Attach((PMX_KEY_VALUE_FULL_INFORMATION)MX_MALLOC((SIZE_T)RetLength));
    if (!aBuffer)
      return E_OUTOFMEMORY;
    nNtStatus = ::MxNtEnumerateValueKey((HANDLE)hKey, dwIndex, MxKeyValueFullInformation, aBuffer.Get(), RetLength,
                                        &RetLength);
  }
  if (!NT_SUCCESS(nNtStatus))
    return HRESULT_FROM_WIN32(::MxRtlNtStatusToDosError(nNtStatus));
  //allocate target string
  Size = (aBuffer.Get()->NameLength > 65534) ? 65534 : aBuffer.Get()->NameLength;
  *pValueName = (PUNICODE_STRING)MX_MALLOC(sizeof(UNICODE_STRING) + (SIZE_T)Size + 2);
  if ((*pValueName) == NULL)
    return E_OUTOFMEMORY;
  //copy value name
  (*pValueName)->Buffer = (PWSTR)((*pValueName) + 1);
  (*pValueName)->Length = (*pValueName)->MaximumLength = (USHORT)Size;
  MemCopy((*pValueName)->Buffer, aBuffer.Get()->Name, Size);
  (*pValueName)->Buffer[Size / 2] = 0;
  //done
  return S_OK;
}

}; //namespace MX

//-----------------------------------------------------------

static NTSTATUS OpenBaseKey(_In_ HKEY hKey, _In_ DWORD dwAccess, _Out_ PHANDLE lphBaseKey)
{
  static const MX_UNICODE_STRING usMachine = { 34, 36, L"\\REGISTRY\\MACHINE" };
  static const MX_UNICODE_STRING usUser = { 28, 30, L"\\REGISTRY\\USER" };
  MX_OBJECT_ATTRIBUTES sObjAttr;

  MX::MemSet(&sObjAttr, 0, sizeof(sObjAttr));
  sObjAttr.Length = (ULONG)sizeof(sObjAttr);
  sObjAttr.Attributes = OBJ_CASE_INSENSITIVE;
  if (hKey == HKEY_LOCAL_MACHINE)
  {
    sObjAttr.ObjectName = (PMX_UNICODE_STRING)&usMachine;
    *lphBaseKey = NULL;
    return ::MxNtOpenKey(lphBaseKey, dwAccess, &sObjAttr);
  }
  if (hKey == HKEY_USERS)
  {
    sObjAttr.ObjectName = (PMX_UNICODE_STRING)&usUser;
    *lphBaseKey = NULL;
    return ::MxNtOpenKey(lphBaseKey, dwAccess, &sObjAttr);
  }
  if (hKey == HKEY_CLASSES_ROOT || hKey == HKEY_CURRENT_USER || hKey == HKEY_PERFORMANCE_DATA ||
      hKey == HKEY_PERFORMANCE_TEXT || hKey == HKEY_PERFORMANCE_NLSTEXT || hKey == HKEY_CURRENT_CONFIG ||
      hKey == HKEY_DYN_DATA || hKey == HKEY_CURRENT_USER_LOCAL_SETTINGS)
  {
    return STATUS_NOT_IMPLEMENTED;
  }
  *lphBaseKey = hKey;
  return STATUS_SUCCESS;
}

static HRESULT RecursiveDeleteKey(_In_ HKEY hKey, _In_opt_ PMX_UNICODE_STRING SubKey)
{
  MX_OBJECT_ATTRIBUTES sObjAttr;
  MX_KEY_FULL_INFORMATION sFullInfoBuffer;
  MX::TAutoFreePtr<BYTE> aBuffer;
  ULONG RetLength;
  HANDLE hChildKey = NULL;
  NTSTATUS nNtStatus;
  HRESULT hRes;

  //prepare
  if (SubKey != NULL)
  {
    MX::MemSet(&sObjAttr, 0, sizeof(sObjAttr));
    sObjAttr.Length = (ULONG)sizeof(sObjAttr);
    sObjAttr.RootDirectory = hKey;
    sObjAttr.Attributes = OBJ_CASE_INSENSITIVE;
    sObjAttr.ObjectName = SubKey;
    nNtStatus = ::MxNtOpenKey(&hChildKey, KEY_READ | DELETE, &sObjAttr);
    if (!NT_SUCCESS(nNtStatus))
    {
err_translate_ntstatus:
      hRes = HRESULT_FROM_WIN32(::MxRtlNtStatusToDosError(nNtStatus));
      goto done;
    }
  }
  else
  {
    hChildKey = (HANDLE)hKey;
  }
  //get maximum size of key items
  nNtStatus = ::MxNtQueryKey(hChildKey, MxKeyFullInformation, &sFullInfoBuffer, (ULONG)sizeof(sFullInfoBuffer),
                              &RetLength);
  if ((!NT_SUCCESS(nNtStatus)) && nNtStatus != STATUS_BUFFER_OVERFLOW)
    goto err_translate_ntstatus;
  //allocate buffer
  aBuffer.Attach((LPBYTE)MX_MALLOC((sizeof(MX_KEY_BASIC_INFORMATION) + sFullInfoBuffer.MaxNameLen >
                                    sizeof(MX_KEY_VALUE_FULL_INFORMATION) + sFullInfoBuffer.MaxValueNameLen)
                                   ? sizeof(MX_KEY_BASIC_INFORMATION) + sFullInfoBuffer.MaxNameLen + 2
                                   : sizeof(MX_KEY_VALUE_FULL_INFORMATION) + sFullInfoBuffer.MaxValueNameLen + 2));
  if (!aBuffer)
  {
    hRes = E_OUTOFMEMORY;
    goto done;
  }
  //recursively delete all the subkeys
  while (1)
  {
    PMX_KEY_BASIC_INFORMATION lpInfo = (PMX_KEY_BASIC_INFORMATION)aBuffer.Get();
    MX_UNICODE_STRING usTemp;

    nNtStatus = ::MxNtEnumerateKey(hChildKey, 0, MxKeyBasicInformation, lpInfo,
                                   (ULONG)(sizeof(MX_KEY_BASIC_INFORMATION) + sFullInfoBuffer.MaxNameLen), &RetLength);
    if (!NT_SUCCESS(nNtStatus))
      break;
    usTemp.Buffer = lpInfo->Name;
    usTemp.Length = usTemp.MaximumLength = (USHORT)(lpInfo->NameLength);
    hRes = RecursiveDeleteKey((HKEY)hChildKey, &usTemp);
    if (hRes == MX_E_PathNotFound || hRes == MX_E_FileNotFound)
      break;
    if (FAILED(hRes))
      goto done;
  }
  //if we have a subkey, delete it
  if (SubKey != NULL)
  {
    nNtStatus = ::MxNtDeleteKey(hChildKey);
    if (!NT_SUCCESS(nNtStatus))
      goto err_translate_ntstatus;
  }
  else
  {
    //else delete values
    while (1)
    {
      PMX_KEY_VALUE_FULL_INFORMATION lpInfo = (PMX_KEY_VALUE_FULL_INFORMATION)aBuffer.Get();
      MX_UNICODE_STRING usTemp;

      nNtStatus = ::MxNtEnumerateValueKey(hChildKey, 0, MxKeyValueFullInformation, lpInfo,
                                 (ULONG)(sizeof(MX_KEY_VALUE_FULL_INFORMATION) + sFullInfoBuffer.MaxValueNameLen),
                                 &RetLength);
      if (!NT_SUCCESS(nNtStatus))
        break;

      usTemp.Buffer = lpInfo->Name;
      usTemp.Length = usTemp.MaximumLength = (USHORT)(lpInfo->NameLength);
      nNtStatus = ::MxNtDeleteValueKey(hChildKey, &usTemp);
      if (!NT_SUCCESS(nNtStatus))
      {
        hRes = HRESULT_FROM_WIN32(::MxRtlNtStatusToDosError(nNtStatus));
        if (hRes != MX_E_PathNotFound && hRes != MX_E_FileNotFound)
          goto done;
        break;
      }
    }
  }
  hRes = S_OK;

done:
  if (hChildKey != NULL && hChildKey != (HANDLE)hKey)
    ::RegCloseKey((HKEY)hChildKey);
  if (FAILED(hRes) && hRes != MX_E_PathNotFound && hRes != MX_E_FileNotFound)
    return HRESULT_FROM_WIN32(::MxRtlNtStatusToDosError(nNtStatus));
  return S_OK;
}
