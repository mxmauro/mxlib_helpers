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
#ifndef _MXLIBHLP_WINDOWS_REGISTRY_H
#define _MXLIBHLP_WINDOWS_REGISTRY_H

#include <Defines.h>
#include <Windows.h>
#include <AutoPtr.h>
#include <ArrayList.h>
#include <Strings\Strings.h>
#include <WinReg.h>
#include <winternl.h>

//-----------------------------------------------------------

namespace MX {

class CWindowsRegistry : public virtual CBaseMemObj, public CNonCopyableObj
{
public:
  CWindowsRegistry();
  ~CWindowsRegistry();

  HRESULT Create(_In_ HKEY hParentKey, _In_z_ LPCWSTR szSubKeyW);
  HRESULT Create(_In_ HKEY hParentKey, _In_ PUNICODE_STRING SubKey);

  HRESULT Open(_In_ HKEY hParentKey, _In_opt_z_ LPCWSTR szSubKeyW, _In_opt_ BOOL bWriteAccess=FALSE);
  HRESULT Open(_In_ HKEY hParentKey, _In_ PUNICODE_STRING SubKey, _In_opt_ BOOL bWriteAccess=FALSE);

  VOID Close();

  operator HKEY() const
    {
    return hKey;
    };

  HRESULT ReadDWord(_In_z_ LPCWSTR szNameW, _Out_ DWORD &dwValue);
  HRESULT ReadDWord(_In_ PUNICODE_STRING Name, _Out_ DWORD &dwValue);

  HRESULT ReadString(_In_z_ LPCWSTR szNameW, _Out_ CStringW &cStrValueW, _In_opt_ BOOL bAutoExpandRegSz=TRUE);
  HRESULT ReadString(_In_ PUNICODE_STRING Name, _Out_ PUNICODE_STRING *pValue, _In_opt_ BOOL bAutoExpandRegSz = TRUE);

  HRESULT ReadPassword(_In_z_ LPCWSTR szNameW, _Out_ CStringW &cStrPasswordW);

  HRESULT ReadMultiString(_In_z_ LPCWSTR szNameW, _Out_ TArrayListWithFree<LPWSTR> &aStrValuesList);
  HRESULT ReadMultiString(_In_ PUNICODE_STRING Name, _Out_ TArrayListWithFree<PUNICODE_STRING> &aStrValuesList);

  HRESULT ReadBlob(_In_z_ LPCWSTR szNameW, _Out_ TAutoFreePtr<BYTE> &cBlob, _Out_ SIZE_T &nBlobSize);
  HRESULT ReadBlob(_In_ PUNICODE_STRING Name, _Out_ TAutoFreePtr<BYTE> &cBlob, _Out_ SIZE_T &nBlobSize);

  HRESULT ReadAny(_In_z_ LPCWSTR szNameW, _Out_ DWORD &dwType, _Out_ TAutoFreePtr<BYTE> &cData,
                  _Out_ SIZE_T &nDataSize);
  HRESULT ReadAny(_In_ PUNICODE_STRING Name, _Out_ DWORD &dwType, _Out_ TAutoFreePtr<BYTE> &cData,
                  _Out_ SIZE_T &nDataSize);

  HRESULT WriteDWord(_In_z_ LPCWSTR szNameW, _In_ DWORD dwValue);

  HRESULT WriteString(_In_z_ LPCWSTR szNameW, _In_z_ LPCWSTR szValueW);

  HRESULT WriteMultiString(_In_z_ LPCWSTR szNameW, _In_ SIZE_T nValuesCount, _In_ LPCWSTR *lpszValuesW);

  HRESULT WriteBlob(_In_z_ LPCWSTR szNameW, _In_opt_ LPCVOID lpValue, _In_ SIZE_T nValueLen);

  HRESULT WriteAny(_In_z_ LPCWSTR szNameW, _In_ DWORD dwType, _In_opt_ LPCVOID lpValue, _In_ SIZE_T nValueLen);

  HRESULT WritePassword(_In_z_ LPCWSTR szNameW, _In_z_ LPCWSTR szPasswordW);

  HRESULT DeleteKey(_In_z_ LPCWSTR szNameW);
  HRESULT DeleteKey(_In_ PUNICODE_STRING Name);

  HRESULT DeleteValue(_In_opt_z_ LPCWSTR szNameW);
  HRESULT DeleteValue(_In_opt_ PUNICODE_STRING Name);

  HRESULT EnumerateKeys(_In_ DWORD dwIndex, _Inout_ CStringW &cStrKeyNameW);
  HRESULT EnumerateKeys(_In_ DWORD dwIndex, _Out_ PUNICODE_STRING *pKeyName);

  HRESULT EnumerateValues(_In_ DWORD dwIndex, _Inout_ CStringW &cStrValueNameW);
  HRESULT EnumerateValues(_In_ DWORD dwIndex, _Out_ PUNICODE_STRING *pValueName);

private:
  HKEY hKey;
};

}; //namespace MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_WINDOWS_REGISTRY_H
