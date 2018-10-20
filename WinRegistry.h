/*
* Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
* All rights reserved.
*
**/

#ifndef _WINREGISTRY_H
#define _WINREGISTRY_H

#include <Defines.h>
#include <Windows.h>
#include <AutoPtr.h>
#include <ArrayList.h>
#include <Strings\Strings.h>
#include <WinReg.h>
#include <winternl.h>

//-----------------------------------------------------------

namespace MXHelpers {

class CWinRegistry : public virtual MX::CBaseMemObj
{
public:
  CWinRegistry();
  ~CWinRegistry();

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

  HRESULT ReadString(_In_z_ LPCWSTR szNameW, _Out_ MX::CStringW &cStrValueW, _In_opt_ BOOL bAutoExpandRegSz=TRUE);
  HRESULT ReadString(_In_ PUNICODE_STRING Name, _Out_ PUNICODE_STRING *pValue, _In_opt_ BOOL bAutoExpandRegSz = TRUE);

  HRESULT ReadPassword(_In_z_ LPCWSTR szNameW, _Out_ MX::CStringW &cStrPasswordW);

  HRESULT ReadMultiString(_In_z_ LPCWSTR szNameW, _Out_ MX::TArrayListWithFree<LPWSTR> &aStrValuesList);
  HRESULT ReadMultiString(_In_ PUNICODE_STRING Name, _Out_ MX::TArrayListWithFree<PUNICODE_STRING> &aStrValuesList);

  HRESULT ReadBlob(_In_z_ LPCWSTR szNameW, _Out_ MX::TAutoFreePtr<BYTE> &cBlob, _Out_ SIZE_T &nBlobSize);
  HRESULT ReadBlob(_In_ PUNICODE_STRING Name, _Out_ MX::TAutoFreePtr<BYTE> &cBlob, _Out_ SIZE_T &nBlobSize);

  HRESULT WriteDWord(_In_z_ LPCWSTR szNameW, _In_ DWORD dwValue);

  HRESULT WriteString(_In_z_ LPCWSTR szNameW, _In_z_ LPCWSTR szValueW);

  HRESULT WriteMultiString(_In_z_ LPCWSTR szNameW, _In_ SIZE_T nValuesCount, _In_ LPCWSTR *lpszValuesW);

  HRESULT WriteBlob(_In_z_ LPCWSTR szNameW, _In_ LPCVOID lpValue, _In_ SIZE_T nValueLen);

  HRESULT WritePassword(_In_z_ LPCWSTR szNameW, _In_z_ LPCWSTR szPasswordW);

  HRESULT DeleteKey(_In_z_ LPCWSTR szNameW);
  HRESULT DeleteKey(_In_ PUNICODE_STRING Name);

  HRESULT DeleteValue(_In_opt_z_ LPCWSTR szNameW);
  HRESULT DeleteValue(_In_opt_ PUNICODE_STRING Name);

  HRESULT EnumerateKeys(_In_ DWORD dwIndex, _Inout_ MX::CStringW &cStrKeyNameW);
  HRESULT EnumerateKeys(_In_ DWORD dwIndex, _Out_ PUNICODE_STRING *pKeyName);

  HRESULT EnumerateValues(_In_ DWORD dwIndex, _Inout_ MX::CStringW &cStrValueNameW);
  HRESULT EnumerateValues(_In_ DWORD dwIndex, _Out_ PUNICODE_STRING *pValueName);

private:
  HKEY hKey;
};

}; //namespace MXHelpers

//-----------------------------------------------------------

#endif //_WINREGISTRY_H
