/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#include "FileRoutines.h"
#include <WaitableObjects.h>
#include <ShlObj.h>
#include <fileapi.h>
#include <Debug.h>

//-----------------------------------------------------------

#define CREATE_RETRIES_COUNT     5
#define CREATE_RETRIES_DELAY_MS 20

#define DELETE_RETRIES_COUNT     5
#define DELETE_RETRIES_DELAY_MS 20

#ifndef FILE_OPEN
  #define FILE_OPEN                               0x00000001
#endif //FILE_OPEN
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
  #define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#endif //FILE_SYNCHRONOUS_IO_NONALERT
#ifndef FILE_NON_DIRECTORY_FILE
  #define FILE_NON_DIRECTORY_FILE                 0x00000040
#endif //FILE_NON_DIRECTORY_FILE
#ifndef FILE_SEQUENTIAL_ONLY
  #define FILE_SEQUENTIAL_ONLY                    0x00000004
#endif //FILE_SEQUENTIAL_ONLY

#ifndef OBJ_CASE_INSENSITIVE
  #define OBJ_CASE_INSENSITIVE                    0x00000040
#endif //OBJ_CASE_INSENSITIVE

#ifndef STATUS_OBJECT_TYPE_MISMATCH
  #define STATUS_OBJECT_TYPE_MISMATCH      ((NTSTATUS)0xC0000024L)
#endif //STATUS_OBJECT_TYPE_MISMATCH
#ifndef STATUS_OBJECT_NAME_INVALID
  #define STATUS_OBJECT_NAME_INVALID       ((NTSTATUS)0xC0000033L)
#endif //STATUS_OBJECT_NAME_INVALID
#ifndef STATUS_OBJECT_PATH_NOT_FOUND
  #define STATUS_OBJECT_PATH_NOT_FOUND     ((NTSTATUS)0xC000003AL)
#endif //STATUS_OBJECT_PATH_NOT_FOUND

//-----------------------------------------------------------

typedef HRESULT (__stdcall *lpfnSHGetKnownFolderPath)(_In_ const GUID &rfid, _In_ DWORD dwFlags,
                                                      _In_opt_ HANDLE hToken, _Out_ PWSTR *ppszPath);
typedef HRESULT (__stdcall *lpfnSHGetFolderPathW)(_Reserved_ HWND hwnd, _In_ int csidl, _In_opt_ HANDLE hToken,
                                                  _In_ DWORD dwFlags, _Out_writes_(MAX_PATH) LPWSTR pszPath);

typedef VOID (__stdcall *lpfnCoTaskMemFree)(_In_opt_ LPVOID pv);

//-----------------------------------------------------------

static LPCWSTR szAppDataSubFolderW = NULL;

//-----------------------------------------------------------

namespace MXHelpers {

HRESULT GetAppFileName(_Inout_ MX::CStringW &cStrDestW)
{
  DWORD dwSize, dwLen;
  HRESULT hRes;

  for (dwSize = 256; dwSize <= 32768; dwSize <<= 1)
  {
    if (cStrDestW.EnsureBuffer((SIZE_T)dwSize + 4) == FALSE)
      return E_OUTOFMEMORY;
    dwLen = ::GetModuleFileNameW(NULL, (LPWSTR)cStrDestW, dwSize);
    if (dwLen == 0)
    {
      hRes = MX_HRESULT_FROM_LASTERROR();
      return (FAILED(hRes)) ? hRes : E_FAIL;
    }
    if (dwLen < dwSize - 2)
      break;
  }
  if (dwSize > 32768)
    return E_OUTOFMEMORY;
  ((LPWSTR)cStrDestW)[dwLen] = 0;
  cStrDestW.Refresh();
  NormalizePath(cStrDestW);
  return ConvertToLongPath(cStrDestW);
}

HRESULT GetAppFolderPath(_Inout_ MX::CStringW &cStrDestW)
{
  HRESULT hRes;

  hRes = GetAppFileName(cStrDestW);
  if (SUCCEEDED(hRes))
  {
    LPCWSTR sW = (LPWSTR)cStrDestW;
    SIZE_T nLen = cStrDestW.GetLength();

    while (nLen > 0 && sW[nLen - 1] != L'\\')
      nLen--;
    cStrDestW.Delete(nLen, (SIZE_T)-1);
  }
  return hRes;
}

VOID SetAppDataFolder(_In_z_ LPCWSTR szSubFolderW)
{
  szAppDataSubFolderW = szSubFolderW;
  return;
}

HRESULT GetAppDataFolderPath(_Inout_ MX::CStringW &cStrDestW)
{
  HRESULT hRes;

  if (szAppDataSubFolderW == NULL || *szAppDataSubFolderW == 0)
    return E_FAIL;
  hRes = GetCommonAppDataFolderPath(cStrDestW);
  if (SUCCEEDED(hRes))
  {
    if (cStrDestW.Concat(szAppDataSubFolderW) == FALSE ||
        cStrDestW.ConcatN(L"\\", 1) == FALSE)
    {
      hRes = E_OUTOFMEMORY;
    }
  }
  return hRes;
}

HRESULT GetCommonAppDataFolderPath(_Inout_ MX::CStringW &cStrDestW)
{
  static LONG volatile nInitLock = 0;
  static HINSTANCE volatile hShell32Dll = NULL;
  static LPVOID volatile fnSHGetKnownFolderPath = NULL;
  static LPVOID volatile fnSHGetFolderPathW = NULL;
  static HINSTANCE volatile hOle32Dll = NULL;
  static LPVOID volatile fnCoTaskMemFree = NULL;
#define ___KF_FLAG_CREATE 0x00008000
  static const GUID __FOLDERID_ProgramData = {
    0x62AB5D82, 0xFDC1, 0x4DC3, { 0xA9, 0xDD, 0x07, 0x0D, 0x1D, 0x49, 0x5D, 0x97 }
  };
  lpfnSHGetKnownFolderPath _fnSHGetKnownFolderPath;
  lpfnSHGetFolderPathW _fnSHGetFolderPathW;
  lpfnCoTaskMemFree _fnCoTaskMemFree;
  WCHAR szPathW[MAX_PATH], *szPathW_2;
  HRESULT hRes;

  cStrDestW.Empty();
  if (__InterlockedReadPointer(&hShell32Dll) == NULL)
  {
    MX::CFastLock cInitLock(&nInitLock);

    if (__InterlockedReadPointer(&hShell32Dll) == NULL)
    {
      ULONG flags = LOAD_WITH_ALTERED_SEARCH_PATH;
      MX_UNICODE_STRING usDllName;
      HINSTANCE _hShell32Dll;
      LPVOID fn;
      LONG nNtStatus;

      usDllName.Buffer = L"shell32.dll";
      usDllName.Length = usDllName.MaximumLength = 22;
      nNtStatus = ::MxLdrLoadDll(NULL, &flags, &usDllName, (PVOID*)&_hShell32Dll);
      if (nNtStatus < 0)
        return MX_HRESULT_FROM_WIN32(::MxRtlNtStatusToDosError(nNtStatus));

      fn = ::GetProcAddress(_hShell32Dll, "SHGetKnownFolderPath");
      _InterlockedExchangePointer(&fnSHGetKnownFolderPath, fn);
      fn = ::GetProcAddress(_hShell32Dll, "SHGetFolderPathW");
      _InterlockedExchangePointer(&fnSHGetFolderPathW, fn);

      _InterlockedExchangePointer((PVOID volatile *)&hShell32Dll, _hShell32Dll);
    }
  }

  if (__InterlockedReadPointer(&hOle32Dll) == NULL)
  {
    MX::CFastLock cInitLock(&nInitLock);

    if (__InterlockedReadPointer(&hOle32Dll) == NULL)
    {
      ULONG flags = LOAD_WITH_ALTERED_SEARCH_PATH;
      MX_UNICODE_STRING usDllName;
      HINSTANCE _hOle32Dll;
      LPVOID fn;
      LONG nNtStatus;

      usDllName.Buffer = L"ole32.dll";
      usDllName.Length = usDllName.MaximumLength = 18;
      nNtStatus = ::MxLdrLoadDll(NULL, &flags, &usDllName, (PVOID*)&_hOle32Dll);
      if (nNtStatus < 0)
        return MX_HRESULT_FROM_WIN32(::MxRtlNtStatusToDosError(nNtStatus));

      fn = ::GetProcAddress(_hOle32Dll, "CoTaskMemFree");
      _InterlockedExchangePointer(&fnCoTaskMemFree, fn);

      _InterlockedExchangePointer((PVOID volatile *)&hOle32Dll, _hOle32Dll);
    }
  }

  _fnSHGetKnownFolderPath = (lpfnSHGetKnownFolderPath)__InterlockedReadPointer(&fnSHGetKnownFolderPath);
  _fnSHGetFolderPathW = (lpfnSHGetFolderPathW)__InterlockedReadPointer(&fnSHGetFolderPathW);
  _fnCoTaskMemFree = (lpfnCoTaskMemFree)__InterlockedReadPointer(&fnCoTaskMemFree);

  //try method 1
  if (_fnSHGetKnownFolderPath != NULL && _fnCoTaskMemFree != NULL)
  {
    hRes = _fnSHGetKnownFolderPath(__FOLDERID_ProgramData, ___KF_FLAG_CREATE, NULL, &szPathW_2);
    if (SUCCEEDED(hRes))
    {
      if (cStrDestW.Copy(szPathW_2) == FALSE)
      {
        _fnCoTaskMemFree(szPathW_2);
        return E_OUTOFMEMORY;
      }
      _fnCoTaskMemFree(szPathW_2);

      goto final_convert;
    }
  }
  //try method 2
  if (_fnSHGetFolderPathW == NULL)
    return MX_HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);

  hRes = _fnSHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA | CSIDL_FLAG_CREATE, NULL, 0, szPathW);
  if (FAILED(hRes))
    return hRes;
  if (cStrDestW.Copy(szPathW) == FALSE)
    return E_OUTOFMEMORY;

final_convert:
  if (cStrDestW.ConcatN(L"\\", 1) == FALSE)
    return E_OUTOFMEMORY;
  NormalizePath(cStrDestW);
  return ConvertToLongPath(cStrDestW);
}

HRESULT GetWindowsPath(_Inout_ MX::CStringW &cStrDestW)
{
  DWORD dwSize, dwLen;
  LPWSTR sW;
  HRESULT hRes;

  for (dwSize=256; dwSize<=32768; dwSize<<=1)
  {
    if (cStrDestW.EnsureBuffer((SIZE_T)dwSize) == FALSE)
      return E_OUTOFMEMORY;
    dwLen = ::GetWindowsDirectoryW((LPWSTR)cStrDestW, dwSize-2);
    if (dwLen == 0)
    {
      hRes = MX_HRESULT_FROM_LASTERROR();
      return (FAILED(hRes)) ? hRes : E_FAIL;
    }
    if (dwLen < dwSize-4)
      break;
  }
  if (dwSize > 32768)
    return E_OUTOFMEMORY;
  sW = (LPWSTR)cStrDestW;
  if (dwLen == 0 || (sW[dwLen-1] != L'/' && sW[dwLen-1] != L'\\'))
    sW[dwLen++] = L'\\';
  sW[dwLen] = 0;
  cStrDestW.Refresh();
  NormalizePath(cStrDestW);
  return S_OK;
}

HRESULT GetWindowsSystemPath(_Inout_ MX::CStringW &cStrDestW)
{
  DWORD dwSize, dwLen;
  LPWSTR sW;
  HRESULT hRes;

  for (dwSize=256; dwSize<=32768; dwSize<<=1)
  {
    if (cStrDestW.EnsureBuffer((SIZE_T)dwSize) == FALSE)
      return E_OUTOFMEMORY;
    dwLen = ::GetSystemDirectoryW((LPWSTR)cStrDestW, dwSize-2);
    if (dwLen == 0)
    {
      hRes = MX_HRESULT_FROM_LASTERROR();
      return (FAILED(hRes)) ? hRes : E_FAIL;
    }
    if (dwLen < dwSize-4)
      break;
  }
  if (dwSize > 32768)
    return E_OUTOFMEMORY;
  sW = (LPWSTR)cStrDestW;
  if (dwLen == 0 || (sW[dwLen-1] != L'/' && sW[dwLen-1] != L'\\'))
    sW[dwLen++] = L'\\';
  sW[dwLen] = 0;
  cStrDestW.Refresh();
  NormalizePath(cStrDestW);
  return S_OK;
}

HRESULT _GetTempPath(_Inout_ MX::CStringW &cStrDestW)
{
  DWORD dwSize, dwLen;
  LPWSTR sW;
  HRESULT hRes;

  for (dwSize=256; dwSize<=32768; dwSize<<=1)
  {
    if (cStrDestW.EnsureBuffer((SIZE_T)dwSize) == FALSE)
      return E_OUTOFMEMORY;
    dwLen = ::GetTempPathW(dwSize-2, (LPWSTR)cStrDestW);
    if (dwLen == 0)
    {
      hRes = MX_HRESULT_FROM_LASTERROR();
      return (FAILED(hRes)) ? hRes : E_FAIL;
    }
    if (dwLen < dwSize-4)
      break;
  }
  if (dwSize > 32768)
    return E_OUTOFMEMORY;
  sW = (LPWSTR)cStrDestW;
  if (dwLen == 0 || (sW[dwLen-1] != L'/' && sW[dwLen-1] != L'\\'))
    sW[dwLen++] = L'\\';
  sW[dwLen] = 0;
  cStrDestW.Refresh();
  NormalizePath(cStrDestW);
  return ConvertToLongPath(cStrDestW);
}

HRESULT CreateDirectoryRecursive(_In_ LPCWSTR szFolderNameW)
{
  MX::CStringW cStrTempW;
  LARGE_INTEGER liTime;
  WCHAR chOrigW, *sW;
  SIZE_T i, nOfs;
  HRESULT hRes;

  if (szFolderNameW == NULL)
    return E_POINTER;
  if (MX::StrLenW(szFolderNameW) < 3)
    return E_INVALIDARG;
  if (szFolderNameW[0] != L'\\')
  {
    if (szFolderNameW[1] != L':' || (szFolderNameW[2] != L'\\' && szFolderNameW[2] != L'/'))
      return E_INVALIDARG;
  }
  else
  {
    if ((szFolderNameW[0] != L'\\' && szFolderNameW[0] != L'/') ||
        (szFolderNameW[1] != L'\\' && szFolderNameW[1] != L'/') ||
        szFolderNameW[2] == L'\\' || szFolderNameW[2] == L'/')
    {
      return E_INVALIDARG;
    }
  }
  if (cStrTempW.Copy(szFolderNameW) == FALSE)
    return E_OUTOFMEMORY;
  //if the path is NOT a network share, append long path mode
  sW = (LPWSTR)cStrTempW;
  if (sW[0] != L'\\')
  {
    if (cStrTempW.Insert(L"\\\\?\\", 0) == FALSE)
      return E_OUTOFMEMORY;
    sW = (LPWSTR)cStrTempW;
  }
  if (cStrTempW.GetLength() > 7 && sW[cStrTempW.GetLength()-1] == L'\\')
  {
    cStrTempW.Delete(cStrTempW.GetLength() - 1, 1);
    sW = (LPWSTR)cStrTempW;
  }
  //first check if the directory can be created directly or already exists
  if (::CreateDirectoryW(sW, NULL) != FALSE)
    return S_OK;
  hRes = MX_HRESULT_FROM_LASTERROR();
  if (hRes == MX_HRESULT_FROM_WIN32(ERROR_FILE_EXISTS) || hRes == MX_E_AlreadyExists)
    return S_OK;
  //skip until \\computer\share\first-folder(\\?) or \\?\drive:\first-folder(\\?)
  for (nOfs=0; sW[nOfs] == L'\\'; nOfs++);
  //advance until third backslash
  for (i=0; sW[nOfs] != 0; nOfs++)
  {
    if (sW[nOfs] == L'\\')
    {
      if ((++i) == 3)
        break;
    }
  }
  //create each directory
  while (sW[nOfs] != 0)
  {
    while (sW[nOfs] != 0 && sW[nOfs] != L'\\')
      nOfs++;
    chOrigW = sW[nOfs];
    sW[nOfs] = 0;
    if (::CreateDirectoryW(sW, NULL) == FALSE)
    {
      hRes = S_OK;
      for (i=CREATE_RETRIES_COUNT; i>0; i--)
      {
        liTime.QuadPart = -(LONGLONG)MX_MILLISECONDS_TO_100NS(CREATE_RETRIES_DELAY_MS);
        ::MxNtDelayExecution(FALSE, &liTime);
        if (::CreateDirectoryW(sW, NULL) != FALSE)
        {
          hRes = S_OK;
          break;
        }
        hRes = MX_HRESULT_FROM_LASTERROR();
        if (hRes == MX_HRESULT_FROM_WIN32(ERROR_FILE_EXISTS) || hRes == MX_E_AlreadyExists)
        {
          hRes = S_OK;
          break;
        }
      }
      if (FAILED(hRes))
        return hRes;
    }
    sW[nOfs] = chOrigW;
    if (chOrigW != 0)
      nOfs++;
  }
  return S_OK;
}

HRESULT RemoveDirectoryRecursive(_In_ LPCWSTR szFolderNameW, _In_opt_ eDelayedDelete nDD)
{
  MX::CStringW cStrTempW;
  LARGE_INTEGER liTime;
  SIZE_T i, nBaseLen;
  HANDLE hFind;
  WIN32_FIND_DATAW sFfData;
  HRESULT hRes;

  if (szFolderNameW == NULL)
    return E_POINTER;
  if (*szFolderNameW == 0)
    return E_INVALIDARG;

  //trasverse folder
  if (cStrTempW.Copy(szFolderNameW) == FALSE)
    return E_OUTOFMEMORY;
  nBaseLen = cStrTempW.GetLength();
  if (nBaseLen == 0)
    return E_INVALIDARG;
  if (((LPWSTR)cStrTempW)[nBaseLen-1] != L'\\')
  {
    if (cStrTempW.Concat(L"\\") == FALSE)
      return E_OUTOFMEMORY;
    nBaseLen++;
  }
  if (cStrTempW.Concat(L"*") == FALSE)
    return E_OUTOFMEMORY;
  hFind = ::FindFirstFileW((LPWSTR)cStrTempW, &sFfData);
  if (hFind == NULL || hFind == INVALID_HANDLE_VALUE)
  {
    hRes = MX_HRESULT_FROM_LASTERROR();
    return (hRes == MX_E_FileNotFound || hRes == MX_E_PathNotFound) ? S_OK : hRes;
  }
  do
  {
    if ((sFfData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 || sFfData.cFileName[0] != L'.' ||
        (sFfData.cFileName[1] != 0 && (sFfData.cFileName[1] != L'.' || sFfData.cFileName[2] != 0)))
    {
      cStrTempW.Delete(nBaseLen, (SIZE_T)-1);
      if (cStrTempW.Concat(sFfData.cFileName) != FALSE)
      {
        if ((sFfData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
          hRes = RemoveDirectoryRecursive((LPCWSTR)cStrTempW, nDD);
        else
          hRes =  _DeleteFile((LPCWSTR)cStrTempW, nDD);
      }
      else
      {
        hRes = E_OUTOFMEMORY;
      }
      if (FAILED(hRes))
      {
        ::FindClose(hFind);
        return hRes;
      }
    }
  }
  while (::FindNextFileW(hFind, &sFfData) != FALSE);
  ::FindClose(hFind);
  //remove directory
  cStrTempW.Delete(nBaseLen-1, (SIZE_T)-1); //remove trailing slash
  if (nDD == WaitUntilReboot)
  {
    if (::MoveFileExW((LPCWSTR)cStrTempW, NULL, MOVEFILE_DELAY_UNTIL_REBOOT) == FALSE)
      return MX_HRESULT_FROM_LASTERROR();
  }
  else if (::RemoveDirectoryW((LPWSTR)cStrTempW) == FALSE)
  {
    ::SetFileAttributesW((LPCWSTR)cStrTempW, FILE_ATTRIBUTE_NORMAL|FILE_ATTRIBUTE_DIRECTORY);
    for (i=DELETE_RETRIES_COUNT; i>0; i--)
    {
      liTime.QuadPart = -(LONGLONG)MX_MILLISECONDS_TO_100NS(DELETE_RETRIES_DELAY_MS);
      ::MxNtDelayExecution(FALSE, &liTime);
      if (::RemoveDirectoryW((LPWSTR)cStrTempW) != FALSE)
        break;
      hRes = MX_HRESULT_FROM_LASTERROR();
      if (hRes == MX_E_FileNotFound || hRes == MX_E_PathNotFound)
        break;
      if (hRes != MX_HRESULT_FROM_WIN32(ERROR_DIR_NOT_EMPTY) &&
          hRes != MX_HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED) &&
          hRes != MX_HRESULT_FROM_WIN32(ERROR_SHARING_VIOLATION))
      {
        return hRes;
      }
      if (i == 1)
      {
        if (nDD == DeleteOnRebootOnFailure)
        {
          if (::MoveFileExW((LPWSTR)cStrTempW, NULL, MOVEFILE_DELAY_UNTIL_REBOOT) == FALSE)
            return MX_HRESULT_FROM_LASTERROR();
          break;
        }
        return hRes;
      }
    }
  }
  return S_OK;
}

HRESULT _DeleteFile(_In_ LPCWSTR szFileNameW, _In_opt_ eDelayedDelete nDD)
{
  LARGE_INTEGER liTime;
  DWORD dw;
  HRESULT hRes;

  if (szFileNameW == NULL)
    return E_POINTER;
  if (*szFileNameW == 0)
    return E_INVALIDARG;
  dw = ::GetFileAttributesW(szFileNameW);
  if (dw != INVALID_FILE_ATTRIBUTES && (dw & FILE_ATTRIBUTE_DIRECTORY) != 0)
    return S_OK;
  if (nDD == WaitUntilReboot)
  {
    if (::MoveFileExW(szFileNameW, NULL, MOVEFILE_DELAY_UNTIL_REBOOT) == FALSE)
      return MX_HRESULT_FROM_LASTERROR();
    return S_OK;
  }
  if (::DeleteFileW(szFileNameW) == FALSE)
  {
    ::SetFileAttributesW(szFileNameW, FILE_ATTRIBUTE_NORMAL);
    for (dw=DELETE_RETRIES_COUNT; dw>0; dw--)
    {
      liTime.QuadPart = -(LONGLONG)MX_MILLISECONDS_TO_100NS(DELETE_RETRIES_DELAY_MS);
      ::MxNtDelayExecution(FALSE, &liTime);
      if (::DeleteFileW(szFileNameW) != FALSE)
        break;
      hRes = MX_HRESULT_FROM_LASTERROR();
      if (hRes == MX_E_PathNotFound || hRes == MX_E_FileNotFound)
        break;
      if (hRes != MX_HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED) && hRes != MX_HRESULT_FROM_WIN32(ERROR_SHARING_VIOLATION))
        return hRes;
      if (dw == 1)
      {
        if (nDD == DeleteOnRebootOnFailure)
        {
          if (::MoveFileExW(szFileNameW, NULL, MOVEFILE_DELAY_UNTIL_REBOOT) == FALSE)
            return MX_HRESULT_FROM_LASTERROR();
          break;
        }
        return hRes;
      }
    }
  }
  return S_OK;
}

HRESULT DeleteDirectoryFiles(_In_ LPCWSTR szFolderNameW, _In_opt_ eDelayedDelete nDD)
{
  MX::CStringW cStrTempW;
  SIZE_T nBaseLen;
  HANDLE hFind;
  WIN32_FIND_DATAW sFfData;
  HRESULT hRes;

  if (szFolderNameW == NULL)
    return E_POINTER;
  if (*szFolderNameW == 0)
    return E_INVALIDARG;

  //trasverse folder
  if (cStrTempW.Copy(szFolderNameW) == FALSE)
    return E_OUTOFMEMORY;
  nBaseLen = cStrTempW.GetLength();
  if (nBaseLen == 0)
    return E_INVALIDARG;
  if (((LPWSTR)cStrTempW)[nBaseLen - 1] != L'\\')
  {
    if (cStrTempW.Concat(L"\\") == FALSE)
      return E_OUTOFMEMORY;
    nBaseLen++;
  }
  if (cStrTempW.Concat(L"*") == FALSE)
    return E_OUTOFMEMORY;
  hFind = ::FindFirstFileW((LPWSTR)cStrTempW, &sFfData);
  if (hFind == NULL || hFind == INVALID_HANDLE_VALUE)
  {
    hRes = MX_HRESULT_FROM_LASTERROR();
    return (hRes == MX_E_FileNotFound || hRes == MX_E_PathNotFound) ? S_OK : hRes;
  }
  do
  {
    if ((sFfData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
    {
      cStrTempW.Delete(nBaseLen, (SIZE_T)-1);
      if (cStrTempW.Concat(sFfData.cFileName) != FALSE)
        hRes = _DeleteFile((LPCWSTR)cStrTempW, nDD);
      else
        hRes = E_OUTOFMEMORY;
      if (FAILED(hRes))
      {
        ::FindClose(hFind);
        return hRes;
      }
    }
  }
  while (::FindNextFileW(hFind, &sFfData) != FALSE);
  ::FindClose(hFind);
  return S_OK;
}

VOID NormalizePath(_Inout_ MX::CStringW &cStrPathW)
{
  LPWSTR sW;
  SIZE_T i;

  sW = (LPWSTR)cStrPathW;
  if (sW[0] == L'\\' && sW[1] == L'\\')
    sW += 2;
  //remove double slashes and convert forward slashes to back slashes
  while (*sW != 0)
  {
    for (i=0; sW[i] == L'/' || sW[i] == L'\\'; i++);
    if (i > 0)
    {
      if (i > 1)
        cStrPathW.Delete((SIZE_T)(sW - (LPWSTR)cStrPathW), i-1);
      *sW = L'\\';
    }
    sW++;
  }
  //remove "." && ".."
  sW = (LPWSTR)cStrPathW;
  while (*sW != 0)
  {
    if (sW[0] == L'\\' && sW[1] == L'.')
    {
      if (sW[2] == L'\\' || sW[2] == 0)
      {
        //remove "\.\"
        i = (SIZE_T)(sW - (LPWSTR)cStrPathW);
        cStrPathW.Delete(i, 2);
        sW = (LPWSTR)cStrPathW + i;
        continue;
      }
      else if (sW[2] == L'.' && (sW[3] == L'\\' || sW[3] == 0))
      {
        LPWSTR szStartW, szPrevSlashW;

        szStartW = (LPWSTR)cStrPathW;
        if (szStartW[0] == L'\\' && szStartW[1] == L'\\')
          szStartW += 2;
        else if (((szStartW[0] >= L'A' && szStartW[0] <= L'Z') || (szStartW[0] >= L'a' && szStartW[0] <= L'z')) &&
                 szStartW[1] == L':' && szStartW[2] == L'\\')
          szStartW += 3;
        szPrevSlashW = sW-1;
        while (szPrevSlashW > szStartW && *(szPrevSlashW-1) != L'\\')
          szPrevSlashW--;
        //remove from szPrevSlashW to sW+4
        i = (SIZE_T)(szPrevSlashW - (LPWSTR)cStrPathW);
        cStrPathW.Delete(i, (SIZE_T)(sW-szPrevSlashW) + 4);
        if (i > 0)
          i--;
        sW = (LPWSTR)cStrPathW + i;
        continue;
      }
    }
    sW++;
  }


  //convert short path to long if not a network folder
  if (((LPCWSTR)cStrPathW)[0] != L'\\')
  {
    MX::CStringW cStrTempW;
    SIZE_T nLen, nSize;

    for (nSize = 256; nSize <= 32768 && nSize < cStrTempW.GetLength(); nSize <<= 1);
    while (nSize <= 32768)
    {
      if (cStrPathW.EnsureBuffer(nSize + 4) == FALSE)
        break;
      nLen = (SIZE_T)::GetLongPathNameW((LPCWSTR)cStrPathW, (LPWSTR)cStrTempW, (DWORD)nSize);
      if (nLen == 0)
        break; //couldn't convert (i.e. access denied to a parent folder), use original temp path
      if (nLen < nSize)
      {
        ((LPWSTR)cStrTempW)[nLen] = 0;
        cStrTempW.Refresh();
        //----
        cStrPathW.Attach(cStrTempW.Detach());
        break;
      }
      nSize <<= 1;
    }
  }
  //done
  return;
}

HRESULT ConvertToLongPath(_Inout_ MX::CStringW &cStrPathW)
{
  MX::CStringW cStrTempW;
  LPCWSTR sW;
  SIZE_T i, nStartOfs, nOfs, nPrefixLen = 0;
  HANDLE hFindFile;
  WIN32_FIND_DATAW sFindDataW;
  WCHAR chOrigW;

  sW = (LPCWSTR)cStrPathW;
  if (sW[0] == L'\\' &&
      (sW[1] == L'\\' || sW[1] == L'?') &&
      (sW[2] == L'.' || sW[2] == L'?') &&
      sW[3] == L'\\')
  {
    //nt path provided
    if ((sW[0] == L'U' || sW[0] == L'u') &&
        (sW[1] == L'N' || sW[1] == L'n') &&
        (sW[2] == L'C' || sW[2] == L'c') &&
        sW[3] == L'\\')
    {
      return S_OK; //skip network folders
    }
    if (cStrTempW.Copy(L"\\\\?\\") == FALSE || cStrTempW.Concat(sW+4) == FALSE)
      return E_OUTOFMEMORY;
  }
  else if ((sW[0] >= L'A' && sW[0] <= L'Z') || (sW[0] >= L'a' && sW[0] <= L'z') &&
           sW[1] == L':')
  {
    if (cStrTempW.Copy(L"\\\\?\\") == FALSE || cStrTempW.Concat(sW) == FALSE)
      return E_OUTOFMEMORY;
    nPrefixLen = 4;
  }
  else
  {
    //skip other path types (like network folders)
    return S_OK;
  }

  //look for the fourth backslash as starting offset
  sW = (LPCWSTR)cStrTempW;
  for (i=nOfs=0; sW[nOfs] !=0; nOfs++)
  {
    if (sW[nOfs] == L'\\')
    {
      if ((++i) == 4)
      {
        nOfs++;
        break;
      }
    }
  }
  //process
  while (sW[nOfs] != 0)
  {
    //skip slashes
    while (sW[nOfs] == L'\\')
      nOfs++;
    //advance until component end
    nStartOfs = nOfs;
    while (sW[nOfs] != 0 && sW[nOfs] != L'\\')
      nOfs++;
    //find file
    if (nOfs > nStartOfs)
    {
      chOrigW = sW[nOfs];
      ((LPWSTR)sW)[nOfs] = 0;
      hFindFile = ::FindFirstFileW(sW, &sFindDataW);
      ((LPWSTR)sW)[nOfs] = chOrigW;
      if (hFindFile == INVALID_HANDLE_VALUE)
        break;
      ::FindClose(hFindFile);
      if (sFindDataW.cFileName[0] != 0)
      {
        cStrTempW.Delete(nStartOfs, nOfs - nStartOfs);
        if (cStrTempW.Insert(sFindDataW.cFileName, nStartOfs) == FALSE)
          return E_OUTOFMEMORY;
        nOfs = nStartOfs + MX::StrLenW(sFindDataW.cFileName);
        sW = (LPCWSTR)cStrTempW;
      }
    }
  }
  //done
  cStrTempW.Delete(0, nPrefixLen);
  cStrPathW.Attach(cStrTempW.Detach());
  return S_OK;
}

HRESULT ConvertToNative(_Inout_ MX::CStringW &cStrPathW)
{
  MX::CStringW cStrTempW;
  LPCWSTR sW;
  HRESULT hRes;

  sW = (LPCWSTR)cStrPathW;
  //try symbolic link path
  if (sW[0] == L'\\' &&
      (sW[1] == L'\\' || sW[1] == L'?') &&
      (sW[2] == L'.' || sW[2] == L'?') &&
      sW[3] == L'\\')
  {
    if (cStrTempW.Format(L"\\??\\%s", sW+4) == FALSE)
      return E_OUTOFMEMORY;
    hRes = ResolveSymbolicLink(cStrTempW);
    if (SUCCEEDED(hRes))
      cStrPathW.Attach(cStrTempW.Detach());
    return hRes;
  }
  //try DOS volume/path
  if (((sW[0] >= L'A' && sW[0] <= L'Z') || (sW[0] >= L'a' && sW[0] <= L'z')) &&
      sW[1] == L':')
  {
    if (cStrTempW.Format(L"\\??\\%s", sW) == FALSE)
      return E_OUTOFMEMORY;
    hRes = ResolveSymbolicLink(cStrTempW);
    if (SUCCEEDED(hRes))
      cStrPathW.Attach(cStrTempW.Detach());
    return hRes;
  }
  //try network paths
  if (sW[0] == L'\\' && sW[1] == L'\\')
  {
    if (cStrPathW.Insert(L"Device\\Mup", 1) == FALSE)
      return E_OUTOFMEMORY;
    return S_OK;
  }
  //done
  return S_OK;
}

HRESULT ConvertToWin32(_Inout_ MX::CStringW &cStrPathW)
{
  MX::CStringW cStrTempW;
  MX_PROCESS_DEVICEMAP_INFORMATION sPdmi;
  SIZE_T i, nLen;
  WCHAR szDriveW[4], szVolumeNameW[512];
  LPCWSTR sW;
  NTSTATUS nNtStatus;
  HRESULT hRes;

  //first resolve symlink
  sW = (LPCWSTR)cStrPathW;
  if (sW[0] == L'\\' &&
      (sW[1] == L'\\' || sW[1] == L'?') &&
      (sW[2] == L'.' || sW[2] == L'?') &&
      sW[3] == L'\\')
  {
    if (cStrTempW.Format(L"\\??\\%s", sW+4) == FALSE)
      return E_OUTOFMEMORY;
    hRes = ResolveSymbolicLink(cStrTempW);
    if (SUCCEEDED(hRes))
      cStrPathW.Attach(cStrTempW.Detach());
  }
  //network path?
  if (MX::StrNCompareW(sW, L"\\Device\\LanmanRedirector\\", 25, TRUE) == 0)
  {
    cStrPathW.Delete(1, 23);
    return S_OK;
  }
  if (MX::StrNCompareW(sW, L"\\Device\\Mup\\", 12, TRUE) == 0)
  {
    cStrPathW.Delete(1, 10);
    return S_OK;
  }
  //can convert to DOS volume?
  if (MX::StrNCompareW(sW, L"\\Device\\", 8, TRUE) == 0)
  {
    nNtStatus = ::MxNtQueryInformationProcess(MX_CURRENTPROCESS, MxProcessDeviceMap, &(sPdmi.Query),
                                              (ULONG)sizeof(sPdmi.Query), NULL);
    if (!NT_SUCCESS(nNtStatus))
      return MX_HRESULT_FROM_WIN32(::MxRtlNtStatusToDosError(nNtStatus));
    szDriveW[1] = L':';
    szDriveW[2] = 0;
    for (i=0; i<26; i++)
    {
      if ((sPdmi.Query.DriveMap & (1UL << i)) != 0)
      {
        szDriveW[0] = (WCHAR)(L'A' + i);
        nLen = (SIZE_T)::QueryDosDeviceW(szDriveW, szVolumeNameW, MX_ARRAYLEN(szVolumeNameW)-1);
        if (nLen > 0)
        {
          szVolumeNameW[nLen] = 0;
          nLen = MX::StrLenW(szVolumeNameW);
          if (MX::StrNCompareW(sW, szVolumeNameW, nLen, TRUE) == 0 && (sW[nLen] == 0 || sW[nLen] == L'\\'))
          {
            //insert drive letter (before deletion to preserve input on error)
            i = 2;
            if (cStrPathW.GetLength() == 0 || *sW != L'\\')
              szDriveW[i++] = L'\\';
            if (cStrPathW.InsertN(szDriveW, 0, i) == FALSE)
              return E_OUTOFMEMORY;
            //delete NT data
            cStrPathW.Delete(i, nLen);
            break;
          }
        }
      }
    }
    //if a drive letter was not found, convert "\Device\" to "\\?\"
    if (i >= 26)
    {
      if (cStrPathW.InsertN(L"\\?", 1, 2) == FALSE)
        return E_OUTOFMEMORY;
      cStrPathW.Delete(3, 6);
    }
  }
  //done
  return S_OK;
}

HRESULT DeviceName2DosName(_Inout_ MX::CStringW &cStrPathW)
{
  WCHAR szNameW[1024], szDriveW[3], *sW;
  DWORD dwDrivesMask;
  SIZE_T nNameLen;
  HRESULT hRes;

  sW = (LPWSTR)cStrPathW;
  //try network shares first
  if (sW[0] == L'\\')
  {
    if (MX::StrNCompareW(sW, L"\\Device\\MUP\\", 12, TRUE) == 0)
    {
      cStrPathW.Delete(1, 10);
      return S_OK;
    }
    if (MX::StrNCompareW(sW, L"\\Device\\LanmanRedirector\\", 25, TRUE) == 0)
    {
      cStrPathW.Delete(1, 23);
      return S_OK;
    }
    if (MX::StrNCompareW(sW, L"\\\\?\\", 4) == 0 || MX::StrNCompareW(sW, L"\\??\\", 4) == 0)
    {
      cStrPathW.Delete(0, 4);
    }
  }
  //translate path in device form to drive letters
  dwDrivesMask = ::GetLogicalDrives();
  szDriveW[1] = L':';
  szDriveW[2] = 0;
  sW = (LPWSTR)cStrPathW;
  hRes = S_OK;
  for (szDriveW[0] = L'A'; szDriveW[0] <= L'Z'; szDriveW[0]++, dwDrivesMask >>= 1)
  {
    if ((dwDrivesMask & 1) != 0)
    {
      if (::QueryDosDeviceW(szDriveW, szNameW, _countof(szNameW)) != FALSE)
      {
        szNameW[_countof(szNameW) - 1] = 0;
        nNameLen = wcslen(szNameW);
        if (MX::StrNCompareW(sW, szNameW, nNameLen, TRUE) == 0 && (sW[nNameLen] == 0 || sW[nNameLen] == L'\\'))
        {
          //first insert and then delete to avoid modifying the string if an error is raised
          if (cStrPathW.InsertN(szDriveW, 0, 2) != FALSE)
            cStrPathW.Delete(2, nNameLen);
          else
            hRes = E_OUTOFMEMORY;
          break;
        }
      }
    }
  }
  //done
  return hRes;
}

HRESULT ResolveSymbolicLink(_Inout_ MX::CStringW &cStrPathW)
{
  MX::CStringW cStrTempPathW, cStrTempW;
  MX_UNICODE_STRING usDevName, CurrName, *TempStr = NULL;
  MX_OBJECT_ATTRIBUTES sObjAttr;
  LPWSTR sW;
  NTSTATUS nNtStatus;

  if (cStrPathW.IsEmpty() != FALSE)
    return S_OK;

  sW = (LPWSTR)cStrPathW;
  if (sW[0] != L'\\')
  {
    if (cStrTempPathW.Format(L"\\??\\%s", (LPCWSTR)cStrPathW) == FALSE)
      return E_OUTOFMEMORY;
    CurrName.Buffer = (LPWSTR)cStrTempPathW;
    CurrName.Length = CurrName.MaximumLength = (USHORT)(cStrTempPathW.GetLength() * 2);
  }
  else if (cStrPathW.GetLength() >= 4 &&
           (sW[1] == L'\\' || sW[1] == L'?') &&
           (sW[2] == L'.' || sW[2] == L'?') &&
           sW[3] == L'\\')
  {
    if (cStrTempPathW.Format(L"\\??\\%s", sW + 4) == FALSE)
      return E_OUTOFMEMORY;
    CurrName.Buffer = (LPWSTR)cStrTempPathW;
    CurrName.Length = CurrName.MaximumLength = (USHORT)(cStrTempPathW.GetLength() * 2);
  }
  else
  {
    CurrName.Buffer = (LPWSTR)cStrPathW;
    CurrName.Length = CurrName.MaximumLength = (USHORT)(cStrPathW.GetLength() * 2);
  }
restart:
  //query for the symbolic link from the full string and going back
  MX::MemCopy(&usDevName, &CurrName, sizeof(CurrName));
  while (usDevName.Length > 0 && usDevName.Buffer[usDevName.Length / 2 - 1] == L'\\')
    usDevName.Length -= 2;
  //loop while we have some string
  nNtStatus = STATUS_SUCCESS;
  while (NT_SUCCESS(nNtStatus) && usDevName.Length > 0)
  {
    ULONG RetLength;
    HANDLE hSymLink;

    //query symbolic link
    MX::MemSet(&sObjAttr, 0, sizeof(sObjAttr));
    sObjAttr.Length = sizeof(sObjAttr);
    sObjAttr.Attributes = OBJ_CASE_INSENSITIVE;
    sObjAttr.ObjectName = &usDevName;
    nNtStatus = ::MxNtOpenSymbolicLinkObject(&hSymLink, GENERIC_READ, &sObjAttr);
    if (NT_SUCCESS(nNtStatus))
    {
      TempStr = (PMX_UNICODE_STRING)MX_MALLOC(sizeof(MX_UNICODE_STRING) + 65534 + 2);
      if (TempStr)
      {
        TempStr->Buffer = (PWCH)(TempStr + 1);
        TempStr->Length = 0;
        TempStr->MaximumLength = 65534;
        TempStr->Buffer[0] = TempStr->Buffer[TempStr->MaximumLength / 2] = 0;

        RetLength = 0;
        nNtStatus = ::MxNtQuerySymbolicLinkObject(hSymLink, TempStr, &RetLength);
      }
      else
      {
        nNtStatus = STATUS_INSUFFICIENT_RESOURCES;
      }
      //close link
      ::MxNtClose(hSymLink);
    }

    if (NT_SUCCESS(nNtStatus))
    {
      MX::CStringW cStrTempW;

      //at this point we have a valid string, build replacement
      if (cStrTempW.CopyN(TempStr->Buffer, (SIZE_T)(TempStr->Length) / 2) != FALSE &&
          cStrTempW.ConcatN(usDevName.Buffer + (SIZE_T)(usDevName.Length) / 2,
                            (SIZE_T)(CurrName.Length - usDevName.Length) / 2) != FALSE)
      {
        //replace current name
        cStrTempPathW.Attach(cStrTempW.Detach());
        CurrName.Buffer = (LPWSTR)cStrTempPathW;
        CurrName.Length = CurrName.MaximumLength = (USHORT)(cStrTempPathW.GetLength() * 2);
        goto restart;
      }
      nNtStatus = STATUS_INSUFFICIENT_RESOURCES;
    }
    else if (nNtStatus != STATUS_OBJECT_TYPE_MISMATCH && nNtStatus != STATUS_OBJECT_NAME_INVALID &&
             nNtStatus != STATUS_OBJECT_PATH_NOT_FOUND && nNtStatus != STATUS_OBJECT_NAME_NOT_FOUND)
    {
      break;
    }
    else
    {
      //go back until previous backslash
      while (usDevName.Length > 0 && usDevName.Buffer[usDevName.Length / 2 - 1] != L'\\')
        usDevName.Length -= 2;
      //skip backslash
      while (usDevName.Length > 0 && usDevName.Buffer[usDevName.Length / 2 - 1] == L'\\')
        usDevName.Length -= 2;

      //try again
      nNtStatus = STATUS_SUCCESS;
    }
  }

  //cleanup
  MX_FREE(TempStr);
  //if we reach here, our job is done
  if (!NT_SUCCESS(nNtStatus))
    return MX_HRESULT_FROM_WIN32(::MxRtlNtStatusToDosError(nNtStatus));
  //if this comparison is equal, then cStrTempPathW has the resolved path
  if (CurrName.Buffer == (LPWSTR)cStrTempPathW)
    cStrPathW.Attach(cStrTempPathW.Detach());
  //done
  return S_OK;
}

HRESULT GetFileNameFromHandle(_In_ HANDLE hFile, _Inout_ MX::CStringW &cStrFileNameW)
{
  PMX_OBJECT_NAME_INFORMATION lpNameInfo = NULL;
  ULONG nBufSize, nReqLength;
  NTSTATUS nNtStatus;

  cStrFileNameW.Empty();

  if (hFile == NULL || hFile == INVALID_HANDLE_VALUE)
    return E_INVALIDARG;
  nBufSize = 2048;
  nReqLength = 0;
  do
  {
    if (nReqLength > nBufSize)
      nBufSize = nReqLength + 256;
    MX::MemFree(lpNameInfo);
    lpNameInfo = (PMX_OBJECT_NAME_INFORMATION)MX::MemAlloc(sizeof(MX_OBJECT_NAME_INFORMATION) + (SIZE_T)nBufSize);
    if (lpNameInfo != NULL)
      nNtStatus = ::MxNtQueryObject(hFile, MxObjectNameInformation, lpNameInfo, nBufSize, &nReqLength);
    else
      nNtStatus = STATUS_INSUFFICIENT_RESOURCES;
  }
  while (nNtStatus == STATUS_BUFFER_OVERFLOW || nNtStatus == STATUS_BUFFER_TOO_SMALL);
  if (NT_SUCCESS(nNtStatus))
  {
    if (cStrFileNameW.CopyN(lpNameInfo->Name.Buffer, (SIZE_T)(lpNameInfo->Name.Length) / 2) == FALSE)
      nNtStatus = STATUS_INSUFFICIENT_RESOURCES;
  }
  MX::MemFree(lpNameInfo);
  if (!NT_SUCCESS(nNtStatus))
    return MX_HRESULT_FROM_WIN32(::MxRtlNtStatusToDosError(nNtStatus));
  return S_OK;
}

HRESULT OpenFileWithEscalatingSharing(_In_z_ LPCWSTR szFileNameW, _Out_ HANDLE *lphFile)
{
  static const BYTE aSharingAccess[4] = {
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SHARE_READ | FILE_SHARE_DELETE,
    FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SHARE_READ
  };
  DWORD i;
  HRESULT hRes = S_OK;

  *lphFile = NULL;

  if (MX::StrNCompareW(szFileNameW, L"\\??\\", 4) == 0 || MX::StrNCompareW(szFileNameW, L"\\Device\\", 8, TRUE) == 0)
  {
    MX_OBJECT_ATTRIBUTES sObjAttrib;
    MX_IO_STATUS_BLOCK sIoStatus;
    MX_UNICODE_STRING usFileName;
    NTSTATUS nNtStatus;

    MX::MemSet(&sObjAttrib, 0, sizeof(sObjAttrib));
    sObjAttrib.Length = (ULONG)sizeof(sObjAttrib);
    sObjAttrib.Attributes = OBJ_CASE_INSENSITIVE;
    sObjAttrib.ObjectName = &usFileName;
    usFileName.Buffer = (PWSTR)szFileNameW;
    usFileName.Length = usFileName.MaximumLength = (USHORT)(MX::StrLenW(szFileNameW) * 2);
    for (i=0; i<4; i++)
    {
      MX::MemSet(&sIoStatus, 0, sizeof(sIoStatus));
      nNtStatus = ::MxNtCreateFile(lphFile, FILE_GENERIC_READ, &sObjAttrib, &sIoStatus, NULL, 0,
                                   (ULONG)aSharingAccess[i], FILE_OPEN, FILE_NON_DIRECTORY_FILE |
                                   FILE_SEQUENTIAL_ONLY | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
      if (NT_SUCCESS(nNtStatus))
        return S_OK;
      hRes = MX_HRESULT_FROM_NT(nNtStatus);
      *lphFile = NULL;
      if (hRes != HRESULT_FROM_WIN32(ERROR_SHARING_VIOLATION))
        break;
    }
  }
  else
  {
    //NOTE: CreateFileW adds FILE_NON_DIRECTORY_FILE flag if FILE_FLAG_BACKUP_SEMANTICS is not specified
    for (i=0; i<4; i++)
    {
      *lphFile = ::CreateFileW(szFileNameW, GENERIC_READ, (DWORD)aSharingAccess[i], NULL, OPEN_EXISTING, 0, NULL);
      if ((*lphFile) != NULL && (*lphFile) != INVALID_HANDLE_VALUE)
        return S_OK;
      hRes = MX_HRESULT_FROM_LASTERROR();
      *lphFile = NULL;
      if (hRes != HRESULT_FROM_WIN32(ERROR_SHARING_VIOLATION))
        break;
    }
  }
  return hRes;
}

}; //MXHelpers
