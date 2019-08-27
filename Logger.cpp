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
#include "Logger.h"
#include "WinRegistry.h"
#include "FileRoutines.h"
#include "System.h"
#include <Shlobj.h>
#include <stdio.h>
#include "FileVersionInfo.h"
#include <WaitableObjects.h>
#include <Finalizer.h>

#pragma comment(lib, "Shell32.lib")

//-----------------------------------------------------------

#ifdef _DEBUG
  #define DEBUGOUTPUT_LOG
#else //_DEBUG
  //#define DEBUGOUTPUT_LOG
#endif //_DEBUG

#define LOGFLAG_Initialized                           0x0001
#define LOGFLAG_OldFilesRemovalProcessed              0x0002
#define LOGFLAG_LogFileOpenProcessed                  0x0004

//-----------------------------------------------------------

static LONG volatile nMutex = 0;
static LONG volatile nInitializedFlags = 0;
static MX::CWindowsHandle cLogH;
static MX::CStringW cStrLogFileNameBaseW;
static MX::CStringW cStrLogFolderW;
static DWORD dwLogKeepDays = 0;
static WCHAR szTempBufW[8192];

//-----------------------------------------------------------

static VOID EndLogger();
static VOID RemoveOldFiles();
static HRESULT OpenLog();
static HRESULT InitLogCommon();
static VOID WriteLogCommon(_In_ BOOL bAddError, _In_ HRESULT hResError, _In_z_ LPCWSTR szFormatW, _In_ va_list argptr);

//-----------------------------------------------------------

namespace MX {

namespace EventLogger {

HRESULT Initialize(_In_z_ LPCWSTR szModuleNameW, _In_z_ LPCWSTR szRegistryKeyW, _In_z_ LPCWSTR szRegistryValueW,
                   _In_ DWORD dwDefaultKeepDays)
{
  CFastLock cLock(&nMutex);
  HKEY hKeyBase = HKEY_LOCAL_MACHINE;
  HRESULT hRes;

  if (szModuleNameW == NULL || szRegistryKeyW == NULL || szRegistryValueW == NULL)
    return E_POINTER;
  if (*szModuleNameW == 0 || *szRegistryKeyW == 0 || *szRegistryValueW == 0 || dwDefaultKeepDays < 1)
    return E_INVALIDARG;
  if (StrNCompareW(szRegistryKeyW, L"HKLM\\", 5, TRUE) == 0)
  {
    szRegistryKeyW += 5;
  }
  else if (StrNCompareW(szRegistryKeyW, L"HKEY_LOCAL_MACHINE\\", 19, TRUE) == 0)
  {
    szRegistryKeyW += 19;
  }
  else if (StrNCompareW(szRegistryKeyW, L"HKCU\\", 5, TRUE) == 0)
  {
    szRegistryKeyW += 5;
    hKeyBase = HKEY_CURRENT_USER;
  }
  else if (StrNCompareW(szRegistryKeyW, L"HKEY_CURRENT_USER\\", 18, TRUE) == 0)
  {
    szRegistryKeyW += 18;
    hKeyBase = HKEY_CURRENT_USER;
  }
  else
  {
    return E_INVALIDARG;
  }
  //copy base module name
  if (cStrLogFileNameBaseW.Copy(szModuleNameW) == FALSE)
    return E_OUTOFMEMORY;
  //setup log folder
  hRes = FileRoutines::GetAppDataFolderPath(cStrLogFolderW);
  if (SUCCEEDED(hRes))
  {
    if (cStrLogFolderW.ConcatN(L"Logs\\", 5) == FALSE)
      hRes = E_OUTOFMEMORY;
  }
  //get settings from registry
  if (SUCCEEDED(hRes))
  {
    CWindowsRegistry cWinReg;

    hRes = cWinReg.Open(hKeyBase, szRegistryKeyW);
    if (SUCCEEDED(hRes))
    {
      //get log keep days
      hRes = cWinReg.ReadDWord(szRegistryValueW, dwLogKeepDays);
      if (SUCCEEDED(hRes))
      {
        if (dwLogKeepDays < 1)
          dwLogKeepDays = 1;
        else if (dwLogKeepDays > 180)
          dwLogKeepDays = 180;
      }
      else if (hRes == MX_E_FileNotFound || hRes == MX_E_PathNotFound)
      {
        dwLogKeepDays = dwDefaultKeepDays;
        hRes = S_OK;
      }
    }
    else if (hRes == MX_E_FileNotFound || hRes == MX_E_PathNotFound)
    {
      dwLogKeepDays = dwDefaultKeepDays;
      hRes = S_OK;
    }
  }
  //register finalizer
  if (SUCCEEDED(hRes))
  {
    hRes = RegisterFinalizer(&EndLogger, 1);
  }
  //done
  if (FAILED(hRes))
  {
    cStrLogFolderW.Empty();
    cStrLogFileNameBaseW.Empty();
    dwLogKeepDays = 0;
    return hRes;
  }
  //done
  _InterlockedOr(&nInitializedFlags, LOGFLAG_Initialized);
  return hRes;
}

HRESULT Log(_Printf_format_string_ LPCWSTR szFormatW, ...)
{
  CFastLock cLock(&nMutex);
  va_list argptr;
  HRESULT hRes;

  if (szFormatW == NULL)
    return E_POINTER;
  //initialize logger on first access
  hRes = InitLogCommon();
  if (FAILED(hRes))
    return hRes;
  //write log
  va_start(argptr, szFormatW);
  WriteLogCommon(FALSE, S_OK, szFormatW, argptr);
  va_end(argptr);
  //done
  return S_OK;
}

HRESULT LogIfError(_In_ HRESULT hResError, _Printf_format_string_ LPCWSTR szFormatW, ...)
{
  CFastLock cLock(&nMutex);
  va_list argptr;
  HRESULT hRes;

  if (FAILED(hResError))
  {
    if (szFormatW == NULL)
      return E_POINTER;
    //initialize logger on first access
    hRes = InitLogCommon();
    if (FAILED(hRes))
      return hRes;
    //write log
    va_start(argptr, szFormatW);
    WriteLogCommon(TRUE, hResError, szFormatW, argptr);
    va_end(argptr);
  }
  //done
  return S_OK;
}

HRESULT LogAlways(_In_ HRESULT hResError, _Printf_format_string_ LPCWSTR szFormatW, ...)
{
  CFastLock cLock(&nMutex);
  va_list argptr;
  HRESULT hRes;

  if (szFormatW == NULL)
    return E_POINTER;
  //initialize logger on first access
  hRes = InitLogCommon();
  if (FAILED(hRes))
    return hRes;
  //write log
  va_start(argptr, szFormatW);
  WriteLogCommon(TRUE, hResError, szFormatW, argptr);
  va_end(argptr);
  //done
  return S_OK;
}

HRESULT LogRaw(_In_z_ LPCWSTR szTextW)
{
  CFastLock cLock(&nMutex);
  DWORD dwLen, dwWritten;
  HRESULT hRes;

  dwLen = (DWORD)StrLenW(szTextW);
  while (dwLen > 0 && (szTextW[dwLen - 1] == L'\r' || szTextW[dwLen - 1] == L'\n'))
    dwLen--;
  if (dwLen == 0)
    return S_OK;
  //initialize logger on first access
  hRes = InitLogCommon();
  if (FAILED(hRes))
    return hRes;
  //write log
  ::WriteFile(cLogH, szTextW, dwLen * 2, &dwWritten, NULL);
  ::WriteFile(cLogH, L"\r\n", 4, &dwWritten, NULL);
#ifdef DEBUGOUTPUT_LOG
  ::OutputDebugStringW(szTextW);
  ::OutputDebugStringW(L"\r\n");
#endif //DEBUGOUTPUT_LOG
  //done
  return S_OK;
}

HRESULT GetLogFolder(_Out_ CStringW &_cStrLogFolderW)
{
  if ((__InterlockedRead(&nInitializedFlags) & LOGFLAG_Initialized) == 0)
    return MX_E_NotReady;
  return (_cStrLogFolderW.CopyN((LPCWSTR)cStrLogFolderW, cStrLogFolderW.GetLength()) != FALSE) ? S_OK : E_OUTOFMEMORY;
}

}; //namespace EventLogger

}; //namespace MX

//-----------------------------------------------------------

static VOID EndLogger()
{
  cLogH.Close();
  _InterlockedAnd(&nInitializedFlags, ~LOGFLAG_Initialized);
  return;
}

static VOID RemoveOldFiles()
{
  FILETIME sFt;
  SYSTEMTIME sSt;
  ULONGLONG nDueTime, nTimeToSub, nFileTime;
  WIN32_FIND_DATAW sFindDataW;
  HANDLE hFindFile;
  MX::CStringW cStrTempW;
  SIZE_T i, nBaseNameLen;

  if (dwLogKeepDays == 0)
    return;
  //calculate due time
  ::GetSystemTimeAsFileTime(&sFt);
  nDueTime = ((ULONGLONG)(sFt.dwHighDateTime) << 32) | (ULONGLONG)(sFt.dwLowDateTime);
  nTimeToSub = MX_MILLISECONDS_TO_100NS((ULONGLONG)dwLogKeepDays * 86400000ui64);
  nDueTime = (nDueTime > nTimeToSub) ? (nDueTime - nTimeToSub) : 0ui64;
  //scan folder
  if (cStrTempW.Copy((LPCWSTR)cStrLogFolderW) == FALSE ||
      cStrTempW.ConcatN(L"*", 1) == FALSE)
  {
    return;
  }
  hFindFile = ::FindFirstFileW((LPCWSTR)cStrTempW, &sFindDataW);
  if (hFindFile != INVALID_HANDLE_VALUE)
  {
    do
    {
      if ((sFindDataW.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
      {
        nBaseNameLen = cStrLogFileNameBaseW.GetLength();
        if (MX::StrNCompareW((LPCWSTR)cStrLogFileNameBaseW, sFindDataW.cFileName, nBaseNameLen, TRUE) == 0 &&
            sFindDataW.cFileName[nBaseNameLen] == L'-')
        {
          for (i=0; i<8; i++)
          {
            if (sFindDataW.cFileName[nBaseNameLen+i+1] < L'0' ||
                sFindDataW.cFileName[nBaseNameLen+i+1] > L'9')
            {
              break;
            }
          }
          if (i >= 8 && MX::StrCompareW(sFindDataW.cFileName+nBaseNameLen+9, L".log", TRUE) == 0)
          {
            //get file date from name
            MX::MemSet(&sSt, 0, sizeof(sSt));
            sSt.wYear = (WORD)(sFindDataW.cFileName[nBaseNameLen+1] - L'0') * 1000 +
                        (WORD)(sFindDataW.cFileName[nBaseNameLen+2] - L'0') * 100 +
                        (WORD)(sFindDataW.cFileName[nBaseNameLen+3] - L'0') * 10 +
                        (WORD)(sFindDataW.cFileName[nBaseNameLen+4] - L'0');
            sSt.wMonth = (WORD)(sFindDataW.cFileName[nBaseNameLen+5] - L'0') * 10 +
                         (WORD)(sFindDataW.cFileName[nBaseNameLen+6] - L'0');
            sSt.wDay = (WORD)(sFindDataW.cFileName[nBaseNameLen+7] - L'0') * 10 +
                       (WORD)(sFindDataW.cFileName[nBaseNameLen+8] - L'0');
            if (sSt.wDay >= 1 && sSt.wDay <= 31 && sSt.wMonth >= 1 && sSt.wMonth <= 12)
            {
              if (::SystemTimeToFileTime(&sSt, &sFt) != FALSE)
              {
                nFileTime = ((ULONGLONG)(sFt.dwHighDateTime) << 32) | (ULONGLONG)(sFt.dwLowDateTime);
                //too old?
                if (nFileTime < nDueTime)
                {
                  if (cStrTempW.Copy((LPCWSTR)cStrLogFolderW) != FALSE &&
                      cStrTempW.Concat(sFindDataW.cFileName) != FALSE)
                  {
                    MX::FileRoutines::_DeleteFile((LPCWSTR)cStrTempW);
                  }
                }
              }
            }
          }
        }
      }
    }
    while (::FindNextFileW(hFindFile, &sFindDataW) != FALSE);
    ::FindClose(hFindFile);
  }
  return;
}

static HRESULT OpenLog()
{
  MX::CStringW cStrTempW, cStrOpSystemW;
  MX::CFileVersionInfo cVersionInfo;
  WCHAR szBufW[256];
  DWORD dw, dwWritten;
  SYSTEMTIME sSt;
  MEMORYSTATUSEX sMemStatusEx;

  MX::FileRoutines::CreateDirectoryRecursive((LPCWSTR)cStrLogFolderW);
  //open/create log file
  ::GetSystemTime(&sSt);
  if (cStrTempW.Format(L"%s%s-%04u%02u%02u.log", (LPCWSTR)cStrLogFolderW, (LPCWSTR)cStrLogFileNameBaseW,
                       sSt.wYear, sSt.wMonth, sSt.wDay) == FALSE)
    return E_OUTOFMEMORY;
  cLogH.Attach(::CreateFileW((LPCWSTR)cStrTempW, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, NULL));
  if (!cLogH)
    return MX_HRESULT_FROM_LASTERROR();
  //if new file, write BOM else write separator
  if (MX_HRESULT_FROM_LASTERROR() != MX_E_AlreadyExists)
  {
    ::WriteFile(cLogH, "\xFF\xFE", 2, &dwWritten, NULL);
  }
  else
  {
    ::WriteFile(cLogH, L"--------------------------------------------------------------------------------\r\n",
                82*2, &dwWritten, NULL);
  }
  //write header
  if (cStrTempW.Format(L"Log start: %04u.%02u.%02u @ %02u:%02u:%02u\r\n", sSt.wYear, sSt.wMonth, sSt.wDay,
                       sSt.wHour, sSt.wMinute, sSt.wSecond) != FALSE)
  {
    ::WriteFile(cLogH, (LPCWSTR)cStrTempW, (DWORD)(cStrTempW.GetLength() * sizeof(WCHAR)), &dwWritten, NULL);
  }

  //write file version
  if (SUCCEEDED(cVersionInfo.InitializeFromProcessHandle(NULL)))
  {
    if (cStrTempW.Format(L"     From: %s (v%u.%u.%u.%u)\r\n", (LPCWSTR)cStrLogFileNameBaseW,
                        (WORD)(cVersionInfo->dwProductVersionMS >> 16),
                        (WORD)(cVersionInfo->dwProductVersionMS & 0xFFFF),
                        (WORD)(cVersionInfo->dwProductVersionLS >> 16),
                        (WORD)(cVersionInfo->dwProductVersionLS & 0xFFFF)) == FALSE)
    {
      return E_OUTOFMEMORY;
    }
  }
  else
  {
    if (cStrTempW.Format(L"     From: %s\r\n", (LPCWSTR)cStrLogFileNameBaseW) == FALSE)
      return E_OUTOFMEMORY;
  }
  ::WriteFile(cLogH, (LPCWSTR)cStrTempW, (DWORD)(cStrTempW.GetLength() * sizeof(WCHAR)), &dwWritten, NULL);

  //write OS version
  if (SUCCEEDED(MX::System::GetOpSystemInfo(cStrTempW)))
  {
#if defined(_M_IX86)
    SYSTEM_INFO sSi;
#endif //_M_IX86

#if defined(_M_IX86)
    ::GetSystemInfo(&sSi);
    dw = (sSi.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) ? 32 : 64;
#elif defined(_M_X64)
    dw = 64;
#endif
    if (cStrTempW.Insert(L"Operating system: ", 0) == FALSE ||
        cStrTempW.AppendFormat(L" (%lu-bit)\r\n", dw) == FALSE)
    {
      return E_OUTOFMEMORY;
    }
    ::WriteFile(cLogH, (LPCWSTR)cStrTempW, (DWORD)(cStrTempW.GetLength() * sizeof(WCHAR)), &dwWritten, NULL);
  }

  //computer name
  dw = (DWORD)MX_ARRAYLEN(szBufW) - 1;
  ::GetComputerNameW(szBufW, &dw);
  if (dw >= (DWORD)MX_ARRAYLEN(szBufW))
    dw = (DWORD)MX_ARRAYLEN(szBufW) - 1;
  szBufW[dw] = 0;
  if (*szBufW != 0)
  {
    if (cStrTempW.Format(L"   Computer Name: %s\r\n", szBufW) == FALSE)
      return E_OUTOFMEMORY;
    ::WriteFile(cLogH, (LPCWSTR)cStrTempW, (DWORD)(cStrTempW.GetLength() * sizeof(WCHAR)), &dwWritten, NULL);
  }

  //memory status
  MX::MemSet(&sMemStatusEx, 0, sizeof(sMemStatusEx));
  sMemStatusEx.dwLength = (DWORD)sizeof(sMemStatusEx);
  ::GlobalMemoryStatusEx(&sMemStatusEx);
  if (sMemStatusEx.ullTotalPhys >= 1024ui64*1024ui64*1024ui64)
  {
    ULONG nRem = (ULONG)(sMemStatusEx.ullTotalPhys & 0x3FFFFFFFui64);
    sMemStatusEx.ullTotalPhys >>= 30;
    nRem = (nRem * 10) / 1073741824;
    _snwprintf_s(szBufW, _countof(szBufW), _TRUNCATE, L"             RAM: %I64u.%lu GiB (Load: %lu%%)\r\n",
                 sMemStatusEx.ullTotalPhys, nRem, sMemStatusEx.dwMemoryLoad);
  }
  else if (sMemStatusEx.ullTotalPhys >= 1024ui64*1024ui64)
  {
    ULONG nRem = (ULONG)(sMemStatusEx.ullTotalPhys & 0xFFFFFui64);
    sMemStatusEx.ullTotalPhys >>= 20;
    nRem = (nRem * 10) / 1048576;
    _snwprintf_s(szBufW, _countof(szBufW), _TRUNCATE, L"             RAM: %I64u.%lu MiB (Load: %lu%%)\r\n",
                 sMemStatusEx.ullTotalPhys, nRem, sMemStatusEx.dwMemoryLoad);
  }
  else if (sMemStatusEx.ullTotalPhys >= 1024ui64)
  {
    ULONG nRem = (ULONG)(sMemStatusEx.ullTotalPhys & 0x3FFui64);
    sMemStatusEx.ullTotalPhys >>= 10;
    nRem = (nRem * 10) / 1024;
    _snwprintf_s(szBufW, _countof(szBufW), _TRUNCATE, L"             RAM: %I64u.%lu KiB (Load: %lu%%)\r\n",
                 sMemStatusEx.ullTotalPhys, nRem, sMemStatusEx.dwMemoryLoad);
  }
  else
  {
    _snwprintf_s(szBufW, _countof(szBufW), _TRUNCATE, L"             RAM: %I64u bytes (Load: %lu%%)\r\n",
                 sMemStatusEx.ullTotalPhys, sMemStatusEx.dwMemoryLoad);
  }
  ::WriteFile(cLogH, szBufW, (DWORD)(MX::StrLenW(szBufW) * sizeof(WCHAR)), &dwWritten, NULL);
  //done
  return S_OK;
}

static HRESULT InitLogCommon()
{
  HRESULT hRes;

  if (!cLogH)
  {
    if ((_InterlockedOr(&nInitializedFlags, LOGFLAG_OldFilesRemovalProcessed) & LOGFLAG_OldFilesRemovalProcessed) == 0)
    {
      RemoveOldFiles();
    }
    //----
    if ((_InterlockedOr(&nInitializedFlags, LOGFLAG_LogFileOpenProcessed) & LOGFLAG_LogFileOpenProcessed) == 0)
      hRes = OpenLog();
    else
      hRes = E_FAIL;
    if (FAILED(hRes))
      return hRes;
  }
  return S_OK;
}

static VOID WriteLogCommon(_In_ BOOL bAddError, _In_ HRESULT hResError, _In_z_ LPCWSTR szFormatW, _In_ va_list argptr)
{
  DWORD dwWritten;
  SYSTEMTIME sSt;
  int count[2];
  SIZE_T nTotal;

  ::GetSystemTime(&sSt);
  if (bAddError == FALSE)
  {
    count[0] = _snwprintf_s(szTempBufW, _countof(szTempBufW), _TRUNCATE, L"#%4lu) [%02lu:%02lu:%02lu.%03lu] ",
                            ::GetCurrentProcessId(), (ULONG)sSt.wHour, (ULONG)sSt.wMinute, (ULONG)sSt.wSecond,
                            (ULONG)sSt.wMilliseconds);
  }
  else
  {
    count[0] = _snwprintf_s(szTempBufW, MX_ARRAYLEN(szTempBufW), _TRUNCATE, L"#%4lu) [%02lu:%02lu:%02lu.%03lu] "
                            L"Error 0x%08X: ", ::GetCurrentProcessId(), (ULONG)sSt.wHour, (ULONG)sSt.wMinute,
                            (ULONG)sSt.wSecond, (ULONG)sSt.wMilliseconds, hResError);
  }
  if (count[0] < 0)
    count[0] = 0;
  count[1] = _vsnwprintf_s(szTempBufW+count[0], MX_ARRAYLEN(szTempBufW)-(SIZE_T)count[0], _TRUNCATE, szFormatW, argptr);
  nTotal = (SIZE_T)count[0] + (SIZE_T)((count[1] >= 0) ? count[1] : 0);
  if (nTotal > MX_ARRAYLEN(szTempBufW)-3)
    nTotal = MX_ARRAYLEN(szTempBufW)-3;
  szTempBufW[nTotal] = L'\r';
  szTempBufW[nTotal+1] = L'\n';
  szTempBufW[nTotal+2] = 0;
  ::WriteFile(cLogH, szTempBufW, (DWORD)(nTotal+2) * 2, &dwWritten, NULL);
#ifdef DEBUGOUTPUT_LOG
  ::OutputDebugStringW(szTempBufW);
#endif //DEBUGOUTPUT_LOG
  //done
  return;
}
