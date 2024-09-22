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
#include <intsafe.h>

#pragma comment(lib, "Shell32.lib")

//-----------------------------------------------------------

#define LOGFLAG_Initialized                           0x0001
#define LOGFLAG_LogFileOpenProcessed                  0x0002
#define LOGFLAG_FinalizerInstalled                    0x0004

#define USE_FILE_CREATION_TIMESTAMP

//-----------------------------------------------------------

static LONG volatile nMutex = 0;
static LONG volatile nFlags = 0;
static MX::CWindowsHandle cLogH;
static MX::CStringW cStrLogFileNameBaseW;
static MX::CStringW cStrLogFolderW;
static DWORD dwLogKeepDays = 0;
static BOOL bDebugOutput = FALSE;
static WCHAR szTempBufW[8192];
static WORD wLastDate[3] = { 0 };
static DWORD dwProductVersionMS = 0;
static DWORD dwProductVersionLS = 0;

//-----------------------------------------------------------

static VOID ShutdownLogger();
static VOID ShutdownLoggerNoLock();

static VOID RemoveOldFiles();

static HRESULT OpenLog(_In_ LPSYSTEMTIME lpSystemTime);
static HRESULT InitLogCommon(_Out_ LPSYSTEMTIME lpSystemTime);
static VOID WriteLogCommon(_In_ BOOL bAddError, _In_ HRESULT hResError, _In_ LPSYSTEMTIME lpSystemTime,
                           _In_z_ LPCWSTR szFormatW, _In_ va_list argptr);

static BOOL GenerateLogFileName(_In_ LPSYSTEMTIME lpSystemTime, _Out_ MX::CStringW &cStrFileNameW);

//-----------------------------------------------------------

namespace MX {

namespace EventLogger {

HRESULT Initialize(_In_z_ LPCWSTR szApplicationNameW, _In_z_ LPCWSTR szModuleNameW, _In_ DWORD dwKeepDays, _In_opt_ BOOL _bDebugOutput)
{
  CFastLock cLock(&nMutex);
  CFileVersionInfo cVersionInfo;
  HRESULT hRes;

  if (szModuleNameW == NULL)
    return E_POINTER;
  if (*szModuleNameW == 0 || dwKeepDays < 1)
    return E_INVALIDARG;
  if (dwKeepDays > 180)
    dwKeepDays = 180;

  ShutdownLoggerNoLock();

  //copy base module name
  if (cStrLogFileNameBaseW.Copy(szModuleNameW) == FALSE)
    return E_OUTOFMEMORY;

  //setup log folder
  if (StrChrW(szApplicationNameW, L'\\') == NULL)
  {
    hRes = FileRoutines::GetCommonAppDataFolderPath(cStrLogFolderW);
    if (SUCCEEDED(hRes))
    {
      if (cStrLogFolderW.AppendFormat(L"%s\\Logs\\", szApplicationNameW) == FALSE)
        hRes = E_OUTOFMEMORY;
    }
  }
  else
  {
    if (cStrLogFolderW.Copy(szApplicationNameW) != FALSE)
    {
      hRes = S_OK;
      if (((LPCWSTR)cStrLogFolderW)[cStrLogFolderW.GetLength() - 1] != L'\\')
      {
        if (cStrLogFolderW.ConcatN(L"\\", 1) == FALSE)
          hRes = E_OUTOFMEMORY;
      }
    }
    else
    {
      hRes = E_OUTOFMEMORY;
    }
  }

  //register finalizer
  if (SUCCEEDED(hRes) && (__InterlockedRead(&nFlags) & LOGFLAG_FinalizerInstalled) == 0)
  {
    hRes = RegisterFinalizer(&ShutdownLogger, 1);
    if (SUCCEEDED(hRes))
      _InterlockedOr(&nFlags, LOGFLAG_FinalizerInstalled);
  }

  //failure?
  if (FAILED(hRes))
  {
    ShutdownLoggerNoLock();
    return hRes;
  }

  //set some options
  dwLogKeepDays = dwKeepDays;
  bDebugOutput = _bDebugOutput;

  //write file version
  if (SUCCEEDED(cVersionInfo.InitializeFromProcessHandle(NULL)))
  {
    dwProductVersionMS = cVersionInfo->dwProductVersionMS;
    dwProductVersionLS = cVersionInfo->dwProductVersionLS;
  }
  else
  {
    dwProductVersionMS = dwProductVersionLS = 0;
  }

  //delete old files
  RemoveOldFiles();

  //done
  _InterlockedOr(&nFlags, LOGFLAG_Initialized);
  return hRes;
}

VOID Finalize()
{
  ShutdownLogger();
  return;
}

HRESULT Log(_Printf_format_string_ LPCWSTR szFormatW, ...)
{
  CFastLock cLock(&nMutex);
  SYSTEMTIME sSt;
  va_list argptr;
  HRESULT hRes;

  if (szFormatW == NULL)
    return E_POINTER;

  //initialize logger on first access
  hRes = ::InitLogCommon(&sSt);
  if (FAILED(hRes))
    return hRes;

  //write log
  va_start(argptr, szFormatW);
  ::WriteLogCommon(FALSE, S_OK, &sSt, szFormatW, argptr);
  va_end(argptr);

  //done
  return S_OK;
}

HRESULT LogIfError(_In_ HRESULT hResError, _Printf_format_string_ LPCWSTR szFormatW, ...)
{
  if (FAILED(hResError))
  {
    CFastLock cLock(&nMutex);
    SYSTEMTIME sSt;
    va_list argptr;
    HRESULT hRes;

    if (szFormatW == NULL)
      return E_POINTER;

    //initialize logger on first access
    hRes = ::InitLogCommon(&sSt);
    if (FAILED(hRes))
      return hRes;
    //write log
    va_start(argptr, szFormatW);
    ::WriteLogCommon(TRUE, hResError, &sSt, szFormatW, argptr);
    va_end(argptr);
  }

  //done
  return S_OK;
}

HRESULT LogAlways(_In_ HRESULT hResError, _Printf_format_string_ LPCWSTR szFormatW, ...)
{
  CFastLock cLock(&nMutex);
  SYSTEMTIME sSt;
  va_list argptr;
  HRESULT hRes;

  if (szFormatW == NULL)
    return E_POINTER;

  //initialize logger on first access
  hRes = ::InitLogCommon(&sSt);
  if (FAILED(hRes))
    return hRes;

  //write log
  va_start(argptr, szFormatW);
  ::WriteLogCommon(TRUE, hResError, &sSt, szFormatW, argptr);
  va_end(argptr);

  //done
  return S_OK;
}

HRESULT LogRaw(_In_z_ LPCWSTR szTextW)
{
  CFastLock cLock(&nMutex);
  SYSTEMTIME sSt;
  DWORD dwLen, dwWritten;
  HRESULT hRes;

  dwLen = (DWORD)StrLenW(szTextW);
  while (dwLen > 0 && (szTextW[dwLen - 1] == L'\r' || szTextW[dwLen - 1] == L'\n'))
    dwLen--;
  if (dwLen == 0)
    return S_OK;

  //initialize logger on first access
  hRes = ::InitLogCommon(&sSt);
  if (FAILED(hRes))
    return hRes;

  //write log
  ::WriteFile(cLogH, szTextW, dwLen * 2, &dwWritten, NULL);
  ::WriteFile(cLogH, L"\r\n", 4, &dwWritten, NULL);
  if (bDebugOutput != FALSE)
  {
    ::OutputDebugStringW(szTextW);
    ::OutputDebugStringW(L"\r\n");
  }

  //done
  return S_OK;
}

HRESULT GetLogFolder(_Out_ CStringW &_cStrLogFolderW, _In_opt_ BOOL bCreate)
{
  _cStrLogFolderW.Empty();
  if ((__InterlockedRead(&nFlags) & LOGFLAG_Initialized) == 0)
    return MX_E_NotReady;
  if (bCreate != FALSE)
  {
    MX::FileRoutines::CreateDirectoryRecursive((LPCWSTR)cStrLogFolderW);
  }
  if (_cStrLogFolderW.CopyN((LPCWSTR)cStrLogFolderW, cStrLogFolderW.GetLength()) == FALSE)
    return E_OUTOFMEMORY;
  return S_OK;
}

HRESULT GetLogFileName(_Out_ CStringW &cStrFileNameW, _In_opt_ BOOL bCreateFolder)
{
  SYSTEMTIME sSystemTime;

  cStrFileNameW.Empty();
  if ((__InterlockedRead(&nFlags) & LOGFLAG_Initialized) == 0)
    return MX_E_NotReady;
  if (bCreateFolder != FALSE)
  {
    MX::FileRoutines::CreateDirectoryRecursive((LPCWSTR)cStrLogFolderW);
  }
  ::GetSystemTime(&sSystemTime);
  if (::GenerateLogFileName(&sSystemTime, cStrFileNameW) == FALSE)
    return E_OUTOFMEMORY;
  return S_OK;
}

}; //namespace EventLogger

}; //namespace MX

//-----------------------------------------------------------

static VOID ShutdownLogger()
{
  MX::CFastLock cLock(&nMutex);

  ShutdownLoggerNoLock();
  return;
}

static VOID ShutdownLoggerNoLock()
{

  cLogH.Close();
  cStrLogFolderW.Empty();
  cStrLogFileNameBaseW.Empty();
  dwLogKeepDays = 0;
  bDebugOutput = FALSE;
  ::MxMemSet(wLastDate, 0, sizeof(wLastDate));
  dwProductVersionMS = dwProductVersionLS = 0;
  _InterlockedAnd(&nFlags, ~(LOGFLAG_Initialized | LOGFLAG_LogFileOpenProcessed));
  return;
}

static VOID RemoveOldFiles()
{
  WIN32_FIND_DATAW sFindDataW;
  HANDLE hFindFile;
  MX::CStringW cStrTempW;

  //scan folder
  if (cStrTempW.CopyN((LPCWSTR)cStrLogFolderW, cStrLogFolderW.GetLength()) == FALSE ||
      cStrTempW.ConcatN(L"*", 1) == FALSE)
  {
    return;
  }

  hFindFile = ::FindFirstFileW((LPCWSTR)cStrTempW, &sFindDataW);
  if (hFindFile != INVALID_HANDLE_VALUE)
  {
    LPCWSTR szBaseNameW = (LPCWSTR)cStrLogFileNameBaseW;
    SIZE_T nBaseNameLen = cStrLogFileNameBaseW.GetLength();
    FILETIME sFt;

    //calculate due time
    ::GetSystemTimeAsFileTime(&sFt);
    ULONGLONG ullDueTime = ((ULONGLONG)(sFt.dwHighDateTime) << 32) | (ULONGLONG)(sFt.dwLowDateTime);
    ULONGLONG ullTimeToSub = MX_MILLISECONDS_TO_100NS((ULONGLONG)dwLogKeepDays * 86400000ui64);
    ullDueTime = (ullDueTime > ullTimeToSub) ? (ullDueTime - ullTimeToSub) : 0ui64;

    //loop
    do
    {
      if ((sFindDataW.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
      {
        if (MX::StrNCompareW(szBaseNameW, sFindDataW.cFileName, nBaseNameLen, TRUE) == 0 &&
            sFindDataW.cFileName[nBaseNameLen] == L'-')
        {
          ULONGLONG ullFileTime;

#ifdef USE_FILE_CREATION_TIMESTAMP

          ullFileTime = ((ULONGLONG)(sFindDataW.ftCreationTime.dwHighDateTime) << 32) |
                        (ULONGLONG)(sFindDataW.ftCreationTime.dwLowDateTime);

#else //USE_FILE_CREATION_TIMESTAMP

          SYSTEMTIME sSt;
          SIZE_T i;

          ullFileTime = ULONG64_MAX;

          for (i = 0; i < 8; i++)
          {
            if (sFindDataW.cFileName[nBaseNameLen + i + 1] < L'0' ||
                sFindDataW.cFileName[nBaseNameLen + i + 1] > L'9')
            {
              break;
            }
          }
          if (i >= 8 && MX::StrCompareW(sFindDataW.cFileName + nBaseNameLen + 9, L".log", TRUE) == 0)
          {
            //get file date from name
            ::MxMemSet(&sSt, 0, sizeof(sSt));
            sSt.wYear = (WORD)(sFindDataW.cFileName[nBaseNameLen + 1] - L'0') * 1000 +
                        (WORD)(sFindDataW.cFileName[nBaseNameLen + 2] - L'0') * 100 +
                        (WORD)(sFindDataW.cFileName[nBaseNameLen + 3] - L'0') * 10 +
                        (WORD)(sFindDataW.cFileName[nBaseNameLen + 4] - L'0');
            sSt.wMonth = (WORD)(sFindDataW.cFileName[nBaseNameLen + 5] - L'0') * 10 +
                         (WORD)(sFindDataW.cFileName[nBaseNameLen + 6] - L'0');
            sSt.wDay = (WORD)(sFindDataW.cFileName[nBaseNameLen + 7] - L'0') * 10 +
                       (WORD)(sFindDataW.cFileName[nBaseNameLen + 8] - L'0');
            if (sSt.wDay >= 1 && sSt.wDay <= 31 && sSt.wMonth >= 1 && sSt.wMonth <= 12)
            {
              if (::SystemTimeToFileTime(&sSt, &sFt) != FALSE)
              {
                ullFileTime = ((ULONGLONG)(sFt.dwHighDateTime) << 32) | (ULONGLONG)(sFt.dwLowDateTime);
              }
            }
          }

#endif //USE_FILE_CREATION_TIMESTAMP

          //too old?
          if (ullFileTime <= ullDueTime)
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
    while (::FindNextFileW(hFindFile, &sFindDataW) != FALSE);

    //cleanup
    ::FindClose(hFindFile);
  }
  return;
}

static HRESULT OpenLog(_In_ LPSYSTEMTIME lpSystemTime)
{
  MX::CStringW cStrTempW, cStrOpSystemW;
  WCHAR szBufW[256];
  DWORD dw, dwWritten;
  MEMORYSTATUSEX sMemStatusEx;

  MX::FileRoutines::CreateDirectoryRecursive((LPCWSTR)cStrLogFolderW);

  //open/create log file
  if (GenerateLogFileName(lpSystemTime, cStrTempW) == FALSE)
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
  if (cStrTempW.Format(L"Log start: %04u.%02u.%02u @ %02u:%02u:%02u\r\n", lpSystemTime->wYear, lpSystemTime->wMonth,
                       lpSystemTime->wDay, lpSystemTime->wHour, lpSystemTime->wMinute, lpSystemTime->wSecond) != FALSE)
  {
    ::WriteFile(cLogH, (LPCWSTR)cStrTempW, (DWORD)(cStrTempW.GetLength() * sizeof(WCHAR)), &dwWritten, NULL);
  }

  //write file version
  if (dwProductVersionMS != 0 || dwProductVersionLS != 0)
  {
    if (cStrTempW.Format(L"     From: %s (v%u.%u.%u.%u)\r\n", (LPCWSTR)cStrLogFileNameBaseW,
                        (WORD)(dwProductVersionMS >> 16), (WORD)(dwProductVersionMS & 0xFFFF),
                        (WORD)(dwProductVersionLS >> 16), (WORD)(dwProductVersionLS & 0xFFFF)) == FALSE)
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
  ::MxMemSet(&sMemStatusEx, 0, sizeof(sMemStatusEx));
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

static HRESULT InitLogCommon(_Out_ LPSYSTEMTIME lpSystemTime)
{
  HRESULT hRes;

  MX_ASSERT(lpSystemTime);
  ::GetSystemTime(lpSystemTime);

  if ((!cLogH) || lpSystemTime->wYear != wLastDate[0] || lpSystemTime->wMonth != wLastDate[1] ||
                  lpSystemTime->wDay != wLastDate[2])
  {
    wLastDate[0] = lpSystemTime->wYear;
    wLastDate[1] = lpSystemTime->wMonth;
    wLastDate[2] = lpSystemTime->wDay;

    cLogH.Close();

    _InterlockedAnd(&nFlags, ~LOGFLAG_LogFileOpenProcessed);
  }

  if (!cLogH)
  {
    if ((_InterlockedOr(&nFlags, LOGFLAG_LogFileOpenProcessed) & LOGFLAG_LogFileOpenProcessed) != 0)
      return E_FAIL;

    RemoveOldFiles();
    hRes = OpenLog(lpSystemTime);
    if (FAILED(hRes))
      return hRes;
  }
  return S_OK;
}

static VOID WriteLogCommon(_In_ BOOL bAddError, _In_ HRESULT hResError, _In_ LPSYSTEMTIME lpSystemTime,
                           _In_z_ LPCWSTR szFormatW, _In_ va_list argptr)
{
  DWORD dwWritten;
  int count[2];
  SIZE_T nTotal;

  if (bAddError == FALSE)
  {
    count[0] = _snwprintf_s(szTempBufW, _countof(szTempBufW), _TRUNCATE, L"#%4lu:%4lu) [%02u:%02u:%02u.%03u] ",
                            ::GetCurrentProcessId(), ::GetCurrentThreadId(), lpSystemTime->wHour, lpSystemTime->wMinute,
                            lpSystemTime->wSecond, lpSystemTime->wMilliseconds);
  }
  else
  {
    count[0] = _snwprintf_s(szTempBufW, MX_ARRAYLEN(szTempBufW), _TRUNCATE, L"#%4lu:%4lu) [%02u:%02u:%02u.%03u] "
                            L"Error 0x%08X: ", ::GetCurrentProcessId(), ::GetCurrentThreadId(), lpSystemTime->wHour,
                            lpSystemTime->wMinute, lpSystemTime->wSecond, lpSystemTime->wMilliseconds, hResError);
  }
  if (count[0] < 0)
    count[0] = 0;
  count[1] = _vsnwprintf_s(szTempBufW+count[0], MX_ARRAYLEN(szTempBufW) - (SIZE_T)count[0], _TRUNCATE,
                           szFormatW, argptr);
  nTotal = (SIZE_T)count[0] + (SIZE_T)((count[1] >= 0) ? count[1] : 0);
  if (nTotal > MX_ARRAYLEN(szTempBufW)-3)
    nTotal = MX_ARRAYLEN(szTempBufW)-3;
  szTempBufW[nTotal] = L'\r';
  szTempBufW[nTotal + 1] = L'\n';
  szTempBufW[nTotal + 2] = 0;
  ::WriteFile(cLogH, szTempBufW, (DWORD)(nTotal + 2) * 2, &dwWritten, NULL);
#ifdef DEBUGOUTPUT_LOG
  ::OutputDebugStringW(szTempBufW);
#endif //DEBUGOUTPUT_LOG
  //done
  return;
}

static BOOL GenerateLogFileName(_In_ LPSYSTEMTIME lpSystemTime, _Out_ MX::CStringW &cStrFileNameW)
{
  return cStrFileNameW.Format(L"%s%s-%04u%02u%02u.log", (LPCWSTR)cStrLogFolderW, (LPCWSTR)cStrLogFileNameBaseW,
                              lpSystemTime->wYear, lpSystemTime->wMonth, lpSystemTime->wDay);
}
