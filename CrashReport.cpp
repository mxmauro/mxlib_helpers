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
#include "CrashReport.h"
#include "FileRoutines.h"
#include "System.h"
#include <WaitableObjects.h>
#include <Strings\Strings.h>
#pragma warning(disable : 4091)
#include <ImageHlp.h>
#pragma warning(default : 4091)
#include <stdio.h>

#define MAX_DUMPS_COUNT                                   20

//-----------------------------------------------------------

typedef struct _CRASHINFO {
  DWORD dwTid;
  PEXCEPTION_POINTERS ExceptionInfo;
} CRASHINFO, *LPCRASHINFO;

//-----------------------------------------------------------

typedef BOOL (WINAPI *lpfnMiniDumpWriteDump)(_In_ HANDLE hProcess, _In_ DWORD ProcessId, _In_ HANDLE hFile,
                                             _In_ MINIDUMP_TYPE DumpType,
                                             _In_opt_ PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
                                             _In_opt_ PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
                                             _In_opt_ PMINIDUMP_CALLBACK_INFORMATION CallbackParam);

//-----------------------------------------------------------

static LONG volatile nInitialized = 0;
static LONG volatile nMutex = 0;
static LPTOP_LEVEL_EXCEPTION_FILTER lpPrevExceptionFilter = NULL;

//-----------------------------------------------------------

static BOOL GetParamValue(_Inout_ LPCWSTR &sW, _Out_ LPVOID *lplpValue, _In_ WCHAR chEndingW);
static LONG WINAPI OnUnhandledExceptionFilter(_In_ PEXCEPTION_POINTERS ExceptionInfo);

static VOID RemoveOldFiles(_In_z_ LPCWSTR szDumpFolderW);

static HANDLE CreateDumpFile(_In_z_ LPCWSTR szDumpFolderW, _In_z_ LPCWSTR szBaseFileNameW);

//-----------------------------------------------------------

namespace MX {

namespace CrashReport {

VOID Initialize()
{
  if (__InterlockedRead(&nInitialized) == 0)
  {
    MX::CFastLock cLock(&nMutex);

    if (__InterlockedRead(&nInitialized) == 0)
    {
      //set unhandled exception filter
      lpPrevExceptionFilter = ::SetUnhandledExceptionFilter(&OnUnhandledExceptionFilter);
    }

    // done
    _InterlockedExchange(&nInitialized, 1);
  }
  return;
}

BOOL HandleCrashDump(_In_z_ LPCWSTR szApplicationNameW, _In_z_ LPCWSTR szModuleNameW)
{
  CStringW cStrDumpFolderW;
  LPCWSTR sW;
  HANDLE hProc;
  LPCRASHINFO lpCrashInfo;
  CRASHINFO sLocalCrashInfo;
  HINSTANCE hDbgHelpDll;

  MX_ASSERT(szApplicationNameW != NULL && *szApplicationNameW != 0);
  MX_ASSERT(szModuleNameW != NULL && *szModuleNameW != 0);

  //parse command line
  sW = ::GetCommandLineW();
  if (sW == NULL || *sW == 0)
    return FALSE;

  //skip spaces before
  while (*sW != 0 && *((LPWORD)sW) <= 32)
    sW++;

  //inside quotes?
  if (*sW == L'"')
  {
    sW++;
    //skip until the closing quotes
    while (*sW != 0 && *sW != L'"')
      sW++;
    if (*sW == L'"')
      sW++; //skip the closing quote
  }
  else
  {
    //skip until the first blank space
    while (*((LPWORD)sW) > 32)
      sW++;
  }

  //skip spaces after
  while (*sW != 0 && *((LPWORD)sW) <= 32)
    sW++;

  //check parameter
  if (StrNCompareW(sW, L"/crash:", 7) != 0)
    return FALSE; //not a crash handler
  sW += 7;

  //get handle to parent process
  if (GetParamValue(sW, (LPVOID*)&hProc, L',') == FALSE)
    return TRUE; //invalid command line parameter (handled)
  //get crash info address
  if (GetParamValue(sW, (LPVOID*)&lpCrashInfo, 0) == FALSE)
    return TRUE; //invalid command line parameter (handled)

  //setup dump folder
  if (FAILED(FileRoutines::GetCommonAppDataFolderPath(cStrDumpFolderW)))
    return TRUE; //error (handled)
  if (cStrDumpFolderW.AppendFormat(L"%s\\Dumps\\", szApplicationNameW) == FALSE)
    return TRUE; //error (handled)

  //read crash info data
  if (::ReadProcessMemory(hProc, lpCrashInfo, &sLocalCrashInfo, sizeof(sLocalCrashInfo), NULL) == FALSE)
    return TRUE; //unable to read memory (handled)

  //write dump
  if (SUCCEEDED(System::LoadSystem32Dll(L"dbghelp.dll", &hDbgHelpDll)))
  {
    lpfnMiniDumpWriteDump fnMiniDumpWriteDump;

    fnMiniDumpWriteDump = (lpfnMiniDumpWriteDump)::GetProcAddress(hDbgHelpDll, "MiniDumpWriteDump");
    if (fnMiniDumpWriteDump != NULL)
    {
      MX::CWindowsHandle cFileH;

      MX::FileRoutines::CreateDirectoryRecursive((LPCWSTR)cStrDumpFolderW);

      RemoveOldFiles((LPCWSTR)cStrDumpFolderW);

      cFileH.Attach(CreateDumpFile((LPCWSTR)cStrDumpFolderW, szModuleNameW));
      if (cFileH)
      {
        MINIDUMP_EXCEPTION_INFORMATION sMiniDumpExceptionInfo;

        sMiniDumpExceptionInfo.ThreadId = sLocalCrashInfo.dwTid;
        sMiniDumpExceptionInfo.ExceptionPointers = sLocalCrashInfo.ExceptionInfo;
        sMiniDumpExceptionInfo.ClientPointers = TRUE;

        fnMiniDumpWriteDump(hProc, ::GetProcessId(hProc), cFileH, (MINIDUMP_TYPE)(MiniDumpWithFullMemory |
                            MiniDumpWithFullMemoryInfo | MiniDumpWithHandleData | MiniDumpWithUnloadedModules |
                            MiniDumpWithThreadInfo), &sMiniDumpExceptionInfo, NULL, NULL);
      }
    }
    ::FreeLibrary(hDbgHelpDll);
  }

  ::CloseHandle(hProc);

  //done
  return TRUE; //handled
}

}; //namespace CrashReport

}; //namespace MX

//-----------------------------------------------------------

static BOOL GetParamValue(_Inout_ LPCWSTR &sW, _Out_ LPVOID *lplpValue, _In_ WCHAR chEndingW)
{
  SIZE_T nCounter, nValue;

  *lplpValue = NULL;

  if (sW[0] != L'0' || sW[1] != L'x')
    return FALSE;
  sW += 2;

  //get hexadecimal value
  nValue = nCounter = 0;
  while (*sW != 0 && *sW != chEndingW)
  {
    if ((++nCounter) > 8 * sizeof(SIZE_T))
      return FALSE;

    if (*sW >= L'0' && *sW <= L'9')
    {
      nValue = (nValue << 4) | (SIZE_T)(*sW - L'0');
    }
    else if (*sW >= L'A' && *sW <= L'F')
    {
      nValue = (nValue << 4) | ((SIZE_T)(*sW - L'A') + 10);
    }
    else
    {
      return FALSE;
    }
    sW++;
  }
  if (chEndingW != 0 && *sW == chEndingW)
    sW++;

  //done
  *lplpValue = (LPVOID)nValue;
  return TRUE;
}

static LONG WINAPI OnUnhandledExceptionFilter(_In_ PEXCEPTION_POINTERS ExceptionInfo)
{
  HANDLE hProcDup;

  if (::DuplicateHandle(::GetCurrentProcess(), ::GetCurrentProcess(), ::GetCurrentProcess(), &hProcDup,
                        PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE | PROCESS_VM_READ |
                        SYNCHRONIZE, TRUE, 0) != FALSE)
  {
    MX::CFastLock cLock(&nMutex);
    MX::CStringW cStrNameW;
    CRASHINFO sCrashInfo;

    sCrashInfo.dwTid = ::GetCurrentThreadId();
    sCrashInfo.ExceptionInfo = ExceptionInfo;

    if (SUCCEEDED(MX::FileRoutines::GetAppFileName(cStrNameW)) &&
        cStrNameW.InsertN(L"\"", 0, 1) != FALSE &&
        cStrNameW.AppendFormat(L"\" /crash:0x%p,0x%p", hProcDup, &sCrashInfo) != FALSE)
    {
      STARTUPINFOW sSiW = { 0 };
      PROCESS_INFORMATION sPi = { 0 };

      sSiW.cb = (DWORD)sizeof(sSiW);
      if (::CreateProcessW(NULL, (LPWSTR)cStrNameW, NULL, NULL, TRUE, CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
                           NULL, NULL, &sSiW, &sPi) != FALSE)
      {
        ::WaitForSingleObject(sPi.hProcess, INFINITE);
        ::CloseHandle(sPi.hThread);
        ::CloseHandle(sPi.hProcess);
      }
    }
    ::CloseHandle(hProcDup);
  }

  //terminate application
  ::TerminateProcess(::GetCurrentProcess(), (ExceptionInfo != NULL && ExceptionInfo->ExceptionRecord != NULL)
                                            ? ExceptionInfo->ExceptionRecord->ExceptionCode
                                            : ERROR_UNHANDLED_EXCEPTION);
  return EXCEPTION_EXECUTE_HANDLER;
}

static VOID RemoveOldFiles(_In_z_ LPCWSTR szDumpFolderW)
{
  MX::CStringW cStrTempW;
  WIN32_FIND_DATAW sFindDataW;
  ULARGE_INTEGER uliLowerTime, uliTemp;
  WCHAR szLowerFileNameW[sizeof(sFindDataW.cFileName)];
  HANDLE hFindFile;
  DWORD dwCount;

loop:
  dwCount = 0;
  if (cStrTempW.Copy(szDumpFolderW) == FALSE || cStrTempW.ConcatN(L"*", 1) == FALSE)
    return;
  hFindFile = ::FindFirstFileW((LPCWSTR)cStrTempW, &sFindDataW);
  if (hFindFile == NULL || hFindFile == INVALID_HANDLE_VALUE)
    return;
  uliLowerTime.QuadPart = (ULONGLONG)-1;
  do
  {
    uliTemp.LowPart = sFindDataW.ftCreationTime.dwLowDateTime;
    uliTemp.HighPart = sFindDataW.ftCreationTime.dwHighDateTime;
    if (uliTemp.QuadPart < uliLowerTime.QuadPart)
    {
      ::MxMemCopy(szLowerFileNameW, sFindDataW.cFileName, sizeof(sFindDataW.cFileName));
      uliLowerTime.QuadPart = uliTemp.QuadPart;
    }
    dwCount++;
  }
  while (::FindNextFileW(hFindFile, &sFindDataW) != FALSE);
  ::FindClose(hFindFile);

  if (dwCount > MAX_DUMPS_COUNT)
  {
    if (cStrTempW.Copy(szDumpFolderW) == FALSE || cStrTempW.Concat(szLowerFileNameW) == FALSE)
      return;
    if (FAILED(MX::FileRoutines::_DeleteFile((LPCWSTR)cStrTempW)))
      return;
    dwCount--;
  }

  if (dwCount > MAX_DUMPS_COUNT)
    goto loop;
  return;
}

static HANDLE CreateDumpFile(_In_z_ LPCWSTR szDumpFolderW, _In_z_ LPCWSTR szBaseFileNameW)
{
  MX::CStringW cStrFileNameW;
  SYSTEMTIME stNow;
  HANDLE hFile;
  HRESULT hRes;

  ::GetLocalTime(&stNow);

  if (cStrFileNameW.Format(L"%s%s_%04lu-%02lu-%02lu.dmp", szDumpFolderW, szBaseFileNameW, stNow.wYear, stNow.wMonth,
                           stNow.wDay) != FALSE)
  {
    hFile = ::CreateFileW((LPCWSTR)cStrFileNameW, GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_NEW,
                          FILE_ATTRIBUTE_NORMAL, 0);
    if (hFile != NULL && hFile != INVALID_HANDLE_VALUE)
      return hFile;
    hRes = MX_HRESULT_FROM_LASTERROR();
    if (hRes != HRESULT_FROM_WIN32(ERROR_FILE_EXISTS))
      return INVALID_HANDLE_VALUE;
  }

  for (ULONG i = 2; i <= 1000; i++)
  {
    if (cStrFileNameW.Format(L"%s%s_%04lu-%02lu-%02lu_%lu.dmp", szDumpFolderW, szBaseFileNameW, stNow.wYear,
                             stNow.wMonth, stNow.wDay, i) != FALSE)
    {
      hFile = ::CreateFileW((LPCWSTR)cStrFileNameW, GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_NEW,
                            FILE_ATTRIBUTE_NORMAL, 0);
      if (hFile != NULL && hFile != INVALID_HANDLE_VALUE)
        return hFile;
      hRes = MX_HRESULT_FROM_LASTERROR();
      if (hRes != HRESULT_FROM_WIN32(ERROR_FILE_EXISTS))
        break;
    }
  }
  return INVALID_HANDLE_VALUE;
}
