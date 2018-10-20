/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#include "Process.h"
#include "FileRoutines.h"
#include <Debug.h>
#include <WaitableObjects.h>
#include <VersionHelpers.h>

//-----------------------------------------------------------

#pragma pack(8)
typedef struct {
  BYTE Revision;
  BYTE SubAuthorityCount;
  SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
  DWORD SubAuthority[8];
} MY_SID;
#pragma pack()

//-----------------------------------------------------------

static HRESULT QueryEnvironmentVariableInternal(_In_ LPCWSTR szVarNameW, _In_ SIZE_T nVarNameLen,
                                                _In_opt_ MX::CStringW *lpStrDestW);
static BOOL IsWinVistaPlus();

//-----------------------------------------------------------

namespace MXHelpers {

HRESULT ResolveChildProcessFileName(_Inout_ MX::CStringW &cStrFullNameW, _In_ LPCWSTR szApplicationNameW,
                                    _In_ LPCWSTR szCommandLineW)
{
  HRESULT hRes;

  cStrFullNameW.Empty();
  if (szApplicationNameW == NULL && szCommandLineW == NULL)
    return E_INVALIDARG;
  if (szApplicationNameW == NULL)
  {
    MX::CStringW cStrSearchPathW, cStrExeNameW, cStrTempW;
    LPCWSTR szNameStartW, szNameEndW;
    SIZE_T nTempBufLen = 1024;

    szNameStartW = szCommandLineW;
    if (*szCommandLineW == L'"')
    {
      szNameEndW = ++szNameStartW;
      while (*szNameEndW != 0 && *szNameEndW != L'"')
        szNameEndW++;
    }
    else
    {
      szNameEndW = szNameStartW;
      while (*szNameEndW != 0 && *szNameEndW != L' ' && *szNameEndW != L'\t')
        szNameEndW++;
    }
    //get the path list to check (based on https://msdn.microsoft.com/en-us/library/ms682425.aspx)
    //1. The directory from which the application loaded.
    hRes = GetAppFolderPath(cStrSearchPathW);
    //2. The current directory for the parent process.
    if (SUCCEEDED(hRes))
    {
      RTL_OSVERSIONINFOW sOviW;

      MX::MemSet(&sOviW, 0, sizeof(sOviW));
      sOviW.dwOSVersionInfoSize = (DWORD)sizeof(sOviW);
      ::MxRtlGetVersion(&sOviW);
      if (sOviW.dwMajorVersion >= 6)
      {
        if (FAILED(QueryEnvironmentVariableInternal(L"NoDefaultCurrentDirectoryInExePath", 34, NULL)))
        {
          if (cStrSearchPathW.ConcatN(L";.", 2) == FALSE)
            hRes = E_OUTOFMEMORY;
        }
      }
    }
    //3. The 32-bit Windows system directory.Use the GetSystemDirectory function to get the path of this directory.
    if (SUCCEEDED(hRes))
    {
      hRes = GetWindowsSystemPath(cStrTempW);
      if (SUCCEEDED(hRes))
      {
        if (cStrSearchPathW.ConcatN(L";", 1) == FALSE ||
            cStrSearchPathW.Concat((LPCWSTR)cStrTempW) == FALSE)
        {
          hRes = E_OUTOFMEMORY;
        }
      }
    }
    //4. The 16-bit Windows system directory.There is no function that obtains the path of this directory, but it is
    //   searched.The name of this directory is System.
    //5. The Windows directory.Use the GetWindowsDirectory function to get the path of this directory.
    if (SUCCEEDED(hRes))
    {
      hRes = GetWindowsPath(cStrTempW);
      if (SUCCEEDED(hRes))
      {
        if (cStrSearchPathW.ConcatN(L";", 1) == FALSE ||
            cStrSearchPathW.Concat((LPCWSTR)cStrTempW) == FALSE ||
            cStrSearchPathW.ConcatN(L"\\System;", 8) == FALSE ||
            cStrSearchPathW.Concat((LPCWSTR)cStrTempW) == FALSE)
        {
          hRes = E_OUTOFMEMORY;
        }
      }
    }
    //6. The directories that are listed in the PATH environment variable.Note that this function does not search the
    //   per-application path specified by the App Paths registry key.To include this per-application path in the
    //   search sequence, use the ShellExecute function.
    if (SUCCEEDED(hRes))
    {
      hRes = QueryEnvironmentVariable(L"PATH", cStrTempW);
      if (SUCCEEDED(hRes))
      {
        if (cStrSearchPathW.ConcatN(L";", 1) == FALSE ||
            cStrSearchPathW.Concat((LPCWSTR)cStrTempW) == FALSE)
        {
          hRes = E_OUTOFMEMORY;
        }
      }
      else if (hRes == MX_HRESULT_FROM_WIN32(ERROR_NOT_FOUND))
      {
        hRes = S_OK;
      }
    }
    //alloc dest buffer
    if (SUCCEEDED(hRes))
    {
      if (cStrTempW.EnsureBuffer(nTempBufLen + 1) == FALSE)
        hRes = E_OUTOFMEMORY;
    }
    //process entries (based on https://msdn.microsoft.com/en-us/library/ms682425.aspx)
    while (SUCCEEDED(hRes))
    {
      if (cStrExeNameW.CopyN(szNameStartW, (SIZE_T)(szNameEndW-szNameStartW)) != FALSE)
      {
        SIZE_T nRetLen;
        DWORD dwAttr;

        //check this entry
        while (SUCCEEDED(hRes))
        {
          nRetLen = ::SearchPathW((LPCWSTR)cStrSearchPathW, (LPCWSTR)cStrExeNameW, L".exe", (DWORD)nTempBufLen,
                                  (LPWSTR)cStrTempW, NULL);
          if (nRetLen == 0 || nRetLen < nTempBufLen-2)
          {
            ((LPWSTR)cStrTempW)[nRetLen] = 0;
            break;
          }
          nTempBufLen = nRetLen + 256;
          if (cStrTempW.EnsureBuffer(nTempBufLen + 1) == FALSE)
            hRes = E_OUTOFMEMORY;
        }
        if (SUCCEEDED(hRes) && nRetLen > 0)
        {
          dwAttr = ::GetFileAttributesW((LPCWSTR)cStrTempW);
          if (dwAttr != INVALID_FILE_ATTRIBUTES && (dwAttr & FILE_ATTRIBUTE_DIRECTORY) == 0)
          {
            cStrFullNameW.Attach(cStrTempW.Detach()); //GOT!
            break;
          }
        }
      }
      else
      {
        hRes = E_OUTOFMEMORY;
      }
      //if we reach here, then no valid name was found and we must advance to next portion
      if (SUCCEEDED(hRes))
      {
        if (*szNameEndW == 0 || (szApplicationNameW != NULL && *szApplicationNameW == L'"'))
        {
          hRes = MX_E_FileNotFound;
        }
        else
        {
          szNameEndW++;
          while (*szNameEndW != 0 && *szNameEndW != L' ' && *szNameEndW != L'\t')
            szNameEndW++;
        }
      }
    }
    //at this point we have a name or an error
  }
  else
  {
    HANDLE hFile;

    //don't bother in checking if the passed name is a directory instead of a file, we don't care because the latter
    //CreateProcess will fail
    hFile = ::CreateFileW(szApplicationNameW, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                          FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != NULL && hFile != INVALID_HANDLE_VALUE)
    {
      hRes = GetFileNameFromHandle(hFile, cStrFullNameW);
      ::MxNtClose(hFile);
    }
    else
    {
      hRes = MX_HRESULT_FROM_LASTERROR();
    }
  }
  //convert NT paths to DOS
  if (SUCCEEDED(hRes))
    hRes = ConvertToWin32(cStrFullNameW);
  //convert to long path
  if (SUCCEEDED(hRes))
    hRes = ConvertToLongPath(cStrFullNameW);
  //done
  return hRes;
}

HRESULT QueryEnvironmentVariable(_In_z_ LPCWSTR szVarNameW, _Inout_ MX::CStringW &cStrDestW)
{
  SIZE_T nVarNameLen;

  cStrDestW.Empty();

  if (szVarNameW == NULL)
    return E_POINTER;
  if (*szVarNameW == L'%')
    szVarNameW++;
  nVarNameLen = MX::StrLenW(szVarNameW);
  if (nVarNameLen > 0 && szVarNameW[nVarNameLen - 1] == L'%')
    nVarNameLen--;
  if (nVarNameLen == 0)
    return E_INVALIDARG;
  return QueryEnvironmentVariableInternal(szVarNameW, nVarNameLen, &cStrDestW);
}

HRESULT _ExpandEnvironmentStrings(_Inout_ MX::CStringW &cStrW)
{
  MX::CStringW cStrTempW;
  SIZE_T nOfs;
  LPCWSTR sW, szStartW;
  HRESULT hRes;

  sW = (LPCWSTR)cStrW;
  while (*sW != 0)
  {
    if (*sW == L'%')
    {
      szStartW = sW++;
      while (*sW != 0 && *sW != L'%')
        sW++;
      if (*sW == L'%')
      {
        //replace
        sW++;
        hRes = QueryEnvironmentVariableInternal(szStartW + 1, (SIZE_T)(sW - szStartW) - 2, &cStrTempW);
        if (SUCCEEDED(hRes))
        {
          nOfs = (SIZE_T)(szStartW - (LPCWSTR)cStrW);
          cStrW.Delete(nOfs, (SIZE_T)(sW - szStartW));
          if (cStrW.Insert((LPCWSTR)cStrTempW, nOfs) == FALSE)
            return E_OUTOFMEMORY;
        }
        else if (FAILED(hRes) && hRes != MX_E_NotFound)
        {
          return hRes;
        }
        //if not found, leave the %VAR% as the original ExpandEnvironmentStrings API
      }
    }
    else
    {
      sW++;
    }
  }
  //done
  return S_OK;
}

HRESULT GetProcessMembershipType(_Out_ eTokenGetMembershipType &nType)
{
  HANDLE hToken;
  HRESULT hRes;

  nType = TokenMembershipTypeLimitedUser;
  if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &hToken) != FALSE)
  {
    hRes = GetTokenMembershipType(hToken, nType);
    ::CloseHandle(hToken);
  }
  else
  {
    hRes = MX_HRESULT_FROM_LASTERROR();
  }
  return hRes;
}

HRESULT GetThreadMembershipType(_Out_ eTokenGetMembershipType &nType)
{
  HANDLE hToken;
  HRESULT hRes;

  nType = TokenMembershipTypeLimitedUser;
  if (::OpenThreadToken(::GetCurrentThread(), TOKEN_QUERY | TOKEN_DUPLICATE, TRUE, &hToken) != FALSE)
  {
    hRes = GetTokenMembershipType(hToken, nType);
    ::CloseHandle(hToken);
  }
  else
  {
    hRes = MX_HRESULT_FROM_LASTERROR();
  }
  return hRes;
}

HRESULT GetTokenMembershipType(_In_ HANDLE hToken, _Out_ eTokenGetMembershipType &nType)
{
  static const MY_SID sLocalSystemSID = {
    SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_LOCAL_SYSTEM_RID }
  };
  static const MY_SID sAdminsSID = {
    SID_REVISION, 2, { SECURITY_NT_AUTHORITY }, { SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS }
  };
  BOOL b;
  DWORD dw;
  HANDLE hTokenToCheck = NULL;
  HRESULT hRes;

  if (::DuplicateToken(hToken, SecurityIdentification, &hTokenToCheck) == FALSE)
    return MX_HRESULT_FROM_LASTERROR();
  //check if system account
  b = FALSE;
  if (::CheckTokenMembership(hTokenToCheck, (PSID)&sLocalSystemSID, &b) != FALSE && b != FALSE)
  {
    nType = TokenMembershipTypeRunningInSystemAccount;
    hRes = S_OK;
    goto done;
  }
  //on Vista+, check if we are elevated
  if (IsWinVistaPlus() != FALSE)
  {
    TOKEN_ELEVATION sTokElev;
    TOKEN_ELEVATION_TYPE sTokElevType;

    MX::MemSet(&sTokElev, 0, sizeof(sTokElev));
    if (::GetTokenInformation(hTokenToCheck, TokenElevation, &sTokElev, (DWORD)sizeof(sTokElev), &dw) != FALSE &&
        sTokElev.TokenIsElevated != 0)
    {
      nType = TokenMembershipTypeRunningOnAdministratorsGroupAndElevated;
      hRes = S_OK;
      goto done;
    }
    //if we are not elevated, lookup for the linked token (if exists) and check if it belongs to administrators group
    MX::MemSet(&sTokElevType, 0, sizeof(sTokElevType));
    if (::GetTokenInformation(hToken, TokenElevationType, &sTokElevType, (DWORD)sizeof(sTokElevType), &dw) != FALSE &&
        sTokElevType == TokenElevationTypeLimited)
    {
      HANDLE hLinkedToken;

      hLinkedToken = NULL;
      if (::GetTokenInformation(hToken, TokenLinkedToken, &hLinkedToken, (DWORD)sizeof(hLinkedToken), &dw) != FALSE &&
          hLinkedToken != NULL)
      {
        ::CloseHandle(hTokenToCheck);
        hTokenToCheck = NULL;
        if (::DuplicateToken(hLinkedToken, SecurityIdentification, &hTokenToCheck) == FALSE)
        {
          hRes = MX_HRESULT_FROM_LASTERROR();
          ::CloseHandle(hLinkedToken);
          goto done;
        }
        ::CloseHandle(hLinkedToken);
      }
    }
    //check if token is member of the administrators group
    b = FALSE;
    if (::CheckTokenMembership(hTokenToCheck, (PSID)&sAdminsSID, &b) != FALSE && b != FALSE)
    {
      nType = TokenMembershipTypeRunningOnAdministratorsGroup;
      hRes = S_OK;
      goto done;
    }
  }
  else
  {
    //on XP, check if we are a member of the administrators group
    b = FALSE;
    if (::CheckTokenMembership(hTokenToCheck, (PSID)&sAdminsSID, &b) != FALSE && b != FALSE)
    {
      nType = TokenMembershipTypeRunningOnAdministratorsGroupAndElevated;
      hRes = S_OK;
      goto done;
    }
  }

  hRes = S_FALSE;

done:
  if (hTokenToCheck != NULL)
    ::CloseHandle(hTokenToCheck);
  return hRes;
}

HRESULT EnablePrivilege(_In_z_ LPCWSTR szPrivilegeW)
{
  HANDLE hToken;
  TOKEN_PRIVILEGES sPriv;
  HRESULT hRes;

  if (szPrivilegeW == NULL)
    return E_POINTER;
  if (*szPrivilegeW == 0)
    return E_INVALIDARG;
  hRes = S_OK;
  if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken) != FALSE)
  {
    MX::MemSet(&sPriv, 0, sizeof(sPriv));
    if (::LookupPrivilegeValueW(NULL, szPrivilegeW, &(sPriv.Privileges[0].Luid)) != FALSE)
    {
      sPriv.PrivilegeCount = 1;
      sPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
      if (::AdjustTokenPrivileges(hToken, FALSE, &sPriv, (DWORD)sizeof(sPriv), NULL, NULL) == FALSE)
      {
        hRes = MX_HRESULT_FROM_LASTERROR();
        //MX::DebugPrint("EnableProcessPrivileges/AdjustTokenPrivileges 0x%08X\n", hRes);
      }
    }
    else
    {
      hRes = MX_HRESULT_FROM_LASTERROR();
      //MX::DebugPrint("EnableProcessPrivileges/LookupPrivilegeValueW 0x%08X\n", hRes);
    }
    ::CloseHandle(hToken);
  }
  else
  {
    hRes = MX_HRESULT_FROM_LASTERROR();
    //MX::DebugPrint("EnableProcessPrivileges/OpenProcessToken 0x%08X\n", hRes);
  }
  return hRes;
}

}; //MXHelpers

//-----------------------------------------------------------

static HRESULT QueryEnvironmentVariableInternal(_In_ LPCWSTR szVarNameW, _In_ SIZE_T nVarNameLen,
                                                _In_opt_ MX::CStringW *lpStrDestW)
{
  LPBYTE lpPeb, lpUserProcParams;
  PRTL_CRITICAL_SECTION lpCS;
  LPCWSTR szEnvW, szNameStartW;
  HRESULT hRes;

  MX_ASSERT(szVarNameW != NULL);
  if (lpStrDestW != NULL)
    lpStrDestW->Empty();

#if defined(_M_IX86)
  lpPeb = (LPBYTE)__readfsdword(0x30); //get PEB from the TIB
  lpUserProcParams = *((LPBYTE*)(lpPeb+0x10)); //PRTL_USER_PROCESS_PARAMETERS
  lpCS = *((PRTL_CRITICAL_SECTION*)(lpPeb+0x1C)); //PEB's critical section
#elif defined(_M_X64)
  LPBYTE lpPtr = (LPBYTE)__readgsqword(0x30); //get TEB
  lpPeb = *((LPBYTE*)(lpPtr+0x60));
  lpUserProcParams = *((LPBYTE*)(lpPeb+0x20)); //PRTL_USER_PROCESS_PARAMETERS
  lpCS = *((PRTL_CRITICAL_SECTION*)(lpPeb+0x38)); //PEB's critical section
#endif
  //lock PEB
  if (lpCS != NULL)
    ::MxRtlEnterCriticalSection(lpCS);

  //get environment variables string
  hRes = MX_E_NotFound;
  if (lpUserProcParams != NULL)
  {
#if defined(_M_IX86)
    szEnvW = *((LPCWSTR*)(lpUserProcParams+0x48));
#elif defined(_M_X64)
    szEnvW = *((LPCWSTR*)(lpUserProcParams+0x80));
#endif
    if (szEnvW != NULL)
    {
      //parse environment variables string
      while (*szEnvW != 0)
      {
        szNameStartW = szEnvW;
        while (*szEnvW != 0 && *szEnvW != L'=')
          szEnvW++;
        //check this name
        if ((SIZE_T)(szEnvW-szNameStartW) == nVarNameLen &&
            MX::StrNCompareW(szVarNameW, szNameStartW, nVarNameLen, TRUE) == 0)
        {
          hRes = S_OK;
          if (*szEnvW == L'=' && lpStrDestW != NULL)
          {
            if (lpStrDestW->Copy(szEnvW+1) == FALSE)
              hRes = E_OUTOFMEMORY;
          }
          break;
        }
        //skip until next
        if (*szEnvW == L'=')
          szEnvW++;
        while (*szEnvW != 0)
          szEnvW++;
        szEnvW++; //skip end-of-var
      }
    }
  }

  //unlock PEB
  if (lpCS != NULL)
    ::MxRtlLeaveCriticalSection(lpCS);
  //done
  return hRes;
}

static BOOL IsWinVistaPlus()
{
  static LONG volatile nIsWinVistaPlus = -1;
  LONG nIsWinVistaPlusLocal;

  nIsWinVistaPlusLocal = __InterlockedRead(&nIsWinVistaPlus);
  if (nIsWinVistaPlusLocal < 0)
  {
    nIsWinVistaPlusLocal = ::IsWindowsVistaOrGreater() ? 1 : 0;
    _InterlockedCompareExchange(&nIsWinVistaPlusLocal, nIsWinVistaPlusLocal, -1);
  }
  return (nIsWinVistaPlusLocal == 1) ? TRUE : FALSE;
}
