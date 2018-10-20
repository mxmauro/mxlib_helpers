/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#include "System.h"
#include "Sid.h"
#include <Windows.h>
#include <lm.h>

//#pragma comment(lib, "netapi32.lib")


//-----------------------------------------------------------

#define X_WCHAR_ENC(_x,_y) (WCHAR)(((USHORT)(_x)) ^ ((USHORT)_y+0x8C32))

#define _EXPAND_W(str)                       \
    i = 0; do                                \
    { szTempW[i] = X_WCHAR_ENC(str[i], i); } \
            while (szTempW[i++] != 0)

//-----------------------------------------------------------

typedef NET_API_STATUS (WINAPI *lpfnNetUserEnum)(_In_opt_ LPCWSTR servername, _In_ DWORD level, _In_ DWORD filter,
                                                 _Outptr_result_buffer_(_Inexpressible_("varies")) LPBYTE *bufptr,
                                                 _In_ DWORD prefmaxlen, _Out_ LPDWORD entriesread,
                                                 _Out_ LPDWORD totalentries, _Inout_opt_ PDWORD resume_handle);
typedef NET_API_STATUS (WINAPI *lpfnNetLocalGroupEnum)(_In_opt_ LPCWSTR servername, _In_ DWORD level,
                                                       _Outptr_result_buffer_(_Inexpressible_("varies")) LPBYTE *bufptr,
                                                       _In_ DWORD prefmaxlen, _Out_ LPDWORD entriesread,
                                                       _Out_ LPDWORD totalentries, _Inout_opt_ PDWORD_PTR resumehandle);
typedef NET_API_STATUS (WINAPI *lpfnNetApiBufferFree)(_Frees_ptr_opt_ LPVOID Buffer);


static LONG volatile nInitialized = 0;
static lpfnNetUserEnum fnNetUserEnum = NULL;
static lpfnNetLocalGroupEnum fnNetLocalGroupEnum = NULL;
static lpfnNetApiBufferFree fnNetApiBufferFree = NULL;

//-----------------------------------------------------------

static VOID InitializeApis();

//-----------------------------------------------------------

namespace MXHelpers {

HRESULT GetOpSystemInfo(_Out_ MX::CStringW &cStrOpSystemW)
{
  static const WCHAR strW_Windows[] = {
    X_WCHAR_ENC(L'W', 0), X_WCHAR_ENC(L'i', 1), X_WCHAR_ENC(L'n',  2), X_WCHAR_ENC(L'd',  3),
    X_WCHAR_ENC(L'o', 4), X_WCHAR_ENC(L'w', 5), X_WCHAR_ENC(L's',  6), X_WCHAR_ENC(0,     7)
  };
  static const WCHAR strW_Windows2000[] = {
    X_WCHAR_ENC(L'2', 0), X_WCHAR_ENC(L'0', 1), X_WCHAR_ENC(L'0',  2), X_WCHAR_ENC(L'0',  3),
    X_WCHAR_ENC(0,    4)
  };
  static const WCHAR strW_WindowsXP[] = {
    X_WCHAR_ENC(L'X', 0), X_WCHAR_ENC(L'P', 1), X_WCHAR_ENC(0, 2)
  };
  static const WCHAR strW_WindowsServer2003[] = {
    X_WCHAR_ENC(L'S', 0), X_WCHAR_ENC(L'e', 1), X_WCHAR_ENC(L'r',  2), X_WCHAR_ENC(L'v',  3),
    X_WCHAR_ENC(L'e', 4), X_WCHAR_ENC(L'r', 5), X_WCHAR_ENC(L' ',  6), X_WCHAR_ENC(L'2',  7),
    X_WCHAR_ENC(L'0', 8), X_WCHAR_ENC(L'0', 9), X_WCHAR_ENC(L'3', 10), X_WCHAR_ENC(0,    11)
  };
  static const WCHAR strW_WindowsServer2003R2[] = {
    X_WCHAR_ENC(L'S',  0), X_WCHAR_ENC(L'e',  1), X_WCHAR_ENC(L'r',  2), X_WCHAR_ENC(L'v',  3),
    X_WCHAR_ENC(L'e',  4), X_WCHAR_ENC(L'r',  5), X_WCHAR_ENC(L' ',  6), X_WCHAR_ENC(L'2',  7),
    X_WCHAR_ENC(L'0',  8), X_WCHAR_ENC(L'0',  9), X_WCHAR_ENC(L'3', 10), X_WCHAR_ENC(L' ', 11),
    X_WCHAR_ENC(L'R', 12), X_WCHAR_ENC(L'2', 13), X_WCHAR_ENC(0,    14)
  };
  static const WCHAR strW_WindowsVista[] = {
    X_WCHAR_ENC(L'V',  0), X_WCHAR_ENC(L'i',  1), X_WCHAR_ENC(L's',  2), X_WCHAR_ENC(L't',  3),
    X_WCHAR_ENC(L'a',  4), X_WCHAR_ENC(0,     5)
  };
  static const WCHAR strW_WindowsServer2008[] = {
    X_WCHAR_ENC(L'S', 0), X_WCHAR_ENC(L'e', 1), X_WCHAR_ENC(L'r',  2), X_WCHAR_ENC(L'v',  3),
    X_WCHAR_ENC(L'e', 4), X_WCHAR_ENC(L'r', 5), X_WCHAR_ENC(L' ',  6), X_WCHAR_ENC(L'2',  7),
    X_WCHAR_ENC(L'0', 8), X_WCHAR_ENC(L'0', 9), X_WCHAR_ENC(L'8', 10), X_WCHAR_ENC(0,    11)
  };
  static const WCHAR strW_WindowsServer2008R2[] = {
    X_WCHAR_ENC(L'S',  0), X_WCHAR_ENC(L'e',  1), X_WCHAR_ENC(L'r',  2), X_WCHAR_ENC(L'v',  3),
    X_WCHAR_ENC(L'e',  4), X_WCHAR_ENC(L'r',  5), X_WCHAR_ENC(L' ',  6), X_WCHAR_ENC(L'2',  7),
    X_WCHAR_ENC(L'0',  8), X_WCHAR_ENC(L'0',  9), X_WCHAR_ENC(L'8', 10), X_WCHAR_ENC(L' ', 11),
    X_WCHAR_ENC(L'R', 12), X_WCHAR_ENC(L'2', 13), X_WCHAR_ENC(0,    14)
  };
  static const WCHAR strW_Windows7[] = {
    X_WCHAR_ENC(L'7', 0), X_WCHAR_ENC(0, 1)
  };
  static const WCHAR strW_WindowsServer2012[] = {
    X_WCHAR_ENC(L'S', 0), X_WCHAR_ENC(L'e', 1), X_WCHAR_ENC(L'r',  2), X_WCHAR_ENC(L'v',  3),
    X_WCHAR_ENC(L'e', 4), X_WCHAR_ENC(L'r', 5), X_WCHAR_ENC(L' ',  6), X_WCHAR_ENC(L'2',  7),
    X_WCHAR_ENC(L'0', 8), X_WCHAR_ENC(L'1', 9), X_WCHAR_ENC(L'2', 10), X_WCHAR_ENC(0,    11)
  };
  static const WCHAR strW_Windows8[] = {
    X_WCHAR_ENC(L'8', 0), X_WCHAR_ENC(0, 1)
  };
  static const WCHAR strW_WindowsServer2012R2[] = {
    X_WCHAR_ENC(L'S',  0), X_WCHAR_ENC(L'e',  1), X_WCHAR_ENC(L'r',  2), X_WCHAR_ENC(L'v',  3),
    X_WCHAR_ENC(L'e',  4), X_WCHAR_ENC(L'r',  5), X_WCHAR_ENC(L' ',  6), X_WCHAR_ENC(L'2',  7),
    X_WCHAR_ENC(L'0',  8), X_WCHAR_ENC(L'1',  9), X_WCHAR_ENC(L'2', 10), X_WCHAR_ENC(L' ', 11),
    X_WCHAR_ENC(L'R', 12), X_WCHAR_ENC(L'2', 13), X_WCHAR_ENC(0,    14)
  };
  static const WCHAR strW_Windows8_1[] = {
    X_WCHAR_ENC(L'8', 0), X_WCHAR_ENC(L'.', 1), X_WCHAR_ENC(L'1', 2), X_WCHAR_ENC(0, 3)
  };
  static const WCHAR strW_Windows10[] = {
    X_WCHAR_ENC(L'1', 0), X_WCHAR_ENC(L'0', 1), X_WCHAR_ENC(0,    2)
  };
  static const WCHAR strW_WindowsServer2016[] = {
    X_WCHAR_ENC(L'S', 0), X_WCHAR_ENC(L'e', 1), X_WCHAR_ENC(L'r',  2), X_WCHAR_ENC(L'v',  3),
    X_WCHAR_ENC(L'e', 4), X_WCHAR_ENC(L'r', 5), X_WCHAR_ENC(L' ',  6), X_WCHAR_ENC(L'2',  7),
    X_WCHAR_ENC(L'0', 8), X_WCHAR_ENC(L'1', 9), X_WCHAR_ENC(L'6', 10), X_WCHAR_ENC(0,    11)
  };
  static const WCHAR strW_Unknown[] = {
    X_WCHAR_ENC(L'?', 0), X_WCHAR_ENC(0, 1)
  };
  RTL_OSVERSIONINFOEXW sOviExW;
  WCHAR szTempW[128];
  SIZE_T i;
  NTSTATUS nNtStatus;

  MX::MemSet(&sOviExW, 0, sizeof(sOviExW));
  sOviExW.dwOSVersionInfoSize = (DWORD)sizeof(sOviExW);
  nNtStatus = ::MxRtlGetVersion((PRTL_OSVERSIONINFOW)&sOviExW);
  if (!NT_SUCCESS(nNtStatus))
  {
    cStrOpSystemW.Empty();
    return MX_HRESULT_FROM_WIN32(::MxRtlNtStatusToDosError(nNtStatus));
  }
  if (sOviExW.dwPlatformId != VER_PLATFORM_WIN32_NT)
  {
    cStrOpSystemW.Empty();
    return E_NOTIMPL;
  }
  _EXPAND_W(strW_Windows);
  if (cStrOpSystemW.Copy(szTempW) == FALSE)
    return E_OUTOFMEMORY;
  _EXPAND_W(strW_Unknown);
  if (sOviExW.dwMajorVersion == 5)
  {
    if (sOviExW.dwMinorVersion == 0)
    {
      _EXPAND_W(strW_Windows2000);
    }
    else if (sOviExW.dwMinorVersion == 1)
    {
      _EXPAND_W(strW_WindowsXP);
    }
    else if (sOviExW.dwMinorVersion == 2)
    {
      if (::GetSystemMetrics(SM_SERVERR2) == 0)
      {
        _EXPAND_W(strW_WindowsServer2003);
      }
      else
      {
        _EXPAND_W(strW_WindowsServer2003R2);
      }
    }
  }
  else if (sOviExW.dwMajorVersion == 6)
  {
    if (sOviExW.dwMinorVersion == 0)
    {
      if (sOviExW.wProductType == VER_NT_WORKSTATION)
      {
        _EXPAND_W(strW_WindowsVista);
      }
      else
      {
        _EXPAND_W(strW_WindowsServer2008);
      }
    }
    else if (sOviExW.dwMinorVersion == 1)
    {
      if (sOviExW.wProductType == VER_NT_WORKSTATION)
      {
        _EXPAND_W(strW_Windows7);
      }
      else
      {
        _EXPAND_W(strW_WindowsServer2008R2);
      }
    }
    else if (sOviExW.dwMinorVersion == 2)
    {
      if (sOviExW.wProductType == VER_NT_WORKSTATION)
      {
        _EXPAND_W(strW_Windows8);
      }
      else
      {
        _EXPAND_W(strW_WindowsServer2012);
      }
    }
    else if (sOviExW.dwMinorVersion == 3)
    {
      if (sOviExW.wProductType == VER_NT_WORKSTATION)
      {
        _EXPAND_W(strW_Windows8_1);
      }
      else
      {
        _EXPAND_W(strW_WindowsServer2012R2);
      }
    }
    else if (sOviExW.dwMinorVersion == 4)
    {
      if (sOviExW.wProductType == VER_NT_WORKSTATION)
      {
        _EXPAND_W(strW_Windows10);
      }
      else
      {
        _EXPAND_W(strW_WindowsServer2016);
      }
    }
  }
  else if (sOviExW.dwMajorVersion == 10)
  {
    if (sOviExW.wProductType == VER_NT_WORKSTATION)
    {
      _EXPAND_W(strW_Windows10);
    }
    else
    {
      _EXPAND_W(strW_WindowsServer2016);
    }
  }
  if (cStrOpSystemW.Concat(L" ") == FALSE ||
      cStrOpSystemW.Concat(szTempW) == FALSE)
  {
    return E_OUTOFMEMORY;
  }
  //done
  return S_OK;
}

HRESULT _GetComputerNameEx(_In_ COMPUTER_NAME_FORMAT NameType, _Out_ MX::CStringW &cStrNameW)
{
  DWORD dwBufLen;
  HRESULT hRes;

  for (dwBufLen = 128; dwBufLen <= 65536; dwBufLen <<= 1)
  {
    if (cStrNameW.EnsureBuffer((SIZE_T)dwBufLen + 1) == FALSE)
    {
      hRes = E_OUTOFMEMORY;
      break;
    }
    if (::GetComputerNameExW(NameType, (LPWSTR)cStrNameW, &dwBufLen) != FALSE)
    {
      hRes = S_OK;
      ((LPWSTR)cStrNameW)[dwBufLen] = 0;
      if (dwBufLen == 0)
        goto try_other_method;
      break;
    }
    hRes = MX_HRESULT_FROM_LASTERROR();
    if (hRes != MX_E_MoreData)
      break;
  }
  if (dwBufLen > 65536)
    hRes = MX_E_BufferOverflow;
  if (FAILED(hRes) && hRes != E_OUTOFMEMORY)
  {
try_other_method:
    if (NameType == ComputerNameDnsDomain || NameType == ComputerNameDnsHostname)
    {
      if (cStrNameW.EnsureBuffer(MAX_COMPUTERNAME_LENGTH + 2) != FALSE)
      {
        dwBufLen = MAX_COMPUTERNAME_LENGTH + 1;
        if (::GetComputerNameW((LPWSTR)cStrNameW, &dwBufLen) != FALSE)
        {
          ((LPWSTR)cStrNameW)[dwBufLen] = 0;
          hRes = S_OK;
        }
        else
        {
          hRes = MX_HRESULT_FROM_LASTERROR();
        }
      }
      else
      {
        hRes = E_OUTOFMEMORY;
      }
    }
  }
  //done
  if (SUCCEEDED(hRes))
    cStrNameW.Refresh();
  else
    cStrNameW.Empty();
  return hRes;
}

VOID RegisterAppInRestartManager()
{
  typedef HRESULT (WINAPI *lpfnRegisterApplicationRestart)(_In_opt_ PCWSTR pwzCommandline, _In_ DWORD dwFlags);
  lpfnRegisterApplicationRestart fnRegisterApplicationRestart;
  HINSTANCE hKernel32Dll;

  hKernel32Dll = ::GetModuleHandleW(L"kernel32.dll");
  if (hKernel32Dll != NULL)
  {
    fnRegisterApplicationRestart = (lpfnRegisterApplicationRestart)::GetProcAddress(hKernel32Dll,
                                                                                    "RegisterApplicationRestart");
    if (fnRegisterApplicationRestart != NULL)
    {
      fnRegisterApplicationRestart(L"/restartmanager", RESTART_NO_CRASH | RESTART_NO_HANG |
                                                       RESTART_NO_REBOOT);
    }
  }
  return;
}

HRESULT GetAllUsers(_Inout_ MX::TArrayListWithFree<LPWSTR> &aUsersList)
{
  static const LPCWSTR aBuiltinUsersW[] = { L"S-1-5-18", L"S-1-5-19", L"S-1-5-20" };
  LPUSER_INFO_0 lpUserInfo0 = NULL;
  DWORD i, dwEntries, dwTotalEntries, dwResumeHandle;
  NET_API_STATUS nStatus;
  CSid cSid;
  MX::CStringW cStrTempW;
  HRESULT hRes, hRes2;

  aUsersList.RemoveAllElements();

  InitializeApis();
  if (fnNetUserEnum == NULL)
    return MX_E_ProcNotFound;

  for (i=0; i<(DWORD)MX_ARRAYLEN(aBuiltinUsersW); i++)
  {
    hRes = cSid.Set(aBuiltinUsersW[i]);
    if (SUCCEEDED(hRes))
    {
      hRes = cSid.GetAccountName(cStrTempW);
      if (SUCCEEDED(hRes))
      {
        if (cStrTempW.InsertN(L"/", 0, 1) == FALSE ||
            cStrTempW.Insert(aBuiltinUsersW[i], 0) == FALSE ||
            cStrTempW.InsertN((cSid.IsAnyWellKnownSid() != FALSE) ? L"+" : L"-", 0, 1) == FALSE)
        {
          hRes = E_OUTOFMEMORY;
        }
      }

      if (SUCCEEDED(hRes))
      {
        if (aUsersList.AddElement((LPWSTR)cStrTempW) != FALSE)
          cStrTempW.Detach();
        else
          hRes = E_OUTOFMEMORY;
      }
    }

    if (FAILED(hRes))
      goto done;
  }

  dwEntries = dwTotalEntries = dwResumeHandle = 0;
  do
  {
    lpUserInfo0 = NULL;
    nStatus = fnNetUserEnum(NULL, 0, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&lpUserInfo0, 16384, &dwEntries, &dwTotalEntries,
                            &dwResumeHandle);
    hRes = HRESULT_FROM_WIN32(nStatus);
    if (nStatus == NERR_Success || nStatus == ERROR_MORE_DATA)
    {
      for (i = 0; i < dwEntries; i++)
      {
        cStrTempW.Empty();

        hRes2 = cSid.Set(lpUserInfo0[i].usri0_name);
        if (SUCCEEDED(hRes2))
          hRes2 = cSid.GetStringSid(cStrTempW);

        if (SUCCEEDED(hRes2))
        {
          if (cStrTempW.ConcatN(L"/", 1) == FALSE ||
              cStrTempW.Concat(lpUserInfo0[i].usri0_name) == FALSE ||
              cStrTempW.InsertN((cSid.IsAnyWellKnownSid() != FALSE) ? L"+" : L"-", 0, 1) == FALSE)
          {
            hRes2 = E_OUTOFMEMORY;
          }
        }

        if (SUCCEEDED(hRes2))
        {
          if (aUsersList.AddElement((LPWSTR)cStrTempW) != FALSE)
            cStrTempW.Detach();
          else
            hRes2 = E_OUTOFMEMORY;
        }

        if (FAILED(hRes2))
        {
          hRes = hRes2;
          break;
        }
      }
    }
    if (lpUserInfo0 != NULL)
      fnNetApiBufferFree(lpUserInfo0);
  }
  while (hRes == HRESULT_FROM_WIN32(ERROR_MORE_DATA));

done:
  //done
  if (FAILED(hRes))
    aUsersList.RemoveAllElements();
  return hRes;
}

HRESULT GetAllGroups(_Inout_ MX::TArrayListWithFree<LPWSTR> &aGroupsList)
{
  static const LPCWSTR aBuiltinUsersW[] = { L"S-1-1-0" };
  LPLOCALGROUP_INFO_0 lpGroupInfo0 = NULL;
  DWORD i, dwEntries, dwTotalEntries;
  DWORD_PTR dwResumeHandle;
  NET_API_STATUS nStatus;
  CSid cSid;
  MX::CStringW cStrTempW;
  HRESULT hRes, hRes2;

  aGroupsList.RemoveAllElements();

  InitializeApis();
  if (fnNetLocalGroupEnum == NULL)
    return MX_E_ProcNotFound;

  for (i=0; i<(DWORD)MX_ARRAYLEN(aBuiltinUsersW); i++)
  {
    hRes = cSid.Set(aBuiltinUsersW[i]);
    if (SUCCEEDED(hRes))
    {
      hRes = cSid.GetAccountName(cStrTempW);
      if (SUCCEEDED(hRes))
      {
        if (cStrTempW.InsertN(L"/", 0, 1) == FALSE ||
            cStrTempW.Insert(aBuiltinUsersW[i], 0) == FALSE ||
            cStrTempW.InsertN((cSid.IsAnyWellKnownSid() != FALSE) ? L"+" : L"-", 0, 1) == FALSE)
        {
          hRes = E_OUTOFMEMORY;
        }
      }

      if (SUCCEEDED(hRes))
      {
        if (aGroupsList.AddElement((LPWSTR)cStrTempW) != FALSE)
          cStrTempW.Detach();
        else
          hRes = E_OUTOFMEMORY;
      }
    }

    if (FAILED(hRes))
      goto done;
  }

  dwEntries = dwTotalEntries = 0;
  dwResumeHandle = 0;
  do
  {
    lpGroupInfo0 = NULL;
    nStatus = fnNetLocalGroupEnum(NULL, 0, (LPBYTE*)&lpGroupInfo0, 16384, &dwEntries, &dwTotalEntries,
                                  &dwResumeHandle);
    hRes = HRESULT_FROM_WIN32(nStatus);
    if (nStatus == NERR_Success || nStatus == ERROR_MORE_DATA)
    {
      for (i = 0; i < dwEntries; i++)
      {
        cStrTempW.Empty();

        hRes2 = cSid.Set(lpGroupInfo0[i].lgrpi0_name);
        if (SUCCEEDED(hRes2))
          hRes2 = cSid.GetStringSid(cStrTempW);

        if (SUCCEEDED(hRes2))
        {
          if (cStrTempW.ConcatN(L"/", 1) == FALSE ||
              cStrTempW.Concat(lpGroupInfo0[i].lgrpi0_name) == FALSE ||
              cStrTempW.InsertN((cSid.IsAnyWellKnownSid() != FALSE) ? L"+" : L"-", 0, 1) == FALSE)
          {
            hRes2 = E_OUTOFMEMORY;
          }
        }
        if (SUCCEEDED(hRes2))
        {
          if (aGroupsList.AddElement((LPWSTR)cStrTempW) != FALSE)
            cStrTempW.Detach();
          else
            hRes2 = E_OUTOFMEMORY;
        }

        if (FAILED(hRes2))
        {
          hRes = hRes2;
          break;
        }
      }
    }
    if (lpGroupInfo0 != NULL)
      fnNetApiBufferFree(lpGroupInfo0);
  }
  while (hRes == HRESULT_FROM_WIN32(ERROR_MORE_DATA));

done:
  //done
  if (FAILED(hRes))
    aGroupsList.RemoveAllElements();
  return hRes;
}

}; //namespace MXHelpers


//-----------------------------------------------------------

static VOID InitializeApis()
{
  if (_InterlockedCompareExchange(&nInitialized, 2, 0) == 0)
  {
    
    HINSTANCE _hNetApi32Dll;
    LPVOID _fnNetUserEnum, _fnNetLocalGroupEnum, _fnNetApiBufferFree;

    _hNetApi32Dll = ::LoadLibraryW(L"netapi32.dll");
    if (_hNetApi32Dll != NULL)
    {
      _fnNetUserEnum = ::GetProcAddress(_hNetApi32Dll, "");
      _fnNetLocalGroupEnum = ::GetProcAddress(_hNetApi32Dll, "");
      _fnNetApiBufferFree = ::GetProcAddress(_hNetApi32Dll, "");
      if (_fnNetUserEnum != NULL && _fnNetLocalGroupEnum != NULL && _fnNetApiBufferFree != NULL)
      {
        fnNetUserEnum = (lpfnNetUserEnum)_fnNetUserEnum;
        fnNetLocalGroupEnum = (lpfnNetLocalGroupEnum)_fnNetLocalGroupEnum;
        fnNetApiBufferFree = (lpfnNetApiBufferFree)_fnNetApiBufferFree;
      }
      else
      {
        ::FreeLibrary(_hNetApi32Dll);
      }
    }

    _InterlockedExchange(&nInitialized, 1);
  }
  else while (__InterlockedRead(&nInitialized) == 2)
  {
    ::MxSleep(50);
  }
  return;
}
