/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#include "HelperRoutines.h"
#include "FileRoutinesLite.h"
#define PSAPI_VERSION 1
#include <Psapi.h>
#include <sddl.h>
#include <wtsapi32.h>
#include <stdio.h>
#include <ShlObj.h>
#include <Msi.h>
#include <VersionHelpers.h>
#include <AutoPtr.h>
#include <AutoHandle.h>
#include <Debug.h>
#include <Strings\Utf8.h>
#include <iphlpapi.h>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "iphlpapi.lib")

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

#define X_WCHAR_ENC(_x,_y) (WCHAR)(((USHORT)(_x)) ^ ((USHORT)_y+0x8C32))

#define _EXPAND_W(str)                       \
    i = 0; do                                \
    { szTempW[i] = X_WCHAR_ENC(str[i], i); } \
            while (szTempW[i++] != 0)

//-----------------------------------------------------------

static HRESULT GetTokenMembershipType(_In_ HANDLE hToken, _Inout_ HelperRoutines::eGetMembershipType &nType);
static HRESULT DeviceName2DosName(_Inout_ MX::CStringW &cStrPathW);

//-----------------------------------------------------------

namespace HelperRoutines {

WORD GetDaysInMonth(_In_ WORD wMonth, _In_ WORD wYear)
{
  static WORD wDaysInMonths[12] = { 31,0,31,30,31,30,31,31,30,31,30,31 };

  if (wMonth < 1 || wMonth > 12)
    return 0;
  if (wMonth != 2)
    return wDaysInMonths[wMonth-1];
  return ((wYear % 400) == 0 || ((wYear % 4) == 0 && (wYear % 100) != 0)) ? 29 : 28;
}

HRESULT GetProcessMembershipType(_Out_ eGetMembershipType &nType)
{
  HANDLE hToken;
  HRESULT hRes;

  nType = MembershipTypeLimitedUser;
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

HRESULT GetThreadMembershipType(_Out_ eGetMembershipType &nType)
{
  HANDLE hToken;
  HRESULT hRes;

  nType = MembershipTypeLimitedUser;
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

HRESULT NormalizePath(_Inout_ MX::CStringW &cStrPathW)
{
  MX::CStringW cStrTempW;
  LPWSTR sW;
  SIZE_T i, nSize, nLen;

  cStrTempW.Empty();
  sW = (LPWSTR)cStrPathW;
  if (sW[0] == L'\\' && sW[1] == L'\\')
  {
    if (cStrTempW.Copy(L"\\\\") == FALSE)
      return E_OUTOFMEMORY;
    sW += 2;
  }
  //remove double slashes and convert forward slashes to back slashes
  while (*sW != 0)
  {
    if (sW[0] == L'/' || sW[0] == L'\\')
    {
      //skip multiple slashes at one
      while (*sW == L'/' || *sW == L'\\')
        sW++;
      if (cStrTempW.ConcatN(L"\\", 1) == FALSE)
        return E_OUTOFMEMORY;
    }
    else
    {
      if (cStrTempW.ConcatN(sW, 1) == FALSE)
        return E_OUTOFMEMORY;
      sW++;
    }
  }
  //remove "." && ".."
  sW = (LPWSTR)cStrTempW;
  while (*sW != 0)
  {
    if (sW[0] == L'\\' && sW[1] == L'.')
    {
      if (sW[2] == L'\\' || sW[2] == 0)
      {
        //remove "\.\"
        i = (SIZE_T)(sW - (LPWSTR)cStrTempW);
        cStrTempW.Delete(i, 2);
        sW = (LPWSTR)cStrTempW + i;
        continue;
      }
      else if (sW[2] == L'.' && (sW[3] == L'\\' || sW[3] == 0))
      {
        LPWSTR szStartW, szPrevSlashW;

        szStartW = (LPWSTR)cStrTempW;
        if (szStartW[0] == L'\\' && szStartW[1] == L'\\')
          szStartW += 2;
        else if (((szStartW[0] >= L'A' && szStartW[0] <= L'Z') || (szStartW[0] >= L'a' && szStartW[0] <= L'z')) &&
                 szStartW[1] == L':' && szStartW[2] == L'\\')
          szStartW += 3;
        szPrevSlashW = sW-1;
        while (szPrevSlashW > szStartW && *(szPrevSlashW-1) != L'\\')
          szPrevSlashW--;
        //remove from szPrevSlashW to sW+4
        i = (SIZE_T)(szPrevSlashW - (LPWSTR)cStrTempW);
        cStrTempW.Delete(i, (SIZE_T)(sW-szPrevSlashW) + 4);
        if (i > 0)
          i--;
        sW = (LPWSTR)cStrTempW + i;
        continue;
      }
    }
    sW++;
  }
  //convert short path to long if not a network folder
  sW = (LPWSTR)cStrTempW;
  if (sW[0] != L'\\')
  {
    for (nSize=256; nSize<=32768; nSize<<=1)
    {
      if (cStrPathW.EnsureBuffer(nSize+4) == FALSE)
        return E_OUTOFMEMORY;
      nLen = (SIZE_T)::GetLongPathNameW((LPWSTR)cStrTempW, (LPWSTR)cStrPathW, (DWORD)nSize);
      if (nLen == 0)
      {
        //couldn't convert (i.e. access denied to a parent folder), use original temp path
        goto cannot_convert_to_longpath;
      }
      if (nLen < nSize)
        break;
    }
    if (nSize > 32768)
      return E_OUTOFMEMORY;
    ((LPWSTR)cStrPathW)[nLen] = 0;
    cStrPathW.Refresh();
  }
  else
  {
cannot_convert_to_longpath:
    cStrPathW.Attach(cStrTempW.Detach());
  }
  //done
  return S_OK;
}

HRESULT GetCurrentProcessUserSid(_Inout_ MX::CStringW &cStrUserSidW)
{
  MX::CWindowsHandle cToken;
  MX::TAutoFreePtr<TOKEN_USER> cTokUser;
  LPWSTR szSidW;
  DWORD dwSize;
  HRESULT hRes;

  cStrUserSidW.Empty();
  if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &cToken) == FALSE)
    return MX_HRESULT_FROM_LASTERROR();
  dwSize = 0;
  if (::GetTokenInformation(cToken, TokenUser, NULL, 0, &dwSize) == FALSE)
  {
    hRes = MX_HRESULT_FROM_LASTERROR();
    if (hRes != MX_HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER))
      return hRes;
  }
  cTokUser.Attach((PTOKEN_USER)MX::MemAlloc((SIZE_T)dwSize));
  if (!cTokUser)
    return E_OUTOFMEMORY;
  if (::GetTokenInformation(cToken, TokenUser, cTokUser.Get(), dwSize, &dwSize) == FALSE)
    return MX_HRESULT_FROM_LASTERROR();
  szSidW = NULL;
  if (::ConvertSidToStringSidW(cTokUser->User.Sid, &szSidW) == FALSE)
    return MX_HRESULT_FROM_LASTERROR();
  hRes = (cStrUserSidW.Copy(szSidW) != FALSE) ? S_OK : E_OUTOFMEMORY;
  ::LocalFree((HLOCAL)szSidW);
  return hRes;
}

BOOL IsWindowsVistaOrLater()
{
  static LONG volatile nIsVistaOrLater = -1;

  if (__InterlockedRead(&nIsVistaOrLater) < 0)
  {
    _InterlockedExchange(&nIsVistaOrLater, (::IsWindowsVistaOrGreater() != FALSE) ? 1 : 0);
  }
  return (__InterlockedRead(&nIsVistaOrLater) > 0) ? TRUE : FALSE;
}

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

HRESULT EnableProcessPrivileges(_In_z_ LPCWSTR szPrivilegeW)
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

HRESULT GetLocalIpAddresses(_Out_ MX::TArrayListWithFree<LPCWSTR> &cStrListW, _In_ int nFlags)
{
  MX::TAutoFreePtr<IP_ADAPTER_ADDRESSES> cIpAddrBuffer;
  PIP_ADAPTER_ADDRESSES lpCurrAdapter;
  PIP_ADAPTER_UNICAST_ADDRESS lpCurrUnicastAddress;
  DWORD dwBufLen, dwRetVal, dwRetryCount;
  SIZE_T nIpV4InsertPos;
  union {
    sockaddr_in *lpAddrV4;
    SOCKADDR_IN6_W2KSP1 *lpAddrV6;
    SOCKADDR_INET *lpAddr;
  } u;
  MX::CStringW cStrTempW;
  HRESULT hRes;

  cStrListW.RemoveAllElements();
  //query addresses
  dwBufLen = 16384;
  for (dwRetryCount=20; dwRetryCount>0; dwRetryCount--)
  {
    cIpAddrBuffer.Attach((IP_ADAPTER_ADDRESSES*)MX_MALLOC(dwBufLen));
    if (!cIpAddrBuffer)
      return E_OUTOFMEMORY;
    dwRetVal = ::GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST|GAA_FLAG_SKIP_DNS_SERVER|
                                      GAA_FLAG_SKIP_FRIENDLY_NAME, NULL, cIpAddrBuffer.Get(), &dwBufLen);
    if (dwRetVal != ERROR_BUFFER_OVERFLOW)
      break;
  }
  if (dwRetVal != NO_ERROR)
    return MX_HRESULT_FROM_WIN32(dwRetVal);
  //enum addresses
  nIpV4InsertPos = 0;
  for (lpCurrAdapter=cIpAddrBuffer.Get(); lpCurrAdapter!=NULL; lpCurrAdapter=lpCurrAdapter->Next)
  {
    if (lpCurrAdapter->PhysicalAddressLength == 0)
      continue;
    if (lpCurrAdapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
      continue;
    if (lpCurrAdapter->Description[0] == L'V')
      continue; //VirtualBox VMnet
    if (MX::StrFindW(lpCurrAdapter->Description, L"loopback", FALSE, TRUE) != NULL)
      continue;
    for (lpCurrUnicastAddress=lpCurrAdapter->FirstUnicastAddress; lpCurrUnicastAddress!=NULL;
         lpCurrUnicastAddress=lpCurrUnicastAddress->Next)
    {
      if ((lpCurrUnicastAddress->Flags & IP_ADAPTER_ADDRESS_DNS_ELIGIBLE) == 0)
        continue;
      if ((lpCurrUnicastAddress->Flags & IP_ADAPTER_ADDRESS_TRANSIENT) != 0)
        continue;
      switch (lpCurrUnicastAddress->Address.lpSockaddr->sa_family)
      {
        case AF_INET:
          if ((nFlags & LocalIpAddressesFlagsDontAddIpV4) != 0)
            break;
          u.lpAddrV4 =  (sockaddr_in*)(lpCurrUnicastAddress->Address.lpSockaddr);
          //ignore zero & localhost
          if (u.lpAddrV4->sin_addr.S_un.S_un_b.s_b2 == 0 && u.lpAddrV4->sin_addr.S_un.S_un_b.s_b3 == 0)
          {
            if ((u.lpAddrV4->sin_addr.S_un.S_un_b.s_b1 == 0 && u.lpAddrV4->sin_addr.S_un.S_un_b.s_b4 == 0) ||
                (u.lpAddrV4->sin_addr.S_un.S_un_b.s_b1 == 127 && u.lpAddrV4->sin_addr.S_un.S_un_b.s_b4 == 1))
            {
              break;
            }
          }
          //add
          hRes = FormatIpAddress(cStrTempW, u.lpAddr);
          if (FAILED(hRes))
            return hRes;
          if (cStrListW.InsertElementAt((LPWSTR)cStrTempW, nIpV4InsertPos) == FALSE)
            return E_OUTOFMEMORY;
          cStrTempW.Detach();
          nIpV4InsertPos++;
          break;

        case AF_INET6:
          if ((nFlags & LocalIpAddressesFlagsDontAddIpV6) != 0)
            break;
          u.lpAddrV6 =  (SOCKADDR_IN6_W2KSP1*)(lpCurrUnicastAddress->Address.lpSockaddr);
          //ignore zero & localhost
          if (u.lpAddrV6->sin6_addr.u.Word[0] == 0 && u.lpAddrV6->sin6_addr.u.Word[1] == 0 &&
              u.lpAddrV6->sin6_addr.u.Word[2] == 0 && u.lpAddrV6->sin6_addr.u.Word[3] == 0 &&
              u.lpAddrV6->sin6_addr.u.Word[4] == 0 && u.lpAddrV6->sin6_addr.u.Word[5] == 0 &&
              u.lpAddrV6->sin6_addr.u.Word[6] == 0 && u.lpAddrV6->sin6_addr.u.Word[7] < 2)
          {
            break;
          }
          //ignore local
          if (u.lpAddrV6->sin6_addr.u.Word[0] >= 0xFE80 && u.lpAddrV6->sin6_addr.u.Word[1] == 0xFEBF)
            break;
          //ignore special use
          if (u.lpAddrV6->sin6_addr.u.Word[0] == 2001 && u.lpAddrV6->sin6_addr.u.Word[1] == 0)
            break;
          //add
          hRes = FormatIpAddress(cStrTempW, u.lpAddr);
          if (FAILED(hRes))
            return hRes;
          if (cStrListW.AddElement((LPWSTR)cStrTempW) == FALSE)
            return E_OUTOFMEMORY;
          cStrTempW.Detach();
          break;
      }
    }
  }

  if ((nFlags & LocalIpAddressesFlagsDontAddNetbiosName) == 0)
  {
    hRes = _GetComputerNameEx(ComputerNameDnsFullyQualified, cStrTempW);
    if (FAILED(hRes))
      return hRes;
    if (cStrTempW.IsEmpty() == FALSE)
    {
      if (cStrListW.InsertElementAt((LPWSTR)cStrTempW, 0) == FALSE)
        return E_OUTOFMEMORY;
      cStrTempW.Detach();
    }
  }
  //done
  return (cStrListW.GetCount() > 0) ? S_OK : MX_E_NotFound;
}

HRESULT FormatIpAddress(_Out_ MX::CStringW &cStrW, _In_ PSOCKADDR_INET lpAddr)
{
  SIZE_T nIdx;

  cStrW.Empty();
  if (lpAddr == NULL)
    return E_POINTER;

  switch (lpAddr->si_family)
  {
    case AF_INET:
      if (cStrW.Format(L"%lu.%lu.%lu.%lu", lpAddr->Ipv4.sin_addr.S_un.S_un_b.s_b1,
                       lpAddr->Ipv4.sin_addr.S_un.S_un_b.s_b2, lpAddr->Ipv4.sin_addr.S_un.S_un_b.s_b3,
                       lpAddr->Ipv4.sin_addr.S_un.S_un_b.s_b4) == FALSE)
      {
        return E_OUTOFMEMORY;
      }
      break;

    case AF_INET6:
      if (cStrW.CopyN(L"[", 1) == FALSE)
        return E_OUTOFMEMORY;
      for (nIdx=0; nIdx<8; nIdx++)
      {
        if (lpAddr->Ipv6.sin6_addr.u.Word[nIdx] == 0)
          break;
        if (cStrW.AppendFormat(L"%04X", lpAddr->Ipv6.sin6_addr.u.Word[nIdx]) == FALSE)
          return E_OUTOFMEMORY;
        if (nIdx < 8)
        {
          if (cStrW.ConcatN(L":", 1) == FALSE)
            return E_OUTOFMEMORY;
        }
      }
      if (nIdx < 8)
      {
        if (cStrW.ConcatN(L"::", 2) == FALSE)
          return E_OUTOFMEMORY;
        while (nIdx < 8 && lpAddr->Ipv6.sin6_addr.u.Word[nIdx] == 0)
          nIdx++;
        while (nIdx < 7)
        {
          if (cStrW.AppendFormat(L"%04X:", lpAddr->Ipv6.sin6_addr.u.Word[nIdx]) == FALSE)
            return E_OUTOFMEMORY;
          nIdx++;
        }
        if (nIdx < 8)
        {
          if (cStrW.AppendFormat(L"%04X", lpAddr->Ipv6.sin6_addr.u.Word[nIdx]) == FALSE)
            return E_OUTOFMEMORY;
        }
      }
      if (cStrW.ConcatN(L"]", 1) == FALSE)
        return E_OUTOFMEMORY;
      break;

    default:
      return MX_E_Unsupported;
  }
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

HRESULT IsMsiExecProcess(_In_ HANDLE hProc)
{
  static WCHAR szSystem32MsiExecW[] = L"System32\\msiexec.exe";
#if defined(_M_X64)
  static WCHAR szSysWow64MsiExecW[] = L"SysWow64\\msiexec.exe";
#endif //_M_X64
  MX::CStringW cStrProcNameW, cStrWinDirW;
  DWORD dwSize, dwRet;
  HRESULT hRes;

  for (dwSize=256; dwSize<=32768; dwSize<<=1)
  {
    if (cStrProcNameW.EnsureBuffer((SIZE_T)dwSize+4) == FALSE)
      return E_OUTOFMEMORY;
    dwRet = ::GetProcessImageFileNameW(hProc, (LPWSTR)cStrProcNameW, dwSize);
    if (dwRet == 0)
    {
      hRes = MX_HRESULT_FROM_LASTERROR();
      return (FAILED(hRes)) ? hRes : E_FAIL;
    }
    if (dwRet < dwSize-2)
      break;
  }
  if (dwSize > 32768)
    return E_OUTOFMEMORY;
  ((LPWSTR)cStrProcNameW)[dwRet] = 0;
  cStrProcNameW.Refresh();

  hRes = FileRoutinesLite::ResolveSymbolicLink(cStrProcNameW);
  if (FAILED(hRes))
    return hRes;

  hRes = FileRoutinesLite::GetWindowsPath(cStrWinDirW);
  if (SUCCEEDED(hRes))
    FileRoutinesLite::ConvertToNative(cStrWinDirW);
  if (FAILED(hRes))
    return hRes;

  //check
  if (cStrProcNameW.GetLength() >= cStrWinDirW.GetLength() &&
      MX::StrNCompareW((LPCWSTR)cStrProcNameW, (LPCWSTR)cStrWinDirW, cStrWinDirW.GetLength(), TRUE) == 0)
  {
    if (MX::StrCompareW((LPCWSTR)cStrProcNameW + cStrWinDirW.GetLength(), szSystem32MsiExecW, TRUE) == 0)
      return S_OK;
#if defined(_M_X64)
    if (MX::StrCompareW((LPCWSTR)cStrProcNameW + cStrWinDirW.GetLength(), szSysWow64MsiExecW, TRUE) == 0)
      return S_OK;
#endif //_M_X64
  }
  return S_FALSE;
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
    if (_wcsnicmp(sW, L"\\Device\\MUP\\", 12) == 0)
    {
      cStrPathW.Delete(1, 10);
      return S_OK;
    }
    if (_wcsnicmp(sW, L"\\Device\\LanmanRedirector\\", 25) == 0)
    {
      cStrPathW.Delete(1, 23);
      return S_OK;
    }
    if (wcsncmp(sW, L"\\\\?\\", 4) == 0 || wcsncmp(sW, L"\\??\\", 4) == 0)
      cStrPathW.Delete(0, 4);
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
        if (_wcsnicmp(sW, szNameW, nNameLen) == 0 && (sW[nNameLen] == 0 || sW[nNameLen] == L'\\'))
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

HRESULT ExpandEnvStrings(_Inout_ MX::CStringW &cStrW)
{
  MX::CStringW cStrTempW;
  DWORD dw;
  SIZE_T nLen;
  HRESULT hRes;

  nLen = cStrW.GetLength() << 1;
  if (nLen == 0)
    return S_OK;
  while (nLen < 65536)
  {
    if (cStrTempW.EnsureBuffer(nLen + 1) == FALSE)
      return E_OUTOFMEMORY;
    dw = ::ExpandEnvironmentStringsW((LPCWSTR)cStrW, (LPWSTR)cStrTempW, (DWORD)nLen);
    if (dw != 0)
    {
      ((LPWSTR)cStrTempW)[nLen] = 0;
      cStrTempW.Refresh();
      cStrW.Attach(cStrTempW.Detach());
      return S_OK;
    }
    hRes = MX_HRESULT_FROM_LASTERROR();
    if (hRes != MX_E_BufferOverflow && hRes != HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER))
      return hRes;
  }
  return MX_E_BufferOverflow;
}

//NOTE: Based on JODD's source code. BSD-License
//      Copyright (c) 2003-2018, Jodd Team All rights reserved.
BOOL WildcardMatch(_In_ LPCWSTR szTextW, _In_ SIZE_T nTextLen, _In_ LPCWSTR szPatternW, _In_ SIZE_T nPatternLen)
{
  LPCWSTR szPatternEndW, szTextEndW;

  if (nTextLen == (SIZE_T)-1)
    nTextLen = MX::StrLenW(szTextW);
  if (nPatternLen == (SIZE_T)-1)
    nPatternLen = MX::StrLenW(szPatternW);
  if (nPatternLen == 1 && *szPatternW == L'*')
    return TRUE; // speed-up

  szPatternEndW = szPatternW + nPatternLen;
  szTextEndW = szTextW + nTextLen;

  for (;;)
  {
    //check if end of string and/or pattern occurred
    if (szTextW >= szTextEndW) {
      //end of string still may have pending '*' in pattern
      while (szPatternW < szPatternEndW && *szPatternW == L'*')
        szPatternW++;
      return (szPatternW >= szPatternEndW) ? TRUE : FALSE;
    }
    if (szPatternW >= szPatternEndW)
      break; //end of pattern, but not end of the string

             //perform logic
    if (*szPatternW == L'?')
    {
      szTextW++;
      szPatternW++;
      continue;
    }
    if (*szPatternW == L'*')
    {
      LPCWSTR t;

      while (szPatternW < szPatternEndW && *szPatternW == L'*')
        szPatternW++; //skip contiguous '*'

                      //find recursively if there is any substring from the end of the
                      //line that matches the rest of the pattern !!!
      for (t = szTextEndW; t >= szTextW; t--)
      {
        if (WildcardMatch(t, (SIZE_T)(szTextEndW - t), szPatternW, (SIZE_T)(szPatternEndW - szPatternW)) != FALSE)
          return TRUE;
      }
      break;
    }

    //check if pattern char and string char are equals
    if (MX::CharToUpperW(*szTextW) != MX::CharToUpperW(*szPatternW))
      break;

    //everything matches for now, continue
    szTextW++;
    szPatternW++;
  }
  return FALSE;
}

BOOL String2Guid(_Out_ GUID &sGuid, _In_z_ LPCSTR szGuidA)
{
  DWORD i, dwVal;

  MX::MemSet(&sGuid, 0, sizeof(sGuid));
  if (szGuidA == NULL)
  {
err_badformat:
    MX::MemSet(&sGuid, 0, sizeof(sGuid));
    return FALSE;
  }
  if (*szGuidA == '{')
    szGuidA++;
  for (i=0; i<36; i++,szGuidA++)
  {
    switch (i)
    {
      case 8:
      case 13:
      case 18:
      case 23:
        if (*szGuidA != '-')
          goto err_badformat;
        break;

      case 14: //1-5
        if (*szGuidA < '1' || *szGuidA > '5')
          goto err_badformat;
        dwVal = (DWORD)(*szGuidA - '0');
        goto set_value;

      case 19: //8-A
        if (*szGuidA >= '8' && *szGuidA <= '9')
          dwVal = (DWORD)(*szGuidA - '0');
        else if (*szGuidA >= 'A' && *szGuidA <= 'B')
          dwVal = (DWORD)(*szGuidA - 'A') + 10;
        else if (*szGuidA >= 'a' && *szGuidA <= 'b')
          dwVal = (DWORD)(*szGuidA - 'a') + 10;
        else
          goto err_badformat;
        goto set_value;

      default:
        if (*szGuidA >= '0' && *szGuidA <= '9')
          dwVal = (DWORD)(*szGuidA - '0');
        else if (*szGuidA >= 'A' && *szGuidA <= 'F')
          dwVal = (DWORD)(*szGuidA - 'A') + 10;
        else if (*szGuidA >= 'a' && *szGuidA <= 'f')
          dwVal = (DWORD)(*szGuidA - 'a') + 10;
        else
          goto err_badformat;

set_value:
        if (i < 8)
          sGuid.Data1 |= dwVal << ((7 - i) << 2);
        else if (i < 13)
          sGuid.Data2 |= (USHORT)dwVal << ((12 - i) << 2);
        else if (i < 18)
          sGuid.Data3 |= (USHORT)dwVal << ((17 - i) << 2);
        else if (i < 21)
          sGuid.Data4[0] |= (BYTE)dwVal << ((20 - i) << 2);
        else if (i < 23)
          sGuid.Data4[1] |= (BYTE)dwVal << ((22 - i) << 2);
        else
          sGuid.Data4[2 + ((i - 24) >> 1)] |= (BYTE)dwVal << ((1-(i & 1)) << 2);
        break;
    }
  }
  if (*szGuidA == '}')
    szGuidA++;
  if (*szGuidA != 0)
    goto err_badformat;
  //done
  return TRUE;
}

BOOL String2Guid(_Out_ GUID &sGuid, _In_z_ LPCWSTR szGuidW)
{
  CHAR szBufA[64];
  SIZE_T i;

  MX::MemSet(&sGuid, 0, sizeof(sGuid));
  for (i = 0; i < MX_ARRAYLEN(szBufA) - 1 && szGuidW[i] != 0; i++)
  {
    if ((szGuidW[i] >= L'0' && szGuidW[i] <= L'9') ||
        (szGuidW[i] >= L'A' && szGuidW[i] <= L'F') ||
        (szGuidW[i] >= L'a' && szGuidW[i] <= L'f') ||
        szGuidW[i] == L'{' || szGuidW[i] == L'}' || szGuidW[i] == L'-')
    {
      szBufA[i] = (char)(BYTE)(USHORT)szGuidW[i];
    }
    else
    {
      return FALSE;
    }
  }
  if (i >= MX_ARRAYLEN(szBufA) - 1)
    return FALSE;
  szBufA[i] = 0;
  return String2Guid(sGuid, szBufA);
}

HRESULT SelfDeleteApp()
{
  MX::CStringW cStrTempW, cStrExeNameW;
  HRESULT hRes;

  hRes = FileRoutinesLite::GetAppFileName(cStrExeNameW);
  if (SUCCEEDED(hRes))
    hRes = FileRoutinesLite::GetWindowsSystemPath(cStrTempW);
  if (SUCCEEDED(hRes))
  {
    if (cStrTempW.InsertN(L"\"", 0, 1) == FALSE ||
        cStrTempW.Concat(L"CMD.EXE\" /C PING 127.0.0.1 -n 5 & DEL \"") == FALSE ||
        cStrTempW.ConcatN((LPCWSTR)cStrExeNameW, cStrExeNameW.GetLength()) == FALSE ||
        cStrTempW.ConcatN("\"", 1) == FALSE)
    {
      hRes = E_OUTOFMEMORY;
    }
  }
  if (SUCCEEDED(hRes))
  {
    STARTUPINFOW sSiW;
    PROCESS_INFORMATION sPi;

    MX::MemSet(&sSiW, 0, sizeof(sSiW));
    sSiW.cb = (DWORD)sizeof(sSiW);
    MX::MemSet(&sPi, 0, sizeof(sPi));
    if (::CreateProcessW(NULL, (LPWSTR)cStrTempW, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &sSiW,
                         &sPi) != FALSE)
    {
      ::CloseHandle(sPi.hThread);
      ::CloseHandle(sPi.hProcess);
    }
    else
    {
      hRes = MX_HRESULT_FROM_LASTERROR();
    }
  }
  //done
  return hRes;
}

}; //HelperRoutines

//-----------------------------------------------------------

static HRESULT GetTokenMembershipType(_In_ HANDLE hToken, _Inout_ HelperRoutines::eGetMembershipType &nType)
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
    nType = HelperRoutines::MembershipTypeRunningInSystemAccount;
    hRes = S_OK;
    goto done;
  }
  //on Vista+, check if we are elevated
  if (HelperRoutines::IsWindowsVistaOrLater() != FALSE)
  {
    TOKEN_ELEVATION sTokElev;
    TOKEN_ELEVATION_TYPE sTokElevType;

    MX::MemSet(&sTokElev, 0, sizeof(sTokElev));
    if (::GetTokenInformation(hTokenToCheck, TokenElevation, &sTokElev, (DWORD)sizeof(sTokElev), &dw) != FALSE &&
        sTokElev.TokenIsElevated != 0)
    {
      nType = HelperRoutines::MembershipTypeRunningOnAdministratorsGroupAndElevated;
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
      nType = HelperRoutines::MembershipTypeRunningOnAdministratorsGroup;
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
      nType = HelperRoutines::MembershipTypeRunningOnAdministratorsGroupAndElevated;
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
