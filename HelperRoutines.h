/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#ifndef _HELPERS_ROUTINES_H
#define _HELPERS_ROUTINES_H

#include <Defines.h>
#include <Strings\Strings.h>
#include <ArrayList.h>
#include <WinSock2.h>
#include <ws2ipdef.h>

//-----------------------------------------------------------

namespace HelperRoutines {

typedef enum {
  LocalIpAddressesFlagsDontAddIpV4        = 1,
  LocalIpAddressesFlagsDontAddIpV6        = 2,
  LocalIpAddressesFlagsDontAddNetbiosName = 4
} eGetLocalIpAddressesFlags;

typedef enum {
  MembershipTypeLimitedUser,
  MembershipTypeRunningInSystemAccount,
  MembershipTypeRunningOnAdministratorsGroup,
  MembershipTypeRunningOnAdministratorsGroupAndElevated
} eGetMembershipType;

//-----------------------------------------------------------

WORD GetDaysInMonth(_In_ WORD wMonth, _In_ WORD wYear);

HRESULT GetProcessMembershipType(_Out_ eGetMembershipType &nType);
HRESULT GetThreadMembershipType(_Out_ eGetMembershipType &nType);

HRESULT GetCurrentProcessUserSid(_Inout_ MX::CStringW &cStrUserSidW);

BOOL IsWindowsVistaOrLater();

HRESULT GetOpSystemInfo(_Out_ MX::CStringW &cStrOpSystemW);

HRESULT EnableProcessPrivileges(_In_z_ LPCWSTR szPrivilegeW);

HRESULT GetLocalIpAddresses(_Out_ MX::TArrayListWithFree<LPCWSTR> &cStrListW, _In_ int nFlags);
HRESULT FormatIpAddress(_Out_ MX::CStringW &cStrW, _In_ PSOCKADDR_INET lpAddr);

HRESULT _GetComputerNameEx(_In_ COMPUTER_NAME_FORMAT NameType, _Out_ MX::CStringW &cStrNameW);

VOID RegisterAppInRestartManager();

HRESULT IsMsiExecProcess(_In_ HANDLE hProc);

HRESULT DeviceName2DosName(_Inout_ MX::CStringW &cStrPathW);

HRESULT ExpandEnvStrings(_Inout_ MX::CStringW &cStrW);

BOOL WildcardMatch(_In_ LPCWSTR szTextW, _In_ SIZE_T nTextLen, _In_ LPCWSTR szPatternW, _In_ SIZE_T nPatternLen);

BOOL String2Guid(_Out_ GUID &sGuid, _In_z_ LPCSTR szGuidA);
BOOL String2Guid(_Out_ GUID &sGuid, _In_z_ LPCWSTR szGuidW);

HRESULT SelfDeleteApp();

}; //HelperRoutines

//-----------------------------------------------------------

#endif //_HELPERS_ROUTINES_H
