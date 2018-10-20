/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#ifndef _MXLIBHLP_PROCESS_H
#define _MXLIBHLP_PROCESS_H

#include <Defines.h>
#include <Strings\Strings.h>
#include <ArrayList.h>

//-----------------------------------------------------------

namespace MXHelpers {

typedef enum {
  TokenMembershipTypeLimitedUser,
  TokenMembershipTypeRunningInSystemAccount,
  TokenMembershipTypeRunningOnAdministratorsGroup,
  TokenMembershipTypeRunningOnAdministratorsGroupAndElevated
} eTokenGetMembershipType;

}; //MXHelpers

//-----------------------------------------------------------

namespace MXHelpers {

HRESULT ResolveChildProcessFileName(_Inout_ MX::CStringW &cStrFullNameW, _In_ LPCWSTR szApplicationNameW,
                                    _In_ LPCWSTR szCommandLineW);

HRESULT QueryEnvironmentVariable(_In_z_ LPCWSTR szVarNameW, _Inout_ MX::CStringW &cStrDestW);

HRESULT _ExpandEnvironmentStrings(_Inout_ MX::CStringW &cStrW);

HRESULT GetProcessMembershipType(_Out_ eTokenGetMembershipType &nType);
HRESULT GetThreadMembershipType(_Out_ eTokenGetMembershipType &nType);
HRESULT GetTokenMembershipType(_In_ HANDLE hToken, _Out_ eTokenGetMembershipType &nType);

HRESULT EnablePrivilege(_In_z_ LPCWSTR szPrivilegeW);

}; //MXHelpers

//-----------------------------------------------------------

#endif //_MXLIBHLP_PROCESS_H
