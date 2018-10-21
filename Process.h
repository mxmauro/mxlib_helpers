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

namespace MX {

namespace Process {

typedef enum {
  TokenMembershipTypeLimitedUser,
  TokenMembershipTypeRunningInSystemAccount,
  TokenMembershipTypeRunningOnAdministratorsGroup,
  TokenMembershipTypeRunningOnAdministratorsGroupAndElevated
} eTokenGetMembershipType;

}; //Process

}; //MX

//-----------------------------------------------------------

namespace MX {

namespace Process {

HRESULT ResolveChildProcessFileName(_Inout_ CStringW &cStrFullNameW, _In_ LPCWSTR szApplicationNameW,
                                    _In_ LPCWSTR szCommandLineW);

HRESULT QueryEnvironmentVariable(_In_z_ LPCWSTR szVarNameW, _Inout_ CStringW &cStrDestW);

HRESULT _ExpandEnvironmentStrings(_Inout_ CStringW &cStrW);

HRESULT GetProcessMembershipType(_Out_ eTokenGetMembershipType &nType);
HRESULT GetThreadMembershipType(_Out_ eTokenGetMembershipType &nType);
HRESULT GetTokenMembershipType(_In_ HANDLE hToken, _Out_ eTokenGetMembershipType &nType);

HRESULT EnablePrivilege(_In_z_ LPCWSTR szPrivilegeW);

}; //Process

}; //MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_PROCESS_H
