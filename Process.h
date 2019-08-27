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
