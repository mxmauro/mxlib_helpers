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
#ifndef _MXLIBHLP_MISCELLANEOUS_H
#define _MXLIBHLP_MISCELLANEOUS_H

#include <Defines.h>
#include <Strings\Strings.h>

//-----------------------------------------------------------

namespace MX {

namespace Misc {

BOOL WildcardMatch(_In_ LPCWSTR szTextW, _In_ SIZE_T nTextLen, _In_ LPCWSTR szPatternW, _In_ SIZE_T nPatternLen);

BOOL String2Guid(_Out_ GUID &sGuid, _In_z_ LPCSTR szGuidA);
BOOL String2Guid(_Out_ GUID &sGuid, _In_z_ LPCWSTR szGuidW);

HRESULT ExecuteApp(_In_z_ LPCWSTR szCmdLineW, _In_ DWORD dwAfterSeconds = 5);
HRESULT SelfDeleteApp(_In_ DWORD dwAfterSeconds = 5);

}; //namespace Misc

}; //namespace MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_MISCELLANEOUS_H
