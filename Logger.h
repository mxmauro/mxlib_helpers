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
#ifndef _MXLIBHLP_EVENT_LOGGER_H
#define _MXLIBHLP_EVENT_LOGGER_H

#include <Defines.h>
#include <Windows.h>
#include <AutoHandle.h>
#include <Strings\Strings.h>

//-----------------------------------------------------------

namespace MX {

namespace EventLogger {

HRESULT Initialize(_In_z_ LPCWSTR szApplicationNameW, _In_z_ LPCWSTR szModuleNameW, _In_z_ LPCWSTR szRegistryKeyW,
                   _In_z_ LPCWSTR szRegistryValueW, _In_ DWORD dwDefaultKeepDays);

HRESULT Log(_Printf_format_string_ LPCWSTR szFormatW, ...);
HRESULT LogIfError(_In_ HRESULT hResError, _Printf_format_string_ LPCWSTR szFormatW, ...);
HRESULT LogAlways(_In_ HRESULT hResError, _Printf_format_string_ LPCWSTR szFormatW, ...);
HRESULT LogRaw(_In_z_ LPCWSTR szTextW);

HRESULT GetLogFolder(_Out_ CStringW &cStrLogFolderW, _In_opt_ BOOL bCreate = FALSE);
HRESULT GetLogFileName(_Out_ CStringW &cStrFileNameW, _In_opt_ BOOL bCreateFolder = FALSE);

}; //namespace EventLogger

}; //namespace MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_EVENT_LOGGER_H
