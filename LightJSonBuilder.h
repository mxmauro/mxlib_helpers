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
#ifndef _MXLIBHLP_LIGHTJSON_BUILDER_H
#define _MXLIBHLP_LIGHTJSON_BUILDER_H

#include "Defines.h"
#include <Windows.h>
#include <ArrayList.h>
#include <Strings\Strings.h>
#include <winternl.h>

//-----------------------------------------------------------

namespace MX {

class CLightJSonBuilder : public CBaseMemObj
{
public:
  CLightJSonBuilder();

  VOID Reset();

  BOOL AddObject(_In_opt_z_ LPCSTR szNameA = NULL);
  BOOL CloseObject();

  BOOL AddArray(_In_opt_z_ LPCSTR szNameA = NULL);
  BOOL CloseArray();

  BOOL AddObjectString(_In_z_ LPCSTR szNameA, _In_ LPCWSTR szValueW, _In_opt_ SIZE_T nValueLen = (SIZE_T)-1);
  BOOL AddObjectFormattedString(_In_z_ LPCSTR szNameA, _Printf_format_string_ LPCWSTR szFormatW, ...);
  BOOL AddObjectString(_In_z_ LPCSTR szNameA, _In_ PUNICODE_STRING Value);
  BOOL AddObjectLong(_In_z_ LPCSTR szNameA, _In_ LONG nValue);
  BOOL AddObjectULong(_In_z_ LPCSTR szNameA, _In_ ULONG nValue, _In_opt_ BOOL bAsHexa = FALSE);
  //IMPORTANT: Stored as strings because ECMA-262 Sec 8.5 states max number is �9007199254740990
  BOOL AddObjectLongLong(_In_z_ LPCSTR szNameA, _In_ LONGLONG nValue);
  //IMPORTANT: Stored as strings because ECMA-262 Sec 8.5 states max number is �9007199254740990
  BOOL AddObjectULongLong(_In_z_ LPCSTR szNameA, _In_ ULONGLONG nValue, _In_opt_ BOOL bAsHexa = FALSE);
  BOOL AddObjectObject(_In_z_ LPCSTR szNameA, _In_ CLightJSonBuilder &cSrc);

  BOOL AddArrayString(_In_ LPCWSTR szValueW, _In_opt_ SIZE_T nValueLen = (SIZE_T)-1);
  BOOL AddArrayFormattedString(_Printf_format_string_ LPCWSTR szFormatW, ...);
  BOOL AddArrayLong(_In_ LONG nValue);
  BOOL AddArrayULong(_In_ ULONG nValue, _In_opt_ BOOL bAsHexa = FALSE);
  //IMPORTANT: Stored as strings because ECMA-262 Sec 8.5 states max number is �9007199254740990
  BOOL AddArrayLongLong(_In_ LONGLONG nValue);
  //IMPORTANT: Stored as strings because ECMA-262 Sec 8.5 states max number is �9007199254740990
  BOOL AddArrayULongLong(_In_ ULONGLONG nValue, _In_opt_ BOOL bAsHexa = FALSE);

  BOOL AddArrayObject(_In_ CLightJSonBuilder &cSrc);

  operator LPCSTR() const
    {
    MX_ASSERT(aNestedTypes.GetCount() == 0); //ensure is closed
    return (LPCSTR)cStrJsonA;
    };

  static BOOL EscapeString(_Inout_ CStringA &cStrA, _In_ LPCWSTR szValueW, _In_ SIZE_T nValueLen,
                           _In_opt_ BOOL bAppend = FALSE);

private:
  BOOL AddEscapedString(_In_ LPCWSTR szValueW, _In_ SIZE_T nValueLen);

private:
  CStringA cStrJsonA;
  TArrayList<BYTE> aNestedTypes;
  BOOL bIsFirstItem;
};

}; //namespace MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_LIGHTJSON_BUILDER_H
