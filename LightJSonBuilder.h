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
#include <AutoPtr.h>
#include <ArrayList.h>
#include <Strings\Strings.h>
#include <winternl.h>

//-----------------------------------------------------------

namespace MX {

class CLightJSonBuilder : public CBaseMemObj, public CNonCopyableObj
{
public:
  CLightJSonBuilder();

  VOID Reset();

  BOOL AddObject(_In_opt_z_ LPCSTR szNameA = NULL);
  BOOL CloseObject();

  BOOL AddArray(_In_opt_z_ LPCSTR szNameA = NULL);
  BOOL CloseArray();

  BOOL AddObjectBoolean(_In_z_ LPCSTR szNameA, _In_ BOOL bValue);
  BOOL AddObjectString(_In_z_ LPCSTR szNameA, _In_ LPCSTR szValueA, _In_opt_ SIZE_T nValueLen = (SIZE_T)-1);
  BOOL AddObjectFormattedString(_In_z_ LPCSTR szNameA, _Printf_format_string_ LPCSTR szFormatA, ...);
  BOOL AddObjectFormattedStringV(_In_z_ LPCSTR szNameA, _Printf_format_string_ LPCSTR szFormatA, _In_ va_list argptr);
  BOOL AddObjectString(_In_z_ LPCSTR szNameA, _In_ LPCWSTR szValueW, _In_opt_ SIZE_T nValueLen = (SIZE_T)-1);
  BOOL AddObjectFormattedString(_In_z_ LPCSTR szNameA, _Printf_format_string_ LPCWSTR szFormatW, ...);
  BOOL AddObjectFormattedStringV(_In_z_ LPCSTR szNameA, _Printf_format_string_ LPCWSTR szFormatW, _In_ va_list argptr);
  BOOL AddObjectString(_In_z_ LPCSTR szNameA, _In_ PUNICODE_STRING Value);
  BOOL AddObjectLong(_In_z_ LPCSTR szNameA, _In_ LONG nValue);
  BOOL AddObjectULong(_In_z_ LPCSTR szNameA, _In_ ULONG nValue, _In_opt_ BOOL bAsHexa = FALSE);
  //IMPORTANT: ECMA-262 Sec 8.5 states max number is 9007199254740990 so, if larger, it is recommended to store it as string
  //           to maximize compatibility, mainly, with javascript.
  BOOL AddObjectLongLong(_In_z_ LPCSTR szNameA, _In_ LONGLONG nValue);
  BOOL AddObjectULongLong(_In_z_ LPCSTR szNameA, _In_ ULONGLONG nValue);
  BOOL AddObjectObject(_In_z_ LPCSTR szNameA, _In_ CLightJSonBuilder &cSrc);

  BOOL AddArrayBoolean(_In_ BOOL bValue);
  BOOL AddArrayString(_In_ LPCSTR szValueA, _In_opt_ SIZE_T nValueLen = (SIZE_T)-1);
  BOOL AddArrayFormattedString(_Printf_format_string_ LPCSTR szFormatA, ...);
  BOOL AddArrayFormattedStringV(_Printf_format_string_ LPCSTR szFormatA, _In_ va_list argptr);
  BOOL AddArrayString(_In_ LPCWSTR szValueW, _In_opt_ SIZE_T nValueLen = (SIZE_T)-1);
  BOOL AddArrayFormattedString(_Printf_format_string_ LPCWSTR szFormatW, ...);
  BOOL AddArrayFormattedStringV(_Printf_format_string_ LPCWSTR szFormatW, _In_ va_list argptr);
  BOOL AddArrayLong(_In_ LONG nValue);
  BOOL AddArrayULong(_In_ ULONG nValue, _In_opt_ BOOL bAsHexa = FALSE);
  //IMPORTANT: ECMA-262 Sec 8.5 states max number is 9007199254740990 so, if larger, it is recommended to store it as string
  //           to maximize compatibility, mainly, with javascript.
  BOOL AddArrayLongLong(_In_ LONGLONG nValue);
  BOOL AddArrayULongLong(_In_ ULONGLONG nValue);
  BOOL AddArrayObject(_In_ CLightJSonBuilder &cSrc);

  BOOL AddRaw(_In_ LPCSTR szStrA, _In_opt_ SIZE_T nStrLen = (SIZE_T)-1);
  BOOL AddRaw(_In_ LPCWSTR szStrW, _In_opt_ SIZE_T nStrLen = (SIZE_T)-1);

  operator LPCSTR() const
    {
    LPCSTR sA;

    MX_ASSERT(aNestedTypes.GetCount() == 0); //ensure is closed
    sA = (LPCSTR)(const_cast<TAutoFreePtr<BYTE>&>(aBuffer).Get());
    return (sA != NULL) ? sA : "";
    };

  SIZE_T GetLength() const
    {
    return nBufferLen;
    };

  LPCSTR Detach()
    {
    LPCSTR sA;

    MX_ASSERT(aNestedTypes.GetCount() == 0); //ensure is closed
    sA = (LPCSTR)(aBuffer.Detach());
    Reset();
    return sA;
    };

  //NOTE: Assume value is in UTF-8 format
  static BOOL EscapeString(_Inout_ CStringA &cStrA, _In_ LPCSTR szStrA, _In_ SIZE_T nStrLen, _In_opt_ BOOL bAppend = FALSE);
  static BOOL EscapeString(_Inout_ CStringA &cStrA, _In_ LPCWSTR szStrW, _In_ SIZE_T nStrLen, _In_opt_ BOOL bAppend = FALSE);

private:
  BOOL AddToBuffer(_In_ LPCSTR szStrA, _In_ SIZE_T nStrLen);
  BOOL AddEscapeStringToBuffer(_In_ LPCSTR szStrA, _In_ SIZE_T nStrLen);
  BOOL AddEscapeStringToBuffer(_In_ LPCWSTR szStrW, _In_ SIZE_T nStrLen);

private:
  TAutoFreePtr<BYTE> aBuffer;
  SIZE_T nBufferLen{ 0 };
  SIZE_T nBufferSize{ 0 };
  TArrayList<BYTE> aNestedTypes;
  BOOL bIsFirstItem{ TRUE };
};

}; //namespace MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_LIGHTJSON_BUILDER_H
