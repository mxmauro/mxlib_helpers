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
#include "LightJSonBuilder.h"
#include <Strings\Utf8.h>
#include <stdio.h>

#define _IS_OBJECT 0
#define _IS_ARRAY  1

//-----------------------------------------------------------

namespace MX {

CLightJSonBuilder::CLightJSonBuilder() : CBaseMemObj(), CNonCopyableObj()
{
  bIsFirstItem;
  return;
}

VOID CLightJSonBuilder::Reset()
{
  aBuffer.Reset();
  nBufferLen = 0;
  nBufferSize = 0;
  aNestedTypes.RemoveAllElements();
  bIsFirstItem = TRUE;
  return;
}

BOOL CLightJSonBuilder::AddObject(_In_opt_z_ LPCSTR szNameA)
{
  BOOL bNeedsName;

  //check the parent object type
  bNeedsName = (aNestedTypes.GetCount() > 0 && aNestedTypes[aNestedTypes.GetCount() - 1] == _IS_OBJECT) ? TRUE : FALSE;
  if (bNeedsName != FALSE)
  {
    MX_ASSERT(szNameA != NULL);
    MX_ASSERT(*szNameA != 0);
  }
  else
  {
    MX_ASSERT(szNameA == NULL);
  }

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (AddToBuffer(", ", 2) == FALSE)
      return FALSE;
  }

  //add nested object
  if (aNestedTypes.AddElement(_IS_OBJECT) == FALSE)
    return FALSE;
  bIsFirstItem = TRUE;

  //insert text
  if (bNeedsName != FALSE)
  {
    if (AddToBuffer("\"", 1) == FALSE)
      return FALSE;
    if (AddEscapeStringToBuffer(szNameA, StrLenA(szNameA)) == FALSE)
      return FALSE;
    return AddToBuffer("\": { ", 5);
  }
  return AddToBuffer("{ ", 2);
}

BOOL CLightJSonBuilder::CloseObject()
{
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_OBJECT);

  //remove nested object
  aNestedTypes.RemoveElementAt(aNestedTypes.GetCount() - 1, 1);
  bIsFirstItem = FALSE;

  //insert text
  return AddToBuffer(" }", 2);
}

BOOL CLightJSonBuilder::AddArray(_In_opt_z_ LPCSTR szNameA)
{
  BOOL bNeedsName;

  //check the parent object type
  bNeedsName = (aNestedTypes.GetCount() > 0 && aNestedTypes[aNestedTypes.GetCount() - 1] == _IS_OBJECT) ? TRUE : FALSE;
  if (bNeedsName != FALSE)
  {
    MX_ASSERT(szNameA != NULL);
    MX_ASSERT(*szNameA != 0);
  }
  else
  {
    MX_ASSERT(szNameA == NULL);
  }

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (AddToBuffer(", ", 2) == FALSE)
      return FALSE;
  }

  //add nested object
  if (aNestedTypes.AddElement(_IS_ARRAY) == FALSE)
    return FALSE;
  bIsFirstItem = TRUE;

  //insert text
  if (bNeedsName != FALSE)
  {
    if (AddToBuffer("\"", 1) == FALSE)
      return FALSE;
    if (AddEscapeStringToBuffer(szNameA, StrLenA(szNameA)) == FALSE)
      return FALSE;
    return AddToBuffer("\": [ ", 5);
  }
  return AddToBuffer("[ ", 2);
}

BOOL CLightJSonBuilder::CloseArray()
{
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_ARRAY);

  //remove nested object
  aNestedTypes.RemoveElementAt(aNestedTypes.GetCount() - 1, 1);
  bIsFirstItem = FALSE;

  //insert text
  return AddToBuffer(" ]", 2);
}

BOOL CLightJSonBuilder::AddObjectBoolean(_In_z_ LPCSTR szNameA, _In_ BOOL bValue)
{
  MX_ASSERT(szNameA != NULL);
  MX_ASSERT(*szNameA != 0);
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_OBJECT);

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (AddToBuffer(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  if (AddToBuffer("\"", 1) == FALSE)
    return FALSE;
  if (AddEscapeStringToBuffer(szNameA, StrLenA(szNameA)) == FALSE)
    return FALSE;
  if (bValue != FALSE)
  {
    if (AddToBuffer("\": true", 7) == FALSE)
      return FALSE;
  }
  else
  {
    if (AddToBuffer("\": false", 8) == FALSE)
      return FALSE;
  }
  return TRUE;
}

BOOL CLightJSonBuilder::AddObjectString(_In_z_ LPCSTR szNameA, _In_ LPCSTR szValueA, _In_opt_ SIZE_T nValueLen)
{
  MX_ASSERT(szNameA != NULL);
  MX_ASSERT(*szNameA != 0);
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_OBJECT);

  if (nValueLen == (SIZE_T)-1)
    nValueLen = StrLenA(szValueA);
  MX_ASSERT(szValueA != NULL || nValueLen == 0);

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (AddToBuffer(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  if (AddToBuffer("\"", 1) == FALSE)
    return FALSE;
  if (AddEscapeStringToBuffer(szNameA, StrLenA(szNameA)) == FALSE)
    return FALSE;
  if (AddToBuffer("\": \"", 4) == FALSE)
    return FALSE;
  if (AddEscapeStringToBuffer(szValueA, nValueLen) == FALSE)
    return FALSE;
  return AddToBuffer("\"", 1);
}

BOOL CLightJSonBuilder::AddObjectFormattedString(_In_z_ LPCSTR szNameA, _Printf_format_string_ LPCSTR szFormatA, ...)
{
  CStringA cStrTempA;
  va_list argptr;

  MX_ASSERT(szFormatA != NULL);

  va_start(argptr, szFormatA);
  if (cStrTempA.FormatV(szFormatA, argptr) == FALSE)
    return FALSE;
  va_end(argptr);

  //done
  return AddObjectString(szNameA, (LPCSTR)cStrTempA, cStrTempA.GetLength());
}

BOOL CLightJSonBuilder::AddObjectFormattedStringV(_In_z_ LPCSTR szNameA, _Printf_format_string_ LPCSTR szFormatA, _In_ va_list argptr)
{
  CStringA cStrTempA;

  MX_ASSERT(szFormatA != NULL);

  if (cStrTempA.FormatV(szFormatA, argptr) == FALSE)
    return FALSE;

  //done
  return AddObjectString(szNameA, (LPCSTR)cStrTempA, cStrTempA.GetLength());
}

BOOL CLightJSonBuilder::AddObjectString(_In_z_ LPCSTR szNameA, _In_ LPCWSTR szValueW, _In_opt_ SIZE_T nValueLen)
{
  MX_ASSERT(szNameA != NULL);
  MX_ASSERT(*szNameA != 0);
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_OBJECT);

  if (nValueLen == (SIZE_T)-1)
    nValueLen = StrLenW(szValueW);
  MX_ASSERT(szValueW != NULL || nValueLen == 0);

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (AddToBuffer(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  if (AddToBuffer("\"", 1) == FALSE)
    return FALSE;
  if (AddEscapeStringToBuffer(szNameA, StrLenA(szNameA)) == FALSE)
    return FALSE;
  if (AddToBuffer("\": \"", 4) == FALSE)
    return FALSE;
  if (AddEscapeStringToBuffer(szValueW, nValueLen) == FALSE)
    return FALSE;
  return AddToBuffer("\"", 1);
}

BOOL CLightJSonBuilder::AddObjectFormattedString(_In_z_ LPCSTR szNameA, _Printf_format_string_ LPCWSTR szFormatW, ...)
{
  CStringW cStrTempW;
  va_list argptr;

  MX_ASSERT(szFormatW != NULL);

  va_start(argptr, szFormatW);
  if (cStrTempW.FormatV(szFormatW, argptr) == FALSE)
    return FALSE;
  va_end(argptr);

  //done
  return AddObjectString(szNameA, (LPCWSTR)cStrTempW, cStrTempW.GetLength());
}

BOOL CLightJSonBuilder::AddObjectFormattedStringV(_In_z_ LPCSTR szNameA, _Printf_format_string_ LPCWSTR szFormatW, _In_ va_list argptr)
{
  CStringW cStrTempW;

  MX_ASSERT(szFormatW != NULL);

  if (cStrTempW.FormatV(szFormatW, argptr) == FALSE)
    return FALSE;

  //done
  return AddObjectString(szNameA, (LPCWSTR)cStrTempW, cStrTempW.GetLength());
}

BOOL CLightJSonBuilder::AddObjectString(_In_z_ LPCSTR szNameA, _In_ PUNICODE_STRING Value)
{
  MX_ASSERT(szNameA != NULL);
  MX_ASSERT(*szNameA != 0);
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_OBJECT);

  MX_ASSERT(Value != NULL);

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (AddToBuffer(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  if (AddToBuffer("\"", 1) == FALSE)
    return FALSE;
  if (AddEscapeStringToBuffer(szNameA, StrLenA(szNameA)) == FALSE)
    return FALSE;
  if (AddToBuffer("\": \"", 4) == FALSE)
    return FALSE;
  if (AddEscapeStringToBuffer(Value->Buffer, (SIZE_T)(Value->Length / 2)) == FALSE)
    return FALSE;
  return AddToBuffer("\"", 1);
}

BOOL CLightJSonBuilder::AddObjectLong(_In_z_ LPCSTR szNameA, _In_ LONG nValue)
{
  CHAR szTempBufA[64];
  int nTempBufLen;

  MX_ASSERT(szNameA != NULL);
  MX_ASSERT(*szNameA != 0);
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_OBJECT);

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (AddToBuffer(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  if (AddToBuffer("\"", 1) == FALSE)
    return FALSE;
  if (AddEscapeStringToBuffer(szNameA, StrLenA(szNameA)) == FALSE)
    return FALSE;
  nTempBufLen = _snprintf_s(szTempBufA, MX_ARRAYLEN(szTempBufA), "\": %ld", nValue);
  return AddToBuffer(szTempBufA, (SIZE_T)nTempBufLen);
}

BOOL CLightJSonBuilder::AddObjectULong(_In_z_ LPCSTR szNameA, _In_ ULONG nValue, _In_opt_ BOOL bAsHexa)
{
  CHAR szTempBufA[64];
  int nTempBufLen;

  MX_ASSERT(szNameA != NULL);
  MX_ASSERT(*szNameA != 0);
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_OBJECT);

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (AddToBuffer(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  if (AddToBuffer("\"", 1) == FALSE)
    return FALSE;
  if (AddEscapeStringToBuffer(szNameA, StrLenA(szNameA)) == FALSE)
    return FALSE;
  nTempBufLen = _snprintf_s(szTempBufA, MX_ARRAYLEN(szTempBufA), ((bAsHexa == FALSE) ? "\": %lu" : "\": \"0x%08X\""), nValue);
  return AddToBuffer(szTempBufA, (SIZE_T)nTempBufLen);
}

BOOL CLightJSonBuilder::AddObjectLongLong(_In_z_ LPCSTR szNameA, _In_ LONGLONG nValue)
{
  CHAR szTempBufA[64];
  int nTempBufLen;

  MX_ASSERT(szNameA != NULL);
  MX_ASSERT(*szNameA != 0);
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_OBJECT);

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (AddToBuffer(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  if (AddToBuffer("\"", 1) == FALSE)
    return FALSE;
  if (AddEscapeStringToBuffer(szNameA, StrLenA(szNameA)) == FALSE)
    return FALSE;
  nTempBufLen = _snprintf_s(szTempBufA, MX_ARRAYLEN(szTempBufA), "\": %I64d", nValue);
  return AddToBuffer(szTempBufA, (SIZE_T)nTempBufLen);
}

BOOL CLightJSonBuilder::AddObjectULongLong(_In_z_ LPCSTR szNameA, _In_ ULONGLONG nValue)
{
  CHAR szTempBufA[64];
  int nTempBufLen;

  MX_ASSERT(szNameA != NULL);
  MX_ASSERT(*szNameA != 0);
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_OBJECT);

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (AddToBuffer(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  if (AddToBuffer("\"", 1) == FALSE)
    return FALSE;
  if (AddEscapeStringToBuffer(szNameA, StrLenA(szNameA)) == FALSE)
    return FALSE;
  nTempBufLen = _snprintf_s(szTempBufA, MX_ARRAYLEN(szTempBufA), "\": %I64u", nValue);
  return AddToBuffer(szTempBufA, (SIZE_T)nTempBufLen);
}

BOOL CLightJSonBuilder::AddObjectObject(_In_z_ LPCSTR szNameA, _In_ CLightJSonBuilder &cSrc)
{
  MX_ASSERT(szNameA != NULL);
  MX_ASSERT(*szNameA != 0);
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_OBJECT);

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (AddToBuffer(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  if (AddToBuffer("\"", 1) == FALSE)
    return FALSE;
  if (AddEscapeStringToBuffer(szNameA, StrLenA(szNameA)) == FALSE)
    return FALSE;
  if (AddToBuffer("\": ", 3) == FALSE)
    return FALSE; 
  return AddToBuffer((LPCSTR)cSrc, cSrc.GetLength());
}

BOOL CLightJSonBuilder::AddArrayBoolean(_In_ BOOL bValue)
{
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_ARRAY);

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (AddToBuffer(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  if (bValue != FALSE)
  {
    if (AddToBuffer("true", 4) == FALSE)
      return FALSE;
  }
  else
  {
    if (AddToBuffer("false", 5) == FALSE)
      return FALSE;
  }
  return TRUE;
}

BOOL CLightJSonBuilder::AddArrayString(_In_ LPCSTR szValueA, _In_opt_ SIZE_T nValueLen)
{
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_ARRAY);

  if (nValueLen == (SIZE_T)-1)
    nValueLen = StrLenA(szValueA);
  MX_ASSERT(szValueA != NULL || nValueLen == 0);

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (AddToBuffer(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  if (AddToBuffer("\"", 1) == FALSE)
    return FALSE;
  if (AddEscapeStringToBuffer(szValueA, nValueLen) == FALSE)
    return FALSE;
  return AddToBuffer("\"", 1);
}

BOOL CLightJSonBuilder::AddArrayFormattedString(_Printf_format_string_ LPCSTR szFormatA, ...)
{
  CStringA cStrTempA;
  va_list argptr;

  MX_ASSERT(szFormatA != NULL);

  va_start(argptr, szFormatA);
  if (cStrTempA.FormatV(szFormatA, argptr) == FALSE)
    return FALSE;
  va_end(argptr);

  //done
  return AddArrayString((LPCSTR)cStrTempA, cStrTempA.GetLength());
}

BOOL CLightJSonBuilder::AddArrayFormattedStringV(_Printf_format_string_ LPCSTR szFormatA, _In_ va_list argptr)
{
  CStringA cStrTempA;

  MX_ASSERT(szFormatA != NULL);

  if (cStrTempA.FormatV(szFormatA, argptr) == FALSE)
    return FALSE;

  //done
  return AddArrayString((LPCSTR)cStrTempA, cStrTempA.GetLength());
}

BOOL CLightJSonBuilder::AddArrayString(_In_ LPCWSTR szValueW, _In_opt_ SIZE_T nValueLen)
{
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_ARRAY);

  if (nValueLen == (SIZE_T)-1)
    nValueLen = StrLenW(szValueW);
  MX_ASSERT(szValueW != NULL || nValueLen == 0);

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (AddToBuffer(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  if (AddToBuffer("\"", 1) == FALSE)
    return FALSE;
  if (AddEscapeStringToBuffer(szValueW, nValueLen) == FALSE)
    return FALSE;
  return AddToBuffer("\"", 1);
}

BOOL CLightJSonBuilder::AddArrayFormattedString(_Printf_format_string_ LPCWSTR szFormatW, ...)
{
  CStringW cStrTempW;
  va_list argptr;

  MX_ASSERT(szFormatW != NULL);

  va_start(argptr, szFormatW);
  if (cStrTempW.FormatV(szFormatW, argptr) == FALSE)
    return FALSE;
  va_end(argptr);

  //done
  return AddArrayString((LPCWSTR)cStrTempW, cStrTempW.GetLength());
}

BOOL CLightJSonBuilder::AddArrayFormattedStringV(_Printf_format_string_ LPCWSTR szFormatW, _In_ va_list argptr)
{
  CStringW cStrTempW;

  MX_ASSERT(szFormatW != NULL);

  if (cStrTempW.FormatV(szFormatW, argptr) == FALSE)
    return FALSE;

  //done
  return AddArrayString((LPCWSTR)cStrTempW, cStrTempW.GetLength());
}

BOOL CLightJSonBuilder::AddArrayLong(_In_ LONG nValue)
{
  CHAR szTempBufA[64];
  int nTempBufLen;

  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_ARRAY);

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (AddToBuffer(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  nTempBufLen = _snprintf_s(szTempBufA, MX_ARRAYLEN(szTempBufA), "%ld", nValue);
  return AddToBuffer(szTempBufA, (SIZE_T)nTempBufLen);
}

BOOL CLightJSonBuilder::AddArrayULong(_In_ ULONG nValue, _In_opt_ BOOL bAsHexa)
{
  CHAR szTempBufA[64];
  int nTempBufLen;

  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_ARRAY);

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (AddToBuffer(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  nTempBufLen = _snprintf_s(szTempBufA, MX_ARRAYLEN(szTempBufA), ((bAsHexa == FALSE) ? "%lu" : "\"0x%08X\""), nValue);
  return AddToBuffer(szTempBufA, (SIZE_T)nTempBufLen);
}

BOOL CLightJSonBuilder::AddArrayLongLong(_In_ LONGLONG nValue)
{
  CHAR szTempBufA[64];
  int nTempBufLen;

  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_ARRAY);

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (AddToBuffer(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  nTempBufLen = _snprintf_s(szTempBufA, MX_ARRAYLEN(szTempBufA), "%I64d", nValue);
  return AddToBuffer(szTempBufA, (SIZE_T)nTempBufLen);
}

BOOL CLightJSonBuilder::AddArrayULongLong(_In_ ULONGLONG nValue)
{
  CHAR szTempBufA[64];
  int nTempBufLen;

  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_ARRAY);

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (AddToBuffer(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  nTempBufLen = _snprintf_s(szTempBufA, MX_ARRAYLEN(szTempBufA), "%I64u", nValue);
  return AddToBuffer(szTempBufA, (SIZE_T)nTempBufLen);
}

BOOL CLightJSonBuilder::AddArrayObject(_In_ CLightJSonBuilder &cSrc)
{
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_ARRAY);

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (AddToBuffer(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  return AddToBuffer((LPCSTR)cSrc, cSrc.GetLength());
}

BOOL CLightJSonBuilder::AddRaw(_In_ LPCSTR szStrA, _In_opt_ SIZE_T nStrLen)
{
  if (nStrLen == (SIZE_T)-1)
    nStrLen = StrLenA(szStrA);
  MX_ASSERT(szStrA != NULL || nStrLen == 0);

  //insert text
  return AddToBuffer(szStrA, nStrLen);
}

BOOL CLightJSonBuilder::AddRaw(_In_ LPCWSTR szStrW, _In_opt_ SIZE_T nStrLen)
{
  CStringA cStrTempA;

  if (nStrLen == (SIZE_T)-1)
    nStrLen = StrLenW(szStrW);
  MX_ASSERT(szStrW != NULL || nStrLen == 0);

  if (FAILED(Utf8_Encode(cStrTempA, szStrW, nStrLen)))
    return FALSE;

  //insert text
  return AddToBuffer((LPCSTR)cStrTempA, cStrTempA.GetLength());
}

BOOL CLightJSonBuilder::EscapeString(_Inout_ CStringA &cStrA, _In_ LPCSTR szStrA, _In_ SIZE_T nStrLen, _In_opt_ BOOL bAppend)
{
  LPCSTR szStartA, szStrEndA;

  if (bAppend == FALSE)
    cStrA.Empty();

  szStrEndA = szStrA + nStrLen;
  while (szStrA < szStrEndA)
  {
    szStartA = szStrA;
    while (szStrA < szStrEndA)
    {
      if (*((LPBYTE)szStrA) < 32 || *szStrA == '\\' || *szStrA == '"')
        break;
      szStrA += 1;
    }
    if (szStrA > szStartA)
    {
      if (cStrA.ConcatN(szStartA, (SIZE_T)(szStrA - szStartA)) == FALSE)
        return FALSE;
    }
    if (szStrA < szStrEndA)
    {
      switch (*szStrA)
      {
        case '\b':
          if (cStrA.ConcatN("\\b", 2) == FALSE)
            return FALSE;
          break;

        case '\f':
          if (cStrA.ConcatN("\\f", 2) == FALSE)
            return FALSE;
          break;

        case '\n':
          if (cStrA.ConcatN("\\n", 2) == FALSE)
            return FALSE;
          break;

        case '\r':
          if (cStrA.ConcatN("\\r", 2) == FALSE)
            return FALSE;
          break;

        case '\t':
          if (cStrA.ConcatN("\\t", 2) == FALSE)
            return FALSE;
          break;

        case '"':
          if (cStrA.ConcatN("\\\"", 2) == FALSE)
            return FALSE;
          break;

        case '\\':
          if (cStrA.ConcatN("\\\\", 2) == FALSE)
            return FALSE;
          break;

        default:
          if (cStrA.AppendFormat("\\u%04lX", (ULONG)*((LPBYTE)szStrA)) == FALSE)
            return FALSE;
          break;
      }
      szStrA += 1;
    }
  }
  return TRUE;
}

BOOL CLightJSonBuilder::EscapeString(_Inout_ CStringA &cStrA, _In_ LPCWSTR szStrW, _In_ SIZE_T nStrLen, _In_opt_ BOOL bAppend)
{
  CHAR szTempBufA[8];
  int nTempBufLen;
  LPCWSTR szStrEndW;

  if (bAppend == FALSE)
    cStrA.Empty();

  szStrEndW = szStrW + nStrLen;
  while (szStrW < szStrEndW)
  {
    switch (*szStrW)
    {
      case L'\b':
        if (cStrA.ConcatN("\\b", 2) == FALSE)
          return FALSE;
        break;

      case L'\f':
        if (cStrA.ConcatN("\\f", 2) == FALSE)
          return FALSE;
        break;

      case L'\n':
        if (cStrA.ConcatN("\\n", 2) == FALSE)
          return FALSE;
        break;

      case L'\r':
        if (cStrA.ConcatN("\\r", 2) == FALSE)
          return FALSE;
        break;

      case L'\t':
        if (cStrA.ConcatN("\\t", 2) == FALSE)
          return FALSE;
        break;

      case L'"':
        if (cStrA.ConcatN("\\\"", 2) == FALSE)
          return FALSE;
        break;

      case L'\\':
        if (cStrA.ConcatN("\\\\", 2) == FALSE)
          return FALSE;
        break;

      default:
        if (*szStrW < 32)
        {
          if (cStrA.AppendFormat("\\u%04lX", (ULONG)*szStrW) == FALSE)
            return FALSE;
        }
        else
        {
          nTempBufLen = -1;
          if (*szStrW >= 0xD800 && *szStrW <= 0xDBFF)
          {
            if (szStrW + 1 < szStrEndW)
            {
              nTempBufLen = Utf8_EncodeChar(szTempBufA, szStrW[0], szStrW[1]);
              szStrW += 1;
            }
          }
          else
          {
            nTempBufLen = Utf8_EncodeChar(szTempBufA, *szStrW);
          }
          if (nTempBufLen > 0)
          {
            if (cStrA.ConcatN(szTempBufA, (SIZE_T)nTempBufLen) == FALSE)
              return FALSE;
          }
        }
        break;
    }
    szStrW += 1;
  }
  return TRUE;
}

BOOL CLightJSonBuilder::AddToBuffer(_In_ LPCSTR szStrA, _In_ SIZE_T nStrLen)
{
  LPBYTE lpPtr;

  if (nStrLen == 0)
    return TRUE;
  if (nStrLen + 1 > nBufferSize - nBufferLen)
  {
    SIZE_T nNewLen = nBufferSize + ((nStrLen + 32768) & (~32767));
    LPBYTE lpNewBuffer = (LPBYTE)MX_MALLOC(nNewLen);
    if (lpNewBuffer == NULL)
      return FALSE;
    ::MxMemCopy(lpNewBuffer, aBuffer.Get(), nBufferLen);
    aBuffer.Attach(lpNewBuffer);
    nBufferSize = nNewLen;
  }
  lpPtr = aBuffer.Get() + nBufferLen;
  ::MxMemCopy(lpPtr, szStrA, nStrLen);
  lpPtr[nStrLen] = 0;
  nBufferLen += nStrLen;
  return TRUE;
}

BOOL CLightJSonBuilder::AddEscapeStringToBuffer(_In_ LPCSTR szStrA, _In_ SIZE_T nStrLen)
{
  CHAR szTempBufA[64];
  int nTempBufLen;
  LPCSTR szStartA, szStrEndA;

  szStrEndA = szStrA + nStrLen;
  while (szStrA < szStrEndA)
  {
    szStartA = szStrA;
    while (szStrA < szStrEndA)
    {
      if (*((LPBYTE)szStrA) < 32 || *szStrA == '\\' || *szStrA == '"')
        break;
      szStrA += 1;
    }
    if (szStrA > szStartA)
    {
      if (AddToBuffer(szStartA, (SIZE_T)(szStrA - szStartA)) == FALSE)
        return FALSE;
    }
    if (szStrA < szStrEndA)
    {
      switch (*szStrA)
      {
        case '\b':
          if (AddToBuffer("\\b", 2) == FALSE)
            return FALSE;
          break;

        case '\f':
          if (AddToBuffer("\\f", 2) == FALSE)
            return FALSE;
          break;

        case '\n':
          if (AddToBuffer("\\n", 2) == FALSE)
            return FALSE;
          break;

        case '\r':
          if (AddToBuffer("\\r", 2) == FALSE)
            return FALSE;
          break;

        case '\t':
          if (AddToBuffer("\\t", 2) == FALSE)
            return FALSE;
          break;

        case '"':
          if (AddToBuffer("\\\"", 2) == FALSE)
            return FALSE;
          break;

        case '\\':
          if (AddToBuffer("\\\\", 2) == FALSE)
            return FALSE;
          break;

        default:
          nTempBufLen = _snprintf_s(szTempBufA, MX_ARRAYLEN(szTempBufA), "\\u%04lX", (ULONG)(*((LPBYTE)szStrA)));
          if (AddToBuffer(szTempBufA, (SIZE_T)nTempBufLen) == FALSE)
            return FALSE;
          break;
      }
      szStrA += 1;
    }
  }
  return TRUE;
}

BOOL CLightJSonBuilder::AddEscapeStringToBuffer(_In_ LPCWSTR szStrW, _In_ SIZE_T nStrLen)
{
  CHAR szTempBufA[64];
  int nTempBufLen;
  LPCWSTR szStrEndW;

  szStrEndW = szStrW + nStrLen;
  while (szStrW < szStrEndW)
  {
    switch (*szStrW)
    {
      case L'\b':
        if (AddToBuffer("\\b", 2) == FALSE)
          return FALSE;
        break;

      case L'\f':
        if (AddToBuffer("\\f", 2) == FALSE)
          return FALSE;
        break;

      case L'\n':
        if (AddToBuffer("\\n", 2) == FALSE)
          return FALSE;
        break;

      case L'\r':
        if (AddToBuffer("\\r", 2) == FALSE)
          return FALSE;
        break;

      case L'\t':
        if (AddToBuffer("\\t", 2) == FALSE)
          return FALSE;
        break;

      case L'"':
        if (AddToBuffer("\\\"", 2) == FALSE)
          return FALSE;
        break;

      case L'\\':
        if (AddToBuffer("\\\\", 2) == FALSE)
          return FALSE;
        break;

      default:
        if (*szStrW < 32)
        {
          nTempBufLen = _snprintf_s(szTempBufA, MX_ARRAYLEN(szTempBufA), "\\u%04lX", (ULONG)(*szStrW));
          if (AddToBuffer(szTempBufA, (SIZE_T)nTempBufLen) == FALSE)
            return FALSE;
        }
        else
        {
          nTempBufLen = -1;
          if (*szStrW >= 0xD800 && *szStrW <= 0xDBFF)
          {
            if (szStrW + 1 < szStrEndW)
            {
              nTempBufLen = Utf8_EncodeChar(szTempBufA, szStrW[0], szStrW[1]);
              szStrW += 1;
            }
          }
          else
          {
            nTempBufLen = Utf8_EncodeChar(szTempBufA, *szStrW);
          }
          if (nTempBufLen > 0)
          {
            if (AddToBuffer(szTempBufA, (SIZE_T)nTempBufLen) == FALSE)
              return FALSE;
          }
        }
        break;
    }
    szStrW += 1;
  }
  return TRUE;
}

}; //namespace MX
