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

#define _IS_OBJECT 0
#define _IS_ARRAY  1

//-----------------------------------------------------------

namespace MX {

CLightJSonBuilder::CLightJSonBuilder() : CBaseMemObj(), CNonCopyableObj()
{
  bIsFirstItem = TRUE;
  return;
}

VOID CLightJSonBuilder::Reset()
{
  cStrJsonA.Empty();
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
    if (cStrJsonA.ConcatN(", ", 2) == FALSE)
      return FALSE;
  }

  //add nested object
  if (aNestedTypes.AddElement(_IS_OBJECT) == FALSE)
    return FALSE;
  bIsFirstItem = TRUE;

  //insert text
  if (bNeedsName != FALSE)
  {
    if (cStrJsonA.ConcatN("\"", 1) == FALSE)
      return FALSE;
    if (EscapeString(cStrJsonA, szNameA, StrLenA(szNameA), TRUE) == FALSE)
      return FALSE;
    return cStrJsonA.ConcatN("\": { ", 5);
  }
  return cStrJsonA.ConcatN("{ ", 2);
}

BOOL CLightJSonBuilder::CloseObject()
{
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_OBJECT);

  //remove nested object
  aNestedTypes.RemoveElementAt(aNestedTypes.GetCount() - 1, 1);
  bIsFirstItem = FALSE;

  //insert text
  return cStrJsonA.ConcatN(" }", 2);
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
    if (cStrJsonA.ConcatN(", ", 2) == FALSE)
      return FALSE;
  }

  //add nested object
  if (aNestedTypes.AddElement(_IS_ARRAY) == FALSE)
    return FALSE;
  bIsFirstItem = TRUE;

  //insert text
  if (bNeedsName != FALSE)
  {
    if (cStrJsonA.ConcatN("\"", 1) == FALSE)
      return FALSE;
    if (EscapeString(cStrJsonA, szNameA, StrLenA(szNameA), TRUE) == FALSE)
      return FALSE;
    return cStrJsonA.ConcatN("\": [ ", 5);
  }
  return cStrJsonA.ConcatN("[ ", 2);
}

BOOL CLightJSonBuilder::CloseArray()
{
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_ARRAY);

  //remove nested object
  aNestedTypes.RemoveElementAt(aNestedTypes.GetCount() - 1, 1);
  bIsFirstItem = FALSE;

  //insert text
  return cStrJsonA.ConcatN(" ]", 2);
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
    if (cStrJsonA.ConcatN(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  if (cStrJsonA.ConcatN("\"", 1) == FALSE)
    return FALSE;
  if (EscapeString(cStrJsonA, szNameA, StrLenA(szNameA), TRUE) == FALSE)
    return FALSE;
  if (bValue != FALSE)
  {
    if (cStrJsonA.ConcatN("\": true", 7) == FALSE)
      return FALSE;
  }
  else
  {
    if (cStrJsonA.ConcatN("\": false", 8) == FALSE)
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
    if (cStrJsonA.ConcatN(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  if (cStrJsonA.ConcatN("\"", 1) == FALSE)
    return FALSE;
  if (EscapeString(cStrJsonA, szNameA, StrLenA(szNameA), TRUE) == FALSE)
    return FALSE;
  if (cStrJsonA.ConcatN("\": \"", 4) == FALSE)
    return FALSE;
  if (EscapeString(cStrJsonA, szValueA, nValueLen, TRUE) == FALSE)
    return FALSE;
  return cStrJsonA.ConcatN("\"", 1);
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
    if (cStrJsonA.ConcatN(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  if (cStrJsonA.ConcatN("\"", 1) == FALSE)
    return FALSE;
  if (EscapeString(cStrJsonA, szNameA, StrLenA(szNameA), TRUE) == FALSE)
    return FALSE;
  if (cStrJsonA.ConcatN("\": \"", 4) == FALSE)
    return FALSE;
  if (EscapeString(cStrJsonA, szValueW, nValueLen, TRUE) == FALSE)
    return FALSE;
  return cStrJsonA.ConcatN("\"", 1);
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
    if (cStrJsonA.ConcatN(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  if (cStrJsonA.ConcatN("\"", 1) == FALSE)
    return FALSE;
  if (EscapeString(cStrJsonA, szNameA, StrLenA(szNameA), TRUE) == FALSE)
    return FALSE;
  if (cStrJsonA.ConcatN("\": \"", 4) == FALSE)
    return FALSE;
  if (EscapeString(cStrJsonA, Value->Buffer, (SIZE_T)(Value->Length / 2), TRUE) == FALSE)
    return FALSE;
  return cStrJsonA.ConcatN("\"", 1);
}

BOOL CLightJSonBuilder::AddObjectLong(_In_z_ LPCSTR szNameA, _In_ LONG nValue)
{
  MX_ASSERT(szNameA != NULL);
  MX_ASSERT(*szNameA != 0);
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_OBJECT);

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (cStrJsonA.ConcatN(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  if (cStrJsonA.ConcatN("\"", 1) == FALSE)
    return FALSE;
  if (EscapeString(cStrJsonA, szNameA, StrLenA(szNameA), TRUE) == FALSE)
    return FALSE;
  return cStrJsonA.AppendFormat("\": %ld", nValue);
}

BOOL CLightJSonBuilder::AddObjectULong(_In_z_ LPCSTR szNameA, _In_ ULONG nValue, _In_opt_ BOOL bAsHexa)
{
  MX_ASSERT(szNameA != NULL);
  MX_ASSERT(*szNameA != 0);
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_OBJECT);

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (cStrJsonA.ConcatN(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  if (cStrJsonA.ConcatN("\"", 1) == FALSE)
    return FALSE;
  if (EscapeString(cStrJsonA, szNameA, StrLenA(szNameA), TRUE) == FALSE)
    return FALSE;
  return cStrJsonA.AppendFormat(((bAsHexa == FALSE) ? "\": %lu" : "\": \"0x%08X\""), nValue);
}

BOOL CLightJSonBuilder::AddObjectLongLong(_In_z_ LPCSTR szNameA, _In_ LONGLONG nValue)
{
  MX_ASSERT(szNameA != NULL);
  MX_ASSERT(*szNameA != 0);
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_OBJECT);

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (cStrJsonA.ConcatN(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  if (cStrJsonA.ConcatN("\"", 1) == FALSE)
    return FALSE;
  if (EscapeString(cStrJsonA, szNameA, StrLenA(szNameA), TRUE) == FALSE)
    return FALSE;
  return cStrJsonA.AppendFormat("\": \"%I64d\"", nValue);
}

BOOL CLightJSonBuilder::AddObjectULongLong(_In_z_ LPCSTR szNameA, _In_ ULONGLONG nValue, _In_opt_ BOOL bAsHexa)
{
  MX_ASSERT(szNameA != NULL);
  MX_ASSERT(*szNameA != 0);
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_OBJECT);

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (cStrJsonA.ConcatN(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  if (cStrJsonA.ConcatN("\"", 1) == FALSE)
    return FALSE;
  if (EscapeString(cStrJsonA, szNameA, StrLenA(szNameA), TRUE) == FALSE)
    return FALSE;
  return cStrJsonA.AppendFormat(((bAsHexa == FALSE) ? "\": \"%I64u\"" : "\": \"0x%016I64X\""), nValue);
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
    if (cStrJsonA.ConcatN(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  if (cStrJsonA.ConcatN("\"", 1) == FALSE)
    return FALSE;
  if (EscapeString(cStrJsonA, szNameA, StrLenA(szNameA), TRUE) == FALSE)
    return FALSE;
  if (cStrJsonA.ConcatN("\": ", 3) == FALSE)
    return FALSE; 
  return cStrJsonA.ConcatN((LPCSTR)cSrc, cSrc.GetLength());
}

BOOL CLightJSonBuilder::AddArrayBoolean(_In_ BOOL bValue)
{
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_ARRAY);

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (cStrJsonA.ConcatN(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  if (bValue != FALSE)
  {
    if (cStrJsonA.ConcatN("true", 4) == FALSE)
      return FALSE;
  }
  else
  {
    if (cStrJsonA.ConcatN("false", 5) == FALSE)
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
    if (cStrJsonA.ConcatN(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  if (cStrJsonA.ConcatN("\"", 1) == FALSE)
    return FALSE;
  if (EscapeString(cStrJsonA, szValueA, nValueLen, TRUE) == FALSE)
    return FALSE;
  return cStrJsonA.ConcatN("\"", 1);
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
    if (cStrJsonA.ConcatN(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  if (cStrJsonA.ConcatN("\"", 1) == FALSE)
    return FALSE;
  if (EscapeString(cStrJsonA, szValueW, nValueLen, TRUE) == FALSE)
    return FALSE;
  return cStrJsonA.ConcatN("\"", 1);
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

BOOL CLightJSonBuilder::AddArrayLong(_In_ LONG nValue)
{
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_ARRAY);

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (cStrJsonA.ConcatN(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  return cStrJsonA.AppendFormat("%ld", nValue);
}

BOOL CLightJSonBuilder::AddArrayULong(_In_ ULONG nValue, _In_opt_ BOOL bAsHexa)
{
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_ARRAY);

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (cStrJsonA.ConcatN(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  return cStrJsonA.AppendFormat((bAsHexa == FALSE) ? "%lu" : "\"0x%08X\"", nValue);
}

BOOL CLightJSonBuilder::AddArrayLongLong(_In_ LONGLONG nValue)
{
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_ARRAY);

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (cStrJsonA.ConcatN(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  return cStrJsonA.AppendFormat("\"%I64d\"", nValue);
}

BOOL CLightJSonBuilder::AddArrayULongLong(_In_ ULONGLONG nValue, _In_opt_ BOOL bAsHexa)
{
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_ARRAY);

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (cStrJsonA.ConcatN(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  return cStrJsonA.AppendFormat((bAsHexa == FALSE) ? "\"%I64u\"" : "\"0x%016I64X\"", nValue);
}

BOOL CLightJSonBuilder::AddArrayObject(_In_ CLightJSonBuilder &cSrc)
{
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_ARRAY);

  //insert separator
  if (bIsFirstItem == FALSE)
  {
    if (cStrJsonA.ConcatN(", ", 2) == FALSE)
      return FALSE;
  }
  else
  {
    bIsFirstItem = FALSE;
  }

  //insert text
  return cStrJsonA.ConcatN((LPCSTR)cSrc, cSrc.GetLength());
}

BOOL CLightJSonBuilder::AddRaw(_In_ LPCSTR szStrA, _In_opt_ SIZE_T nStrLen)
{
  if (nStrLen == (SIZE_T)-1)
    nStrLen = StrLenA(szStrA);
  MX_ASSERT(szStrA != NULL || nStrLen == 0);

  //insert text
  return cStrJsonA.ConcatN(szStrA, nStrLen);
}

BOOL CLightJSonBuilder::AddRaw(_In_ LPCWSTR szStrW, _In_opt_ SIZE_T nStrLen)
{
  if (nStrLen == (SIZE_T)-1)
    nStrLen = StrLenW(szStrW);
  MX_ASSERT(szStrW != NULL || nStrLen == 0);

  //insert text
  return (SUCCEEDED(Utf8_Encode(cStrJsonA, szStrW, nStrLen, TRUE))) ? TRUE : FALSE;
}

BOOL CLightJSonBuilder::EscapeString(_Inout_ CStringA &cStrA, _In_ LPCSTR szValueA, _In_ SIZE_T nValueLen, _In_opt_ BOOL bAppend)
{
  LPCSTR szStartA, szValueEndA;

  if (bAppend == FALSE)
    cStrA.Empty();

  szValueEndA = szValueA + nValueLen;
  while (szValueA < szValueEndA)
  {
    szStartA = szValueA;
    while (szValueA < szValueEndA)
    {
      if (*((LPBYTE)szValueA) < 32 || *szValueA == '\\' || *szValueA == '"')
        break;
      szValueA++;
    }
    if (szValueA > szStartA)
    {
      if (cStrA.ConcatN(szStartA, (SIZE_T)(szValueA - szStartA)) == FALSE)
        return FALSE;
    }
    if (szValueA < szValueEndA)
    {
      switch (*szValueA)
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
          if (cStrA.AppendFormat("\\u%04lX", (ULONG)*((LPBYTE)szValueA)) == FALSE)
            return FALSE;
          break;
      }
      szValueA++;
    }
  }
  return TRUE;
}

BOOL CLightJSonBuilder::EscapeString(_Inout_ CStringA &cStrA, _In_ LPCWSTR szValueW, _In_ SIZE_T nValueLen, _In_opt_ BOOL bAppend)
{
  LPCWSTR szValueEndW;
  CHAR szDestA[6];
  int len;

  if (bAppend == FALSE)
    cStrA.Empty();

  szValueEndW = szValueW + nValueLen;
  while (szValueW < szValueEndW)
  {
    switch (*szValueW)
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
        if (*szValueW < 32)
        {
          if (cStrA.AppendFormat("\\u%04lX", (ULONG)*szValueW) == FALSE)
            return FALSE;
        }
        else
        {
          len = -1;
          if (*szValueW >= 0xD800 && *szValueW <= 0xDBFF)
          {
            if (szValueW + 1 < szValueEndW)
            {
              len = Utf8_EncodeChar(szDestA, szValueW[0], szValueW[1]);
              szValueW++;
            }
          }
          else
          {
            len = Utf8_EncodeChar(szDestA, *szValueW);
          }
          if (len > 0)
          {
            if (cStrA.ConcatN(szDestA, (SIZE_T)len) == FALSE)
              return FALSE;
          }
        }
        break;
    }
    szValueW++;
  }
  return TRUE;
}

}; //namespace MX
