/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#include "LightJSonBuilder.h"
#include <Strings\Utf8.h>

#define _IS_OBJECT 0
#define _IS_ARRAY  1

//-----------------------------------------------------------

CLightJSonBuilder::CLightJSonBuilder() : MX::CBaseMemObj()
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
    if (cStrJsonA.Concat(szNameA) == FALSE)
      return FALSE;
    return cStrJsonA.ConcatN("\": {", 4);
  }
  return cStrJsonA.ConcatN("{", 1);
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
    if (cStrJsonA.Concat(szNameA) == FALSE)
      return FALSE;
    return cStrJsonA.ConcatN("\": [", 4);
  }
  return cStrJsonA.ConcatN("[", 1);
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

BOOL CLightJSonBuilder::AddObjectString(_In_z_ LPCSTR szNameA, _In_ LPCWSTR szValueW, _In_opt_ SIZE_T nValueLen)
{
  MX_ASSERT(szNameA != NULL);
  MX_ASSERT(*szNameA != 0);
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_OBJECT);

  if (nValueLen == (SIZE_T)-1)
    nValueLen = MX::StrLenW(szValueW);
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
  if (cStrJsonA.Concat(szNameA) == FALSE)
    return FALSE;
  if (cStrJsonA.ConcatN("\": \"", 4) == FALSE)
    return FALSE;
  if (AddEscapedString(szValueW, nValueLen) == FALSE)
    return FALSE;
  return cStrJsonA.ConcatN("\"", 1);
}

BOOL CLightJSonBuilder::AddObjectFormattedString(_In_z_ LPCSTR szNameA, _Printf_format_string_ LPCWSTR szFormatW, ...)
{
  MX::CStringW cStrTempW;
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
  if (cStrJsonA.Concat(szNameA) == FALSE)
    return FALSE;
  if (cStrJsonA.ConcatN("\": \"", 4) == FALSE)
    return FALSE;
  if (AddEscapedString(Value->Buffer, (SIZE_T)(Value->Length) / 2) == FALSE)
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
  return cStrJsonA.AppendFormat("\"%s\": %ld", szNameA, nValue);
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
  return cStrJsonA.AppendFormat((bAsHexa == FALSE) ? "\"%s\": %lu" : "\"%s\": \"0x%08X\"", szNameA, nValue);
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
  return cStrJsonA.AppendFormat("\"%s\": \"%I64d\"", szNameA, nValue);
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
  return cStrJsonA.AppendFormat((bAsHexa == FALSE) ? "\"%s\": \"%I64u\"" : "\"%s\": \"0x%016I64X\"", szNameA, nValue);
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
  return cStrJsonA.AppendFormat("\"%s\": %s", szNameA, (LPCSTR)cSrc);
}

BOOL CLightJSonBuilder::AddArrayString(_In_ LPCWSTR szValueW, _In_opt_ SIZE_T nValueLen)
{
  MX_ASSERT(aNestedTypes.GetCount() > 0);
  MX_ASSERT(aNestedTypes.GetElementAt(aNestedTypes.GetCount() - 1) == _IS_OBJECT);

  if (nValueLen == (SIZE_T)-1)
    nValueLen = MX::StrLenW(szValueW);
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
  if (AddEscapedString(szValueW, nValueLen) == FALSE)
    return FALSE;
  return cStrJsonA.ConcatN("\"", 1);
}

BOOL CLightJSonBuilder::AddArrayFormattedString(_Printf_format_string_ LPCWSTR szFormatW, ...)
{
  MX::CStringW cStrTempW;
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
  return cStrJsonA.Concat((LPCSTR)cSrc);
}

BOOL CLightJSonBuilder::EscapeString(_Inout_ MX::CStringA &cStrA, _In_ LPCWSTR szValueW, _In_ SIZE_T nValueLen,
                                     _In_opt_ BOOL bAppend)
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
          if (cStrA.AppendFormat("\\u%04lu", (ULONG)*szValueW) == FALSE)
            return FALSE;
        }
        else
        {
          len = -1;
          if (*szValueW >= 0xD800 && *szValueW <= 0xDBFF)
          {
            if (szValueW + 1 < szValueEndW)
            {
              len = MX::Utf8_EncodeChar(szDestA, szValueW[0], szValueW[1]);
              szValueW++;
            }
          }
          else
          {
            len = MX::Utf8_EncodeChar(szDestA, *szValueW);
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

BOOL CLightJSonBuilder::AddEscapedString(_In_ LPCWSTR szValueW, _In_ SIZE_T nValueLen)
{
  return EscapeString(cStrJsonA, szValueW, nValueLen, TRUE);
}
