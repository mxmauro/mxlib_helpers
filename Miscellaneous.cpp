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
#include "Miscellaneous.h"
#include "FileRoutines.h"
#include <stdio.h>
#include <stdlib.h>

//-----------------------------------------------------------

static BOOL AddRepeatedChar(_Inout_ MX::CStringW &cStrW, _In_ WCHAR chW, _In_ SIZE_T nCount);

//-----------------------------------------------------------

namespace MX {

namespace Misc {

//NOTE: Based on JODD's source code. BSD-License
//      Copyright (c) 2003-2018, Jodd Team All rights reserved.
BOOL WildcardMatch(_In_ LPCWSTR szTextW, _In_ SIZE_T nTextLen, _In_ LPCWSTR szPatternW, _In_ SIZE_T nPatternLen)
{
  LPCWSTR szPatternEndW, szTextEndW;

  if (nTextLen == (SIZE_T)-1)
    nTextLen = StrLenW(szTextW);
  if (nPatternLen == (SIZE_T)-1)
    nPatternLen = StrLenW(szPatternW);
  if (nPatternLen == 1 && *szPatternW == L'*')
    return TRUE; // speed-up

  szPatternEndW = szPatternW + nPatternLen;
  szTextEndW = szTextW + nTextLen;

  for (;;)
  {
    //check if end of string and/or pattern occurred
    if (szTextW >= szTextEndW)
    {
      //end of string still may have pending '*' in pattern
      while (szPatternW < szPatternEndW && *szPatternW == L'*')
        szPatternW++;
      return (szPatternW >= szPatternEndW) ? TRUE : FALSE;
    }
    if (szPatternW >= szPatternEndW)
      break; //end of pattern, but not end of the string

    //perform logic
    if (*szPatternW == L'?')
    {
      szTextW++;
      szPatternW++;
      continue;
    }
    if (*szPatternW == L'*')
    {
      LPCWSTR t;

      while (szPatternW < szPatternEndW && *szPatternW == L'*')
        szPatternW++; //skip contiguous '*'

      //find recursively if there is any substring from the end of the
      //line that matches the rest of the pattern !!!
      for (t = szTextEndW; t >= szTextW; t--)
      {
        if (WildcardMatch(t, (SIZE_T)(szTextEndW - t), szPatternW, (SIZE_T)(szPatternEndW - szPatternW)) != FALSE)
          return TRUE;
      }
      break;
    }

    //check if pattern char and string char are equals
    if (CharToUpperW(*szTextW) != CharToUpperW(*szPatternW))
      break;

    //everything matches for now, continue
    szTextW++;
    szPatternW++;
  }
  return FALSE;
}

// NOTE: Based Robert-van-Engelen code
//       https://github.com/Robert-van-Engelen/FastGlobbing
//
// Gitignore - style globbing applies the following rules to determine file and directory pathname matches :
// *        matches anything except a /
// ?        matches any one character except a /
// [a-z]    matches one character in the selected range of characters
// [^a-z]   matches one character not in the selected range of characters
// [!a-z]   matches one character not in the selected range of characters
// /        when used at the begin of a szPatternW, matches if pathname has no /
// **/      matches zero or more directories
// /**      when at the end of a szPatternW, matches everything after the /
// \?       matches a ? (or any character specified after the backslash)
//
// Examples:
// *          a, b, x/a, x/y/b
// a          a, x/a, x/y/a but not b, x/b, a/a/b
// /*         a, b but not x/a, x/b, x/y/a
// /a         a but not x/a, x/y/a
// a?b        axb, ayb but not a, b, ab, a/b
// a[xy]b     axb, ayb but not a, b, azb
// a[a-z]b    aab, abb, acb, azb but not a, b, a3b, aAb, aZb
// a[^xy]b    aab, abb, acb, azb but not a, b, axb, ayb
// a[^a-z]b   a3b, aAb, aZb but not a, b, aab, abb, acb, azb
// a/*/b      a/x/b, a/y/b but not a/b, a/x/y/b
// **/a       a, x/a, x/y/a but not b, x/b
// a/**/b     a/b, a/x/b, a/x/y/b but not x/a/b, a/b/x
// a/**       a/x, a/y, a/x/y but not a, b/x
// a\?b       a?b but not a, b, ab, axb, a/b
BOOL GitWildcardMatch(_In_ LPCWSTR szTextW, _In_ SIZE_T nTextLen, _In_ LPCWSTR szPatternW, _In_ SIZE_T nPatternLen)
{
  SIZE_T nText1Backup = (SIZE_T)-1;
  SIZE_T nPattern1Backup = (SIZE_T)-1;
  SIZE_T nText2Backup = (SIZE_T)-1;
  SIZE_T nPattern2Backup = (SIZE_T)-1;
  SIZE_T nTextOfs = 0;
  SIZE_T nPatternOfs = 0;

  if (nTextLen == (SIZE_T)-1)
    nTextLen = StrLenW(szTextW);
  if (nPatternLen == (SIZE_T)-1)
    nPatternLen = StrLenW(szPatternW);
  if (nPatternLen == 1 && *szPatternW == L'*')
    return TRUE; // speed-up

  //if pattern does not contain a path, skip it
  if (StrNChrW(szPatternW, L'\\', nPatternLen) == NULL)
  {
    LPCWSTR szSepW = StrNChrW(szTextW, L'\\', nTextLen, TRUE);
    if (szSepW != NULL)
      nTextOfs = (SIZE_T)(szSepW - szTextW) + 1;
  }

  //main loop
  while (nTextOfs < nTextLen)
  {
    if (nPatternOfs < nPatternLen)
    {
      switch (szPatternW[nPatternOfs])
      {
        case L'*':
          // match anything except . after /
          if (++nPatternOfs < nPatternLen && szPatternW[nPatternOfs] == L'*')
          {
            // trailing ** match everything after /
            if (++nPatternOfs >= nPatternLen)
              return TRUE;

            // ** followed by a / match zero or more directories
            if (szPatternW[nPatternOfs] != L'\\')
              return FALSE;

            // new **-loop, discard *-loop
            nText1Backup = (SIZE_T)-1;
            nPattern1Backup = (SIZE_T)-1;
            nText2Backup = nTextOfs;
            nPattern2Backup = nPatternOfs;
            if (szTextW[nTextOfs] == L'\\')
              nPatternOfs++;
            continue;
          }

          // trailing * matches everything except /
          nText1Backup = nTextOfs;
          nPattern1Backup = nPatternOfs;
          continue;

        case L'?':
          // match any character except /
          if (szTextW[nTextOfs] == L'\\')
            break;
          nTextOfs++;
          nPatternOfs++;
          continue;

        case L'[':
          {
          DWORD dwLastChr;
          BOOL bMatched;
          BOOL bReverse;

          // match any character in [...] except /
          if (szTextW[nTextOfs] == L'\\')
            break;

          // inverted character class
          bReverse = (nPatternOfs + 1 < nPatternLen) &&
                      (szPatternW[nPatternOfs + 1] == L'^' || szPatternW[nPatternOfs + 1] == L'!');
          if (bReverse != FALSE)
            nPatternOfs++;

          // match character class
          bMatched = FALSE;
          for (dwLastChr = 0xFFFFFFFFUL;
               ++nPatternOfs < nPatternLen && szPatternW[nPatternOfs] != L']';
               dwLastChr = CharToUpperW(szPatternW[nPatternOfs]))
          {
            if ((dwLastChr < 0xFFFFFFFFUL &&
                 szPatternW[nPatternOfs] == L'-' &&
                 nPatternOfs + 1 < nPatternLen && szPatternW[nPatternOfs + 1] != L']')
                ? (CharToUpperW(szTextW[nTextOfs]) <= CharToUpperW(szPatternW[++nPatternOfs]) &&
                   (DWORD)CharToUpperW(szTextW[nTextOfs]) >= dwLastChr)
                : (CharToUpperW(szTextW[nTextOfs]) == CharToUpperW(szPatternW[nPatternOfs])))
            {
              bMatched = TRUE;
            }
          }
          if (bMatched == bReverse)
            break;
          nTextOfs++;
          if (nPatternOfs < nPatternLen)
            nPatternOfs++;
          }
          continue;

        //case L'\\':
        //  // literal match \-escaped character
        //  if (nPatternOfs + 1 < nPatternLen)
        //    nPatternOfs++;
        //  //fall through

        default:
          // match the current non-NUL character
          if (CharToUpperW(szPatternW[nPatternOfs]) != CharToUpperW(szTextW[nTextOfs]) &&
              (!(szPatternW[nPatternOfs] == L'\\' && szTextW[nTextOfs] == L'\\')))
          {
            break;
          }
          // do not match a . with *, ? [] after /
          nTextOfs++;
          nPatternOfs++;
          continue;
      }
    }
    if (nPattern1Backup != (SIZE_T)-1 && szPatternW[nPattern1Backup] != L'\\')
    {
      // *-loop: backtrack to the last * but do not jump over /
      nTextOfs = ++nText1Backup;
      nPatternOfs = nPattern1Backup;
      continue;
    }
    if (nPattern2Backup != (SIZE_T)-1)
    {
      // **-loop: backtrack to the last **
      nTextOfs = ++nText2Backup;
      nPatternOfs = nPattern2Backup;
      continue;
    }
    return FALSE;
  }
  //ignore trailing stars
  while (nPatternOfs < nPatternLen && szPatternW[nPatternOfs] == L'*')
    nPatternOfs++;
  //at end of text means success if nothing else is left to match
  return (nPatternOfs >= nPatternLen) ? TRUE : FALSE;
}

BOOL String2Guid(_Out_ GUID &sGuid, _In_ LPCSTR szGuidA, _In_ SIZE_T nGuidLength)
{
  DWORD i, dwVal;

  if (nGuidLength == (SIZE_T)-1)
    nGuidLength = MX::StrLenA(szGuidA);

  if ((nGuidLength != 36 && nGuidLength != 38) || szGuidA == NULL)
  {
err_badformat:
    ::MxMemSet(&sGuid, 0, sizeof(sGuid));
    return FALSE;
  }
  if (nGuidLength == 38)
  {
    if (szGuidA[0] != '{' || szGuidA[37] != '}')
      goto err_badformat;
    szGuidA++;
  }

  ::MxMemSet(&sGuid, 0, sizeof(sGuid));
  for (i = 0; i < 36; i++, szGuidA++)
  {
    switch (i)
    {
      case 8:
      case 13:
      case 18:
      case 23:
        if (*szGuidA != '-')
          goto err_badformat;
        break;

      case 14: //1-5
        if ((*szGuidA) < '1' || (*szGuidA) > '5')
          goto err_badformat;
        dwVal = (DWORD)(*szGuidA - '0');
        goto set_value;

      case 19: //8-A
        if ((*szGuidA) >= '8' && (*szGuidA) <= '9')
          dwVal = (DWORD)((*szGuidA) - '0');
        else if ((*szGuidA) >= 'A' && (*szGuidA) <= 'B')
          dwVal = (DWORD)((*szGuidA) - 'A') + 10;
        else if ((*szGuidA) >= 'a' && (*szGuidA) <= 'b')
          dwVal = (DWORD)((*szGuidA) - 'a') + 10;
        else
          goto err_badformat;
        goto set_value;

      default:
        if ((*szGuidA) >= '0' && (*szGuidA) <= '9')
          dwVal = (DWORD)((*szGuidA) - '0');
        else if ((*szGuidA) >= 'A' && (*szGuidA) <= 'F')
          dwVal = (DWORD)((*szGuidA) - 'A') + 10;
        else if ((*szGuidA) >= 'a' && (*szGuidA) <= 'f')
          dwVal = (DWORD)((*szGuidA) - 'a') + 10;
        else
          goto err_badformat;

set_value:
        if (i < 8)
          sGuid.Data1 |= dwVal << ((7 - i) << 2);
        else if (i < 13)
          sGuid.Data2 |= (USHORT)dwVal << ((12 - i) << 2);
        else if (i < 18)
          sGuid.Data3 |= (USHORT)dwVal << ((17 - i) << 2);
        else if (i < 21)
          sGuid.Data4[0] |= (BYTE)dwVal << ((20 - i) << 2);
        else if (i < 23)
          sGuid.Data4[1] |= (BYTE)dwVal << ((22 - i) << 2);
        else
          sGuid.Data4[2 + ((i - 24) >> 1)] |= (BYTE)dwVal << ((1 - (i & 1)) << 2);
        break;
    }
  }

  //done
  return TRUE;
}

BOOL String2Guid(_Out_ GUID &sGuid, _In_ LPCWSTR szGuidW, _In_ SIZE_T nGuidLength)
{
  CHAR szBufA[36];
  SIZE_T i;

  if (nGuidLength == (SIZE_T)-1)
    nGuidLength = MX::StrLenW(szGuidW);
  ::MxMemSet(&sGuid, 0, sizeof(sGuid));

  if ((nGuidLength != 36 && nGuidLength != 38) || szGuidW == NULL)
  {
err_badformat:
    ::MxMemSet(&sGuid, 0, sizeof(sGuid));
    return FALSE;
  }
  if (nGuidLength == 38)
  {
    if (szGuidW[0] != L'{' || szGuidW[37] != L'}')
      goto err_badformat;
    szGuidW++;
  }

  for (i = 0; i < 36; i++, szGuidW++)
  {
    if (((*szGuidW) >= L'0' && (*szGuidW) <= L'9') ||
        ((*szGuidW) >= L'A' && (*szGuidW) <= L'F') ||
        ((*szGuidW) >= L'a' && (*szGuidW) <= L'f') || (*szGuidW) == L'-')
    {
      szBufA[i] = (CHAR)(BYTE)(USHORT)(*szGuidW);
    }
    else
    {
      return FALSE;
    }
  }

  return String2Guid(sGuid, szBufA, 36);
}

HRESULT ExecuteApp(_In_z_ LPCWSTR szCmdLineW, _In_ DWORD dwAfterSeconds)
{
  CStringW cStrTempW;
  HRESULT hRes;

  if (szCmdLineW == NULL)
    return E_POINTER;
  if (*szCmdLineW == 0 || dwAfterSeconds < 1)
    return E_INVALIDARG;

  hRes = FileRoutines::GetWindowsSystemPath(cStrTempW);
  if (SUCCEEDED(hRes))
  {
    if (cStrTempW.InsertN(L"\"", 0, 1) != FALSE &&
        cStrTempW.AppendFormat(L"CMD.EXE\" /C PING 127.0.0.1 -n %lu & ", dwAfterSeconds) != FALSE &&
        cStrTempW.Concat(szCmdLineW) != FALSE)
    {
      STARTUPINFOW sSiW;
      PROCESS_INFORMATION sPi;

      ::MxMemSet(&sSiW, 0, sizeof(sSiW));
      sSiW.cb = (DWORD)sizeof(sSiW);
      ::MxMemSet(&sPi, 0, sizeof(sPi));
      if (::CreateProcessW(NULL, (LPWSTR)cStrTempW, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &sSiW,
                           &sPi) != FALSE)
      {
        ::CloseHandle(sPi.hThread);
        ::CloseHandle(sPi.hProcess);
      }
      else
      {
        hRes = MX_HRESULT_FROM_LASTERROR();
      }
    }
    else
    {
      hRes = E_OUTOFMEMORY;
    }
  }
  //done
  return hRes;
}

HRESULT ExecuteApp(_In_ BOOL bWait, _In_ BOOL bHide, _In_z_ LPCWSTR szAppNameW, _In_ ULONG nParamsCount, ...)
{
  MX::CStringW cStrCmdLineW;
  STARTUPINFOW sSiW;
  PROCESS_INFORMATION sPi;
  DWORD dwCreationFlags;
  va_list argptr;
  HRESULT hRes;

  if (szAppNameW == NULL)
    return E_POINTER;
  if (szAppNameW[0] == 0)
    return E_INVALIDARG;

  //quote application name if needed
  if (MX::StrChrW(szAppNameW, L' ') != NULL)
  {
    if (cStrCmdLineW.Format(L"\"%s\"", szAppNameW) == FALSE)
      return E_OUTOFMEMORY;
  }
  else
  {
    if (cStrCmdLineW.Copy(szAppNameW) == FALSE)
      return E_OUTOFMEMORY;
  }

  //process arguments
  va_start(argptr, nParamsCount);
  for (ULONG i = nParamsCount; i > 0; i--)
  {
    LPCWSTR szParamW = va_arg(argptr, LPCWSTR);

    if (szParamW == NULL || szParamW[0] == 0)
      continue;

    //insert separator
    if (cStrCmdLineW.ConcatN(L" ", 1) == FALSE)
      return E_OUTOFMEMORY;

    //insert parameter
    if (MX::StrChrW(szParamW, L' ') != FALSE || MX::StrChrW(szParamW, L'\t') != FALSE ||
        MX::StrChrW(szParamW, L'\n') != FALSE || MX::StrChrW(szParamW, L'\v') != FALSE ||
        MX::StrChrW(szParamW, L'\"') != FALSE)
    {
      //escape parameter

      //opening quotes
      if (cStrCmdLineW.ConcatN(L"\"", 1) == FALSE)
      {
        va_end(argptr);
        return E_OUTOFMEMORY;
      }

      for (;;)
      {
        SIZE_T nBackSlashCounter = 0;

        while (*szParamW == L'\\')
        {
          szParamW += 1;
          nBackSlashCounter += 1;
        }

        if (*szParamW == 0)
        {
          //escape all backslashes, but let the terminating double quotation mark we add below be interpreted
          //as a metacharacter
          if (AddRepeatedChar(cStrCmdLineW, L'\\', nBackSlashCounter * 2) == FALSE)
          {
            va_end(argptr);
            return E_OUTOFMEMORY;
          }
          break;
        }

        if (*szParamW == L'"')
        {
          //escape all backslashes and the following double quotation mark
          nBackSlashCounter = nBackSlashCounter * 2 + 1;
        }
        //else backslashes aren't special

        if (AddRepeatedChar(cStrCmdLineW, L'\\', nBackSlashCounter) == FALSE ||
            cStrCmdLineW.ConcatN(szParamW, 1) == FALSE)
        {
          va_end(argptr);
          return E_OUTOFMEMORY;
        }

        //advance char
        szParamW += 1;
      }

      //closing quotes
      if (cStrCmdLineW.ConcatN(L"\"", 1) == FALSE)
        return E_OUTOFMEMORY;
    }
    else
    {
      if (cStrCmdLineW.Concat(szParamW) == FALSE)
        return E_OUTOFMEMORY;
    }
  }
  va_end(argptr);

  //prepare to execute process
  ::MxMemSet(&sSiW, 0, sizeof(sSiW));
  sSiW.cb = (DWORD)sizeof(sSiW);
  ::MxMemSet(&sPi, 0, sizeof(sPi));

  dwCreationFlags = 0;
  if (bHide != FALSE)
  {
    dwCreationFlags |= CREATE_NO_WINDOW;
    sSiW.dwFlags |= STARTF_USESHOWWINDOW;
    sSiW.wShowWindow = SW_HIDE;
  }

  //run child process
  if (::CreateProcessW(NULL, (LPWSTR)cStrCmdLineW, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &sSiW,
                       &sPi) == FALSE)
  {
    return MX_HRESULT_FROM_LASTERROR();
  }

  //wait for exit code if requested
  if (bWait != FALSE)
  {
    DWORD dwExitCode;

    ::WaitForSingleObject(sPi.hProcess, INFINITE);
    ::GetExitCodeProcess(sPi.hProcess, &dwExitCode);

    hRes = MX_HRESULT_FROM_WIN32(dwExitCode);
  }
  else
  {
    hRes = S_OK;
  }

  //cleanup
  ::CloseHandle(sPi.hThread);
  ::CloseHandle(sPi.hProcess);

  //done
  return hRes;
}

HRESULT SelfDeleteApp(_In_ DWORD dwAfterSeconds)
{
  CStringW cStrAppNameW, cStrCmdExeW;
  WCHAR szSecondsW[16];
  HRESULT hRes;

  hRes = FileRoutines::GetAppFileName(cStrAppNameW);
  if (FAILED(hRes))
    return hRes;

  hRes = FileRoutines::GetWindowsSystemPath(cStrCmdExeW);
  if (FAILED(hRes))
    return hRes;
  if (cStrCmdExeW.ConcatN(L"CMD.EXE", 7) == FALSE)
    return E_OUTOFMEMORY;

  _snwprintf_s(szSecondsW, _countof(szSecondsW), _TRUNCATE, L"%lu", dwAfterSeconds);

  //done
  return ExecuteApp(FALSE, TRUE, (LPCWSTR)cStrCmdExeW, 8, L"/C", L"PING", L"127.0.0.1", L"-n", szSecondsW, L"&",
                    L"DEL", (LPCWSTR)cStrAppNameW);
}

}; //namespace Misc

}; //namespace MX

//-----------------------------------------------------------

static BOOL AddRepeatedChar(_Inout_ MX::CStringW &cStrW, _In_ WCHAR chW, _In_ SIZE_T nCount)
{
  while (nCount > 0)
  {
    if (cStrW.ConcatN(&chW, 1) == FALSE)
      return FALSE;
    nCount -= 1;
  }
  return TRUE;
}
