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

HRESULT SelfDeleteApp(_In_ DWORD dwAfterSeconds)
{
  CStringW cStrCmdW;
  HRESULT hRes;

  hRes = FileRoutines::GetAppFileName(cStrCmdW);
  if (SUCCEEDED(hRes))
  {
    if (cStrCmdW.InsertN(L"DEL \"", 0, 5) != FALSE && cStrCmdW.ConcatN("\"", 1) != FALSE)
    {
      hRes = ExecuteApp((LPCWSTR)cStrCmdW, dwAfterSeconds);
    }
    else
    {
      hRes = E_OUTOFMEMORY;
    }
  }
  //done
  return hRes;
}

}; //namespace Misc

}; //namespace MX
