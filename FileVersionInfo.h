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
#ifndef _MXLIBHLP_FILE_VERSION_INFO_H
#define _MXLIBHLP_FILE_VERSION_INFO_H

#include <Defines.h>
#include <AutoPtr.h>
#include <Strings\Strings.h>

//-----------------------------------------------------------

namespace MX {

class CFileVersionInfo : public CBaseMemObj, public CNonCopyableObj
{
public:
  CFileVersionInfo();

  HRESULT InitializeFromFileName(_In_z_ LPCWSTR szFileNameW);
  HRESULT InitializeFromFileHandle(_In_ HANDLE hFile);
  HRESULT InitializeFromProcessHandle(_In_opt_ HANDLE hProc);

  SIZE_T GetLanguagesCount() const
    {
    return nTranslationBlocksCount;
    };

  WORD GetLanguage(_In_opt_ SIZE_T nIndex) const;
  WORD GetCharset(_In_opt_ SIZE_T nIndex) const;

  HRESULT GetString(_In_z_ LPCWSTR szFieldW, _Inout_ CStringW &cStrW, _In_opt_ SIZE_T nLangIndex=0);
  MX_UNICODE_STRING GetString(_In_z_ LPCWSTR szFieldW, _In_opt_ SIZE_T nLangIndex=0);

  VS_FIXEDFILEINFO* operator->() const
    {
    return lpFfi;
    };

private:
  HRESULT AnalyzeVersionInfo(_In_ LPVOID lpPeParser);

private:
#pragma pack(1)
  typedef struct {
    WORD wLang;
    WORD wCharSet;
  } TRANSLATION_BLOCK, *LPTRANSLATION_BLOCK;
#pragma pack()

  TAutoFreePtr<BYTE> cVersionInfo;
  VS_FIXEDFILEINFO *lpFfi;
  LPTRANSLATION_BLOCK lpTranslationBlock;
  SIZE_T nTranslationBlocksCount;
};

}; //namespace MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_FILE_VERSION_INFO_H
