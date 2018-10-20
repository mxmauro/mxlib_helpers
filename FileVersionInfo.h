/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#ifndef _MXLIBHLP_FILE_VERSION_INFO_H
#define _MXLIBHLP_FILE_VERSION_INFO_H

#include <Defines.h>
#include <AutoPtr.h>
#include <Strings\Strings.h>

//-----------------------------------------------------------

namespace MXHelpers {

class CFileVersionInfo : public MX::CBaseMemObj
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

  HRESULT GetString(_In_z_ LPCWSTR szFieldW, _Inout_ MX::CStringW &cStrW, _In_opt_ SIZE_T nLangIndex=0);
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

  MX::TAutoFreePtr<BYTE> cVersionInfo;
  VS_FIXEDFILEINFO *lpFfi;
  LPTRANSLATION_BLOCK lpTranslationBlock;
  SIZE_T nTranslationBlocksCount;
};

}; //namespace MXHelpers

//-----------------------------------------------------------

#endif //_MXLIBHLP_FILE_VERSION_INFO_H
