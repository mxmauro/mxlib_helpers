#include "FileVersionInfo.h"
#include "PeParser.h"
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "version.lib")

//-----------------------------------------------------------

static VS_FIXEDFILEINFO sNoFixedInfo = { 0 };

//-----------------------------------------------------------

namespace MX {

CFileVersionInfo::CFileVersionInfo() : CBaseMemObj()
{
  lpFfi = &sNoFixedInfo;
  lpTranslationBlock = NULL;
  nTranslationBlocksCount = 0;
  return;
}

HRESULT CFileVersionInfo::InitializeFromFileName(_In_z_ LPCWSTR szFileNameW)
{
  CPEParser cPeParser;
  HRESULT hRes;

  hRes = cPeParser.InitializeFromFileName(szFileNameW, MX_PEPARSER_FLAG_ParseResources);
  if (SUCCEEDED(hRes))
    hRes = AnalyzeVersionInfo(&cPeParser);
  return hRes;
}

HRESULT CFileVersionInfo::InitializeFromFileHandle(_In_ HANDLE hFile)
{
  CPEParser cPeParser;
  HRESULT hRes;

  hRes = cPeParser.InitializeFromFileHandle(hFile, MX_PEPARSER_FLAG_ParseResources);
  if (SUCCEEDED(hRes))
    hRes = AnalyzeVersionInfo(&cPeParser);
  return hRes;
}

HRESULT CFileVersionInfo::InitializeFromProcessHandle(_In_opt_ HANDLE hProc)
{
  CPEParser cPeParser;
  HRESULT hRes;

  hRes = cPeParser.InitializeFromProcessHandle(hProc, MX_PEPARSER_FLAG_ParseResources);
  if (SUCCEEDED(hRes))
    hRes = AnalyzeVersionInfo(&cPeParser);
  return hRes;
}

WORD CFileVersionInfo::GetLanguage(_In_opt_ SIZE_T nIndex) const
{
  return (nIndex < nTranslationBlocksCount) ? lpTranslationBlock[nIndex].wLang : 0;
}

WORD CFileVersionInfo::GetCharset(_In_opt_ SIZE_T nIndex) const
{
  return (nIndex < nTranslationBlocksCount) ? lpTranslationBlock[nIndex].wCharSet : 0;
}

HRESULT CFileVersionInfo::GetString(_In_z_ LPCWSTR szFieldW, _Inout_ CStringW &cStrW, _In_opt_ SIZE_T nLangIndex)
{
  WCHAR szStrFileInfoW[256];
  LPCWSTR sW;
  UINT i, nLen, nMaxLen;

  cStrW.Empty();
  if (szFieldW == NULL)
    return E_POINTER;
  if (*szFieldW == 0 || StrLenW(szFieldW) > 128 || nLangIndex >= nTranslationBlocksCount)
    return E_INVALIDARG;
  _snwprintf_s(szStrFileInfoW, _countof(szStrFileInfoW), _TRUNCATE, L"\\StringFileInfo\\%04X%04X\\%s",
               lpTranslationBlock[nLangIndex].wLang, lpTranslationBlock[nLangIndex].wCharSet, szFieldW);
  __try
  {
    if (::VerQueryValueW(cVersionInfo.Get(), szStrFileInfoW, (LPVOID*)&sW, &nMaxLen) == FALSE)
      return MX_E_NotFound;
    for (nLen=0; nLen<nMaxLen && sW[nLen]!=0; nLen++);
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    return MX_E_UnhandledException;
  }
  while (nLen > 0 && *sW <= 32)
  {
    sW++;
    nLen--;
  }
  while (nLen > 0 && sW[nLen - 1] <= 32)
    nLen--;
  if (cStrW.CopyN(sW, nLen) == FALSE)
    return E_OUTOFMEMORY;
  for (i=0; i<nLen; i++)
  {
    if (((LPWSTR)cStrW)[i] < 32)
      ((LPWSTR)cStrW)[i] = 32;
  }
  //done
  return S_OK;
}

MX_UNICODE_STRING CFileVersionInfo::GetString(_In_z_ LPCWSTR szFieldW, _In_opt_ SIZE_T nLangIndex)
{
  MX_UNICODE_STRING usRes = { 0 };
  WCHAR szStrFileInfoW[256];
  PWSTR sW;
  UINT nLen, nMaxLen;

  if (szFieldW != NULL && *szFieldW != 0 && StrLenW(szFieldW) <= 128 && nLangIndex < nTranslationBlocksCount)
  {
    _snwprintf_s(szStrFileInfoW, _countof(szStrFileInfoW), _TRUNCATE, L"\\StringFileInfo\\%04X%04X\\%s",
                 lpTranslationBlock[nLangIndex].wLang, lpTranslationBlock[nLangIndex].wCharSet, szFieldW);
    __try
    {
      if (::VerQueryValueW(cVersionInfo.Get(), szStrFileInfoW, (LPVOID*)&sW, &nMaxLen) != FALSE)
      {
        for (nLen=0; nLen<nMaxLen && nLen<32767 && sW[nLen]!=0; nLen++);
        while (nLen > 0 && *sW <= 32)
        {
          sW++;
          nLen--;
        }
        while (nLen > 0 && sW[nLen - 1] <= 32)
          nLen--;
        usRes.Buffer = sW;
        usRes.Length = usRes.MaximumLength = (USHORT)nLen * 2;
      }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
      MemSet(&usRes, 0, sizeof(usRes));
    }
  }
  //done
  return usRes;
}

HRESULT CFileVersionInfo::AnalyzeVersionInfo(_In_ LPVOID _lpPeParser)
{
  CPEParser *lpPeParser = (CPEParser*)_lpPeParser;
  UINT nLen;

  if (lpPeParser->GetVersionInfoSize() > 0)
  {
    cVersionInfo.Attach((LPBYTE)MX_MALLOC(lpPeParser->GetVersionInfoSize()));
    if (!cVersionInfo)
      return E_OUTOFMEMORY;
    MemCopy(cVersionInfo.Get(), lpPeParser->GetVersionInfo(), lpPeParser->GetVersionInfoSize());
    __try
    {
      if (::VerQueryValueW(cVersionInfo.Get(), L"\\", (LPVOID*)&lpFfi, &nLen) == FALSE)
        goto set_default;
      if ((SIZE_T)nLen < sizeof(VS_FIXEDFILEINFO) || lpFfi->dwSignature != VS_FFI_SIGNATURE)
        goto set_default;
      if (::VerQueryValueW(cVersionInfo.Get(), L"\\VarFileInfo\\Translation\\", (LPVOID*)&lpTranslationBlock,
                           &nLen) == FALSE)
      {
        goto set_default;
      }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
      goto set_default;
    }
    nTranslationBlocksCount = (SIZE_T)nLen / sizeof(TRANSLATION_BLOCK);
    if (nTranslationBlocksCount == 0)
      lpTranslationBlock = NULL;
  }
  else
  {
set_default:
    lpFfi = &sNoFixedInfo;
    nTranslationBlocksCount = 0;
    lpTranslationBlock = NULL;
  }
  //done
  return S_OK;
}

}; //namespace MX
