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
#ifndef _MXLIBHLP_PE_PARSER_H
#define _MXLIBHLP_PE_PARSER_H

#include <Defines.h>
#include <AutoPtr.h>
#include <ArrayList.h>
#include <Strings\Strings.h>

#define MX_PEPARSER_FLAG_ParseResources               0x0001
#define MX_PEPARSER_FLAG_ParseExportTable             0x0002
#define MX_PEPARSER_FLAG_ParseImportTables            0x0004
#define MX_PEPARSER_FLAG_IgnoreMalformed              0x1000

//-----------------------------------------------------------

namespace MX {

class CPEParser : public CBaseMemObj, public CNonCopyableObj
{
public:
  typedef struct tagEXPORTED_FUNCTION {
    DWORD dwOrdinal;
    DWORD dwAddressRVA;
    LPVOID lpAddress;
    LPSTR szForwardsToA; //NULL if not a forward
    CHAR szNameA[1];
  } EXPORTED_FUNCTION, *LPEXPORTED_FUNCTION;

  typedef struct tagIMPORTED_FUNCTION {
    DWORD dwOrdinal; //0xFFFFFFFF if not used
    LPVOID lpAddress; //can be NULL on non-running images
    CHAR szNameA[1];
  } IMPORTED_FUNCTION, *LPIMPORTED_FUNCTION;

public:
  CPEParser();
  ~CPEParser();

  HRESULT InitializeFromFileName(_In_z_ LPCWSTR szFileNameW, _In_opt_ DWORD dwParseFlags = 0xFFFFFFFFUL);
  HRESULT InitializeFromFileHandle(_In_ HANDLE hFile, _In_opt_ DWORD dwParseFlags = 0xFFFFFFFFUL);
  HRESULT InitializeFromProcessHandle(_In_opt_ HANDLE hProc, _In_opt_ DWORD dwParseFlags = 0xFFFFFFFFUL);
  HRESULT InitializeFromMemory(_In_ LPCVOID lpBaseAddress, _In_ SIZE_T nImageSize, _In_ BOOL bImageIsMapped,
                               _In_opt_ DWORD dwParseFlags = 0xFFFFFFFFUL);
  VOID Finalize();

  WORD GetMachineType() const
    {
    return wMachine;
    };

  PIMAGE_DOS_HEADER GetDosHeader() const
    {
    return &(const_cast<CPEParser*>(this)->sDosHdr);
    };

  PIMAGE_NT_HEADERS32 GetNtHeaders32() const
    {
    return &(const_cast<CPEParser*>(this)->uNtHdr.s32);
    };

#if defined(_M_X64)
  PIMAGE_NT_HEADERS64 GetNtHeaders64() const
    {
    return &(const_cast<CPEParser*>(this)->uNtHdr.s64);
    };
#endif //_M_X64

  SIZE_T GetSectionsCount() const
    {
    return nSectionsCount;
    };

  PIMAGE_SECTION_HEADER GetSection(_In_ SIZE_T nSectionIndex) const
    {
    MX_ASSERT(nSectionIndex < nSectionsCount);
    return const_cast<CPEParser*>(this)->cFileImgSect.Get() + nSectionIndex;
    };

  SIZE_T GetImportedDllsCount() const
    {
    return sImportsInfo.aDllList.GetCount();
    };

  LPCSTR GetImportedDllName(_In_ SIZE_T nDllIndex) const
    {
    MX_ASSERT(nDllIndex < sImportsInfo.aDllList.GetCount());
    return (LPCSTR)(sImportsInfo.aDllList[nDllIndex]->cStrNameA);
    };

  SIZE_T GetImportedFunctionsCount(_In_ SIZE_T nDllIndex) const
    {
    MX_ASSERT(nDllIndex < sImportsInfo.aDllList.GetCount());
    return sImportsInfo.aDllList[nDllIndex]->aEntries.GetCount();
    };

  LPIMPORTED_FUNCTION GetImportedFunction(_In_ SIZE_T nDllIndex, _In_ SIZE_T nFuncIndex) const
    {
    MX_ASSERT(nDllIndex < sImportsInfo.aDllList.GetCount());
    MX_ASSERT(nFuncIndex < sImportsInfo.aDllList[nDllIndex]->aEntries.GetCount());
    return sImportsInfo.aDllList[nDllIndex]->aEntries.GetElementAt(nFuncIndex);
    };

  SIZE_T GetExportedFunctionsCount() const
    {
    return sExportsInfo.aEntries.GetCount();
    };

  LPEXPORTED_FUNCTION GetExportedFunction(_In_ SIZE_T nFuncIndex) const
    {
    MX_ASSERT(nFuncIndex < sExportsInfo.aEntries.GetCount());
    return sExportsInfo.aEntries.GetElementAt(nFuncIndex);
    };

  LPBYTE GetVersionInfo() const
    {
    return const_cast<CPEParser*>(this)->cVersionInfo.Get();
    };

  SIZE_T GetVersionInfoSize() const
    {
    return nVersionInfoSize;
    };

  //NOTE: Returns NULL if invalid RVA
  LPBYTE RvaToVa(_In_ DWORD dwVirtualAddress);

  BOOL ReadRaw(_Out_writes_(nBytes) LPVOID lpDest, _In_ LPCVOID lpSrc, _In_ SIZE_T nBytes);
  HRESULT ReadAnsiString(_Out_ CStringA &cStrA, _In_ LPVOID lpNameAddress, _In_ SIZE_T nMaxLength);

private:
  VOID ClearVars();

  HRESULT DoParse(_In_ DWORD dwParseFlags);
  HRESULT DoParseImportTable(_In_ PIMAGE_IMPORT_DESCRIPTOR lpImportDesc);
  HRESULT DoParseExportTable(_In_ PIMAGE_EXPORT_DIRECTORY lpExportDir, _In_ DWORD dwStartRVA, _In_ DWORD dwEndRVA);
  HRESULT DoParseResources();

  HRESULT _FindResource(_In_ LPCWSTR szNameW, _In_ LPCWSTR szTypeW, _In_ WORD wLang, _Out_ LPBYTE *lplpData,
                        _Out_ SIZE_T *lpnDataSize);
  HRESULT LookupResourceEntry(_In_ PIMAGE_RESOURCE_DIRECTORY lpRootDir, _In_ PIMAGE_RESOURCE_DIRECTORY lpDir,
                              _In_ LPCWSTR szKeyW, _Out_ PIMAGE_RESOURCE_DIRECTORY_ENTRY *lplpDirEntry);

private:
  HANDLE hFile;
  HANDLE hProc;

  LPBYTE lpBaseAddress;
  SIZE_T nDataSize;
  BOOL bImageIsMapped;
  struct {
    BYTE aBuffer[8192];
    SIZE_T nOffset, nLength;
  } sFileCache;

  WORD wMachine;
  LPVOID lpOriginalImageBaseAddress;

  IMAGE_DOS_HEADER sDosHdr;
  union {
    IMAGE_NT_HEADERS32 s32;
#if defined(_M_X64)
    IMAGE_NT_HEADERS64 s64;
#endif //_M_X64
  } uNtHdr;

  SIZE_T nSectionsCount;
  TAutoFreePtr<IMAGE_SECTION_HEADER> cFileImgSect;

  class CImportedDll : public CBaseMemObj
  {
  public:
    CStringA cStrNameA;
    TArrayListWithFree<LPIMPORTED_FUNCTION> aEntries;
  };

  struct {
    TArrayListWithDelete<CImportedDll*> aDllList;
  } sImportsInfo;

  struct {
    DWORD dwCharacteristics;
    WORD wMajorVersion;
    WORD wMinorVersion;
    TArrayListWithFree<LPEXPORTED_FUNCTION> aEntries;
  } sExportsInfo;

  PIMAGE_RESOURCE_DIRECTORY lpResourceDir;

  TAutoFreePtr<BYTE> cVersionInfo;
  SIZE_T nVersionInfoSize;
};

}; //namespace MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_FILE_VERSION_INFO_H
