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
#include "PeParser.h"
#include "FileRoutines.h"
#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>

//-----------------------------------------------------------

#define MAX_EXPORTS_COUNT                              65536
#define MAX_EXPORTS_FUNCTION_NAME_LENGTH                 512
#define MAX_EXPORTS_FORWARDER_NAME_LENGTH                512

#define MAX_IMPORTS_PER_DLL_COUNT                      65536
#define MAX_IMPORTS_DLL_NAME_LENGTH                      512
#define MAX_IMPORTS_FUNCTION_NAME_LENGTH                 512

#define __ALLOCATION_GRANULARITY                       65536
#define __CACHE_SIZE          (4 * __ALLOCATION_GRANULARITY)

#define ViewShare 1

//-----------------------------------------------------------

namespace MX {

CPEParser::CPEParser() : CBaseMemObj(), CNonCopyableObj()
{
  ClearVars();
  return;
}

CPEParser::~CPEParser()
{
  Finalize();
  return;
}

HRESULT CPEParser::InitializeFromFileName(_In_z_ LPCWSTR szFileNameW, _In_opt_ DWORD dwParseFlags)
{
  CWindowsHandle cFileH;
  HRESULT hRes;

  Finalize();

  //open file
  hRes = FileRoutines::OpenFileWithEscalatingSharing(szFileNameW, &cFileH);
  if (SUCCEEDED(hRes))
    hRes = InitializeFromFileHandle(cFileH.Get(), dwParseFlags);
  //done
  return hRes;
}

HRESULT CPEParser::InitializeFromFileHandle(_In_ HANDLE _hFile, _In_opt_ DWORD dwParseFlags)
{
  ULARGE_INTEGER uliFileSize;
  HRESULT hRes;

  if (_hFile == NULL || _hFile == INVALID_HANDLE_VALUE)
    return E_INVALIDARG;

  Finalize();

  if (::DuplicateHandle(::GetCurrentProcess(), _hFile, ::GetCurrentProcess(), &hFile, 0, FALSE,
                        DUPLICATE_SAME_ACCESS) == FALSE)
  {
    return MX_HRESULT_FROM_LASTERROR();
  }

  if (::GetFileSizeEx(hFile, (PLARGE_INTEGER)&uliFileSize) == FALSE)
    return MX_HRESULT_FROM_LASTERROR();
#if defined(_M_IX86)
  nDataSize = (uliFileSize.HighPart != 0) ? 0xFFFFFFFFUL : (SIZE_T)(uliFileSize.LowPart);
#elif defined(_M_X64)
  nDataSize = uliFileSize.QuadPart;
#else
  #error Unsupported platform
#endif

  lpBaseAddress = (LPBYTE)0x100000; //dummy value used as a reference

  //parse PE
  hRes = DoParse(dwParseFlags);
  if (FAILED(hRes))
  {
    Finalize();
    return hRes;
  }

  //done
  return S_OK;
}

HRESULT CPEParser::InitializeFromProcessHandle(_In_opt_ HANDLE _hProc, _In_opt_ DWORD dwParseFlags)
{
  LPBYTE lpPeb;
#if defined(_M_X64)
  BOOL bIs32BitProcess = FALSE;
#endif //_M_X64
  ULONG dwTemp;
  SIZE_T nRead;
  HRESULT hRes;

  //get process' PEB
  if (_hProc == NULL || _hProc == MX_CURRENTPROCESS)
  {
#if defined(_M_IX86)
    lpPeb = (LPBYTE)__readfsdword(0x30); //get PEB from the TIB
#elif defined(_M_X64)
    LPBYTE lpPtr = (LPBYTE)__readgsqword(0x30); //get TEB
    lpPeb = *((LPBYTE*)(lpPtr + 0x60));
#else
  #error Unsupported platform
#endif
  }
  else
  {
#if defined(_M_X64)
    ULONGLONG nPeb32;
#endif
    PROCESS_BASIC_INFORMATION sPbi;
    ULONG k;
    NTSTATUS nNtStatus;

    if (::DuplicateHandle(::GetCurrentProcess(), _hProc, ::GetCurrentProcess(), &hProc, 0, FALSE,
                          DUPLICATE_SAME_ACCESS) == FALSE)
    {
      hRes = MX_HRESULT_FROM_LASTERROR();
      Finalize();
      return hRes;
    }

#if defined(_M_X64)
    nNtStatus = ::MxNtQueryInformationProcess(hProc, MxProcessWow64Information, &nPeb32, (ULONG)sizeof(nPeb32), &k);
    if (NT_SUCCESS(nNtStatus) && nPeb32 != 0)
    {
      lpPeb = (LPBYTE)nPeb32;
      bIs32BitProcess = TRUE;
    }
    else
    {
#endif //_M_X64
      nNtStatus = ::MxNtQueryInformationProcess(hProc, MxProcessBasicInformation, &sPbi, (ULONG)sizeof(sPbi), &k);
      if (!NT_SUCCESS(nNtStatus))
      {
        Finalize();
        return MX_HRESULT_FROM_WIN32(::MxRtlNtStatusToDosError(nNtStatus));
      }
      lpPeb = (LPBYTE)sPbi.PebBaseAddress;
#if defined(_M_X64)
    }
#endif //_M_X64
  }

  //read ImageBaseAddress from PEB
#if defined(_M_X64)
  if (bIs32BitProcess == FALSE)
  {
    ULONGLONG qwTemp;

    if (hProc != NULL)
    {
      if (::ReadProcessMemory(hProc, lpPeb + 0x10, &qwTemp, sizeof(qwTemp), &nRead) == FALSE || nRead != sizeof(qwTemp))
      {
        Finalize();
        return MX_E_ReadFault;
      }
    }
    else
    {
      if (::MxTryMemCopy(&qwTemp, lpPeb + 0x10, sizeof(qwTemp)) != sizeof(qwTemp))
      {
        Finalize();
        return MX_E_ReadFault;
      }
    }
    lpBaseAddress = (LPBYTE)qwTemp;
  }
  else
  {
#endif //_M_X64
    if (hProc != NULL)
    {
      if (::ReadProcessMemory(hProc, lpPeb + 0x08, &dwTemp, sizeof(dwTemp), &nRead) == FALSE || nRead != sizeof(dwTemp))
      {
        Finalize();
        return MX_E_ReadFault;
      }
    }
    else
    {
      if (::MxTryMemCopy(&dwTemp, lpPeb + 0x08, sizeof(dwTemp)) != sizeof(dwTemp))
      {
        Finalize();
        return MX_E_ReadFault;
    }
    }
#if defined(_M_X64)
    lpBaseAddress = (LPBYTE)UlongToPtr(dwTemp);
#else //_M_X64
    lpBaseAddress = (LPBYTE)dwTemp;
#endif //_M_X64
#if defined(_M_X64)
  }
#endif //_M_X64

  nDataSize = 0x80000000; //we can do a fine-tunning of image size but this should be enough

  //setup image mapping type
  bImageIsMapped = TRUE;

  //parse PE
  hRes = DoParse(dwParseFlags);
  if (FAILED(hRes))
  {
    Finalize();
    return hRes;
  }

  //done
  return S_OK;
}

HRESULT CPEParser::InitializeFromMemory(_In_ LPCVOID _lpBaseAddress, _In_ SIZE_T nImageSize, _In_ BOOL _bImageIsMapped,
                                        _In_opt_ DWORD dwParseFlags)
{
  HRESULT hRes;

  if (_lpBaseAddress == NULL)
    return E_POINTER;
  if (nImageSize < sizeof(IMAGE_DOS_HEADER))
    return MX_HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT);

  lpBaseAddress = (LPBYTE)_lpBaseAddress;
  nDataSize = nImageSize;
  bImageIsMapped = _bImageIsMapped;

  //parse PE
  hRes = DoParse(dwParseFlags);
  if (FAILED(hRes))
  {
    Finalize();
    return hRes;
  }

  //done
  return S_OK;
}

VOID CPEParser::Finalize()
{
  if (hFile != NULL && hFile != INVALID_HANDLE_VALUE)
    ::CloseHandle(hFile);
  if (hProc != NULL)
    ::CloseHandle(hProc);
  //----
  ClearVars();
  return;
}

LPBYTE CPEParser::RvaToVa(_In_ DWORD dwVirtualAddress)
{
  PIMAGE_SECTION_HEADER lpFileImgSect;
  SIZE_T i;

  if (bImageIsMapped != FALSE)
    return lpBaseAddress + (SIZE_T)dwVirtualAddress;

  lpFileImgSect = cFileImgSect.Get();
  for (i = 0; i < nSectionsCount; i++)
  {
    if (dwVirtualAddress >= lpFileImgSect[i].VirtualAddress &&
        dwVirtualAddress < lpFileImgSect[i].VirtualAddress + lpFileImgSect[i].Misc.VirtualSize)
    {
      return lpBaseAddress + (SIZE_T)(dwVirtualAddress - lpFileImgSect[i].VirtualAddress +
                                      lpFileImgSect[i].PointerToRawData);
    }
  }
  return NULL;
}

BOOL CPEParser::ReadRaw(_Out_writes_(nBytes) LPVOID lpDest, _In_ LPCVOID lpSrc, _In_ SIZE_T nBytes)
{
  SIZE_T nOffset;

  if ((SIZE_T)lpSrc < (SIZE_T)lpBaseAddress)
    return FALSE;
  nOffset = (SIZE_T)lpSrc - (SIZE_T)lpBaseAddress;
  if (nOffset > nDataSize)
    return FALSE;
  if (nBytes > nDataSize - nOffset)
    return FALSE;
  if (nBytes == 0)
    return TRUE;

  if (hProc != NULL)
  {
    SIZE_T nRead;

    if (::ReadProcessMemory(hProc, lpBaseAddress + nOffset, lpDest, nBytes, &nRead) == FALSE || nBytes != nRead)
      return FALSE;
  }
  else if (hFile != NULL)
  {
    while (nBytes > 0)
    {
      SIZE_T nOffsetInCache, nToReadThisRound;

      //check if data to read is in cache
      if (nOffset < sFileCache.nOffset || nOffset >= sFileCache.nOffset + sFileCache.nLength)
      {
        //cache is invalid, refresh
        DWORD dwRead;
        ULARGE_INTEGER uliOffset;

        //read from file
        uliOffset.QuadPart = (ULONGLONG)nOffset;

        if (::SetFilePointer(hFile, (LONG)(uliOffset.LowPart), (PLONG)&(uliOffset.HighPart),
                             FILE_BEGIN) == INVALID_SET_FILE_POINTER ||
            ::ReadFile(hFile, sFileCache.aBuffer, (DWORD)sizeof(sFileCache.aBuffer), &dwRead, NULL) == FALSE ||
            dwRead == 0)
        {
          sFileCache.nOffset = sFileCache.nLength = 0; //invalidate cache
          return FALSE;
        }

        //update cache info
        sFileCache.nOffset = nOffset;
        sFileCache.nLength = (SIZE_T)dwRead;
      }

      //here cache is valid, proceed with read
      nOffsetInCache = nOffset - sFileCache.nOffset;
      nToReadThisRound = nBytes;
      if (nToReadThisRound > sFileCache.nLength - nOffsetInCache)
        nToReadThisRound = sFileCache.nLength - nOffsetInCache;

      //copy data
      ::MxMemCopy(lpDest, sFileCache.aBuffer + nOffsetInCache, nToReadThisRound);

      //advance offset
      lpDest = (LPBYTE)lpDest + nToReadThisRound;
      nOffset += nToReadThisRound;
      nBytes -= nToReadThisRound;
    }
  }
  else
  {
    if (::MxTryMemCopy(lpDest, lpSrc, nBytes) != nBytes)
      return FALSE;
  }
  return TRUE;
}

HRESULT CPEParser::ReadAnsiString(_Out_ CStringA &cStrA, _In_ LPVOID lpNameAddress, _In_ SIZE_T nMaxLength)
{
  CHAR szTempBufA[8];
  SIZE_T nThisLen;

  cStrA.Empty();
  if (cStrA.EnsureBuffer(nMaxLength) == FALSE)
    return E_OUTOFMEMORY;

  while (cStrA.GetLength() < nMaxLength)
  {
    if (ReadRaw(szTempBufA, lpNameAddress, MX_ARRAYLEN(szTempBufA)) == FALSE)
      return MX_E_ReadFault;

    for (nThisLen=0; nThisLen<MX_ARRAYLEN(szTempBufA) && szTempBufA[nThisLen]!=0; nThisLen++);

    if (cStrA.ConcatN(szTempBufA, nThisLen) == FALSE)
      return E_OUTOFMEMORY;

    if (nThisLen < MX_ARRAYLEN(szTempBufA))
      break;

    lpNameAddress = (LPBYTE)lpNameAddress + MX_ARRAYLEN(szTempBufA);
  }
  return (cStrA.GetLength() < nMaxLength) ? S_OK : MX_E_InvalidData;
}

VOID CPEParser::ClearVars()
{
  hFile = NULL;
  hProc = NULL;

  wMachine = IMAGE_FILE_MACHINE_UNKNOWN;
  lpOriginalImageBaseAddress = NULL;

  lpBaseAddress = NULL;
  nDataSize = 0;
  bImageIsMapped = FALSE;

  ::MxMemSet(&sDosHdr, 0, sizeof(sDosHdr));
  ::MxMemSet(&uNtHdr, 0, sizeof(uNtHdr));

  nSectionsCount = 0;
  cFileImgSect.Reset();

  sImportsInfo.aDllList.RemoveAllElements();

  sExportsInfo.dwCharacteristics = 0;
  sExportsInfo.wMajorVersion = sExportsInfo.wMinorVersion = 0;
  sExportsInfo.aEntries.RemoveAllElements();

  lpResourceDir = NULL;
  cVersionInfo.Reset();
  nVersionInfoSize = 0;
  return;
}

HRESULT CPEParser::DoParse(_In_ DWORD dwParseFlags)
{
#define DATADIR32(entry) uNtHdr.s32.OptionalHeader.DataDirectory[entry]
#define DATADIR64(entry) uNtHdr.s64.OptionalHeader.DataDirectory[entry]
  union {
    DWORD dwImageSignature;
    IMAGE_FILE_HEADER sFileHeader;
  };
  LPBYTE lpNtHdr;
  HRESULT hRes;

  if (ReadRaw(&sDosHdr, lpBaseAddress, sizeof(sDosHdr)) == FALSE)
    return MX_E_ReadFault;
  if (sDosHdr.e_magic != IMAGE_DOS_SIGNATURE)
    return MX_E_InvalidData;

   //calculate NT header
  lpNtHdr = lpBaseAddress + (SIZE_T)(ULONG)(sDosHdr.e_lfanew);

  //check signature
  if (ReadRaw(&dwImageSignature, lpNtHdr, sizeof(dwImageSignature)) == FALSE)
    return MX_E_ReadFault;
  if (dwImageSignature != IMAGE_NT_SIGNATURE)
    return MX_E_InvalidData;

  //read file header
  if (ReadRaw(&sFileHeader, lpNtHdr + sizeof(DWORD), sizeof(sFileHeader)) == FALSE)
    return MX_E_ReadFault;
  //check machine
  switch (wMachine = sFileHeader.Machine)
  {
    case IMAGE_FILE_MACHINE_I386:
      if (ReadRaw(&(uNtHdr.s32), lpNtHdr, sizeof(uNtHdr.s32)) == FALSE)
        return MX_E_ReadFault;

      //get original image base address
      lpOriginalImageBaseAddress = UlongToPtr(uNtHdr.s32.OptionalHeader.ImageBase);

      //get PE sections
      nSectionsCount = (SIZE_T)(uNtHdr.s32.FileHeader.NumberOfSections);
      if (nSectionsCount > 0)
      {
        cFileImgSect.Attach((PIMAGE_SECTION_HEADER)MX_MALLOC(nSectionsCount * sizeof(IMAGE_SECTION_HEADER)));
        if (!cFileImgSect)
          return E_OUTOFMEMORY;
        if (ReadRaw(cFileImgSect.Get(), (PIMAGE_SECTION_HEADER)(lpNtHdr + sizeof(uNtHdr.s32)),
                    nSectionsCount * sizeof(IMAGE_SECTION_HEADER)) == FALSE)
        {
          return MX_E_ReadFault;
        }
      }

      //parse import table
      if ((dwParseFlags & MX_PEPARSER_FLAG_ParseImportTables) != 0)
      {
        if (DATADIR32(IMAGE_DIRECTORY_ENTRY_IMPORT).VirtualAddress != 0 &&
            DATADIR32(IMAGE_DIRECTORY_ENTRY_IMPORT).Size != 0)
        {
          PIMAGE_IMPORT_DESCRIPTOR lpImportDesc;

          lpImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)RvaToVa(DATADIR32(IMAGE_DIRECTORY_ENTRY_IMPORT).VirtualAddress);
          if (lpImportDesc != NULL)
            hRes = DoParseImportTable(lpImportDesc);
          else
            hRes = MX_E_InvalidData;
          if (FAILED(hRes))
          {
            if ((hRes != MX_E_InvalidData && hRes != MX_E_ReadFault) ||
                (dwParseFlags & MX_PEPARSER_FLAG_IgnoreMalformed) == 0)
            {
              return hRes;
            }
            sImportsInfo.aDllList.RemoveAllElements();
          }
        }
      }

      //parse export table
      if ((dwParseFlags & MX_PEPARSER_FLAG_ParseExportTable) != 0)
      {
        if (DATADIR32(IMAGE_DIRECTORY_ENTRY_EXPORT).VirtualAddress != 0 &&
            DATADIR32(IMAGE_DIRECTORY_ENTRY_EXPORT).Size != 0)
        {
          PIMAGE_EXPORT_DIRECTORY lpExportDir;

          lpExportDir = (PIMAGE_EXPORT_DIRECTORY)RvaToVa(DATADIR32(IMAGE_DIRECTORY_ENTRY_EXPORT).VirtualAddress);
          if (lpExportDir != NULL)
          {
            hRes = DoParseExportTable(lpExportDir, DATADIR32(IMAGE_DIRECTORY_ENTRY_EXPORT).VirtualAddress,
                                      DATADIR32(IMAGE_DIRECTORY_ENTRY_EXPORT).VirtualAddress +
                                      DATADIR32(IMAGE_DIRECTORY_ENTRY_EXPORT).Size);
          }
          else
          {
            hRes = MX_E_InvalidData;
          }
          if (FAILED(hRes))
          {
            if ((hRes != MX_E_InvalidData && hRes != MX_E_ReadFault) ||
                (dwParseFlags & MX_PEPARSER_FLAG_IgnoreMalformed) == 0)
            {
              return hRes;
            }
            sExportsInfo.dwCharacteristics = 0;
            sExportsInfo.wMajorVersion = 0;
            sExportsInfo.wMinorVersion = 0;
            sExportsInfo.aEntries.RemoveAllElements();
          }
        }
      }

      //parse resources
      if ((dwParseFlags & MX_PEPARSER_FLAG_ParseResources) != 0)
      {
        if (DATADIR32(IMAGE_DIRECTORY_ENTRY_RESOURCE).VirtualAddress != 0 &&
            DATADIR32(IMAGE_DIRECTORY_ENTRY_RESOURCE).Size != 0)
        {
          lpResourceDir = (PIMAGE_RESOURCE_DIRECTORY)RvaToVa(DATADIR32(IMAGE_DIRECTORY_ENTRY_RESOURCE).VirtualAddress);
          if (lpResourceDir != NULL)
            hRes = DoParseResources();
          else
            hRes = MX_E_InvalidData;
          if (FAILED(hRes))
          {
            if ((hRes != MX_E_InvalidData && hRes != MX_E_ReadFault) ||
                (dwParseFlags & MX_PEPARSER_FLAG_IgnoreMalformed) == 0)
            {
              return hRes;
            }
            lpResourceDir = NULL;
            cVersionInfo.Reset();
            nVersionInfoSize = 0;
          }
        }
      }
      break;

#if defined(_M_X64)
    case IMAGE_FILE_MACHINE_AMD64:
      if (ReadRaw(&(uNtHdr.s64), lpNtHdr, sizeof(uNtHdr.s64)) == FALSE)
        return MX_E_ReadFault;

      //get original image base address
      lpOriginalImageBaseAddress = (LPVOID)(uNtHdr.s64.OptionalHeader.ImageBase);

      //get PE sections
      nSectionsCount = (SIZE_T)(uNtHdr.s64.FileHeader.NumberOfSections);
      if (nSectionsCount > 0)
      {
        cFileImgSect.Attach((PIMAGE_SECTION_HEADER)MX_MALLOC(nSectionsCount * sizeof(IMAGE_SECTION_HEADER)));
        if (!cFileImgSect)
          return E_OUTOFMEMORY;
        if (ReadRaw(cFileImgSect.Get(), (PIMAGE_SECTION_HEADER)(lpNtHdr + sizeof(uNtHdr.s64)),
                    nSectionsCount * sizeof(IMAGE_SECTION_HEADER)) == FALSE)
        {
          return MX_E_ReadFault;
        }
      }

      //parse import table
      if ((dwParseFlags & MX_PEPARSER_FLAG_ParseImportTables) != 0)
      {
        if (DATADIR64(IMAGE_DIRECTORY_ENTRY_IMPORT).VirtualAddress != 0 &&
            DATADIR64(IMAGE_DIRECTORY_ENTRY_IMPORT).Size != 0)
        {
          PIMAGE_IMPORT_DESCRIPTOR lpImportDesc;

          lpImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)RvaToVa(DATADIR64(IMAGE_DIRECTORY_ENTRY_IMPORT).VirtualAddress);
          if (lpImportDesc != NULL)
            hRes = DoParseImportTable(lpImportDesc);
          else
            hRes = MX_E_InvalidData;
          if (FAILED(hRes))
          {
            if ((hRes != MX_E_InvalidData && hRes != MX_E_ReadFault) ||
               (dwParseFlags & MX_PEPARSER_FLAG_IgnoreMalformed) == 0)
            {
              return hRes;
            }
            sImportsInfo.aDllList.RemoveAllElements();
          }
        }
      }

      //parse export table
      if ((dwParseFlags & MX_PEPARSER_FLAG_ParseExportTable) != 0)
      {
        if (DATADIR64(IMAGE_DIRECTORY_ENTRY_EXPORT).VirtualAddress != 0 &&
            DATADIR64(IMAGE_DIRECTORY_ENTRY_EXPORT).Size != 0)
        {
          PIMAGE_EXPORT_DIRECTORY lpExportDir;

          lpExportDir = (PIMAGE_EXPORT_DIRECTORY)RvaToVa(DATADIR64(IMAGE_DIRECTORY_ENTRY_EXPORT).VirtualAddress);
          if (lpExportDir != NULL)
          {
            hRes = DoParseExportTable(lpExportDir, DATADIR32(IMAGE_DIRECTORY_ENTRY_EXPORT).VirtualAddress,
                                      DATADIR32(IMAGE_DIRECTORY_ENTRY_EXPORT).VirtualAddress +
                                      DATADIR32(IMAGE_DIRECTORY_ENTRY_EXPORT).Size);
          }
          else
          {
            hRes = MX_E_InvalidData;
          }
          if (FAILED(hRes))
          {
            if ((hRes != MX_E_InvalidData && hRes != MX_E_ReadFault) ||
                (dwParseFlags & MX_PEPARSER_FLAG_IgnoreMalformed) == 0)
            {
              return hRes;
            }
            sExportsInfo.dwCharacteristics = 0;
            sExportsInfo.wMajorVersion = 0;
            sExportsInfo.wMinorVersion = 0;
            sExportsInfo.aEntries.RemoveAllElements();
          }
        }
      }

      //parse resources
      if ((dwParseFlags & MX_PEPARSER_FLAG_ParseResources) != 0)
      {
        if (DATADIR64(IMAGE_DIRECTORY_ENTRY_RESOURCE).VirtualAddress != 0 &&
            DATADIR64(IMAGE_DIRECTORY_ENTRY_RESOURCE).Size != 0)
        {
          lpResourceDir = (PIMAGE_RESOURCE_DIRECTORY)RvaToVa(DATADIR64(IMAGE_DIRECTORY_ENTRY_RESOURCE).VirtualAddress);
          if (lpResourceDir != NULL)
            hRes = DoParseResources();
          else
            hRes = MX_E_InvalidData;
          if (FAILED(hRes))
          {
            if ((hRes != MX_E_InvalidData && hRes != MX_E_ReadFault) ||
                (dwParseFlags & MX_PEPARSER_FLAG_IgnoreMalformed) == 0)
            {
              return hRes;
            }
            lpResourceDir = NULL;
            cVersionInfo.Reset();
            nVersionInfoSize = 0;
          }
        }
      }
      break;
#endif //_M_X64

    default:
      return MX_E_Unsupported;
  }

  //done
  return S_OK;
#undef DATADIR64
#undef DATADIR32
}

HRESULT CPEParser::DoParseImportTable(_In_ PIMAGE_IMPORT_DESCRIPTOR lpImportDesc)
{
  TAutoDeletePtr<CImportedDll> cDllEntry;
  IMAGE_IMPORT_DESCRIPTOR sImportDesc;
  LPBYTE lpNameAddress, lpThunk, lpFunctionThunk;
  union {
    IMAGE_THUNK_DATA32 s32;
#if defined(_M_X64)
    IMAGE_THUNK_DATA64 s64;
#endif //_M_X64
  } uThunkData;
  CStringA cStrFuncNameA;
  LPIMPORTED_FUNCTION lpNewEntry;
  DWORD dwOrdinal;
  LPVOID lpFuncAddress;
  HRESULT hRes;

restart:
  cDllEntry.Attach(MX_DEBUG_NEW CImportedDll());
  if (!cDllEntry)
    return E_OUTOFMEMORY;

  if (ReadRaw(&sImportDesc, lpImportDesc, sizeof(sImportDesc)) == FALSE)
    return MX_E_ReadFault;

  // See if we've reached an empty IMAGE_IMPORT_DESCRIPTOR
  if (sImportDesc.TimeDateStamp == 0 && sImportDesc.Name == 0)
    return S_OK;

  lpNameAddress = RvaToVa(sImportDesc.Name);
  if (lpNameAddress == NULL)
    return MX_E_InvalidData;
  hRes = ReadAnsiString(cDllEntry->cStrNameA, lpNameAddress, MAX_IMPORTS_DLL_NAME_LENGTH);
  if (FAILED(hRes))
    return hRes;
  if (cDllEntry->cStrNameA.IsEmpty() != FALSE)
    return MX_E_InvalidData;

  lpFunctionThunk = NULL;
  if (sImportDesc.OriginalFirstThunk == 0)
  {
    if (sImportDesc.FirstThunk == 0)
      return MX_E_InvalidData;
    lpThunk = RvaToVa(sImportDesc.FirstThunk);
  }
  else
  {
    lpThunk = RvaToVa(sImportDesc.OriginalFirstThunk);
    if (bImageIsMapped != FALSE)
    {
      lpFunctionThunk = RvaToVa(sImportDesc.FirstThunk);
      if (lpFunctionThunk == NULL || lpThunk == NULL)
        return MX_E_InvalidData;
    }
  }

  switch (wMachine)
  {
    case IMAGE_FILE_MACHINE_I386:
      while (1)
      {
        if (ReadRaw(&uThunkData, lpThunk, sizeof(uThunkData.s32)) == FALSE)
          return MX_E_ReadFault;
        if (uThunkData.s32.u1.AddressOfData == 0)
          break;

        if (uThunkData.s32.u1.Ordinal & IMAGE_ORDINAL_FLAG32)
        {
          dwOrdinal = (DWORD)IMAGE_ORDINAL32(uThunkData.s32.u1.Ordinal);
          cStrFuncNameA.Empty();
        }
        else
        {
          dwOrdinal = 0xFFFFFFFFUL;

          if (uThunkData.s32.u1.AddressOfData == 0)
            return MX_E_InvalidData;
          lpNameAddress = RvaToVa((DWORD)(uThunkData.s32.u1.AddressOfData));
          if (lpNameAddress == NULL)
            return MX_E_InvalidData;

          lpNameAddress += 2; //skip hint
          hRes = ReadAnsiString(cStrFuncNameA, lpNameAddress, MAX_IMPORTS_FUNCTION_NAME_LENGTH);
          if (FAILED(hRes))
            return hRes;
        }

        lpFuncAddress = NULL;
        if (lpFunctionThunk != NULL)
        {
          if (ReadRaw(&uThunkData, lpFunctionThunk, sizeof(uThunkData.s32)) == FALSE)
            return MX_E_ReadFault;
          lpFuncAddress = ULongToPtr(uThunkData.s32.u1.Function);
        }

        //create new entry
        lpNewEntry = (LPIMPORTED_FUNCTION)MX_MALLOC(sizeof(IMPORTED_FUNCTION) + cStrFuncNameA.GetLength());
        if (lpNewEntry == NULL)
          return E_OUTOFMEMORY;
        lpNewEntry->dwOrdinal = dwOrdinal;
        lpNewEntry->lpAddress = lpFuncAddress;
        ::MxMemCopy(lpNewEntry->szNameA, (LPCSTR)cStrFuncNameA, cStrFuncNameA.GetLength());
        lpNewEntry->szNameA[cStrFuncNameA.GetLength()] = 0;

        //add to list
        if (cDllEntry->aEntries.AddElement(lpNewEntry) == FALSE)
        {
          MX_FREE(lpNewEntry);
          return E_OUTOFMEMORY;
        }

        //advance to next
        lpThunk += sizeof(uThunkData.s32);
        if (lpFunctionThunk != NULL)
          lpFunctionThunk += sizeof(uThunkData.s32);
      }
      break;

#if defined(_M_X64)
    case IMAGE_FILE_MACHINE_AMD64:
      while (1)
      {
        if (ReadRaw(&uThunkData, lpThunk, sizeof(uThunkData.s64)) == FALSE)
          return MX_E_ReadFault;
        if (uThunkData.s64.u1.AddressOfData == 0)
          break;

        if (uThunkData.s64.u1.Ordinal & IMAGE_ORDINAL_FLAG64)
        {
          dwOrdinal = (DWORD)IMAGE_ORDINAL64(uThunkData.s64.u1.Ordinal);
          cStrFuncNameA.Empty();
        }
        else
        {
          dwOrdinal = 0xFFFFFFFFUL;

          if (uThunkData.s64.u1.AddressOfData == 0)
            return MX_E_InvalidData;
          lpNameAddress = RvaToVa((DWORD)(uThunkData.s64.u1.AddressOfData));
          if (lpNameAddress == NULL)
            return MX_E_InvalidData;

          lpNameAddress += 2; //skip hint
          hRes = ReadAnsiString(cStrFuncNameA, lpNameAddress, MAX_IMPORTS_FUNCTION_NAME_LENGTH);
          if (FAILED(hRes))
            return hRes;
        }

        lpFuncAddress = NULL;
        if (lpFunctionThunk != NULL)
        {
          if (ReadRaw(&uThunkData, lpFunctionThunk, sizeof(uThunkData.s64)) == FALSE)
            return MX_E_ReadFault;
          lpFuncAddress = (LPVOID)(uThunkData.s64.u1.Function);
        }

        //create new entry
        lpNewEntry = (LPIMPORTED_FUNCTION)MX_MALLOC(sizeof(IMPORTED_FUNCTION) + cStrFuncNameA.GetLength());
        if (lpNewEntry == NULL)
          return E_OUTOFMEMORY;
        lpNewEntry->dwOrdinal = dwOrdinal;
        lpNewEntry->lpAddress = lpFuncAddress;
        ::MxMemCopy(lpNewEntry->szNameA, (LPCSTR)cStrFuncNameA, cStrFuncNameA.GetLength());
        lpNewEntry->szNameA[cStrFuncNameA.GetLength()] = 0;

        //add to list
        if (cDllEntry->aEntries.AddElement(lpNewEntry) == FALSE)
        {
          MX_FREE(lpNewEntry);
          return E_OUTOFMEMORY;
        }

        //advance to next
        lpThunk += sizeof(uThunkData.s64);
        if (lpFunctionThunk != NULL)
          lpFunctionThunk += sizeof(uThunkData.s64);
      }
      break;
#endif //_M_X64
  }

  //add dll to list
  if (sImportsInfo.aDllList.AddElement(cDllEntry.Get()) == FALSE)
    return E_OUTOFMEMORY;
  cDllEntry.Detach();

  lpImportDesc++;
  goto restart;
}

HRESULT CPEParser::DoParseExportTable(_In_ PIMAGE_EXPORT_DIRECTORY lpExportDir, _In_ DWORD dwStartRVA,
                                      _In_ DWORD dwEndRVA)
{
  IMAGE_EXPORT_DIRECTORY sExportDir;
  LPEXPORTED_FUNCTION lpNewEntry;
  CStringA cStrFuncNameA, cStrForwardsToA;
  LPDWORD lpdwAddressOfFunctions, lpdwAddressOfNames;
  LPWORD lpwAddressOfNameOrdinals;
  TAutoFreePtr<WORD> aNameOrdinalsList;
  DWORD dw, dw2, dwNumberOfNames, dwFuncAddress, dwNameAddress;
  LPVOID lpFuncAddress;
  HRESULT hRes;

  if (ReadRaw(&sExportDir, lpExportDir, sizeof(sExportDir)) == FALSE)
    return MX_E_ReadFault;

  sExportsInfo.dwCharacteristics = sExportDir.Characteristics;
  sExportsInfo.wMajorVersion = sExportDir.MajorVersion;
  sExportsInfo.wMinorVersion = sExportDir.MinorVersion;

  //get addresses
  lpdwAddressOfFunctions = NULL;
  if (sExportDir.NumberOfFunctions > 0)
  {
    lpdwAddressOfFunctions = (LPDWORD)RvaToVa(sExportDir.AddressOfFunctions);
    if (lpdwAddressOfFunctions == NULL)
      return MX_E_InvalidData;
  }
  lpdwAddressOfNames = NULL;
  lpwAddressOfNameOrdinals = NULL;
  if (sExportDir.NumberOfNames > 0)
  {
    lpdwAddressOfNames = (LPDWORD)RvaToVa(sExportDir.AddressOfNames);
    lpwAddressOfNameOrdinals = (LPWORD)RvaToVa(sExportDir.AddressOfNameOrdinals);
    if (lpdwAddressOfNames == NULL || lpwAddressOfNameOrdinals == NULL)
      return MX_E_InvalidData;
  }

  dwNumberOfNames = (sExportDir.NumberOfNames > MAX_EXPORTS_COUNT) ? MAX_EXPORTS_COUNT : sExportDir.NumberOfNames;
  if (dwNumberOfNames > 0)
  {
    aNameOrdinalsList.Attach((LPWORD)MX_MALLOC((SIZE_T)dwNumberOfNames * sizeof(WORD)));
    if (!aNameOrdinalsList)
      return E_OUTOFMEMORY;
    if (ReadRaw(aNameOrdinalsList.Get(), lpwAddressOfNameOrdinals, (SIZE_T)dwNumberOfNames * sizeof(WORD)) == FALSE)
      return MX_E_ReadFault;
  }

  for (dw=0; dw<sExportDir.NumberOfFunctions && dw<MAX_EXPORTS_COUNT; dw++)
  {
    if (ReadRaw(&dwFuncAddress, &lpdwAddressOfFunctions[dw], sizeof(dwFuncAddress)) == FALSE)
      return MX_E_ReadFault;
    if (dwFuncAddress == 0)
      continue; //skip gaps

    lpFuncAddress = NULL;
    cStrForwardsToA.Empty();
    if (dwFuncAddress >= dwStartRVA && dwFuncAddress < dwEndRVA)
    {
      //forwarder function
      LPBYTE lpNameAddress;
      LPCSTR sA;

      lpNameAddress = RvaToVa(dwFuncAddress);
      if (lpNameAddress == NULL)
        return MX_E_InvalidData;

      hRes = ReadAnsiString(cStrForwardsToA, lpNameAddress, MAX_EXPORTS_FORWARDER_NAME_LENGTH);
      if (FAILED(hRes))
        return hRes;
      if (cStrForwardsToA.IsEmpty() != FALSE)
        return MX_E_InvalidData;

      sA = StrChrA((LPCSTR)cStrForwardsToA, '.');
      if (sA == NULL || sA == (LPCSTR)cStrForwardsToA || *(sA+1) == 0)
        return MX_E_InvalidData;
    }
    else
    {
      lpFuncAddress = RvaToVa(dwFuncAddress);
      if (lpFuncAddress == NULL)
        return MX_E_InvalidData;
    }

    //check if a name exists
    dwNameAddress = 0;
    for (dw2=0; dw2<dwNumberOfNames; dw2++)
    {
      if (aNameOrdinalsList[dw2] == dw)
      {
        if (ReadRaw(&dwNameAddress, &lpdwAddressOfNames[dw2], sizeof(dwNameAddress)) == FALSE)
          return MX_E_ReadFault;
        if (dwNameAddress != 0)
        {
          LPBYTE lpNameAddress;

          lpNameAddress = RvaToVa(dwNameAddress);
          if (lpNameAddress == NULL)
            return MX_E_InvalidData;

          hRes = ReadAnsiString(cStrFuncNameA, lpNameAddress, MAX_EXPORTS_FUNCTION_NAME_LENGTH);
          if (FAILED(hRes))
            return hRes;
        }
        break;
      }
    }

    //create new entry
    lpNewEntry = (LPEXPORTED_FUNCTION)MX_MALLOC(sizeof(EXPORTED_FUNCTION) + cStrFuncNameA.GetLength() +
                                                ((cStrForwardsToA.IsEmpty() == FALSE)
                                                ? (cStrForwardsToA.GetLength() + 1) : 0));
    if (lpNewEntry == NULL)
      return E_OUTOFMEMORY;
    lpNewEntry->dwOrdinal = dw + sExportDir.Base;
    lpNewEntry->dwAddressRVA = dwFuncAddress;
    lpNewEntry->lpAddress = lpFuncAddress;
    ::MxMemCopy(lpNewEntry->szNameA, (LPCSTR)cStrFuncNameA, cStrFuncNameA.GetLength());
    lpNewEntry->szNameA[cStrFuncNameA.GetLength()] = 0;
    if (cStrForwardsToA.IsEmpty() != FALSE)
    {
      lpNewEntry->szForwardsToA = NULL;
    }
    else
    {
      lpNewEntry->szForwardsToA = lpNewEntry->szNameA + cStrFuncNameA.GetLength() + 1;
      ::MxMemCopy(lpNewEntry->szForwardsToA, (LPCSTR)cStrForwardsToA, cStrForwardsToA.GetLength());
      lpNewEntry->szForwardsToA[cStrForwardsToA.GetLength()] = 0;
    }
    //add to list
    if (sExportsInfo.aEntries.AddElement(lpNewEntry) == FALSE)
    {
      MX_FREE(lpNewEntry);
      return E_OUTOFMEMORY;
    }
  }
  //done
  return S_OK;
}

HRESULT CPEParser::DoParseResources()
{
  LPBYTE lpData;
  SIZE_T nDataSize;
  HRESULT hRes;

  hRes = _FindResource(MAKEINTRESOURCEW(VS_VERSION_INFO), VS_FILE_INFO, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                       &lpData, &nDataSize);
  if (SUCCEEDED(hRes))
  {
    if (nDataSize > 0)
    {
      cVersionInfo.Attach((LPBYTE)MX_MALLOC(nDataSize));
      if (!cVersionInfo)
        return E_OUTOFMEMORY;
      if (ReadRaw(cVersionInfo.Get(), lpData, nDataSize) == FALSE)
        return MX_E_ReadFault;
      nVersionInfoSize = nDataSize;
    }
  }
  else if (hRes != MX_E_NotFound)
  {
    return hRes;
  }
  //done
  return S_OK;
}

HRESULT CPEParser::_FindResource(_In_ LPCWSTR szNameW, _In_ LPCWSTR szTypeW, _In_ WORD wLang,
                                 _Out_ LPBYTE *lplpData, _Out_ SIZE_T *lpnDataSize)
{
  PIMAGE_RESOURCE_DIRECTORY_ENTRY lpDirEntry;
  PIMAGE_RESOURCE_DIRECTORY lpTypeResDir, lpNameResDir;
  IMAGE_RESOURCE_DIRECTORY sResDir;
  IMAGE_RESOURCE_DIRECTORY_ENTRY sDirEntry;
  IMAGE_RESOURCE_DATA_ENTRY sResDataEntry;
  HRESULT hRes;

  *lplpData = NULL;
  *lpnDataSize = 0;

  if (wLang == MAKELANGID(LANG_NEUTRAL,SUBLANG_NEUTRAL))
    wLang = LANGIDFROMLCID(::GetThreadLocale());

  hRes = LookupResourceEntry(lpResourceDir, lpResourceDir, szTypeW, &lpDirEntry);
  if (FAILED(hRes))
    return hRes;
  if (ReadRaw(&sDirEntry, lpDirEntry, sizeof(sDirEntry)) == FALSE)
    return MX_E_ReadFault;
  lpTypeResDir = (PIMAGE_RESOURCE_DIRECTORY)((LPBYTE)lpResourceDir +
                                             (SIZE_T)(sDirEntry.OffsetToData & 0x7FFFFFFF));

  hRes = LookupResourceEntry(lpResourceDir, lpTypeResDir, szNameW, &lpDirEntry);
  if (FAILED(hRes))
    return hRes;
  if (ReadRaw(&sDirEntry, lpDirEntry, sizeof(sDirEntry)) == FALSE)
    return MX_E_ReadFault;
  lpNameResDir = (PIMAGE_RESOURCE_DIRECTORY)((LPBYTE)lpResourceDir +
                                             (SIZE_T)(sDirEntry.OffsetToData & 0x7FFFFFFF));

  hRes = LookupResourceEntry(lpResourceDir, lpNameResDir, MAKEINTRESOURCEW(wLang), &lpDirEntry);
  if (FAILED(hRes))
  {
    if (hRes != MX_E_NotFound)
      return hRes;
    //get the first entry if provided language is not found
    if (ReadRaw(&sResDir, lpNameResDir, sizeof(sResDir)) == FALSE)
      return MX_E_ReadFault;
    if (sResDir.NumberOfIdEntries == 0)
      return MX_E_NotFound;
    lpDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(lpNameResDir + 1);
  }
  if (ReadRaw(&sDirEntry, lpDirEntry, sizeof(sDirEntry)) == FALSE)
    return MX_E_ReadFault;

  //get data entry
  if (ReadRaw(&sResDataEntry, (LPBYTE)lpResourceDir + (SIZE_T)(sDirEntry.OffsetToData & 0x7FFFFFFF),
              sizeof(sResDataEntry)) == FALSE)
  {
    return MX_E_ReadFault;
  }

  *lplpData = RvaToVa(sResDataEntry.OffsetToData);
  if ((*lplpData) == NULL)
    return MX_E_InvalidData;
  *lpnDataSize = (SIZE_T)(sResDataEntry.Size);
  return S_OK;
}

HRESULT CPEParser::LookupResourceEntry(_In_ PIMAGE_RESOURCE_DIRECTORY lpRootDir, _In_ PIMAGE_RESOURCE_DIRECTORY lpDir,
                                       _In_ LPCWSTR szKeyW, _Out_ PIMAGE_RESOURCE_DIRECTORY_ENTRY *lplpDirEntry)
{
  IMAGE_RESOURCE_DIRECTORY sResDir;
  IMAGE_RESOURCE_DIRECTORY_ENTRY sResDirEntry, *lpEntries;
  DWORD dwStart, dwMiddle, dwEnd;

  *lplpDirEntry = NULL;

  if ((!IS_INTRESOURCE(szKeyW)) && *szKeyW == L'#')
  {
    LPCWSTR sW;
    ULONG nValue;

    nValue = 0;
    for (sW=szKeyW+1; *sW!=0 && nValue < 65536; sW++)
    {
      if (*sW < L'0' || *sW >= L'9')
        break;
      nValue = nValue * 10 + (ULONG)(*sW - L'0');
    }
    if (*sW == 0 && nValue < 65536)
      szKeyW = MAKEINTRESOURCEW(nValue);
  }

  //read dir entry header
  if (ReadRaw(&sResDir, lpDir, sizeof(sResDir)) == FALSE)
    return MX_E_ReadFault;
  lpEntries = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(lpDir + 1);

  if (IS_INTRESOURCE(szKeyW))
  {
    WORD wCheck;

    wCheck = PtrToUshort(szKeyW);
    if (wCheck == 0)
      return E_INVALIDARG;

    dwStart = (DWORD)(sResDir.NumberOfNamedEntries);
    dwEnd = dwStart + (DWORD)(sResDir.NumberOfIdEntries);
    while (dwEnd > dwStart)
    {
      dwMiddle = (dwStart + dwEnd) >> 1;
      if (ReadRaw(&sResDirEntry, lpEntries + (SIZE_T)dwMiddle, sizeof(sResDirEntry)) == FALSE)
        return MX_E_ReadFault;

      if (wCheck < sResDirEntry.Id)
      {
        dwEnd = (dwEnd != dwMiddle ? dwMiddle : dwMiddle - 1);
      }
      else if (wCheck > sResDirEntry.Id)
      {
        dwStart = (dwStart != dwMiddle ? dwMiddle : dwMiddle + 1);
      }
      else
      {
        *lplpDirEntry = lpEntries + (SIZE_T)dwMiddle;
        return S_OK;
      }
    }
  }
  else
  {
    LPBYTE lpPtr;
    WCHAR szTempBufW[64];
    LPCWSTR szCopyOfKeyW;
    WORD wResDirStringLen;
    int nCmpResult;

    if (*szKeyW == 0)
      return E_INVALIDARG;

    dwStart = 0;
    dwEnd = sResDir.NumberOfIdEntries;
    while (dwEnd > dwStart)
    {
      dwMiddle = (dwStart + dwEnd) >> 1;
      if (ReadRaw(&sResDirEntry, lpEntries + (SIZE_T)dwMiddle, sizeof(sResDirEntry)) == FALSE)
        return MX_E_ReadFault;

      lpPtr = (LPBYTE)lpRootDir + (SIZE_T)(sResDirEntry.Name & 0x7FFFFFFF);
      if (ReadRaw(&wResDirStringLen, lpPtr, sizeof(wResDirStringLen)) == FALSE)
        return MX_E_ReadFault;
      lpPtr += sizeof(WORD);

      nCmpResult = 1; //if name string is zero-length, then the key will be greater
      szCopyOfKeyW = szKeyW;
      while (wResDirStringLen > 0)
      {
        WORD wThisRound = (wResDirStringLen > 64) ? 64 : wResDirStringLen;

        if (ReadRaw(szTempBufW, lpPtr, (SIZE_T)wThisRound * sizeof(WCHAR)) == FALSE)
          return MX_E_ReadFault;
        nCmpResult = ::MxMemCompare(szCopyOfKeyW, szTempBufW, (SIZE_T)wThisRound);
        if (nCmpResult != 0)
          break;
        lpPtr += (SIZE_T)wThisRound * sizeof(WCHAR);
        szCopyOfKeyW += (SIZE_T)wThisRound;
      }
      if (nCmpResult == 0 && wResDirStringLen > 0)
        nCmpResult = 1;

      if (nCmpResult < 0)
      {
        dwEnd = (dwMiddle != dwEnd ? dwMiddle : dwMiddle - 1);
      }
      else if (nCmpResult > 0)
      {
        dwStart = (dwMiddle != dwStart ? dwMiddle : dwMiddle + 1);
      }
      else
      {
        *lplpDirEntry = lpEntries + (SIZE_T)dwMiddle;
        return S_OK;
      }
    }
  }
  //done
  return MX_E_NotFound;
}

}; //namespace MX
