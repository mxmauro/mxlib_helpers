#include "PeParser.h"
#include "FileRoutines.h"
#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>

//-----------------------------------------------------------

#ifndef FILE_OPEN
  #define FILE_OPEN                               0x00000001
#endif //FILE_OPEN
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
  #define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#endif //FILE_SYNCHRONOUS_IO_NONALERT
#ifndef FILE_NON_DIRECTORY_FILE
  #define FILE_NON_DIRECTORY_FILE                 0x00000040
#endif //FILE_NON_DIRECTORY_FILE
#ifndef OBJ_CASE_INSENSITIVE
  #define OBJ_CASE_INSENSITIVE                    0x00000040
#endif //OBJ_CASE_INSENSITIVE

#define MAX_EXPORTS_COUNT                              65536
#define MAX_EXPORTS_FUNCTION_NAME_LENGTH                 512
#define MAX_EXPORTS_FORWARDER_NAME_LENGTH                512

#define MAX_IMPORTS_PER_DLL_COUNT                      65536
#define MAX_IMPORTS_DLL_NAME_LENGTH                      512
#define MAX_IMPORTS_FUNCTION_NAME_LENGTH                 512

//-----------------------------------------------------------

namespace MXHelpers {

CPeParser::CPeParser()
{
  hFile = hFileMap = NULL;
  hProc = NULL;
  //--------
  Reset();
  return;
}

CPeParser::~CPeParser()
{
  Finalize();
  return;
}

HRESULT CPeParser::InitializeFromFileName(_In_z_ LPCWSTR szFileNameW, _In_opt_ DWORD dwParseFlags)
{
  MX::CWindowsHandle cFileH;
  HRESULT hRes;

  Finalize();

  //open file
  hRes = OpenFileWithEscalatingSharing(szFileNameW, &cFileH);
  if (SUCCEEDED(hRes))
    hRes = InitializeFromFileHandle(cFileH.Get(), dwParseFlags);
  //done
  return hRes;
}

HRESULT CPeParser::InitializeFromFileHandle(_In_ HANDLE _hFile, _In_opt_ DWORD dwParseFlags)
{
  HRESULT hRes;

  if (_hFile == NULL || _hFile == INVALID_HANDLE_VALUE)
    return E_INVALIDARG;

  Finalize();

  if (::DuplicateHandle(::GetCurrentProcess(), _hFile, ::GetCurrentProcess(), &hFile, 0, FALSE,
                        DUPLICATE_SAME_ACCESS) == FALSE)
  {
    return MX_HRESULT_FROM_LASTERROR();
  }

  //map file
  hFileMap = ::CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
  if (hFileMap == NULL)
  {
    hRes = MX_HRESULT_FROM_LASTERROR();
    Finalize();
    return hRes;
  }
  //----
  lpBaseAddress = (LPBYTE)::MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
  if (lpBaseAddress == NULL)
  {
    hRes = MX_HRESULT_FROM_LASTERROR();
    Finalize();
    return hRes;
  }

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

HRESULT CPeParser::InitializeFromProcessHandle(_In_opt_ HANDLE _hProc, _In_opt_ DWORD dwParseFlags)
{
  LPBYTE lpPeb;
#if defined(_M_X64)
  BOOL bIs32BitProcess = FALSE;
#endif //_M_X64
  ULONG dwTemp;
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
        return MX_HRESULT_FROM_NT(nNtStatus);
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

    if (ReadMem(&qwTemp, lpPeb + 0x10, sizeof(qwTemp)) == FALSE)
    {
      Finalize();
      return MX_E_ReadFault;
    }
    lpBaseAddress = (LPBYTE)qwTemp;
  }
  else
  {
#endif //_M_X64
    if (ReadMem(&dwTemp, lpPeb + 0x08, sizeof(dwTemp)) == FALSE)
    {
      Finalize();
      return MX_E_ReadFault;
    }
#if defined(_M_X64)
    lpBaseAddress = (LPBYTE)UlongToPtr(dwTemp);
#else //_M_X64
    lpBaseAddress = (LPBYTE)dwTemp;
#endif //_M_X64
#if defined(_M_X64)
  }
#endif //_M_X64

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

HRESULT CPeParser::InitializeFromMemory(_In_ LPCVOID _lpBaseAddress, _In_ BOOL _bImageIsMapped,
                                        _In_opt_ DWORD dwParseFlags)
{
  HRESULT hRes;

  lpBaseAddress = (LPBYTE)_lpBaseAddress;
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

VOID CPeParser::Finalize()
{
  if (hFileMap != NULL && hFileMap != INVALID_HANDLE_VALUE)
  {
    if (lpBaseAddress != NULL)
      ::UnmapViewOfFile(lpBaseAddress);
    ::CloseHandle(hFileMap);
  }
  hFileMap = NULL;
  //----
  if (hFile != NULL && hFile != INVALID_HANDLE_VALUE)
    ::CloseHandle(hFile);
  hFile = NULL;
  //----
  if (hProc != NULL)
    ::CloseHandle(hProc);
  hProc = NULL;
  //----
  Reset();
  return;
}

LPBYTE CPeParser::RvaToVa(_In_ DWORD dwVirtualAddress)
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

BOOL CPeParser::ReadMem(_Out_writes_(nBytes) LPVOID lpDest, _In_ LPCVOID lpSrc, _In_ SIZE_T nBytes)
{
  if (hProc != NULL)
  {
    SIZE_T nRead;

    if (::ReadProcessMemory(hProc, lpSrc, lpDest, nBytes, &nRead) == FALSE || nBytes != nRead)
      return FALSE;
  }
  else
  {
    if (MX::TryMemCopy(lpDest, lpSrc, nBytes) != nBytes)
      return FALSE;
  }
  return TRUE;
}

HRESULT CPeParser::ReadAnsiString(_Out_ MX::CStringA &cStrA, _In_ LPVOID lpNameAddress, _In_ SIZE_T nMaxLength)
{
  CHAR szTempBufA[8];
  SIZE_T nThisLen;

  cStrA.Empty();
  if (cStrA.EnsureBuffer(nMaxLength) == FALSE)
    return E_OUTOFMEMORY;

  while (cStrA.GetLength() < nMaxLength)
  {
    if (ReadMem(szTempBufA, lpNameAddress, MX_ARRAYLEN(szTempBufA)) == FALSE)
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

VOID CPeParser::Reset()
{
  wMachine = IMAGE_FILE_MACHINE_UNKNOWN;
  lpOriginalImageBaseAddress = NULL;

  lpBaseAddress = NULL;
  bImageIsMapped = FALSE;

  MX::MemSet(&sDosHdr, 0, sizeof(sDosHdr));
  MX::MemSet(&uNtHdr, 0, sizeof(uNtHdr));

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

HRESULT CPeParser::DoParse(_In_ DWORD dwParseFlags)
{
#define DATADIR32(entry) uNtHdr.s32.OptionalHeader.DataDirectory[entry]
#define DATADIR64(entry) uNtHdr.s64.OptionalHeader.DataDirectory[entry]
  union {
    DWORD dwImageSignature;
    IMAGE_FILE_HEADER sFileHeader;
  };
  LPBYTE lpNtHdr;
  HRESULT hRes;

  if (ReadMem(&sDosHdr, lpBaseAddress, sizeof(sDosHdr)) == FALSE)
    return MX_E_ReadFault;
  if (sDosHdr.e_magic != IMAGE_DOS_SIGNATURE)
    return MX_E_InvalidData;

   //calculate NT header
  lpNtHdr = lpBaseAddress + (SIZE_T)(ULONG)(sDosHdr.e_lfanew);

  //check signature
  if (ReadMem(&dwImageSignature, lpNtHdr, sizeof(dwImageSignature)) == FALSE)
    return MX_E_ReadFault;
  if (dwImageSignature != IMAGE_NT_SIGNATURE)
    return MX_E_InvalidData;

  //read file header
  if (ReadMem(&sFileHeader, lpNtHdr + sizeof(DWORD), sizeof(sFileHeader)) == FALSE)
    return MX_E_ReadFault;
  //check machine
  switch (wMachine = sFileHeader.Machine)
  {
    case IMAGE_FILE_MACHINE_I386:
      if (ReadMem(&(uNtHdr.s32), lpNtHdr, sizeof(uNtHdr.s32)) == FALSE)
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
        if (ReadMem(cFileImgSect.Get(), (PIMAGE_SECTION_HEADER)(lpNtHdr + sizeof(uNtHdr.s32)),
                    nSectionsCount * sizeof(IMAGE_SECTION_HEADER)) == FALSE)
        {
          return MX_E_ReadFault;
        }
      }

      //parse import table
      if ((dwParseFlags & MXLIBHLP_PEPARSER_FLAG_ParseImportTables) != 0)
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
                (dwParseFlags & MXLIBHLP_PEPARSER_FLAG_IgnoreMalformed) == 0)
            {
              return hRes;
            }
            sImportsInfo.aDllList.RemoveAllElements();
          }
        }
      }

      //parse export table
      if ((dwParseFlags & MXLIBHLP_PEPARSER_FLAG_ParseExportTable) != 0)
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
                (dwParseFlags & MXLIBHLP_PEPARSER_FLAG_IgnoreMalformed) == 0)
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
      if ((dwParseFlags & MXLIBHLP_PEPARSER_FLAG_ParseResources) != 0)
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
                (dwParseFlags & MXLIBHLP_PEPARSER_FLAG_IgnoreMalformed) == 0)
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
      if (ReadMem(&(uNtHdr.s64), lpNtHdr, sizeof(uNtHdr.s64)) == FALSE)
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
        if (ReadMem(cFileImgSect.Get(), (PIMAGE_SECTION_HEADER)(lpNtHdr + sizeof(uNtHdr.s64)),
                    nSectionsCount * sizeof(IMAGE_SECTION_HEADER)) == FALSE)
        {
          return MX_E_ReadFault;
        }
      }

      //parse import table
      if ((dwParseFlags & MXLIBHLP_PEPARSER_FLAG_ParseImportTables) != 0)
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
               (dwParseFlags & MXLIBHLP_PEPARSER_FLAG_IgnoreMalformed) == 0)
            {
              return hRes;
            }
            sImportsInfo.aDllList.RemoveAllElements();
          }
        }
      }

      //parse export table
      if ((dwParseFlags & MXLIBHLP_PEPARSER_FLAG_ParseExportTable) != 0)
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
                (dwParseFlags & MXLIBHLP_PEPARSER_FLAG_IgnoreMalformed) == 0)
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
      if ((dwParseFlags & MXLIBHLP_PEPARSER_FLAG_ParseResources) != 0)
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
                (dwParseFlags & MXLIBHLP_PEPARSER_FLAG_IgnoreMalformed) == 0)
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

HRESULT CPeParser::DoParseImportTable(_In_ PIMAGE_IMPORT_DESCRIPTOR lpImportDesc)
{
  MX::TAutoDeletePtr<CImportedDll> cDllEntry;
  IMAGE_IMPORT_DESCRIPTOR sImportDesc;
  LPBYTE lpNameAddress, lpThunk, lpFunctionThunk;
  union {
    IMAGE_THUNK_DATA32 s32;
#if defined(_M_X64)
    IMAGE_THUNK_DATA64 s64;
#endif //_M_X64
  } uThunkData;
  MX::CStringA cStrFuncNameA;
  LPIMPORTED_FUNCTION lpNewEntry;
  DWORD dwOrdinal;
  LPVOID lpFuncAddress;
  HRESULT hRes;

restart:
  cDllEntry.Attach(MX_DEBUG_NEW CImportedDll());
  if (!cDllEntry)
    return E_OUTOFMEMORY;

  if (ReadMem(&sImportDesc, lpImportDesc, sizeof(sImportDesc)) == FALSE)
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
        if (ReadMem(&uThunkData, lpThunk, sizeof(uThunkData.s32)) == FALSE)
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
          if (ReadMem(&uThunkData, lpFunctionThunk, sizeof(uThunkData.s32)) == FALSE)
            return MX_E_ReadFault;
          lpFuncAddress = ULongToPtr(uThunkData.s32.u1.Function);
        }

        //create new entry
        lpNewEntry = (LPIMPORTED_FUNCTION)MX_MALLOC(sizeof(IMPORTED_FUNCTION) + cStrFuncNameA.GetLength());
        if (lpNewEntry == NULL)
          return E_OUTOFMEMORY;
        lpNewEntry->dwOrdinal = dwOrdinal;
        lpNewEntry->lpAddress = lpFuncAddress;
        MX::MemCopy(lpNewEntry->szNameA, (LPCSTR)cStrFuncNameA, cStrFuncNameA.GetLength());
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
        if (ReadMem(&uThunkData, lpThunk, sizeof(uThunkData.s64)) == FALSE)
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
          if (ReadMem(&uThunkData, lpFunctionThunk, sizeof(uThunkData.s64)) == FALSE)
            return MX_E_ReadFault;
          lpFuncAddress = (LPVOID)(uThunkData.s64.u1.Function);
        }

        //create new entry
        lpNewEntry = (LPIMPORTED_FUNCTION)MX_MALLOC(sizeof(IMPORTED_FUNCTION) + cStrFuncNameA.GetLength());
        if (lpNewEntry == NULL)
          return E_OUTOFMEMORY;
        lpNewEntry->dwOrdinal = dwOrdinal;
        lpNewEntry->lpAddress = lpFuncAddress;
        MX::MemCopy(lpNewEntry->szNameA, (LPCSTR)cStrFuncNameA, cStrFuncNameA.GetLength());
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

HRESULT CPeParser::DoParseExportTable(_In_ PIMAGE_EXPORT_DIRECTORY lpExportDir, _In_ DWORD dwStartRVA,
                                      _In_ DWORD dwEndRVA)
{
  IMAGE_EXPORT_DIRECTORY sExportDir;
  LPEXPORTED_FUNCTION lpNewEntry;
  MX::CStringA cStrFuncNameA, cStrForwardsToA;
  LPDWORD lpdwAddressOfFunctions, lpdwAddressOfNames;
  LPWORD lpwAddressOfNameOrdinals;
  MX::TAutoFreePtr<WORD> aNameOrdinalsList;
  DWORD dw, dw2, dwNumberOfNames, dwFuncAddress, dwNameAddress;
  LPVOID lpFuncAddress;
  HRESULT hRes;

  if (ReadMem(&sExportDir, lpExportDir, sizeof(sExportDir)) == FALSE)
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
    if (ReadMem(aNameOrdinalsList.Get(), lpwAddressOfNameOrdinals, (SIZE_T)dwNumberOfNames * sizeof(WORD)) == FALSE)
      return MX_E_ReadFault;
  }

  for (dw=0; dw<sExportDir.NumberOfFunctions && dw<MAX_EXPORTS_COUNT; dw++)
  {
    if (ReadMem(&dwFuncAddress, &lpdwAddressOfFunctions[dw], sizeof(dwFuncAddress)) == FALSE)
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

      sA = MX::StrChrA((LPCSTR)cStrForwardsToA, '.');
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
        if (ReadMem(&dwNameAddress, &lpdwAddressOfNames[dw2], sizeof(dwNameAddress)) == FALSE)
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
    MX::MemCopy(lpNewEntry->szNameA, (LPCSTR)cStrFuncNameA, cStrFuncNameA.GetLength());
    lpNewEntry->szNameA[cStrFuncNameA.GetLength()] = 0;
    if (cStrForwardsToA.IsEmpty() != FALSE)
    {
      lpNewEntry->szForwardsToA = NULL;
    }
    else
    {
      lpNewEntry->szForwardsToA = lpNewEntry->szNameA + cStrFuncNameA.GetLength() + 1;
      MX::MemCopy(lpNewEntry->szForwardsToA, (LPCSTR)cStrForwardsToA, cStrForwardsToA.GetLength());
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

HRESULT CPeParser::DoParseResources()
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
      if (ReadMem(cVersionInfo.Get(), lpData, nDataSize) == FALSE)
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

HRESULT CPeParser::_FindResource(_In_ LPCWSTR szNameW, _In_ LPCWSTR szTypeW, _In_ WORD wLang,
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
  if (ReadMem(&sDirEntry, lpDirEntry, sizeof(sDirEntry)) == FALSE)
    return MX_E_ReadFault;
  lpTypeResDir = (PIMAGE_RESOURCE_DIRECTORY)((LPBYTE)lpResourceDir +
                                             (SIZE_T)(sDirEntry.OffsetToData & 0x7FFFFFFF));

  hRes = LookupResourceEntry(lpResourceDir, lpTypeResDir, szNameW, &lpDirEntry);
  if (FAILED(hRes))
    return hRes;
  if (ReadMem(&sDirEntry, lpDirEntry, sizeof(sDirEntry)) == FALSE)
    return MX_E_ReadFault;
  lpNameResDir = (PIMAGE_RESOURCE_DIRECTORY)((LPBYTE)lpResourceDir +
                                             (SIZE_T)(sDirEntry.OffsetToData & 0x7FFFFFFF));

  hRes = LookupResourceEntry(lpResourceDir, lpNameResDir, MAKEINTRESOURCEW(wLang), &lpDirEntry);
  if (FAILED(hRes))
  {
    if (hRes != MX_E_NotFound)
      return hRes;
    //get the first entry if provided language is not found
    if (ReadMem(&sResDir, lpNameResDir, sizeof(sResDir)) == FALSE)
      return MX_E_ReadFault;
    if (sResDir.NumberOfIdEntries == 0)
      return MX_E_NotFound;
    lpDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(lpNameResDir + 1);
  }
  if (ReadMem(&sDirEntry, lpDirEntry, sizeof(sDirEntry)) == FALSE)
    return MX_E_ReadFault;

  //get data entry
  if (ReadMem(&sResDataEntry, (LPBYTE)lpResourceDir + (SIZE_T)(sDirEntry.OffsetToData & 0x7FFFFFFF),
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

HRESULT CPeParser::LookupResourceEntry(_In_ PIMAGE_RESOURCE_DIRECTORY lpRootDir, _In_ PIMAGE_RESOURCE_DIRECTORY lpDir,
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
  if (ReadMem(&sResDir, lpDir, sizeof(sResDir)) == FALSE)
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
      if (ReadMem(&sResDirEntry, lpEntries + (SIZE_T)dwMiddle, sizeof(sResDirEntry)) == FALSE)
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
      if (ReadMem(&sResDirEntry, lpEntries + (SIZE_T)dwMiddle, sizeof(sResDirEntry)) == FALSE)
        return MX_E_ReadFault;

      lpPtr = (LPBYTE)lpRootDir + (SIZE_T)(sResDirEntry.Name & 0x7FFFFFFF);
      if (ReadMem(&wResDirStringLen, lpPtr, sizeof(wResDirStringLen)) == FALSE)
        return MX_E_ReadFault;
      lpPtr += sizeof(WORD);

      nCmpResult = 1; //if name string is zero-length, then the key will be greater
      szCopyOfKeyW = szKeyW;
      while (wResDirStringLen > 0)
      {
        WORD wThisRound = (wResDirStringLen > 64) ? 64 : wResDirStringLen;

        if (ReadMem(szTempBufW, lpPtr, (SIZE_T)wThisRound * sizeof(WCHAR)) == FALSE)
          return MX_E_ReadFault;
        nCmpResult = MX::MemCompare(szCopyOfKeyW, szTempBufW, (SIZE_T)wThisRound);
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

}; //namespace MXHelpers
