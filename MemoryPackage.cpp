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
#include "MemoryPackage.h"
#include <FnvHash.h>
#include <Strings\Strings.h>
#include <search.h>
#include <ZipLib\ZipLib.h>

//-----------------------------------------------------------

namespace MX {

namespace MemoryPackage {

namespace Internals {

class CFileStream : public CStream
{
private:
  CFileStream();

public:
  HRESULT Read(_Out_writes_bytes_(nRead) LPVOID lpDest, _In_ SIZE_T nBytes, _Out_ SIZE_T &nRead,
               _In_opt_ ULONGLONG nStartOffset = ULONGLONG_MAX);
  HRESULT Write(_In_reads_bytes_(nBytes) LPCVOID lpSrc, _In_ SIZE_T nBytes, _Out_ SIZE_T &nWritten,
                _In_opt_ ULONGLONG nStartOffset = ULONGLONG_MAX);

  HRESULT Seek(_In_ ULONGLONG nPosition, _In_opt_ eSeekMethod nMethod = SeekStart);

  ULONGLONG GetLength() const;

private:
  friend class CMemoryPackage;

  struct
  {
    LPBYTE lpStart, lpNext;
    SIZE_T nLength;
  } sCompressedData;
  ULONGLONG nOffset, nUncompressedSize;
  ULONGLONG nFileHash;
  TAutoDeletePtr<CZipLib> cDecompressor;
};

}; //namespace Internals

}; //namespace MemoryPackage

}; //namespace MX

//-----------------------------------------------------------

namespace MX {

CMemoryPackage::CMemoryPackage() : CBaseMemObj(), CNonCopyableObj()
{
  return;
}

CMemoryPackage::~CMemoryPackage()
{
  ClosePackage();
  return;
}

HRESULT CMemoryPackage::OpenPackage(_In_ LPCVOID lpData, _In_ SIZE_T nDataSize, _In_ ULONGLONG nPasswordHash)
{
  TAutoFreePtr<FILEITEM> cFileItem;
  DWORD dwFilesCount, dwFileDataOffset, dwFileSize, dwNameLength;
  ULONGLONG nHeaderHash[2];
  LPWSTR szCurrFileNameW = NULL;
  union {
    ULONGLONG ullValue;
    BYTE aByteValues[8];
  };
  SIZE_T i, nCount, nState, nDataPos, nAvailable;
  LPBYTE p;
  HRESULT hRes;

  if (lpData == NULL)
    return E_POINTER;
  if (nDataSize < sizeof(DWORD) || nDataSize > 0x7FFFFFFF)
    return E_INVALIDARG;
  //get files count
  dwFilesCount = *((DWORD MX_UNALIGNED*)lpData);
  //get header hash
  nHeaderHash[0] = (ULONGLONG)fnv_64a_buf(&dwFilesCount, sizeof(DWORD), nPasswordHash);
  //parse header
  p = (LPBYTE)lpData + sizeof(DWORD);
  nDataPos = nAvailable = nState = 0;
  dwFileDataOffset = dwFileSize = dwNameLength = 0;
  hRes = S_OK;
  while (SUCCEEDED(hRes) && dwFilesCount > 0)
  {
    //need data?
    if (nDataPos >= nAvailable)
    {
      //calculate available
      nAvailable = nDataSize - (SIZE_T)(p - (LPBYTE)lpData);
      if (nAvailable == 0)
      {
        hRes = MX_E_InvalidData;
        break;
      }
      //calculate hash
      nHeaderHash[1] = (ULONGLONG)((SIZE_T)(p - ((LPBYTE)lpData + sizeof(DWORD))));
      nHeaderHash[1] = fnv_64a_buf(&nHeaderHash[1], sizeof(ULONGLONG), nHeaderHash[0]);
      //entire ULONGLONG available?
      if (nAvailable >= 8)
      {
        ullValue = *((ULONGLONG MX_UNALIGNED*)p);
        p += 8;
        nAvailable = 8;
      }
      else if (nAvailable > 0)
      {
        ullValue = 0ui64;
        ::MxMemCopy(aByteValues, p, nAvailable);
        p += nAvailable;
      }
      else
      {
        hRes = MX_E_InvalidData;
        break;
      }
      ullValue ^= nHeaderHash[1];
      nDataPos = 0;
    }
    //process byte
    switch (nState)
    {
      case 0:
      case 1:
      case 2:
      case 3:
        dwFileDataOffset |= (DWORD)aByteValues[nDataPos++] << (nState << 3);
        nState++;
        break;

      case 4:
      case 5:
      case 6:
      case 7:
        dwFileSize |= (DWORD)aByteValues[nDataPos++] << ((nState - 4) << 3);
        nState++;
        break;

      case 8:
      case 9:
        dwNameLength |= (DWORD)aByteValues[nDataPos++] << ((nState - 8) << 3);
        if ((++nState) == 10)
        {
          if (dwFileDataOffset > nDataSize || dwNameLength == 0 || dwNameLength >= 32768)
          {
            hRes = MX_E_InvalidData;
            break;
          }
          cFileItem.Attach((LPFILEITEM)MX_MALLOC(sizeof(FILEITEM) + (SIZE_T)dwNameLength*sizeof(WCHAR)));
          if (!cFileItem)
          {
            hRes = E_OUTOFMEMORY;
            break;
          }
          cFileItem->lpCompressedData = (LPBYTE)lpData + (SIZE_T)dwFileDataOffset;
          cFileItem->nCompressedSize = 0;
          cFileItem->dwUncompressedSize = dwFileSize;
          cFileItem->nHash = nPasswordHash;
          szCurrFileNameW = cFileItem->szNameW;
        }
        break;

      case 10:
        *szCurrFileNameW = (WCHAR)aByteValues[nDataPos++];
        nState++;
        break;

      case 11:
        *szCurrFileNameW |= (WCHAR)aByteValues[nDataPos++] << 8;
        cFileItem->nHash = fnv_64a_buf(szCurrFileNameW, sizeof(WCHAR), cFileItem->nHash);
        szCurrFileNameW++;
        if ((--dwNameLength) > 0)
        {
          nState = 10;
        }
        else
        {
          //zero-terminate filename string
          *szCurrFileNameW = 0;
          //add to file list
          if (aFileItemsList.AddElement(cFileItem.Get()) == FALSE)
          {
            hRes = E_OUTOFMEMORY;
            break;
          }
          cFileItem.Detach();
          //reset state
          nState = 0;
          dwFileDataOffset = dwFileSize = dwNameLength = 0;
          szCurrFileNameW = NULL;
          dwFilesCount--;
        }
        break;
    }
  }

  //set compressed data size
  if (SUCCEEDED(hRes))
  {
    nCount = aFileItemsList.GetCount();
    for (i = 0; i < nCount; i++)
    {
      p = (i+1 < nCount) ? (aFileItemsList[i+1]->lpCompressedData) : ((LPBYTE)lpData + nDataSize);
      if (p < aFileItemsList[i]->lpCompressedData)
      {
        hRes = MX_E_InvalidData;
        break;
      }
      aFileItemsList[i]->nCompressedSize = (SIZE_T)(p - aFileItemsList[i]->lpCompressedData);
    }
  }

  //sort files
  if (SUCCEEDED(hRes))
  {
#pragma warning(suppress : 6387)
    qsort_s(aFileItemsList.GetBuffer(), aFileItemsList.GetCount(), sizeof(FILEITEM*),
            reinterpret_cast<int(__cdecl *)(void *, const void *, const void *)>(&CMemoryPackage::FileItemCompare),
            NULL);
  }

  //done
  if (FAILED(hRes))
    aFileItemsList.RemoveAllElements();
  return hRes;
}

VOID CMemoryPackage::ClosePackage()
{
  aFileItemsList.RemoveAllElements();
  return;
}

HRESULT CMemoryPackage::GetStream(_In_z_ LPCWSTR szFileNameW, _Deref_out_ CStream **lplpStream)
{
  CStringW cStrFileNameW;
  MemoryPackage::Internals::CFileStream *lpFileStream;
  FILEITEM *lpFileItem;
  LPVOID lpPtr;

  if (lplpStream != NULL)
    *lplpStream = NULL;
  if (szFileNameW == NULL || lplpStream == NULL)
    return E_POINTER;
  if (*szFileNameW == 0)
    return E_INVALIDARG;
  //normalize name
  while (*szFileNameW != 0)
  {
    if (*szFileNameW == L'/' || *szFileNameW == L'\\')
    {
      if (cStrFileNameW.ConcatN(L"\\", 1) == FALSE)
        return E_OUTOFMEMORY;
      while (*szFileNameW == L'/' || *szFileNameW == L'\\')
        szFileNameW++;
    }
    else
    {
      LPCWSTR szStartW = szFileNameW;

      while (*szFileNameW != 0 && *szFileNameW != L'/' && *szFileNameW != L'\\')
        szFileNameW++;
      if (cStrFileNameW.ConcatN(szStartW, (SIZE_T)(szFileNameW - szStartW)) == FALSE)
        return E_OUTOFMEMORY;
    }
  }
  //locate the item
#pragma warning(suppress : 6387)
  lpPtr = bsearch_s((LPCWSTR)cStrFileNameW, aFileItemsList.GetBuffer(), aFileItemsList.GetCount(), sizeof(FILEITEM*),
                    reinterpret_cast<int(__cdecl*)(void*, const void*, const void*)>(&CMemoryPackage::FileItemSearch),
                    NULL);
  if (lpPtr == NULL)
    return MX_E_FileNotFound;
  lpFileItem = *((FILEITEM**)lpPtr);
  //create stream
  lpFileStream = MX_DEBUG_NEW MemoryPackage::Internals::CFileStream();
  if (lpFileStream == NULL)
    return E_OUTOFMEMORY;
  lpFileStream->sCompressedData.lpStart = lpFileItem->lpCompressedData;
  lpFileStream->sCompressedData.nLength = lpFileItem->nCompressedSize;
  lpFileStream->nFileHash = lpFileItem->nHash;
  lpFileStream->nUncompressedSize = (ULONGLONG)(lpFileItem->dwUncompressedSize);
  //done
  *lplpStream = lpFileStream;
  return S_OK;
}

HRESULT CMemoryPackage::GetFiles(_In_z_ LPCWSTR szFolderNameW, _Out_ TArrayListWithFree<LPCWSTR> &aFilesList)
{
  MX::CStringW cStrTempW;
  LPFILEITEM *lplpFileItem;
  SIZE_T nFolderNameLen, nCount;

  aFilesList.RemoveAllElements();

  if (szFolderNameW == NULL)
    return E_POINTER;
  while (*szFolderNameW == L'/' || *szFolderNameW == L'\\')
    szFolderNameW++;
  nFolderNameLen = StrLenW(szFolderNameW);
  while (nFolderNameLen > 0 &&
         (szFolderNameW[nFolderNameLen - 1] == L'/' || szFolderNameW[nFolderNameLen - 1] == L'\\'))
  {
    nFolderNameLen--;
  }

  lplpFileItem = aFileItemsList.GetBuffer();
  for (nCount = aFileItemsList.GetCount(); nCount > 0; lplpFileItem++, nCount--)
  {
    LPCWSTR szNameW;
    BOOL bAlreadyOnList;

    szNameW = (*lplpFileItem)->szNameW;

    //if we are non-root, check folder
    if (nFolderNameLen > 0)
    {
      LPCWSTR szFolderSpecW;
      int comp;

      szFolderSpecW = szFolderNameW;
      comp = FileSpecCompare(&szFolderSpecW, &szNameW, nFolderNameLen);
      if (comp != 0)
        continue;
      if (*szNameW != L'\\')
        continue;
      szNameW++;
    }

    //check if the remaining filename does not contains a slash
    if (StrChrW(szNameW, L'\\') != NULL)
      continue; //yes => it a file on a subdirectory, skip

    //found a file to add
    if (cStrTempW.Copy(szNameW) == FALSE)
      return E_OUTOFMEMORY;
    if (aFilesList.SortedInsert((LPCWSTR)cStrTempW, &CMemoryPackage::ListFilesInsert, NULL, TRUE,
                                &bAlreadyOnList) != FALSE)
    {
      cStrTempW.Detach();
    }
    else
    {
      if (bAlreadyOnList == FALSE)
        return E_OUTOFMEMORY;
    }
  }

  //done
  return S_OK;
}

HRESULT CMemoryPackage::GetFolders(_In_z_ LPCWSTR szFolderNameW, _Out_ TArrayListWithFree<LPCWSTR> &aFoldersList)
{
  MX::CStringW cStrTempW;
  LPFILEITEM *lplpFileItem;
  SIZE_T nFolderNameLen, nCount;

  aFoldersList.RemoveAllElements();

  if (szFolderNameW == NULL)
    return E_POINTER;
  while (*szFolderNameW == L'/' || *szFolderNameW == L'\\')
    szFolderNameW++;
  nFolderNameLen = StrLenW(szFolderNameW);
  while (nFolderNameLen > 0 &&
         (szFolderNameW[nFolderNameLen - 1] == L'/' || szFolderNameW[nFolderNameLen - 1] == L'\\'))
  {
    nFolderNameLen--;
  }

  lplpFileItem = aFileItemsList.GetBuffer();
  for (nCount = aFileItemsList.GetCount(); nCount > 0; lplpFileItem++, nCount--)
  {
    LPCWSTR szNameW, szNextSlashW;
    SIZE_T nLen;
    BOOL bAlreadyOnList;

    szNameW = (*lplpFileItem)->szNameW;

    //if we are non-root, check folder
    if (nFolderNameLen > 0)
    {
      LPCWSTR szFolderSpecW;
      int comp;

      szFolderSpecW = szFolderNameW;
      comp = FileSpecCompare(&szFolderSpecW, &szNameW, nFolderNameLen);
      if (comp != 0)
        continue;
      if (*szNameW != L'\\')
        continue;
      szNameW++;
    }

    //check if the remaining filename does not contains a slash
    szNextSlashW = StrChrW(szNameW, L'\\');
    if (szNextSlashW == NULL)
      continue; //no => it's a file!!!

    //found a folder to add but we must also check if it was already added
    nLen = (SIZE_T)(szNextSlashW - szNameW);

    if (cStrTempW.CopyN(szNameW, nLen) == FALSE)
      return E_OUTOFMEMORY;
    if (aFoldersList.SortedInsert((LPCWSTR)cStrTempW, &CMemoryPackage::ListFilesInsert, NULL, TRUE,
                                  &bAlreadyOnList) != FALSE)
    {
      cStrTempW.Detach();
    }
    else
    {
      if (bAlreadyOnList == FALSE)
        return E_OUTOFMEMORY;
    }
  }

  //done
  return S_OK;
}

int CMemoryPackage::FileItemCompare(void *lpContext, const FILEITEM **lplpItem1, const FILEITEM **lplpItem2)
{
  LPCWSTR sW_1, sW_2;

  sW_1 = (*lplpItem1)->szNameW;
  sW_2 = (*lplpItem2)->szNameW;
  return FileSpecCompare(&sW_1, &sW_2, (SIZE_T)-1);
}

int CMemoryPackage::FileItemSearch(void *lpContext, const LPCWSTR szSearchNameW, const FILEITEM **lplpItem)
{
  LPCWSTR sW_1, sW_2;

  sW_1 = szSearchNameW;
  sW_2 = (*lplpItem)->szNameW;
  return FileSpecCompare(&sW_1, &sW_2, (SIZE_T)-1);
}

int CMemoryPackage::ListFilesInsert(_In_ LPVOID lpContext, _In_ LPCWSTR *lpszElem1, _In_ LPCWSTR *lpszElem2)
{
  return StrCompareW(*lpszElem1, *lpszElem2, TRUE);
}

int CMemoryPackage::FileSpecCompare(_In_ LPCWSTR *lpszStrW_1, _In_ LPCWSTR *lpszStrW_2, _In_ SIZE_T nLen)
{
  LPCWSTR sW_1, sW_2;
  int comp;
  SIZE_T nThisLen;

  sW_1 = *lpszStrW_1;
  sW_2 = *lpszStrW_2;

restart:
  //compare until next folder separator or EOS
  for (nThisLen = 0;
        nThisLen < nLen &&
        sW_1[nThisLen] != 0 && sW_1[nThisLen] != L'/' && sW_1[nThisLen] != L'\\' &&
        sW_2[nThisLen] != 0 && sW_2[nThisLen] != L'/' && sW_2[nThisLen] != L'\\';
        nThisLen++);

  if (nThisLen > 0)
  {
    comp = StrNCompareW(sW_1, sW_2, nThisLen, TRUE);
    if (comp != 0)
      return comp;

    sW_1 += nThisLen;
    sW_2 += nThisLen;
    if (nLen != (SIZE_T)-1)
      nLen -= nThisLen;
  }

  //if we reach the end of a counted string, stop
  if (nLen == 0)
  {
    *lpszStrW_1 = sW_1;
    *lpszStrW_2 = sW_2;
    return 0;
  }

  //skip slashes if both strings are placed in the folder separator
  if ((*sW_1 == L'/' || *sW_1 == L'\\') && (*sW_2 == L'/' || *sW_2 == L'\\'))
  {
    while ((*sW_1 == L'/' || *sW_1 == L'\\') && (*sW_2 == L'/' || *sW_2 == L'\\'))
    {
      sW_1++;
      sW_2++;
      if (nLen != (SIZE_T)-1)
      {
        if ((--nLen) == 0)
        {
          *lpszStrW_1 = sW_1;
          *lpszStrW_2 = sW_2;
          return 0;
        }
      }
    }
  }

  //if one of the strings is a slash, then we have a mismatch
  if (*sW_1 == L'/' || *sW_1 == L'\\' || *sW_2 == L'/' || *sW_2 == L'\\')
  {
    return (*sW_1 < *sW_2) ? -1 : 1;
  }

  //check if we reached the EOS of one or both strings
  if (*sW_1 == 0)
  {
    if (*sW_2 == 0)
    {
      *lpszStrW_1 = sW_1;
      *lpszStrW_2 = sW_2;
      return 0;
    }
    return -1;
  }
  else if (*sW_2 == 0)
  {
    return 1;
  }

  goto restart;
}

}; //namespace MX

//-----------------------------------------------------------

namespace MX {

namespace MemoryPackage {

namespace Internals {

CFileStream::CFileStream() : MX::CStream()
{
  sCompressedData.lpStart = sCompressedData.lpNext = NULL;
  sCompressedData.nLength = 0;
  nOffset = nUncompressedSize = nFileHash = 0ui64;
  return;
}

HRESULT CFileStream::Read(_Out_writes_bytes_(nRead) LPVOID lpDest, _In_ SIZE_T nBytes, _Out_ SIZE_T &nRead,
                          _In_opt_ ULONGLONG nStartOffset)
{
  union {
    ULONGLONG ullValue;
    BYTE aByteValues[1024];
  };
  ULONGLONG nBytesToSkip, nCurrHash;
  SIZE_T nAvailable;
  BOOL bDecompressEndCalled;
  HRESULT hRes;

  nRead = 0;
  if (lpDest == NULL)
    return E_POINTER;
  if (nStartOffset != ULONGLONG_MAX)
  {
    //NOTE: CFileStream::Read is only called during HTML output while sending data to socket so no problem to
    //      modify the current offset with seek.
    hRes = Seek(nStartOffset, MX::CStream::SeekStart);
    if (FAILED(hRes))
      return hRes;
  }
  if (nOffset >= nUncompressedSize)
    return MX_E_EndOfFileReached;
  nBytesToSkip = 0;
  bDecompressEndCalled = FALSE;
  if (!cDecompressor)
  {
    cDecompressor.Attach(MX_DEBUG_NEW MX::CZipLib(FALSE));
    if (!cDecompressor)
      return E_OUTOFMEMORY;
    hRes = cDecompressor->BeginDecompress();
    if (FAILED(hRes))
    {
      cDecompressor.Reset();
      return hRes;
    }
    nBytesToSkip = nOffset;
    sCompressedData.lpNext = sCompressedData.lpStart;
  }
  //read
  hRes = S_OK;
  while (SUCCEEDED(hRes) && nRead < nBytes)
  {
    if ((nAvailable = cDecompressor->GetAvailableData()) > 0)
    {
      //process alredy decompressed data
      if (nBytesToSkip > 0)
      {
        if ((ULONGLONG)nAvailable > nBytesToSkip)
          nAvailable = (SIZE_T)nBytesToSkip;
        if (nAvailable > sizeof(aByteValues))
          nAvailable = sizeof(aByteValues);
        cDecompressor->GetData(aByteValues, nAvailable);
        nBytesToSkip -= (ULONGLONG)nAvailable;
      }
      else
      {
        if (nAvailable > nBytes-nRead)
          nAvailable = nBytes-nRead;
        cDecompressor->GetData((LPBYTE)lpDest+nRead, nAvailable);
        nRead += nAvailable;
        nOffset += nAvailable;
      }
    }
    else
    {
      //feed the decompressor with compressed data
      //calculate hash
      nCurrHash = (ULONGLONG)((SIZE_T)(sCompressedData.lpNext - sCompressedData.lpStart));
      nCurrHash = fnv_64a_buf(&nCurrHash, sizeof(ULONGLONG), nFileHash);
      //entire ULONGLONG available?
      nAvailable = sCompressedData.nLength - (SIZE_T)(sCompressedData.lpNext - sCompressedData.lpStart);
      if (nAvailable > 0)
      {
        if (nAvailable >= 8)
        {
          ullValue = *((ULONGLONG MX_UNALIGNED*)(sCompressedData.lpNext));
          sCompressedData.lpNext += 8;
          nAvailable = 8;
        }
        else
        {
          ullValue = 0ui64;
          ::MxMemCopy(aByteValues, sCompressedData.lpNext, nAvailable);
          sCompressedData.lpNext += nAvailable;
        }
        ullValue ^= nCurrHash;
        hRes = cDecompressor->DecompressStream(aByteValues, nAvailable);
      }
      else if (bDecompressEndCalled == FALSE)
      {
        bDecompressEndCalled = TRUE;
        hRes = cDecompressor->End();
      }
      else
      {
        break;
      }
    }
  }
  //done
  if (FAILED(hRes) || bDecompressEndCalled != FALSE)
    cDecompressor.Reset();
  return hRes;
}

HRESULT CFileStream::Write(_In_reads_bytes_(nBytes) LPCVOID lpSrc, _In_ SIZE_T nBytes, _Out_ SIZE_T &nWritten,
                           _In_opt_ ULONGLONG nStartOffset)
{
  UNREFERENCED_PARAMETER(nStartOffset);
  nWritten = 0;
  if (lpSrc == NULL)
    return E_POINTER;
  return MX_E_WriteFault;
}

HRESULT CFileStream::Seek(_In_ ULONGLONG nPosition, _In_opt_ eSeekMethod nMethod)
{
  switch (nMethod)
  {
    case SeekStart:
      if (nPosition > nUncompressedSize)
        nPosition = nUncompressedSize;
      break;

    case SeekCurrent:
      if ((LONGLONG)nPosition >= 0)
      {
        if (nPosition > nUncompressedSize - nOffset)
          nPosition = nUncompressedSize - nOffset;
        nPosition += nOffset;
      }
      else
      {
        nPosition = (~nPosition) + 1;
        if (nPosition > nOffset)
          return E_FAIL;
        nPosition = nOffset - nPosition;
      }
      break;

    case SeekEnd:
      if (nPosition > nUncompressedSize)
        nPosition = nUncompressedSize;
      nPosition = nUncompressedSize - nPosition;
      break;

    default:
      return E_INVALIDARG;
  }
  if (nPosition > nOffset)
  {
    BYTE aTempBuf[1024];
    SIZE_T nToRead, nRead;
    HRESULT hRes;

    //on advance, read
    while (nOffset < nPosition)
    {
      nToRead = ((nPosition - nOffset) > (ULONGLONG)sizeof(aTempBuf)) ? sizeof(aTempBuf) :
                                                                        (SIZE_T)(nPosition - nOffset);
      hRes = Read(aTempBuf, nToRead, nRead);
      if (FAILED(hRes))
      {
        cDecompressor.Reset();
        nOffset = nPosition;
        return hRes;
      }
      if (nToRead != nRead)
      {
        cDecompressor.Reset();
        nOffset = nPosition;
        return E_FAIL;
      }
      nOffset += (ULONGLONG)nRead;
    }
  }
  else if (nPosition < nOffset)
  {
    //on rewind, reset decompressor
    cDecompressor.Reset();
    nOffset = nPosition;
  }
  else
  {
    nOffset = nPosition;
  }
  //done
  return S_OK;
}

ULONGLONG CFileStream::GetLength() const
{
  return nUncompressedSize;
}

}; //namespace Internals

}; //namespace MemoryPackage

}; //namespace MX
