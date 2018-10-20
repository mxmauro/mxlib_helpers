/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#include "ResourceExtract.h"

//-----------------------------------------------------------

namespace MXHelpers {

HRESULT ExtractResourceToFile(_In_ HINSTANCE hInst, _In_ LPCWSTR szResNameW, _In_ LPCWSTR szResTypeW,
                              _In_ HANDLE hFile)
{
  HRSRC hRsrc;
  DWORD dwResSize, dwWritten;
  HGLOBAL hGbl;
  LPVOID p = NULL;

  //locate resource
  hRsrc = ::FindResourceW(hInst, szResNameW, szResTypeW);
  if (hRsrc == NULL)
    return MX_HRESULT_FROM_LASTERROR();
  //get resource size & pointer
  dwResSize = ::SizeofResource(hInst, hRsrc);
  if (dwResSize == 0)
    return S_OK;
  //load & lock resource
  hGbl = ::LoadResource(hInst, hRsrc);
  if (hGbl == NULL)
    return E_OUTOFMEMORY;
  p = ::LockResource(hGbl);
  if (p == NULL)
    return E_OUTOFMEMORY;
  //write to file
  if (::WriteFile(hFile, p, dwResSize, &dwWritten, NULL) == FALSE)
    return MX_HRESULT_FROM_LASTERROR();
  //done
  return (dwWritten == dwResSize) ? S_OK : MX_E_PartialCopy;
}

HRESULT ExtractResourceToMemory(_In_ HINSTANCE hInst, _In_ LPCWSTR szResNameW, _In_ LPCWSTR szResTypeW,
                                _Outptr_result_maybenull_ LPBYTE *lplpDest, _Out_ SIZE_T *lpnDestSize)
{
  HRSRC hRsrc;
  DWORD dwResSize;
  HGLOBAL hGbl;
  LPVOID p;

  if (lplpDest != NULL)
    *lplpDest = NULL;
  if (lpnDestSize != NULL)
    *lpnDestSize = 0;
  if (lplpDest == NULL || lpnDestSize == NULL)
    return E_POINTER;
  //locate resource
  hRsrc = ::FindResourceW(hInst, szResNameW, szResTypeW);
  if (hRsrc == NULL)
    return MX_HRESULT_FROM_LASTERROR();
  //get resource size & pointer
  dwResSize = ::SizeofResource(hInst, hRsrc);
  if (dwResSize == 0)
    return S_OK;
  //load & lock resource
  hGbl = ::LoadResource(hInst, hRsrc);
  if (hGbl == NULL)
    return E_OUTOFMEMORY;
  p = ::LockResource(hGbl);
  if (p == NULL)
    return E_OUTOFMEMORY;
  //create destination
  *lplpDest = (LPBYTE)MX_MALLOC((SIZE_T)dwResSize);
  if ((*lplpDest) == NULL)
    return E_OUTOFMEMORY;
  *lpnDestSize = (SIZE_T)dwResSize;
  MX::MemCopy(*lplpDest, p, (SIZE_T)dwResSize);
  //done
  return S_OK;
}

HRESULT ExtractResourceToStream(_In_ HINSTANCE hInst, _In_ LPCWSTR szResNameW, _In_ LPCWSTR szResTypeW,
                                _COM_Outptr_opt_result_maybenull_ MX::CMemoryStream **lplpStream)
{
  MX::TAutoRefCounted<MX::CMemoryStream> cStream;
  HRSRC hRsrc;
  DWORD dwResSize;
  SIZE_T nWritten;
  HGLOBAL hGbl;
  LPVOID p;
  HRESULT hRes;

  if (lplpStream == NULL)
    return E_POINTER;
  *lplpStream = NULL;
  //locate resource
  hRsrc = ::FindResourceW(hInst, szResNameW, szResTypeW);
  if (hRsrc == NULL)
    return MX_HRESULT_FROM_LASTERROR();
  //create stream
  cStream.Attach(MX_DEBUG_NEW MX::CMemoryStream());
  if (!cStream)
    return E_OUTOFMEMORY;
  hRes = cStream->Create();
  if (FAILED(hRes))
    return hRes;
  //get resource size & pointer
  dwResSize = ::SizeofResource(hInst, hRsrc);
  if (dwResSize == 0)
  {
    *lplpStream = cStream.Detach();
    return S_OK;
  }
  //load and lock resource
  hGbl = ::LoadResource(hInst, hRsrc);
  if (hGbl == NULL)
    return E_OUTOFMEMORY;
  p = ::LockResource(hGbl);
  if (p == NULL)
    return E_OUTOFMEMORY;
  //write to stream
  hRes = cStream->Write(p, (SIZE_T)dwResSize, nWritten);
  if (SUCCEEDED(hRes) && (SIZE_T)dwResSize != nWritten)
    hRes = MX_E_WriteFault;
  if (SUCCEEDED(hRes))
    hRes = cStream->Seek(0, MX::CStream::SeekStart);
  if (FAILED(hRes))
    return hRes;
  //done
  *lplpStream = cStream.Detach();
  return S_OK;
}

}; //namespace MXHelpers
