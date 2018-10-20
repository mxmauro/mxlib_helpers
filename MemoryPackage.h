/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#ifndef _MEMORY_PACKAGE_H
#define _MEMORY_PACKAGE_H

#include <Defines.h>
#include <Streams.h>
#include <AutoPtr.h>
#include <ArrayList.h>

//-----------------------------------------------------------

class CMemoryPackage : public virtual MX::CBaseMemObj
{
  MX_DISABLE_COPY_CONSTRUCTOR(CMemoryPackage);
public:
  CMemoryPackage();
  ~CMemoryPackage();

  HRESULT OpenPackage(_In_ LPCVOID lpData, _In_ SIZE_T nDataSize, _In_ ULONGLONG nPasswordHash);
  VOID ClosePackage();

  HRESULT GetStream(_In_z_ LPCWSTR szFileNameW, __deref_out MX::CStream **lplpStream);

private:
  typedef struct {
    union {
      LPBYTE lpCompressedData;
      LPCWSTR szSearchNameW;
    };
    SIZE_T nCompressedSize;
    DWORD dwUncompressedSize;
    ULONGLONG nHash;
    WCHAR szNameW[1];
  } FILEITEM, *LPFILEITEM;

  static int FileItemCompare(void *lpContext, const FILEITEM **lplpItem1, const FILEITEM **lplpItem2);
  static int FileItemSearch(void *lpContext, const FILEITEM **lplpItem1, const FILEITEM **lplpItem2);

  MX::TArrayListWithFree<LPFILEITEM, 256> aFileItemsList;
};

//-----------------------------------------------------------

#endif //_MEMORY_PACKAGE_H
