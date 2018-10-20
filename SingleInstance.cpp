/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#include "SingleInstance.h"
#include <WaitableObjects.h>
#include <Strings\Strings.h>
#include <FnvHash.h>

//-----------------------------------------------------------

static MX::CWindowsMutex cSingleInstanceMutex;

//-----------------------------------------------------------

namespace SingleInstance {

HRESULT Check(_In_z_ LPCWSTR szNameW)
{
  MX::CStringW cStrTempW;
  Fnv64_t nHash;
  HRESULT hRes;
  BOOL b;

  if (szNameW == NULL)
    return E_POINTER;
  if (*szNameW == 0)
    return E_INVALIDARG;
  //check for single instance
  nHash = fnv_64a_buf(szNameW, MX::StrLenW(szNameW) * sizeof(WCHAR), FNV1A_64_INIT);
  if (cStrTempW.Format(L"%s_%16IX", szNameW, nHash) == FALSE)
    return E_OUTOFMEMORY;
  hRes = cSingleInstanceMutex.Create((LPCWSTR)cStrTempW, TRUE, NULL, &b);
  if (FAILED(hRes))
    return hRes;
  //done
  return (b == FALSE) ? S_OK : S_FALSE;
}

}; //namespace SingleInstance
