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
#include "SingleInstance.h"
#include <WaitableObjects.h>
#include <Strings\Strings.h>
#include <FnvHash.h>

//-----------------------------------------------------------

static MX::CWindowsMutex cSingleInstanceMutex;

//-----------------------------------------------------------

namespace MX {

HRESULT SingleInstanceCheck(_In_z_ LPCWSTR szNameW)
{
  CStringW cStrTempW;
  Fnv64_t nHash;
  HRESULT hRes;
  BOOL b;

  if (szNameW == NULL)
    return E_POINTER;
  if (*szNameW == 0)
    return E_INVALIDARG;
  //check for single instance
  nHash = fnv_64a_buf(szNameW, StrLenW(szNameW) * sizeof(WCHAR), FNV1A_64_INIT);
  if (cStrTempW.Format(L"%s_%16IX", szNameW, nHash) == FALSE)
    return E_OUTOFMEMORY;
  hRes = cSingleInstanceMutex.Create((LPCWSTR)cStrTempW, TRUE, NULL, &b);
  if (FAILED(hRes))
    return hRes;
  //done
  return (b == FALSE) ? S_OK : S_FALSE;
}

}; //namespace MX
