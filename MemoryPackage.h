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
#ifndef _MXLIBHLP_MEMORY_PACKAGE_H
#define _MXLIBHLP_MEMORY_PACKAGE_H

#include <Defines.h>
#include <Streams.h>
#include <AutoPtr.h>
#include <ArrayList.h>

//-----------------------------------------------------------

namespace MX {

class CMemoryPackage : public virtual CBaseMemObj, public CNonCopyableObj
{
public:
  CMemoryPackage();
  ~CMemoryPackage();

  HRESULT OpenPackage(_In_ LPCVOID lpData, _In_ SIZE_T nDataSize, _In_ ULONGLONG nPasswordHash);
  VOID ClosePackage();

  HRESULT GetStream(_In_z_ LPCWSTR szFileNameW, __deref_out CStream **lplpStream);

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

  TArrayListWithFree<LPFILEITEM, 256> aFileItemsList;
};

}; //namespace MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_MEMORY_PACKAGE_H
