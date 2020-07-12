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
#ifndef _MXLIBHLP_PE_SIGNATURE_AND_INFO_H
#define _MXLIBHLP_PE_SIGNATURE_AND_INFO_H

#include <Defines.h>
#include <Strings\Strings.h>
#include <SoftPub.h>

#define MX_E_TRUST_FAILED_CVE_2020_0601     MAKE_HRESULT(1, MX_SCODE_FACILITY, 0x8001) //0x8F188001

//-----------------------------------------------------------

namespace MX {

namespace Signatures {

typedef struct tagHASHES {
  BYTE aSha256[32];
  BYTE aSha1[20];
  BYTE aMd5[16];
} HASHES, *LPHASHES;

} //namespace Signatures

} //namespace MX

//-----------------------------------------------------------

namespace MX {

namespace Signatures {

HRESULT Initialize();

//NOTE: Returns TRUST_E_NOSIGNATURE if no certificates are found.
//      If an error is returned, check 'lplpCertCtx' and 'lpTimeStamp' might contain valid data. In this
//      scenario, the file contains a certificate but it is untrusted for some reason.
HRESULT GetPeSignature(_In_z_ LPCWSTR szPeFileNameW, _In_opt_ HANDLE hFile, _In_opt_ HANDLE hProcess,
                       _In_opt_ HANDLE hCancelEvent, _Out_ PCERT_CONTEXT *lplpCertCtx, _Out_ PFILETIME lpTimeStamp);
VOID FreeCertificate(_In_opt_ PCCERT_CONTEXT lpCertCtx);
PCCERT_CONTEXT DuplicateCertificate(_In_ PCCERT_CONTEXT lpCertCtx);

HRESULT GetCertificateName(_In_ PCCERT_CONTEXT lpCertCtx, DWORD dwType, _Inout_ CStringW &cStrNameW,
                           _In_opt_ BOOL bFromIssuer=FALSE);
HRESULT GetCertificateSerialNumber(_In_ PCCERT_CONTEXT lpCertCtx, _Out_ LPBYTE *lplpSerialNumber,
                                   _Out_ PSIZE_T lpnSerialNumberLength);

HRESULT CalculateHashes(_In_z_ LPCWSTR szFileNameW, _In_opt_ HANDLE hFile, _In_opt_ HANDLE hCancelEvent,
                        _Out_ LPHASHES lpHashes);

} //namespace Signatures

} //namespace MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_PE_SIGNATURE_AND_INFO_H
