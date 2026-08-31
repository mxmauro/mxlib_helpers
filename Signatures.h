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
#include <ArrayList.h>
#include <RefCounted.h>
#include <Strings\Strings.h>
#include <SoftPub.h>

 //-----------------------------------------------------------

namespace MX {

namespace Signatures {

typedef struct tagHASHES {
    BYTE aSha256[32];
    BYTE aSha1[20];
    BYTE aMd5[16];
} HASHES, *LPHASHES;

class Certificate : public TRefCounted<CBaseMemObj>, public CNonCopyableObj
{
public:
    Certificate();
    ~Certificate();

    HRESULT InitFromProviderCertificate(_In_ PCRYPT_PROVIDER_CERT lpProvCert);

    HRESULT GetName(DWORD dwType, _Inout_ CStringW &cStrNameW, _In_opt_ BOOL bFromIssuer = FALSE);

    LPBYTE GetSerialNumber() const;
    SIZE_T GetSerialNumberLength() const;

    BOOL IsCommercial() const
    {
        return bCommercial;
    };

    BOOL IsTrustedRoot() const
    {
        return bTrustedRoot;
    };

    BOOL IsSelfSigned() const
    {
        return bSelfSigned;
    };

    operator PCERT_CONTEXT() const
    {
        return lpCertCtx;
    };

    PCERT_CONTEXT GetContext() const
    {
        return lpCertCtx;
    };

private:
    PCERT_CONTEXT lpCertCtx;
    BOOL bCommercial;
    BOOL bTrustedRoot;
    BOOL bSelfSigned;
};

typedef MX::TArrayListWithRelease<Certificate*> CertificateArray;

} // namespace Signatures

} // namespace MX

//-----------------------------------------------------------

namespace MX {

namespace Signatures {

HRESULT Initialize();

// NOTE: Returns TRUST_E_NOSIGNATURE if no certificates are found.
//       If an error is returned, check 'lplpCertCtx' and 'lpTimeStamp' might contain valid data. In this
//       scenario, the file contains a certificate but it is untrusted for some reason.

HRESULT GetPeSignature(_In_opt_z_ LPCWSTR szPeFileNameW, _In_opt_ HANDLE hFile, _In_opt_ HANDLE hProcess, _In_opt_ HANDLE hCancelEvent,
                       _In_ BOOL bCheckRevocation, _Out_ CertificateArray &cCerts, _Out_opt_ PFILETIME lpTimeStamp = NULL);

HRESULT CalculateHashes(_In_z_ LPCWSTR szFileNameW, _In_opt_ HANDLE hFile, _In_opt_ HANDLE hCancelEvent, _Out_ LPHASHES lpHashes);

} // namespace Signatures

} // namespace MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_PE_SIGNATURE_AND_INFO_H
