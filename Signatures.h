/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#ifndef _MXLIBHLP_PE_SIGNATURE_AND_INFO_H
#define _MXLIBHLP_PE_SIGNATURE_AND_INFO_H

#include <Defines.h>
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

} //namespace Signatures

} //namespace MX

//-----------------------------------------------------------

namespace MX {

namespace Signatures {

HRESULT Initialize();

//NOTE: Returns TRUST_E_NOSIGNATURE if no certificates are found.
//      If an error is returned, check 'lplpCertCtx' and 'lpTimeStamp' might contain valid data. In this
//      scenario, the file contains a certificate but it is untrusted for some reason.
HRESULT GetPeSignature(_In_z_ LPCWSTR szPeFileNameW, _In_opt_ HANDLE hProcess, _Out_ PCERT_CONTEXT *lplpCertCtx,
                       _Out_ PFILETIME lpTimeStamp, _In_opt_ BOOL bIgnoreCache = FALSE);
VOID FreeCertificate(_In_opt_ PCERT_CONTEXT lpCertCtx);

HRESULT GetCertificateName(_In_ PCERT_CONTEXT lpCertCtx, DWORD dwType, _Inout_ CStringW &cStrNameW,
                           _In_opt_ BOOL bFromIssuer=FALSE);
HRESULT GetCertificateSerialNumber(_In_ PCERT_CONTEXT lpCertCtx, _Out_ LPBYTE *lplpSerialNumber,
                                   _Out_ PSIZE_T lpnSerialNumberLength);

HRESULT CalculateHashes(_In_z_ LPCWSTR szFileNameW, _Out_ LPHASHES lpHashes, _In_opt_ BOOL bIgnoreCache = FALSE);

} //namespace Signatures

} //namespace MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_PE_SIGNATURE_AND_INFO_H
