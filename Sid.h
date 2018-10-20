/*
* Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
* All rights reserved.
*
**/

#ifndef _SID_H
#define _SID_H

#include <Defines.h>
#include <Windows.h>
#include <sddl.h>
#include <AutoPtr.h>
#include <Strings\Strings.h>

//-----------------------------------------------------------

class CSid : public virtual MX::CBaseMemObj
{
  MX_DISABLE_COPY_CONSTRUCTOR(CSid);
public:
  CSid();
  ~CSid();

  VOID Reset();

  HRESULT Set(_In_ PSID lpSid);
  HRESULT Set(_In_z_ LPCWSTR szAccountNameOrSidStringW);

  BOOL operator==(_In_ PSID lpSid) const;

  HRESULT SetCurrentUserSid();
  HRESULT SetWellKnownAccount(_In_ WELL_KNOWN_SID_TYPE nSidType);

  HRESULT GetStringSid(_Inout_ MX::CStringW &cStrSidW);
  HRESULT GetAccountName(_Inout_ MX::CStringW &cStrNameW, _In_opt_ MX::CStringW *lpStrDomainW=NULL);

  HRESULT GetCompatibleSidString(_Inout_ MX::CStringW &cStrNameOrSidW, _In_opt_ MX::CStringW *lpStrDomainW)
    {
    if (lpStrDomainW != NULL)
      lpStrDomainW->Empty();
    return IsAnyWellKnownSid() ? GetStringSid(cStrNameOrSidW) : GetAccountName(cStrNameOrSidW, lpStrDomainW);
    };

  operator PSID() const
    {
    return (PSID)(const_cast<MX::TAutoFreePtr<BYTE>&>(cSid).Get());
    };

  BOOL IsAnyWellKnownSid() const;

  BOOL IsWellKnownSid(_In_ WELL_KNOWN_SID_TYPE nSidType) const;

private:
  MX::TAutoFreePtr<BYTE> cSid;
};

//-----------------------------------------------------------

#endif //_SID_H
