/*
* Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
* All rights reserved.
*
**/

#ifndef _MXLIBHLP_ADS_HELPER_H
#define _MXLIBHLP_ADS_HELPER_H

#include <Defines.h>
#include <Windows.h>
#include <objbase.h>
#include <Iads.h>
#include <ActiveDS.h>
#include "Sid.h"
#include <ArrayList.h>

//-----------------------------------------------------------

namespace MX {

class CAdsHelper : public CBaseMemObj
{
public:
  CAdsHelper();
  ~CAdsHelper();

  HRESULT Initialize(_In_opt_z_ LPCWSTR szServerAddressW=NULL, _In_opt_z_ LPCWSTR szUsernameW=NULL,
                     _In_opt_z_ LPCWSTR szPasswordW=NULL);

  VOID SetCancelEvent(_In_ HANDLE hEvent);
  VOID SetQueryTimeoutMs(_In_ DWORD dwTimeoutMs);

  HRESULT GetAllUsers(_Inout_ TArrayListWithFree<LPWSTR> &aUsersList);
  HRESULT GetAllGroups(_Inout_ TArrayListWithFree<LPWSTR> &aGroupsList);
  HRESULT GetAllComputers(_Inout_ TArrayListWithFree<LPWSTR> &aComputersList);

  HRESULT GetSidFromADsPath(_In_z_ LPCWSTR szADsPathW, _Inout_ CSid &cSid);
  HRESULT GetDomainFromUrl(_In_z_ LPCWSTR szUrlW, _Inout_ CStringW &cStrDomainW);
  HRESULT GetDomainFromDn(_In_z_ LPCWSTR szDistinguishedNameW, _Inout_ CStringW &cStrDomainW);

  HRESULT GetRootADSPath(_Inout_ CStringW &cStrRootPathW);

  HRESULT GetComputerSids(_Out_ CSid **lplpComputerSid, _Inout_ TArrayListWithDelete<CSid*> &aGroupSids);

  HRESULT EnumerateContainerFolders(_In_z_ LPCWSTR szParentW, _Inout_ TArrayListWithFree<LPWSTR> &aChildrenList);
  HRESULT GetContainerMembers(_In_z_ LPCWSTR szParentW, _Inout_ TArrayListWithFree<LPWSTR> &aMembersList);

  static HRESULT GetUrlFromDn(_In_ LPCWSTR szDnW, _Inout_ CStringW &cStrW);
  static HRESULT GetUrlFromDn(_Inout_ CStringW &cStrW);
  static LPCWSTR GetDnFromUrl(_In_ LPCWSTR szUrlW);

private:
  static BOOL EscapeSlashes(_Inout_ CStringW &cStrW);
  HRESULT AdsOpen(_In_z_ LPCWSTR szPathNameW, _In_ REFIID riid, __deref_out LPVOID *ppObject);
  BOOL IsCancelled();

private:
  CStringW cStrServerAddressW, cStrUserNameW, cStrPasswordW;
  HRESULT hResComInit;
  HANDLE hCancelEvent;
  DWORD dwQueryTimeoutMs;
};

}; //namespace MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_ADS_HELPER_H
