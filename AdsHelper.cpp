#include "AdsHelper.h"
#include "Sid.h"
#include "WinRegistry.h"
#include <RefCounted.h>
#include <Http\Url.h>
#include <stdio.h>

#pragma comment(lib, "Activeds.lib")

#pragma warning(disable : 28159)

//-----------------------------------------------------------

namespace MX {

CAdsHelper::CAdsHelper() : CBaseMemObj()
{
  hResComInit = S_FALSE;
  hCancelEvent = NULL;
  dwQueryTimeoutMs = INFINITE;
  return;
}

CAdsHelper::~CAdsHelper()
{
  if (cStrServerAddressW.IsEmpty() == FALSE)
    MemSet((LPWSTR)cStrServerAddressW, '*', cStrServerAddressW.GetLength() * 2);
  if (cStrUserNameW.IsEmpty() == FALSE)
    MemSet((LPWSTR)cStrUserNameW, '*', cStrUserNameW.GetLength() * 2);
  if (cStrPasswordW.IsEmpty() == FALSE)
    MemSet((LPWSTR)cStrPasswordW, '*', cStrPasswordW.GetLength() * 2);
  //----
  if (SUCCEEDED(hResComInit))
    ::CoUninitialize();
  return;
}

HRESULT CAdsHelper::Initialize(_In_opt_z_ LPCWSTR szServerAddressW, _In_opt_z_ LPCWSTR szUsernameW,
                               _In_opt_z_ LPCWSTR szPasswordW)
{
  if (hResComInit != S_FALSE)
    return MX_E_AlreadyInitialized;

  if (szServerAddressW != NULL && *szServerAddressW != 0)
  {
    if (CUrl::IsValidHostAddress(szServerAddressW) == FALSE)
      return E_INVALIDARG;
    if (cStrServerAddressW.Copy(szServerAddressW) == FALSE)
      return E_OUTOFMEMORY;
  }
  if (szUsernameW != NULL && *szUsernameW != 0)
  {
    if (cStrUserNameW.Copy(szUsernameW) == FALSE)
      return E_OUTOFMEMORY;
    if (szPasswordW != NULL && *szPasswordW != 0)
    {
      if (cStrPasswordW.Copy(szPasswordW) == FALSE)
        return E_OUTOFMEMORY;
    }
  }

  hResComInit = ::CoInitializeEx(NULL, COINIT_MULTITHREADED);
  if (FAILED(hResComInit) && hResComInit != RPC_E_CHANGED_MODE)
  {
    HRESULT hRes = hResComInit;

    hResComInit = S_FALSE;
    return hRes;
  }
  //done
  return S_OK;
}

//HRESULT IsUserInGroup(_In_ LPCWSTR szGroupW, _In_ LPCWSTR szUserW, _In_ BOOL bCheckNestedGroups)
//{
//  /*
//  HRESULT            hr = S_OK;
//  VARIANT_BOOL        bIsMember;
//  std::vector< std::wstring >  groupsToCheck;
//  std::vector< std::wstring >  groups;
//  std::wstring        groupUrl, userUrl;
//  bool            isMember = false;
//  _bstr_t            userBstr;
//  size_t            i;
//  */
//  TAutoRefCounted<IADsGroup> cAdsGroup;
//  StringW cStrGroupUrlW, cStrUserUrlW;
//  TArrayListWithFree<LPWSTR> aGroupsList;
//  VARIANT_BOOL bIsMember = VARIANT_FALSE;
//  HRESULT hRes;
//
//  if (szGroupW == NULL || szUserW == NULL)
//    return E_POINTER;
//  if (*szGroupW == 0 || *szUserW == 0)
//    return S_FALSE;
//
//  hRes = GetUrlFromDn(szGroupW, cStrGroupUrlW);
//
//  if (SUCCEEDED(hRes))
//    hRes = AdsOpen((LPCWSTR)cStrGroupUrlW, __uuidof(IADsGroup), (LPVOID*)&cAdsGroup);
//
//  if (SUCCEEDED(hRes))
//    hRes = GetUrlFromDn(szUserW, cStrUserUrlW);
//  if (SUCCEEDED(hRes))
//    hRes = cAdsGroup->IsMember(cStrGroupUrlW, &bIsMember);
//  if (FAILED(hRes))
//    return hRes;
//
//
//  if (!bCheckNestedGroups || bIsMember != VARIANT_FALSE)
//    return S_OK;
//  /*
//  // Check nested groups
//  hr = getObjectsInGroup(szGroupW, aGroupsList, L"group");
//  if ( FAILED( hr ) )
//  {
//    fn_return( NOTHING );
//  }
//
//  for( i = 0; i < groupsToCheck.size(); i++ )
//  {
//    hr = isUserInGroup( groupsToCheck[i], user, false );
//    if ( hr == S_OK )
//    {
//      isMember = true;
//      fn_return( NOTHING );
//    }
//    if ( FAILED( hr ) )
//    {
//      fn_return( NOTHING );
//    }
//
//    hr = getObjectsInGroup( groupsToCheck[i], groups, L"group" );
//    if ( FAILED( hr ) )
//    {
//      fn_return( NOTHING );
//    }
//
//    try
//    {
//      for( auto gName : groups )
//      {
//        if ( std::find( groupsToCheck.begin(), groupsToCheck.end(), gName ) == groupsToCheck.end() )
//          {
//        groupsToCheck.push_back( gName );
//        }
//      }
//    }
//    catch ( std::bad_alloc& )
//    {
//      fn_return( hr = E_OUTOFMEMORY );
//    }
//    groups.clear();
//  }
//  
//fn_exit:
//
//  if ( pGroup )
//  {
//    pGroup->Release();
//  }
//
//  if ( SUCCEEDED( hr ) && isMember == false )
//  {
//    return S_FALSE;
//  }
//  */
//  return hRes;
//}

VOID CAdsHelper::SetCancelEvent(_In_ HANDLE hEvent)
{
  hCancelEvent = hEvent;
  return;
}

VOID CAdsHelper::SetQueryTimeoutMs(_In_ DWORD dwTimeoutMs)
{
  dwQueryTimeoutMs = dwTimeoutMs;
  return;
}

HRESULT CAdsHelper::GetAllUsers(_Inout_ TArrayListWithFree<LPWSTR> &aUsersList)
{
  static const LPCWSTR szSearchFilterW = L"(samAccountType=805306368)";
  static const LPCWSTR szAttribW[] = { L"distinguishedName", L"sAMAccountName", L"objectSid" };
  TAutoRefCounted<IDirectorySearch> cDirSearch;
  ADS_SEARCH_HANDLE hSearch = INVALID_HANDLE_VALUE;
  CStringW cStrTempW, cStrDomainW;
  ADS_SEARCH_COLUMN sColumns[3];
  CSid cSid;
  DWORD dw, dwCurrTickMs, dwTimeoutMs;
  SIZE_T nLen;
  HRESULT hRes;

  aUsersList.RemoveAllElements();
  dwTimeoutMs = dwQueryTimeoutMs;
  dwCurrTickMs = ::GetTickCount();

  hRes = GetRootADSPath(cStrTempW);
  if (SUCCEEDED(hRes))
    hRes = AdsOpen((LPCWSTR)cStrTempW, __uuidof(IDirectorySearch), (LPVOID*)&cDirSearch);

  if (SUCCEEDED(hRes))
  {
    ADS_SEARCHPREF_INFO sSearchPrefs[2];

    sSearchPrefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
    sSearchPrefs[0].vValue.dwType = ADSTYPE_INTEGER;
    sSearchPrefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
    sSearchPrefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
    sSearchPrefs[1].vValue.dwType = ADSTYPE_INTEGER;
    sSearchPrefs[1].vValue.Integer = 256;
    hRes = cDirSearch->SetSearchPreference(sSearchPrefs, _countof(sSearchPrefs));
  }

  if (SUCCEEDED(hRes))
    hRes = cDirSearch->ExecuteSearch((LPWSTR)szSearchFilterW, (LPWSTR*)szAttribW, _countof(szAttribW), &hSearch);

  if (SUCCEEDED(hRes))
  {
    hRes = cDirSearch->GetFirstRow(hSearch);
    while (SUCCEEDED(hRes) && hRes != S_ADS_NOMORE_ROWS)
    {
      if (dwTimeoutMs != INFINITE)
      {
        dw = ::GetTickCount();
        if (dwTimeoutMs < dw - dwCurrTickMs)
        {
          hRes = MX_E_Timeout;
          break;
        }
        dwTimeoutMs -= (dw - dwCurrTickMs);
        dwCurrTickMs = dw;
      }
      if (IsCancelled() != FALSE)
      {
        hRes = MX_E_Cancelled;
        break;
      }

      hRes = cDirSearch->GetColumn(hSearch, (LPWSTR)(szAttribW[0]), &sColumns[0]);
      if (SUCCEEDED(hRes))
      {
        hRes = cDirSearch->GetColumn(hSearch, (LPWSTR)(szAttribW[1]), &sColumns[1]);
        if (SUCCEEDED(hRes))
        {
          hRes = cDirSearch->GetColumn(hSearch, (LPWSTR)(szAttribW[2]), &sColumns[2]);
          if (SUCCEEDED(hRes))
          {
            if (sColumns[0].dwNumValues > 0 && sColumns[1].dwNumValues > 0 && sColumns[2].dwNumValues > 0 &&
                sColumns[0].pADsValues[0].DNString != NULL && sColumns[1].pADsValues[0].DNString != NULL &&
                sColumns[2].pADsValues[0].OctetString.lpValue != NULL &&
                sColumns[0].pADsValues[0].DNString[0] != 0 && sColumns[1].pADsValues[0].DNString[0] != 0 &&
                sColumns[2].pADsValues[0].OctetString.dwLength > 0)
            {
              //sid
              hRes = cSid.Set(sColumns[2].pADsValues[0].OctetString.lpValue);
              if (SUCCEEDED(hRes))
              {
                hRes = cSid.GetStringSid(cStrTempW);
                if (SUCCEEDED(hRes))
                {
                  if (cStrTempW.InsertN((cSid.IsAnyWellKnownSid() != FALSE) ? L"+" : L"-", 0, 1) == FALSE)
                    hRes = E_OUTOFMEMORY;
                }
              }

              //name
              if (SUCCEEDED(hRes))
              {
                nLen = StrLenW(sColumns[1].pADsValues[0].DNString);
                if (nLen > 0 && sColumns[1].pADsValues[0].DNString[nLen-1] == L'$')
                  nLen--;

                if (cStrTempW.ConcatN(L"/", 1) == FALSE ||
                    cStrTempW.ConcatN(sColumns[1].pADsValues[0].DNString, nLen) == FALSE)
                {
                  hRes = E_OUTOFMEMORY;
                }
              }

              //domain
              if (SUCCEEDED(hRes))
              {
                hRes = GetDomainFromDn(sColumns[0].pADsValues[0].DNString, cStrDomainW);

                if (SUCCEEDED(hRes))
                {
                  if (cStrTempW.ConcatN(L"@", 1) == FALSE ||
                      cStrTempW.ConcatN((LPCWSTR)cStrDomainW, cStrDomainW.GetLength()) == FALSE)
                  {
                    hRes = E_OUTOFMEMORY;
                  }
                }
              }

              //add to list
              if (SUCCEEDED(hRes))
              {
                if (aUsersList.AddElement((LPWSTR)cStrTempW) != FALSE)
                  cStrTempW.Detach();
                else
                  hRes = E_OUTOFMEMORY;
              }
            }
            cDirSearch->FreeColumn(&sColumns[2]);
          }
          cDirSearch->FreeColumn(&sColumns[1]);
        }
        cDirSearch->FreeColumn(&sColumns[0]);
      }
      if (SUCCEEDED(hRes))
        hRes = cDirSearch->GetNextRow(hSearch);
    }
    if (hRes == S_ADS_NOMORE_ROWS)
      hRes = S_OK;
  }
  //done
  if (hSearch != INVALID_HANDLE_VALUE && cDirSearch)
    cDirSearch->CloseSearchHandle(hSearch);
  if (FAILED(hRes))
    aUsersList.RemoveAllElements();
  return hRes;
}

HRESULT CAdsHelper::GetAllGroups(_Inout_ TArrayListWithFree<LPWSTR> &aGroupsList)
{
  static const LPCWSTR szSearchFilterW = L"(objectClass=group)";
  static const LPCWSTR szAttribW[] = { L"distinguishedName", L"sAMAccountName", L"objectSid" };
  TAutoRefCounted<IDirectorySearch> cDirSearch;
  ADS_SEARCH_HANDLE hSearch = INVALID_HANDLE_VALUE;
  CStringW cStrTempW, cStrDomainW;
  ADS_SEARCH_COLUMN sColumns[3];
  CSid cSid;
  DWORD dw, dwCurrTickMs, dwTimeoutMs;
  SIZE_T nLen;
  HRESULT hRes;

  aGroupsList.RemoveAllElements();
  dwTimeoutMs = dwQueryTimeoutMs;
  dwCurrTickMs = ::GetTickCount();

  hRes = GetRootADSPath(cStrTempW);
  if (SUCCEEDED(hRes))
    hRes = AdsOpen((LPCWSTR)cStrTempW, __uuidof(IDirectorySearch), (LPVOID*)&cDirSearch);

  if (SUCCEEDED(hRes))
  {
    ADS_SEARCHPREF_INFO sSearchPrefs[2];

    sSearchPrefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
    sSearchPrefs[0].vValue.dwType = ADSTYPE_INTEGER;
    sSearchPrefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
    sSearchPrefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
    sSearchPrefs[1].vValue.dwType = ADSTYPE_INTEGER;
    sSearchPrefs[1].vValue.Integer = 256;
    hRes = cDirSearch->SetSearchPreference(sSearchPrefs, _countof(sSearchPrefs));
  }

  if (SUCCEEDED(hRes))
    hRes = cDirSearch->ExecuteSearch((LPWSTR)szSearchFilterW, (LPWSTR*)szAttribW, _countof(szAttribW), &hSearch);

  if (SUCCEEDED(hRes))
  {
    hRes = cDirSearch->GetFirstRow(hSearch);
    while (SUCCEEDED(hRes) && hRes != S_ADS_NOMORE_ROWS)
    {
      if (dwTimeoutMs != INFINITE)
      {
        dw = ::GetTickCount();
        if (dwTimeoutMs < dw - dwCurrTickMs)
        {
          hRes = MX_E_Timeout;
          break;
        }
        dwTimeoutMs -= (dw - dwCurrTickMs);
        dwCurrTickMs = dw;
      }
      if (IsCancelled() != FALSE)
      {
        hRes = MX_E_Cancelled;
        break;
      }

      hRes = cDirSearch->GetColumn(hSearch, (LPWSTR)(szAttribW[0]), &sColumns[0]);
      if (SUCCEEDED(hRes))
      {
        hRes = cDirSearch->GetColumn(hSearch, (LPWSTR)(szAttribW[1]), &sColumns[1]);
        if (SUCCEEDED(hRes))
        {
          hRes = cDirSearch->GetColumn(hSearch, (LPWSTR)(szAttribW[2]), &sColumns[2]);
          if (SUCCEEDED(hRes))
          {
            if (sColumns[0].dwNumValues > 0 && sColumns[1].dwNumValues > 0 && sColumns[2].dwNumValues > 0 &&
                sColumns[0].pADsValues[0].DNString != NULL && sColumns[1].pADsValues[0].DNString != NULL &&
                sColumns[2].pADsValues[0].OctetString.lpValue != NULL &&
                sColumns[0].pADsValues[0].DNString[0] != 0 && sColumns[1].pADsValues[0].DNString[0] != 0 &&
                sColumns[2].pADsValues[0].OctetString.dwLength > 0)
            {
              //sid
              hRes = cSid.Set(sColumns[2].pADsValues[0].OctetString.lpValue);
              if (SUCCEEDED(hRes))
              {
                hRes = cSid.GetStringSid(cStrTempW);
                if (SUCCEEDED(hRes))
                {
                  if (cStrTempW.InsertN((cSid.IsAnyWellKnownSid() != FALSE) ? L"+" : L"-", 0, 1) == FALSE)
                    hRes = E_OUTOFMEMORY;
                }
              }

              //name
              if (SUCCEEDED(hRes))
              {
                nLen = StrLenW(sColumns[1].pADsValues[0].DNString);
                if (nLen > 0 && sColumns[1].pADsValues[0].DNString[nLen-1] == L'$')
                  nLen--;

                if (cStrTempW.ConcatN(L"/", 1) == FALSE ||
                    cStrTempW.ConcatN(sColumns[1].pADsValues[0].DNString, nLen) == FALSE)
                {
                  hRes = E_OUTOFMEMORY;
                }
              }

              //domain
              if (SUCCEEDED(hRes))
              {
                hRes = GetDomainFromDn(sColumns[0].pADsValues[0].DNString, cStrDomainW);

                if (SUCCEEDED(hRes))
                {
                  if (cStrTempW.ConcatN(L"@", 1) == FALSE ||
                      cStrTempW.ConcatN((LPCWSTR)cStrDomainW, cStrDomainW.GetLength()) == FALSE)
                  {
                    hRes = E_OUTOFMEMORY;
                  }
                }
              }

              //add to list
              if (SUCCEEDED(hRes))
              {
                if (aGroupsList.AddElement((LPWSTR)cStrTempW) != FALSE)
                  cStrTempW.Detach();
                else
                  hRes = E_OUTOFMEMORY;
              }
            }
            cDirSearch->FreeColumn(&sColumns[2]);
          }
          cDirSearch->FreeColumn(&sColumns[1]);
        }
        cDirSearch->FreeColumn(&sColumns[0]);
      }
      if (SUCCEEDED(hRes))
        hRes = cDirSearch->GetNextRow(hSearch);
    }
    if (hRes == S_ADS_NOMORE_ROWS)
      hRes = S_OK;
  }
  //done
  if (hSearch != INVALID_HANDLE_VALUE && cDirSearch)
    cDirSearch->CloseSearchHandle(hSearch);
  if (FAILED(hRes))
    aGroupsList.RemoveAllElements();
  return hRes;
}

HRESULT CAdsHelper::GetAllComputers(_Inout_ TArrayListWithFree<LPWSTR> &aComputersList)
{
  static const LPCWSTR szSearchFilterW = L"(objectClass=computer)";
  static const LPCWSTR szAttribW[] = { L"distinguishedName", L"sAMAccountName", L"objectSid" };
  TAutoRefCounted<IDirectorySearch> cDirSearch;
  ADS_SEARCH_HANDLE hSearch = INVALID_HANDLE_VALUE;
  CStringW cStrTempW, cStrDomainW;
  ADS_SEARCH_COLUMN sColumns[3];
  CSid cSid;
  DWORD dw, dwCurrTickMs, dwTimeoutMs;
  SIZE_T nLen;
  HRESULT hRes;

  aComputersList.RemoveAllElements();
  dwTimeoutMs = dwQueryTimeoutMs;
  dwCurrTickMs = ::GetTickCount();

  hRes = GetRootADSPath(cStrTempW);
  if (SUCCEEDED(hRes))
    hRes = AdsOpen((LPCWSTR)cStrTempW, __uuidof(IDirectorySearch), (LPVOID*)&cDirSearch);

  if (SUCCEEDED(hRes))
  {
    ADS_SEARCHPREF_INFO sSearchPrefs[2];

    sSearchPrefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
    sSearchPrefs[0].vValue.dwType = ADSTYPE_INTEGER;
    sSearchPrefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
    sSearchPrefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
    sSearchPrefs[1].vValue.dwType = ADSTYPE_INTEGER;
    sSearchPrefs[1].vValue.Integer = 256;
    hRes = cDirSearch->SetSearchPreference(sSearchPrefs, _countof(sSearchPrefs));
  }

  if (SUCCEEDED(hRes))
    hRes = cDirSearch->ExecuteSearch((LPWSTR)szSearchFilterW, (LPWSTR*)szAttribW, _countof(szAttribW), &hSearch);

  if (SUCCEEDED(hRes))
  {
    hRes = cDirSearch->GetFirstRow(hSearch);
    while (SUCCEEDED(hRes) && hRes != S_ADS_NOMORE_ROWS)
    {
      if (dwTimeoutMs != INFINITE)
      {
        dw = ::GetTickCount();
        if (dwTimeoutMs < dw - dwCurrTickMs)
        {
          hRes = MX_E_Timeout;
          break;
        }
        dwTimeoutMs -= (dw - dwCurrTickMs);
        dwCurrTickMs = dw;
      }
      if (IsCancelled() != FALSE)
      {
        hRes = MX_E_Cancelled;
        break;
      }

      hRes = cDirSearch->GetColumn(hSearch, (LPWSTR)(szAttribW[0]), &sColumns[0]);
      if (SUCCEEDED(hRes))
      {
        hRes = cDirSearch->GetColumn(hSearch, (LPWSTR)(szAttribW[1]), &sColumns[1]);
        if (SUCCEEDED(hRes))
        {
          hRes = cDirSearch->GetColumn(hSearch, (LPWSTR)(szAttribW[2]), &sColumns[2]);
          if (SUCCEEDED(hRes))
          {
            if (sColumns[0].dwNumValues > 0 && sColumns[1].dwNumValues > 0 && sColumns[2].dwNumValues > 0 &&
                sColumns[0].pADsValues[0].DNString != NULL && sColumns[1].pADsValues[0].DNString != NULL &&
                sColumns[2].pADsValues[0].OctetString.lpValue != NULL &&
                sColumns[0].pADsValues[0].DNString[0] != 0 && sColumns[1].pADsValues[0].DNString[0] != 0 &&
                sColumns[2].pADsValues[0].OctetString.dwLength > 0)
            {
              //sid
              hRes = cSid.Set(sColumns[2].pADsValues[0].OctetString.lpValue);
              if (SUCCEEDED(hRes))
                hRes = cSid.GetStringSid(cStrTempW);

              //name
              if (SUCCEEDED(hRes))
              {
                nLen = StrLenW(sColumns[1].pADsValues[0].DNString);
                if (nLen > 0 && sColumns[1].pADsValues[0].DNString[nLen-1] == L'$')
                  nLen--;

                if (cStrTempW.ConcatN(L"/", 1) == FALSE ||
                    cStrTempW.ConcatN(sColumns[1].pADsValues[0].DNString, nLen) == FALSE)
                {
                  hRes = E_OUTOFMEMORY;
                }
              }

              //domain
              if (SUCCEEDED(hRes))
              {
                hRes = GetDomainFromDn(sColumns[0].pADsValues[0].DNString, cStrDomainW);

                if (SUCCEEDED(hRes))
                {
                  if (cStrTempW.ConcatN(L"@", 1) == FALSE ||
                      cStrTempW.ConcatN((LPCWSTR)cStrDomainW, cStrDomainW.GetLength()) == FALSE)
                  {
                    hRes = E_OUTOFMEMORY;
                  }
                }
              }

              //add to list
              if (SUCCEEDED(hRes))
              {
                if (aComputersList.AddElement((LPWSTR)cStrTempW) != FALSE)
                  cStrTempW.Detach();
                else
                  hRes = E_OUTOFMEMORY;
              }
            }
            cDirSearch->FreeColumn(&sColumns[2]);
          }
          cDirSearch->FreeColumn(&sColumns[1]);
        }
        cDirSearch->FreeColumn(&sColumns[0]);
      }
      if (SUCCEEDED(hRes))
        hRes = cDirSearch->GetNextRow(hSearch);
    }
    if (hRes == S_ADS_NOMORE_ROWS)
      hRes = S_OK;
  }
  //done
  if (hSearch != INVALID_HANDLE_VALUE && cDirSearch)
    cDirSearch->CloseSearchHandle(hSearch);
  if (FAILED(hRes))
    aComputersList.RemoveAllElements();
  return hRes;
}

HRESULT CAdsHelper::GetComputerSids(_Out_ CSid **lplpComputerSid, _Inout_ TArrayListWithDelete<CSid*> &aGroupSids)
{
  static const LPCWSTR szAttributeW[] = { L"tokenGroups", L"objectSid" };
  CWindowsRegistry cWinReg;
  TAutoDeletePtr<CSid> cComputerSid;
  TAutoRefCounted<IADs> cAdsComputer;
  CStringW cStrTempW;
  VARIANT vt;
  PSID lpInnerSid;
  TAutoDeletePtr<CSid> cSid;
  //DWORD dw, dwCurrTickMs, dwTimeoutMs;
  HRESULT hRes;

  if (lplpComputerSid == NULL)
    return E_POINTER;

  *lplpComputerSid = NULL;
  aGroupSids.RemoveAllElements();
  //dwTimeoutMs = dwQueryTimeoutMs;
  //dwCurrTickMs = ::GetTickCount();

  ::VariantInit(&vt);

  hRes = cWinReg.Open(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
                                          L"Group Policy\\State\\Machine", FALSE);
  if (SUCCEEDED(hRes))
  {
    hRes = cWinReg.ReadString(L"Distinguished-Name", cStrTempW);
    cWinReg.Close();
  }
  if (FAILED(hRes))
    return hRes;

  if (SUCCEEDED(hRes))
  {
    if (cStrTempW.InsertN(L"LDAP://", 0, 7) == FALSE)
      hRes = E_OUTOFMEMORY;
  }

  hRes = AdsOpen((LPCWSTR)cStrTempW, __uuidof(IADs), (LPVOID*)&cAdsComputer);
  if (SUCCEEDED(hRes))
  {
    hRes = ::ADsBuildVarArrayStr((LPWSTR*)szAttributeW, _countof(szAttributeW), &vt);
    if (SUCCEEDED(hRes))
      hRes = cAdsComputer->GetInfoEx(vt, 0);
    ::VariantClear(&vt);
  }
  if (FAILED(hRes))
    return hRes;

  //get computer sid
  hRes = cAdsComputer->Get((BSTR)szAttributeW[0], &vt);
  if (SUCCEEDED(hRes))
  {
    if (vt.vt == (VT_ARRAY | VT_UI1))
    {
      hRes = ::SafeArrayAccessData(V_ARRAY(&vt), (LPVOID*)&lpInnerSid);
      if (SUCCEEDED(hRes))
      {
        cComputerSid.Attach(MX_DEBUG_NEW CSid());
        if (cComputerSid)
          hRes = cComputerSid->Set(lpInnerSid);
        else
          hRes = E_OUTOFMEMORY;
        ::SafeArrayUnaccessData(V_ARRAY(&vt));
      }
    }
    else
    {
      hRes = MX_E_Unsupported;
    }
  }

  //get groups
  if (SUCCEEDED(hRes))
  {
    ::VariantClear(&vt);
    hRes = cAdsComputer->Get((BSTR)szAttributeW[1], &vt);
  }
  if (SUCCEEDED(hRes))
  {
    if (vt.vt == (VT_ARRAY | VT_VARIANT))
    {
      LONG i, iLBound, iUBound;
      LPVARIANT lpElems = NULL;

      hRes = ::SafeArrayGetLBound(V_ARRAY(&vt), 1, &iLBound);
      if (SUCCEEDED(hRes))
        hRes = ::SafeArrayGetUBound(V_ARRAY(&vt), 1, &iUBound);
      if (SUCCEEDED(hRes))
        hRes = ::SafeArrayAccessData(V_ARRAY(&vt), (LPVOID*)&lpElems);
      if (SUCCEEDED(hRes))
      {
        iUBound = iUBound - iLBound + 1;
        for (i=0; SUCCEEDED(hRes) && i<iUBound; i++)
        {
          if (lpElems[i].vt == (VT_ARRAY | VT_UI1))
          {
            hRes = ::SafeArrayAccessData(lpElems[i].parray, (LPVOID*)&lpInnerSid);
            if (SUCCEEDED(hRes))
            {
              cSid.Attach(MX_DEBUG_NEW CSid());
              if (cSid)
              {
                if (SUCCEEDED(cSid->Set(lpInnerSid)))
                {
                  if (aGroupSids.AddElement(cSid.Get()) != FALSE)
                    cSid.Detach();
                  else
                    hRes = E_OUTOFMEMORY;
                }
              }
              else
              {
                hRes = E_OUTOFMEMORY;
              }
              ::SafeArrayUnaccessData(lpElems[i].parray);
            }
          }
        }
        ::SafeArrayUnaccessData(V_ARRAY(&vt));
      }
    }
    else if (vt.vt == (VT_ARRAY | VT_UI1))
    {
      hRes = ::SafeArrayAccessData(V_ARRAY(&vt), (LPVOID*)&lpInnerSid);
      if (SUCCEEDED(hRes))
      {
        cSid.Attach(MX_DEBUG_NEW CSid());
        if (cSid)
        {
          if (SUCCEEDED(cSid->Set(lpInnerSid)))
          {
            if (aGroupSids.AddElement(cSid.Get()) != FALSE)
              cSid.Detach();
            else
              hRes = E_OUTOFMEMORY;
          }
        }
        else
        {
          hRes = E_OUTOFMEMORY;
        }
        ::SafeArrayUnaccessData(V_ARRAY(&vt));
      }
    }
    else
    {
      hRes = MX_E_Unsupported;
    }
  }

  //done
  ::VariantClear(&vt);
  if (SUCCEEDED(hRes))
    *lplpComputerSid = cComputerSid.Detach();
  else
    aGroupSids.RemoveAllElements();
  return hRes;
}

HRESULT CAdsHelper::EnumerateContainerFolders(_In_z_ LPCWSTR szParentW,
                                              _Inout_ TArrayListWithFree<LPWSTR> &aChildrenList)
{
  static const LPCWSTR szSearchFilterW = L"(|(objectCategory=organizationalUnit)(objectCategory=container)"
                                         L"(objectCategory=group))";
  static const LPCWSTR szAttribW[] = { L"distinguishedName", L"cn", L"ou" };
  TAutoRefCounted<IDirectorySearch> cDirSearch;
  ADS_SEARCH_HANDLE hSearch = INVALID_HANDLE_VALUE;
  CStringW cStrTempW;
  ADS_SEARCH_COLUMN sColumns[2];
  CSid cSid;
  DWORD dw, dwCurrTickMs, dwTimeoutMs;
  SIZE_T nLen;
  HRESULT hRes;

  aChildrenList.RemoveAllElements();
  dwTimeoutMs = dwQueryTimeoutMs;
  dwCurrTickMs = ::GetTickCount();

  if (szParentW == NULL || *szParentW == 0)
  {
    hRes = GetRootADSPath(cStrTempW);
    if (SUCCEEDED(hRes))
      hRes = AdsOpen((LPCWSTR)cStrTempW, __uuidof(IDirectorySearch), (LPVOID*)&cDirSearch);
  }
  else
  {
    if (cStrTempW.Copy(szParentW) != FALSE)
    {
      hRes = GetUrlFromDn(cStrTempW);
      if (SUCCEEDED(hRes))
        hRes = AdsOpen((LPCWSTR)cStrTempW, __uuidof(IDirectorySearch), (LPVOID*)&cDirSearch);
    }
    else
    {
      hRes = E_OUTOFMEMORY;
    }
  }

  if (SUCCEEDED(hRes))
  {
    ADS_SEARCHPREF_INFO sSearchPrefs[2];

    sSearchPrefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
    sSearchPrefs[0].vValue.dwType = ADSTYPE_INTEGER;
    sSearchPrefs[0].vValue.Integer = ADS_SCOPE_ONELEVEL;
    sSearchPrefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
    sSearchPrefs[1].vValue.dwType = ADSTYPE_INTEGER;
    sSearchPrefs[1].vValue.Integer = 256;
    hRes = cDirSearch->SetSearchPreference(sSearchPrefs, _countof(sSearchPrefs));
  }

  if (SUCCEEDED(hRes))
    hRes = cDirSearch->ExecuteSearch((LPWSTR)szSearchFilterW, (LPWSTR*)szAttribW, _countof(szAttribW), &hSearch);

  if (SUCCEEDED(hRes))
  {
    hRes = cDirSearch->GetFirstRow(hSearch);
    while (SUCCEEDED(hRes) && hRes != S_ADS_NOMORE_ROWS)
    {
      if (dwTimeoutMs != INFINITE)
      {
        dw = ::GetTickCount();
        if (dwTimeoutMs < dw - dwCurrTickMs)
        {
          hRes = MX_E_Timeout;
          break;
        }
        dwTimeoutMs -= (dw - dwCurrTickMs);
        dwCurrTickMs = dw;
      }
      if (IsCancelled() != FALSE)
      {
        hRes = MX_E_Cancelled;
        break;
      }

      hRes = cDirSearch->GetColumn(hSearch, (LPWSTR)(szAttribW[0]), &sColumns[0]);
      if (SUCCEEDED(hRes))
      {
        hRes = cDirSearch->GetColumn(hSearch, (LPWSTR)(szAttribW[1]), &sColumns[1]); //try CN first
        if (hRes == E_ADS_COLUMN_NOT_SET)
          hRes = cDirSearch->GetColumn(hSearch, (LPWSTR)(szAttribW[2]), &sColumns[1]); //else try OU
        if (SUCCEEDED(hRes))
        {
          if (sColumns[0].dwNumValues > 0 && sColumns[1].dwNumValues > 0 &&
              sColumns[0].pADsValues[0].DNString != NULL && sColumns[1].pADsValues[0].DNString != NULL &&
              sColumns[0].pADsValues[0].DNString[0] != 0 && sColumns[1].pADsValues[0].DNString[0] != 0)
          {
            //distinguished name
            if (cStrTempW.Copy(sColumns[0].pADsValues[0].DNString) == FALSE ||
                EscapeSlashes(cStrTempW) == FALSE)
            {
              hRes = E_OUTOFMEMORY;
            }

            //common name
            if (SUCCEEDED(hRes))
            {
              nLen = StrLenW(sColumns[1].pADsValues[0].DNString);
              if (nLen > 0 && sColumns[1].pADsValues[0].DNString[nLen-1] == L'$')
                nLen--;

              if (cStrTempW.ConcatN(L"/", 1) == FALSE ||
                  cStrTempW.ConcatN(sColumns[1].pADsValues[0].DNString, nLen) == FALSE)
              {
                hRes = E_OUTOFMEMORY;
              }
            }

            //add to list
            if (SUCCEEDED(hRes))
            {
              if (aChildrenList.AddElement((LPWSTR)cStrTempW) != FALSE)
                cStrTempW.Detach();
              else
                hRes = E_OUTOFMEMORY;
            }
          }
          cDirSearch->FreeColumn(&sColumns[1]);
        }
        cDirSearch->FreeColumn(&sColumns[0]);
      }
      if (SUCCEEDED(hRes))
        hRes = cDirSearch->GetNextRow(hSearch);
    }
    if (hRes == S_ADS_NOMORE_ROWS)
      hRes = S_OK;
  }
  //done
  if (hSearch != INVALID_HANDLE_VALUE && cDirSearch)
    cDirSearch->CloseSearchHandle(hSearch);
  if (FAILED(hRes))
    aChildrenList.RemoveAllElements();
  return hRes;
}

HRESULT CAdsHelper::GetContainerMembers(_In_z_ LPCWSTR szParentW, _Inout_ TArrayListWithFree<LPWSTR> &aMembersList)
{
  static const LPCWSTR szTypeW[] = { L"user", L"group", L"computer" };
  static const LPCWSTR szAttribW[] = { L"distinguishedName", L"objectSid", L"objectClass" };
  TArrayListWithFree<LPWSTR> aGroupsList;
  TAutoRefCounted<IDirectorySearch> cDirSearch;
  ADS_SEARCH_HANDLE hSearch = INVALID_HANDLE_VALUE;
  CStringW cStrTempW, cStrRootRseW, cStrSidW;
  ADS_SEARCHPREF_INFO sSearchPrefs[2];
  ADS_SEARCH_COLUMN sColumns[3];
  CSid cSid;
  DWORD dw, dwType, dwCurrTickMs, dwTimeoutMs;
  SIZE_T i;
  HRESULT hRes;

  aMembersList.RemoveAllElements();
  dwTimeoutMs = dwQueryTimeoutMs;
  dwCurrTickMs = ::GetTickCount();

  hRes = GetRootADSPath(cStrRootRseW);
  if (FAILED(hRes))
    return hRes;

  if (szParentW == NULL || *szParentW == 0)
  {
    if (cStrTempW.Copy(GetDnFromUrl((LPCWSTR)cStrRootRseW)) == FALSE)
      return E_OUTOFMEMORY;
  }
  else
  {
    if (cStrTempW.Copy(szParentW) == FALSE)
      return E_OUTOFMEMORY;
  }

  if (StrNCompareW((LPCWSTR)cStrTempW, L"CN=", 3) == 0)
  {
    if (aGroupsList.AddElement((LPWSTR)cStrTempW) == FALSE)
      return E_OUTOFMEMORY;
    cStrTempW.Detach();
  }
  else
  {
    //query first for container's groups
    static const LPCWSTR szSearchFilterW_2 = L"(objectClass=group)";
    static const LPCWSTR szAttribW_2[] = { L"distinguishedName" };

    hRes = GetUrlFromDn(cStrTempW);
    if (SUCCEEDED(hRes))
      hRes = AdsOpen((LPCWSTR)cStrTempW, __uuidof(IDirectorySearch), (LPVOID*)&cDirSearch);

    if (SUCCEEDED(hRes))
    {
      ADS_SEARCHPREF_INFO sSearchPrefs[2];

      sSearchPrefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
      sSearchPrefs[0].vValue.dwType = ADSTYPE_INTEGER;
      sSearchPrefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
      sSearchPrefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
      sSearchPrefs[1].vValue.dwType = ADSTYPE_INTEGER;
      sSearchPrefs[1].vValue.Integer = 256;
      hRes = cDirSearch->SetSearchPreference(sSearchPrefs, _countof(sSearchPrefs));
    }

    if (SUCCEEDED(hRes))
      hRes = cDirSearch->ExecuteSearch((LPWSTR)szSearchFilterW_2, (LPWSTR*)szAttribW, _countof(szAttribW), &hSearch);

    if (SUCCEEDED(hRes))
    {
      hRes = cDirSearch->GetFirstRow(hSearch);
      while (SUCCEEDED(hRes) && hRes != S_ADS_NOMORE_ROWS)
      {
        if (dwTimeoutMs != INFINITE)
        {
          dw = ::GetTickCount();
          if (dwTimeoutMs < dw - dwCurrTickMs)
          {
            hRes = MX_E_Timeout;
            break;
          }
          dwTimeoutMs -= (dw - dwCurrTickMs);
          dwCurrTickMs = dw;
        }
        if (IsCancelled() != FALSE)
        {
          hRes = MX_E_Cancelled;
          break;
        }

        hRes = cDirSearch->GetColumn(hSearch, (LPWSTR)(szAttribW[0]), &sColumns[0]);
        if (SUCCEEDED(hRes))
        {
          if (sColumns[0].dwNumValues > 0 &&
              sColumns[0].pADsValues[0].DNString != NULL &&
              sColumns[0].pADsValues[0].DNString[0] != 0)
          {
            //add distinguished name to list
            if (cStrTempW.Copy(sColumns[0].pADsValues[0].DNString) != FALSE &&
                aGroupsList.AddElement((LPWSTR)cStrTempW) != FALSE)
            {
              cStrTempW.Detach();
            }
            else
            {
              hRes = E_OUTOFMEMORY;
            }
          }
          cDirSearch->FreeColumn(&sColumns[0]);
        }
        if (SUCCEEDED(hRes))
          hRes = cDirSearch->GetNextRow(hSearch);
      }
      if (hRes == S_ADS_NOMORE_ROWS)
        hRes = S_OK;
    }
    //done
    if (hSearch != INVALID_HANDLE_VALUE && cDirSearch)
      cDirSearch->CloseSearchHandle(hSearch);

    cDirSearch.Release();

    if (FAILED(hRes))
      return hRes;
  }

  //we have a list of group we have to scan
  hRes = S_OK;

  sSearchPrefs[0].dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
  sSearchPrefs[0].vValue.dwType = ADSTYPE_INTEGER;
  sSearchPrefs[0].vValue.Integer = ADS_SCOPE_SUBTREE;
  sSearchPrefs[1].dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
  sSearchPrefs[1].vValue.dwType = ADSTYPE_INTEGER;
  sSearchPrefs[1].vValue.Integer = 256;

  for (i=0; SUCCEEDED(hRes) && i<aGroupsList.GetCount(); i++)
  {
    cDirSearch.Release();
    hRes = AdsOpen((LPCWSTR)cStrRootRseW, __uuidof(IDirectorySearch), (LPVOID*)&cDirSearch);

    if (SUCCEEDED(hRes))
      hRes = cDirSearch->SetSearchPreference(sSearchPrefs, _countof(sSearchPrefs));

    if (SUCCEEDED(hRes))
    {
      if (cStrTempW.Format(L"(&(memberOf:1.2.840.113556.1.4.1941:=%s)(|(&(objectClass=user)(objectCategory=person))"
                           L"(objectClass=group)(objectClass=computer)))", aGroupsList.GetElementAt(i)) == FALSE)
      {
        hRes = E_OUTOFMEMORY;
      }
    }

    hSearch = INVALID_HANDLE_VALUE;
    if (SUCCEEDED(hRes))
      hRes = cDirSearch->ExecuteSearch((LPWSTR)cStrTempW, (LPWSTR*)szAttribW, _countof(szAttribW), &hSearch);

    if (SUCCEEDED(hRes))
    {
      hRes = cDirSearch->GetFirstRow(hSearch);
      while (SUCCEEDED(hRes) && hRes != S_ADS_NOMORE_ROWS)
      {
        if (dwTimeoutMs != INFINITE)
        {
          dw = ::GetTickCount();
          if (dwTimeoutMs < dw - dwCurrTickMs)
          {
            hRes = MX_E_Timeout;
            break;
          }
          dwTimeoutMs -= (dw - dwCurrTickMs);
          dwCurrTickMs = dw;
        }
        if (IsCancelled() != FALSE)
        {
          hRes = MX_E_Cancelled;
          break;
        }

        hRes = cDirSearch->GetColumn(hSearch, (LPWSTR)(szAttribW[0]), &sColumns[0]);
        if (SUCCEEDED(hRes))
        {
          hRes = cDirSearch->GetColumn(hSearch, (LPWSTR)(szAttribW[1]), &sColumns[1]);
          if (SUCCEEDED(hRes))
          {
            hRes = cDirSearch->GetColumn(hSearch, (LPWSTR)(szAttribW[2]), &sColumns[2]);
            if (SUCCEEDED(hRes))
            {
              if (sColumns[0].dwNumValues > 0 && sColumns[1].dwNumValues > 0 && sColumns[2].dwNumValues > 0 &&
                  sColumns[0].pADsValues[0].DNString != NULL && sColumns[1].pADsValues[0].OctetString.lpValue != NULL &&
                  sColumns[0].pADsValues[0].DNString[0] != 0 && sColumns[1].pADsValues[0].OctetString.dwLength > 0)
              {
                //type
                dwType = 0;
                for (dw=sColumns[2].dwNumValues; dw>0;)
                {
                  PADSVALUE lpValue = &(sColumns[2].pADsValues[--dw]);

                  if (lpValue->DNString != NULL)
                  {
                    if (StrCompareW(lpValue->DNString, L"computer", FALSE) == 0)
                    {
                      dwType = 3;
                      break;
                    }
                    if (StrCompareW(lpValue->DNString, L"group", FALSE) == 0)
                    {
                      dwType = 2;
                      break;
                    }
                    if (StrCompareW(lpValue->DNString, L"user", FALSE) == 0)
                      dwType = 1;
                  }
                }
                if (dwType != 0) //valid type?
                {
                  //distinguished name
                  if (cStrTempW.Copy(sColumns[0].pADsValues[0].DNString) == FALSE)
                    hRes = E_OUTOFMEMORY;

                  //sid
                  if (SUCCEEDED(hRes))
                  {
                    hRes = cSid.Set(sColumns[1].pADsValues[0].OctetString.lpValue);
                    if (SUCCEEDED(hRes))
                      hRes = cSid.GetStringSid(cStrSidW);
                  }
                  //build and add complete name
                  if (SUCCEEDED(hRes))
                  {
                    if (cStrTempW.InsertN(L"/", 0, 1) != FALSE &&
                        cStrTempW.Insert((LPCWSTR)cStrSidW, 0) != FALSE &&
                        cStrTempW.InsertN(L"/", 0, 1) != FALSE &&
                        cStrTempW.Insert(szTypeW[dwType-1], 0) != FALSE)
                    {
                      if (aMembersList.AddElement((LPWSTR)cStrTempW) != FALSE)
                        cStrTempW.Detach();
                      else
                        hRes = E_OUTOFMEMORY;
                    }
                    else
                    {
                      hRes = E_OUTOFMEMORY;
                    }
                  }
                }
              }
              cDirSearch->FreeColumn(&sColumns[2]);
            }
            cDirSearch->FreeColumn(&sColumns[1]);
          }
          cDirSearch->FreeColumn(&sColumns[0]);
        }
        if (SUCCEEDED(hRes))
          hRes = cDirSearch->GetNextRow(hSearch);
      }
      if (hRes == S_ADS_NOMORE_ROWS)
        hRes = S_OK;
    }

    //done this round
    if (hSearch != INVALID_HANDLE_VALUE && cDirSearch)
      cDirSearch->CloseSearchHandle(hSearch);
  }

  //done
  return hRes;
}

HRESULT CAdsHelper::GetSidFromADsPath(_In_z_ LPCWSTR szADsPathW, _Inout_ CSid &cSid)
{
  TAutoRefCounted<IADs> cAdsUser;
  CStringW cStrADsPathUrlW;
  VARIANT vt;
  BSTR bstr;
  HRESULT hRes;

  cSid.Reset();
  if (szADsPathW == NULL)
    return E_POINTER;
  if (*szADsPathW == 0)
    return E_INVALIDARG;

  hRes = GetUrlFromDn(szADsPathW, cStrADsPathUrlW);
  if (SUCCEEDED(hRes))
    hRes = AdsOpen((LPCWSTR)cStrADsPathUrlW, __uuidof(IADs), (LPVOID*)&cAdsUser);
  if (FAILED(hRes))
    return hRes;

  ::VariantInit(&vt);
  bstr = ::SysAllocString(L"ObjectSid");
  if (bstr != NULL)
  {
    hRes = cAdsUser->Get(bstr, &vt);
    if (SUCCEEDED(hRes))
      hRes = cSid.Set((PSID)(vt.parray->pvData));
    ::SysFreeString(bstr);
  }
  else
  {
    hRes = E_OUTOFMEMORY;
  }
  //done
  ::VariantClear(&vt);
  return hRes;
}

HRESULT CAdsHelper::GetDomainFromUrl(_In_z_ LPCWSTR szUrlW, _Inout_ CStringW &cStrDomainW)
{
  LPCWSTR sW;

  cStrDomainW.Empty();
  if (szUrlW == NULL)
    return E_POINTER;
  if (*szUrlW == 0)
    return E_INVALIDARG;
  sW = StrFindW(szUrlW, L"://");
  if (sW == NULL)
  {
    sW = szUrlW;
  }
  else
  {
    for (sW+=3; *sW==L'/'; sW++);
  }
  return GetDomainFromDn(sW, cStrDomainW);
}

HRESULT CAdsHelper::GetDomainFromDn(_In_z_ LPCWSTR szDistinguishedNameW, _Inout_ CStringW &cStrDomainW)
{
  TAutoRefCounted<IADsPathname> cADsPathname;
  BSTR bstrTemp;
  long i, nNumPathElements;
  HRESULT hRes;

  cStrDomainW.Empty();
  if (szDistinguishedNameW == NULL)
    return E_POINTER;
  if (*szDistinguishedNameW == 0)
    return E_INVALIDARG;

  hRes = ::CoCreateInstance(__uuidof(Pathname), NULL, CLSCTX_INPROC_SERVER, __uuidof(IADsPathname),
                            (LPVOID*)&cADsPathname);
  if (SUCCEEDED(hRes))
  {
    bstrTemp = ::SysAllocString(szDistinguishedNameW);
    if (bstrTemp != NULL)
    {
      hRes = cADsPathname->Set(bstrTemp, ADS_SETTYPE_DN);
      ::SysFreeString(bstrTemp);

      if (SUCCEEDED(hRes))
        hRes = cADsPathname->GetNumElements(&nNumPathElements);

      for (i=0; SUCCEEDED(hRes) && i<nNumPathElements; i++)
      {
        hRes = cADsPathname->GetElement(i, &bstrTemp);
        if (SUCCEEDED(hRes))
        {
          if (StrNCompareW(bstrTemp, L"DC=", 3) == 0)
          {
            if (cStrDomainW.IsEmpty() == FALSE)
            {
              if (cStrDomainW.ConcatN(L".", 1) == FALSE)
                hRes = E_OUTOFMEMORY;
            }
            if (SUCCEEDED(hRes) && cStrDomainW.Concat(bstrTemp+3) == FALSE)
              hRes = E_OUTOFMEMORY;
          }
          ::SysFreeString(bstrTemp);
        }
      }
    }
    else
    {
      hRes = E_OUTOFMEMORY;
    }
  }
  //done
  return hRes;
}

HRESULT CAdsHelper::GetRootADSPath(_Inout_ CStringW &cStrRootPathW)
{
  TAutoRefCounted<IADs> cRootDSE;
  BSTR bstrTemp;
  VARIANT vt;
  HRESULT hRes;

  cStrRootPathW.Empty();
  ::VariantInit(&vt);

  hRes = AdsOpen(L"LDAP://rootDSE", __uuidof(IADs), (LPVOID*)&cRootDSE);
  if (SUCCEEDED(hRes))
  {
    bstrTemp = ::SysAllocString(L"defaultNamingContext");
    if (bstrTemp != NULL)
    {
      hRes = cRootDSE->Get(bstrTemp, &vt);
      ::SysFreeString(bstrTemp);
      if (SUCCEEDED(hRes))
      {
        if (vt.vt == VT_BSTR)
        {
          if (cStrRootPathW.Format(L"LDAP://%s", vt.bstrVal) == FALSE)
            hRes = E_OUTOFMEMORY;
        }
        else
        {
          hRes = MX_E_InvalidData;
        }
      }
    }
    else
    {
      hRes = E_OUTOFMEMORY;
    }
  }
  ::VariantClear(&vt);
  return hRes;
}

HRESULT CAdsHelper::GetUrlFromDn(_In_ LPCWSTR szDnW, _Inout_ CStringW &cStrW)
{
  cStrW.Empty();
  if (szDnW == NULL)
    return E_POINTER;
  if (*szDnW == 0)
    return E_INVALIDARG;
  if (StrNCompareW(szDnW, L"LDAP://", 7, TRUE) != 0)
  {
    if (cStrW.Copy(L"LDAP://") == FALSE)
      return E_OUTOFMEMORY;
  }
  if (cStrW.Concat(szDnW) == FALSE)
    return E_OUTOFMEMORY;
  return S_OK;
}

HRESULT CAdsHelper::GetUrlFromDn(_Inout_ CStringW &cStrW)
{
  if (cStrW.IsEmpty() != FALSE)
    return E_INVALIDARG;
  if (StrNCompareW((LPCWSTR)cStrW, L"LDAP://", 7, TRUE) != 0)
  {
    if (cStrW.InsertN(L"LDAP://", 0, 7) == FALSE)
      return E_OUTOFMEMORY;
  }
  return S_OK;
}

LPCWSTR CAdsHelper::GetDnFromUrl(_In_ LPCWSTR szUrlW)
{
  LPCWSTR sW;

  if (szUrlW == NULL)
    return NULL;
  sW = StrChrW(szUrlW, L'/', TRUE);
  return (sW == NULL) ? szUrlW : (sW + 1);
}

BOOL CAdsHelper::EscapeSlashes(_Inout_ CStringW &cStrW)
{
  LPCWSTR sW;
  SIZE_T nOfs;

  nOfs = 0;
  for (;;)
  {
    sW = StrChrW((LPCWSTR)cStrW + nOfs, L'/');
    if (sW == NULL)
      break;

    nOfs = (SIZE_T)(sW - (LPCWSTR)cStrW);
    if (cStrW.InsertN(L"\\", nOfs, 1) == FALSE)
      return FALSE;
    nOfs += 2;
  }
  return TRUE;
}

HRESULT CAdsHelper::AdsOpen(_In_z_ LPCWSTR szPathNameW, _In_ REFIID riid, __deref_out LPVOID *ppObject)
{
  CStringW cStrTempPathW;

  MX_ASSERT(szPathNameW != NULL);
  if (StrNCompareW(szPathNameW, L"LDAP://", 7) != 0)
    return E_INVALIDARG;
  if (cStrServerAddressW.IsEmpty() == FALSE)
  {
    if (cStrTempPathW.Copy(szPathNameW) == FALSE ||
        cStrTempPathW.InsertN(L"/", 7, 1) == FALSE ||
        cStrTempPathW.Insert((LPCWSTR)cStrServerAddressW, 7) == FALSE)
    {
      return E_OUTOFMEMORY;
    }
    szPathNameW = (LPCWSTR)cStrTempPathW;
  }
  if (cStrUserNameW.IsEmpty() != FALSE)
    return ::ADsGetObject(szPathNameW, riid, ppObject);
  return ::ADsOpenObject(szPathNameW, (LPCWSTR)cStrUserNameW, (LPCWSTR)cStrPasswordW, 0, riid, ppObject);
}

BOOL CAdsHelper::IsCancelled()
{
  if (hCancelEvent != NULL)
  {
    if (::WaitForSingleObject(hCancelEvent, 0) == WAIT_OBJECT_0)
      return TRUE;
  }
  return FALSE;
}

}; //namespace MX
