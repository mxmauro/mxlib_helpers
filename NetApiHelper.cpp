#include "NetApiHelper.h"
#include "Sid.h"
#include <RefCounted.h>

#pragma comment(lib, "netapi32.lib")

//-----------------------------------------------------------

namespace NetApiHelper {

HRESULT GetAllUsers(_Inout_ MX::TArrayListWithFree<LPWSTR> &aUsersList)
{
  static const LPCWSTR aBuiltinUsersW[] = { L"S-1-5-18", L"S-1-5-19", L"S-1-5-20" };
  LPUSER_INFO_0 lpUserInfo0 = NULL;
  DWORD i, dwEntries, dwTotalEntries, dwResumeHandle;
  NET_API_STATUS nStatus;
  CSid cSid;
  MX::CStringW cStrTempW;
  HRESULT hRes, hRes2;

  aUsersList.RemoveAllElements();

  for (i=0; i<(DWORD)MX_ARRAYLEN(aBuiltinUsersW); i++)
  {
    hRes = cSid.Set(aBuiltinUsersW[i]);
    if (SUCCEEDED(hRes))
    {
      hRes = cSid.GetAccountName(cStrTempW);
      if (SUCCEEDED(hRes))
      {
        if (cStrTempW.InsertN(L"/", 0, 1) == FALSE ||
            cStrTempW.Insert(aBuiltinUsersW[i], 0) == FALSE ||
            cStrTempW.InsertN((cSid.IsAnyWellKnownSid() != FALSE) ? L"+" : L"-", 0, 1) == FALSE)
        {
          hRes = E_OUTOFMEMORY;
        }
      }

      if (SUCCEEDED(hRes))
      {
        if (aUsersList.AddElement((LPWSTR)cStrTempW) != FALSE)
          cStrTempW.Detach();
        else
          hRes = E_OUTOFMEMORY;
      }
    }

    if (FAILED(hRes))
      goto done;
  }

  dwEntries = dwTotalEntries = dwResumeHandle = 0;
  do
  {
    lpUserInfo0 = NULL;
    nStatus = ::NetUserEnum(NULL, 0, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&lpUserInfo0, 16384, &dwEntries, &dwTotalEntries,
                            &dwResumeHandle);
    hRes = HRESULT_FROM_WIN32(nStatus);
    if (nStatus == NERR_Success || nStatus == ERROR_MORE_DATA)
    {
      for (i = 0; i < dwEntries; i++)
      {
        cStrTempW.Empty();

        hRes2 = cSid.Set(lpUserInfo0[i].usri0_name);
        if (SUCCEEDED(hRes2))
          hRes2 = cSid.GetStringSid(cStrTempW);

        if (SUCCEEDED(hRes2))
        {
          if (cStrTempW.ConcatN(L"/", 1) == FALSE ||
              cStrTempW.Concat(lpUserInfo0[i].usri0_name) == FALSE ||
              cStrTempW.InsertN((cSid.IsAnyWellKnownSid() != FALSE) ? L"+" : L"-", 0, 1) == FALSE)
          {
            hRes2 = E_OUTOFMEMORY;
          }
        }

        if (SUCCEEDED(hRes2))
        {
          if (aUsersList.AddElement((LPWSTR)cStrTempW) != FALSE)
            cStrTempW.Detach();
          else
            hRes2 = E_OUTOFMEMORY;
        }

        if (FAILED(hRes2))
        {
          hRes = hRes2;
          break;
        }
      }
    }
    if (lpUserInfo0 != NULL)
      ::NetApiBufferFree(lpUserInfo0);
  }
  while (hRes == HRESULT_FROM_WIN32(ERROR_MORE_DATA));

done:
  //done
  if (FAILED(hRes))
    aUsersList.RemoveAllElements();
  return hRes;
}

HRESULT GetAllGroups(_Inout_ MX::TArrayListWithFree<LPWSTR> &aGroupsList)
{
  static const LPCWSTR aBuiltinUsersW[] = { L"S-1-1-0" };
  LPLOCALGROUP_INFO_0 lpGroupInfo0 = NULL;
  DWORD i, dwEntries, dwTotalEntries;
  DWORD_PTR dwResumeHandle;
  NET_API_STATUS nStatus;
  CSid cSid;
  MX::CStringW cStrTempW;
  HRESULT hRes, hRes2;

  aGroupsList.RemoveAllElements();

  for (i=0; i<(DWORD)MX_ARRAYLEN(aBuiltinUsersW); i++)
  {
    hRes = cSid.Set(aBuiltinUsersW[i]);
    if (SUCCEEDED(hRes))
    {
      hRes = cSid.GetAccountName(cStrTempW);
      if (SUCCEEDED(hRes))
      {
        if (cStrTempW.InsertN(L"/", 0, 1) == FALSE ||
            cStrTempW.Insert(aBuiltinUsersW[i], 0) == FALSE ||
            cStrTempW.InsertN((cSid.IsAnyWellKnownSid() != FALSE) ? L"+" : L"-", 0, 1) == FALSE)
        {
          hRes = E_OUTOFMEMORY;
        }
      }

      if (SUCCEEDED(hRes))
      {
        if (aGroupsList.AddElement((LPWSTR)cStrTempW) != FALSE)
          cStrTempW.Detach();
        else
          hRes = E_OUTOFMEMORY;
      }
    }

    if (FAILED(hRes))
      goto done;
  }

  dwEntries = dwTotalEntries = 0;
  dwResumeHandle = 0;
  do
  {
    lpGroupInfo0 = NULL;
    nStatus = ::NetLocalGroupEnum(NULL, 0, (LPBYTE*)&lpGroupInfo0, 16384, &dwEntries, &dwTotalEntries,
                                  &dwResumeHandle);
    hRes = HRESULT_FROM_WIN32(nStatus);
    if (nStatus == NERR_Success || nStatus == ERROR_MORE_DATA)
    {
      for (i = 0; i < dwEntries; i++)
      {
        cStrTempW.Empty();

        hRes2 = cSid.Set(lpGroupInfo0[i].lgrpi0_name);
        if (SUCCEEDED(hRes2))
          hRes2 = cSid.GetStringSid(cStrTempW);

        if (SUCCEEDED(hRes2))
        {
          if (cStrTempW.ConcatN(L"/", 1) == FALSE ||
              cStrTempW.Concat(lpGroupInfo0[i].lgrpi0_name) == FALSE ||
              cStrTempW.InsertN((cSid.IsAnyWellKnownSid() != FALSE) ? L"+" : L"-", 0, 1) == FALSE)
          {
            hRes2 = E_OUTOFMEMORY;
          }
        }
        if (SUCCEEDED(hRes2))
        {
          if (aGroupsList.AddElement((LPWSTR)cStrTempW) != FALSE)
            cStrTempW.Detach();
          else
            hRes2 = E_OUTOFMEMORY;
        }

        if (FAILED(hRes2))
        {
          hRes = hRes2;
          break;
        }
      }
    }
    if (lpGroupInfo0 != NULL)
      ::NetApiBufferFree(lpGroupInfo0);
  }
  while (hRes == HRESULT_FROM_WIN32(ERROR_MORE_DATA));

done:
  //done
  if (FAILED(hRes))
    aGroupsList.RemoveAllElements();
  return hRes;
}

}; //namespace NetApiHelper
