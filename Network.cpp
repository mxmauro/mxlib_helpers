#include "Network.h"
#include "System.h"
#include <AutoPtr.h>
#include <IPTypes.h>
#include <IPHlpApi.h>

#pragma comment(lib, "iphlpapi.lib")

//-----------------------------------------------------------

namespace MXHelpers {

HRESULT GetLocalIpAddresses(_Out_ MX::TArrayListWithFree<LPCWSTR> &cStrListW, _In_ int nFlags)
{
  MX::TAutoFreePtr<IP_ADAPTER_ADDRESSES> cIpAddrBuffer;
  PIP_ADAPTER_ADDRESSES lpCurrAdapter;
  PIP_ADAPTER_UNICAST_ADDRESS lpCurrUnicastAddress;
  DWORD dwBufLen, dwRetVal, dwRetryCount;
  SIZE_T nIpV4InsertPos;
  union {
    sockaddr_in *lpAddrV4;
    SOCKADDR_IN6_W2KSP1 *lpAddrV6;
    SOCKADDR_INET *lpAddr;
  } u;
  MX::CStringW cStrTempW;
  HRESULT hRes;

  cStrListW.RemoveAllElements();
  //query addresses
  dwBufLen = 16384;
  for (dwRetryCount=20; dwRetryCount>0; dwRetryCount--)
  {
    cIpAddrBuffer.Attach((IP_ADAPTER_ADDRESSES*)MX_MALLOC(dwBufLen));
    if (!cIpAddrBuffer)
      return E_OUTOFMEMORY;
    dwRetVal = ::GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST|GAA_FLAG_SKIP_DNS_SERVER|
                                      GAA_FLAG_SKIP_FRIENDLY_NAME, NULL, cIpAddrBuffer.Get(), &dwBufLen);
    if (dwRetVal != ERROR_BUFFER_OVERFLOW)
      break;
  }
  if (dwRetVal != NO_ERROR)
    return MX_HRESULT_FROM_WIN32(dwRetVal);
  //enum addresses
  nIpV4InsertPos = 0;
  for (lpCurrAdapter=cIpAddrBuffer.Get(); lpCurrAdapter!=NULL; lpCurrAdapter=lpCurrAdapter->Next)
  {
    if (lpCurrAdapter->PhysicalAddressLength == 0)
      continue;
    if (lpCurrAdapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
      continue;
    if (lpCurrAdapter->Description[0] == L'V')
      continue; //VirtualBox VMnet
    if (MX::StrFindW(lpCurrAdapter->Description, L"loopback", FALSE, TRUE) != NULL)
      continue;
    for (lpCurrUnicastAddress=lpCurrAdapter->FirstUnicastAddress; lpCurrUnicastAddress!=NULL;
         lpCurrUnicastAddress=lpCurrUnicastAddress->Next)
    {
      if ((lpCurrUnicastAddress->Flags & IP_ADAPTER_ADDRESS_DNS_ELIGIBLE) == 0)
        continue;
      if ((lpCurrUnicastAddress->Flags & IP_ADAPTER_ADDRESS_TRANSIENT) != 0)
        continue;
      switch (lpCurrUnicastAddress->Address.lpSockaddr->sa_family)
      {
        case AF_INET:
          if ((nFlags & LocalIpAddressesFlagsDontAddIpV4) != 0)
            break;
          u.lpAddrV4 =  (sockaddr_in*)(lpCurrUnicastAddress->Address.lpSockaddr);
          //ignore zero & localhost
          if (u.lpAddrV4->sin_addr.S_un.S_un_b.s_b2 == 0 && u.lpAddrV4->sin_addr.S_un.S_un_b.s_b3 == 0)
          {
            if ((u.lpAddrV4->sin_addr.S_un.S_un_b.s_b1 == 0 && u.lpAddrV4->sin_addr.S_un.S_un_b.s_b4 == 0) ||
              (u.lpAddrV4->sin_addr.S_un.S_un_b.s_b1 == 127 && u.lpAddrV4->sin_addr.S_un.S_un_b.s_b4 == 1))
            {
              break;
            }
          }
          //add
          hRes = FormatIpAddress(cStrTempW, u.lpAddr);
          if (FAILED(hRes))
            return hRes;
          if (cStrListW.InsertElementAt((LPWSTR)cStrTempW, nIpV4InsertPos) == FALSE)
            return E_OUTOFMEMORY;
          cStrTempW.Detach();
          nIpV4InsertPos++;
          break;

        case AF_INET6:
          if ((nFlags & LocalIpAddressesFlagsDontAddIpV6) != 0)
            break;
          u.lpAddrV6 =  (SOCKADDR_IN6_W2KSP1*)(lpCurrUnicastAddress->Address.lpSockaddr);
          //ignore zero & localhost
          if (u.lpAddrV6->sin6_addr.u.Word[0] == 0 && u.lpAddrV6->sin6_addr.u.Word[1] == 0 &&
              u.lpAddrV6->sin6_addr.u.Word[2] == 0 && u.lpAddrV6->sin6_addr.u.Word[3] == 0 &&
              u.lpAddrV6->sin6_addr.u.Word[4] == 0 && u.lpAddrV6->sin6_addr.u.Word[5] == 0 &&
              u.lpAddrV6->sin6_addr.u.Word[6] == 0 && u.lpAddrV6->sin6_addr.u.Word[7] < 2)
          {
            break;
          }
          //ignore local
          if (u.lpAddrV6->sin6_addr.u.Word[0] >= 0xFE80 && u.lpAddrV6->sin6_addr.u.Word[1] == 0xFEBF)
            break;
          //ignore special use
          if (u.lpAddrV6->sin6_addr.u.Word[0] == 2001 && u.lpAddrV6->sin6_addr.u.Word[1] == 0)
            break;
          //add
          hRes = FormatIpAddress(cStrTempW, u.lpAddr);
          if (FAILED(hRes))
            return hRes;
          if (cStrListW.AddElement((LPWSTR)cStrTempW) == FALSE)
            return E_OUTOFMEMORY;
          cStrTempW.Detach();
          break;
      }
    }
  }

  if ((nFlags & LocalIpAddressesFlagsDontAddNetbiosName) == 0)
  {
    hRes = _GetComputerNameEx(ComputerNameDnsFullyQualified, cStrTempW);
    if (FAILED(hRes))
      return hRes;
    if (cStrTempW.IsEmpty() == FALSE)
    {
      if (cStrListW.InsertElementAt((LPWSTR)cStrTempW, 0) == FALSE)
        return E_OUTOFMEMORY;
      cStrTempW.Detach();
    }
  }
  //done
  return (cStrListW.GetCount() > 0) ? S_OK : MX_E_NotFound;
}

HRESULT FormatIpAddress(_Out_ MX::CStringW &cStrW, _In_ PSOCKADDR_INET lpAddr)
{
  SIZE_T nIdx;

  cStrW.Empty();
  if (lpAddr == NULL)
    return E_POINTER;

  switch (lpAddr->si_family)
  {
    case AF_INET:
      if (cStrW.Format(L"%lu.%lu.%lu.%lu", lpAddr->Ipv4.sin_addr.S_un.S_un_b.s_b1,
          lpAddr->Ipv4.sin_addr.S_un.S_un_b.s_b2, lpAddr->Ipv4.sin_addr.S_un.S_un_b.s_b3,
          lpAddr->Ipv4.sin_addr.S_un.S_un_b.s_b4) == FALSE)
      {
        return E_OUTOFMEMORY;
      }
      break;

    case AF_INET6:
      if (cStrW.CopyN(L"[", 1) == FALSE)
        return E_OUTOFMEMORY;
      for (nIdx=0; nIdx<8; nIdx++)
      {
        if (lpAddr->Ipv6.sin6_addr.u.Word[nIdx] == 0)
          break;
        if (cStrW.AppendFormat(L"%04X", lpAddr->Ipv6.sin6_addr.u.Word[nIdx]) == FALSE)
          return E_OUTOFMEMORY;
        if (nIdx < 8)
        {
          if (cStrW.ConcatN(L":", 1) == FALSE)
            return E_OUTOFMEMORY;
        }
      }
      if (nIdx < 8)
      {
        if (cStrW.ConcatN(L"::", 2) == FALSE)
          return E_OUTOFMEMORY;
        while (nIdx < 8 && lpAddr->Ipv6.sin6_addr.u.Word[nIdx] == 0)
          nIdx++;
        while (nIdx < 7)
        {
          if (cStrW.AppendFormat(L"%04X:", lpAddr->Ipv6.sin6_addr.u.Word[nIdx]) == FALSE)
            return E_OUTOFMEMORY;
          nIdx++;
        }
        if (nIdx < 8)
        {
          if (cStrW.AppendFormat(L"%04X", lpAddr->Ipv6.sin6_addr.u.Word[nIdx]) == FALSE)
            return E_OUTOFMEMORY;
        }
      }
      if (cStrW.ConcatN(L"]", 1) == FALSE)
        return E_OUTOFMEMORY;
      break;

    default:
      return MX_E_Unsupported;
  }
  return S_OK;
}

}; //namespace MXHelpers
