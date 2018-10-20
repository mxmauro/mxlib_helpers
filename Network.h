/*
* Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
* All rights reserved.
*
**/

#ifndef _MXLIBHLP_NETWORK_H
#define _MXLIBHLP_NETWORK_H

#include <Defines.h>
#include <ArrayList.h>
#include <WinSock2.h>
#include <ws2ipdef.h>
#include <Strings\Strings.h>

namespace MXHelpers {

typedef enum {
  LocalIpAddressesFlagsDontAddIpV4 = 1,
  LocalIpAddressesFlagsDontAddIpV6 = 2,
  LocalIpAddressesFlagsDontAddNetbiosName = 4
} eGetLocalIpAddressesFlags;

}; //namespace MXHelpers

//-----------------------------------------------------------

namespace MXHelpers {

HRESULT GetLocalIpAddresses(_Out_ MX::TArrayListWithFree<LPCWSTR> &cStrListW, _In_ int nFlags);
HRESULT FormatIpAddress(_Out_ MX::CStringW &cStrW, _In_ PSOCKADDR_INET lpAddr);

}; //namespace MXHelpers

//-----------------------------------------------------------

#endif //_MXLIBHLP_NETWORK_H
