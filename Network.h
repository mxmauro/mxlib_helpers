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
#ifndef _MXLIBHLP_NETWORK_H
#define _MXLIBHLP_NETWORK_H

#include <Defines.h>
#include <ArrayList.h>
#include <WinSock2.h>
#include <ws2ipdef.h>
#include <Strings\Strings.h>

//-----------------------------------------------------------

namespace MX {

namespace Network {

enum class eLocalIpAddressesFlags
{
  DontAddIpV4 = 1,
  DontAddIpV6 = 2,
  DontAddNetbiosName = 4
};

inline eLocalIpAddressesFlags operator|(eLocalIpAddressesFlags lhs, eLocalIpAddressesFlags rhs)
{
  return static_cast<eLocalIpAddressesFlags>(static_cast<int>(lhs) | static_cast<int>(rhs));
}

inline eLocalIpAddressesFlags operator&(eLocalIpAddressesFlags lhs, eLocalIpAddressesFlags rhs)
{
  return static_cast<eLocalIpAddressesFlags>(static_cast<int>(lhs) & static_cast<int>(rhs));
}

}; //namespace Network

}; //namespace MX

//-----------------------------------------------------------

namespace MX {

namespace Network {

HRESULT GetLocalIpAddresses(_Out_ TArrayListWithFree<LPCWSTR> &cStrListW, _In_ eLocalIpAddressesFlags nFlags);
HRESULT FormatIpAddress(_Out_ CStringW &cStrW, _In_ PSOCKADDR_INET lpAddr);

}; //namespace Network

}; //namespace MX


//-----------------------------------------------------------

#endif //_MXLIBHLP_NETWORK_H
