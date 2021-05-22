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
#ifndef _MXLIBHLP_SERVICE_H
#define _MXLIBHLP_SERVICE_H

#include <Defines.h>
#include <Callbacks.h>
#include <Dbt.h>

//-----------------------------------------------------------

namespace MX {

namespace Service {

typedef Callback<HRESULT (_In_ int argc, _In_ WCHAR* argv[])> OnStartCallback;
typedef Callback<HRESULT ()> OnStopCallback;
typedef Callback<VOID (_In_ DWORD dwEventType, _In_ PDEV_BROADCAST_HDR lpDevBroadcastHdr)> OnDeviceChangeCallback;

}; //namespace Service

}; //namespace MX

//-----------------------------------------------------------

namespace MX {

namespace Service {

HRESULT Run(_In_opt_z_ LPCWSTR szServiceNameW, _In_ OnStartCallback cStartCallback, _In_ OnStopCallback cStopCallback,
            _In_opt_ OnDeviceChangeCallback cDeviceChangeCallback, _In_ int argc, _In_ WCHAR* argv[]);

VOID SignalShutdown();

VOID SignalStarting();
VOID SignalStopping();

VOID EnableStop();
VOID DisableStop();

BOOL IsInteractive();

}; //namespace Service

}; //namespace MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_SERVICE_H
