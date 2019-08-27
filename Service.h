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

//-----------------------------------------------------------

namespace MX {

namespace Service {

typedef Callback<HRESULT (_In_ HANDLE hShutdownEvent, _In_ int argc, _In_ WCHAR* argv[],
                          _In_ BOOL bIsInteractiveApp)> OnStartCallback;
typedef Callback<HRESULT ()> OnStopCallback;

}; //namespace Service

}; //namespace MX

//-----------------------------------------------------------

namespace MX {

namespace Service {

HRESULT Run(_In_opt_z_ LPCWSTR szServiceNameW, _In_ OnStartCallback cStartCallback, _In_ OnStopCallback cStopCallback,
            _In_ int argc, _In_ WCHAR* argv[]);

VOID SignalStarting();
VOID SignalStopping();

VOID EnableStop();
VOID DisableStop();

}; //namespace Service

}; //namespace MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_SERVICE_H
