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
#ifndef _MXLIBHLP_CRASH_REPORT_H
#define _MXLIBHLP_CRASH_REPORT_H

#include <Defines.h>

//-----------------------------------------------------------

namespace MX {

namespace CrashReport {

VOID Initialize();
BOOL HandleCrashDump(_In_z_ LPCWSTR szApplicationNameW, _In_z_ LPCWSTR szModuleNameW);

}; //namespace CrashReport

}; //namespace MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_CRASH_REPORT_H
