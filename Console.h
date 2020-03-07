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
#ifndef _MXLIBHLP_CONSOLE_H
#define _MXLIBHLP_CONSOLE_H

#include <Defines.h>

//-----------------------------------------------------------

namespace MX {

namespace Console {

typedef enum {
  ColorNormal, ColorError, ColorSuccess, ColorYellow, ColorBlue
} eColor;

}; //namespace Console

}; //namespace MX

//-----------------------------------------------------------

namespace MX {

namespace Console {

VOID Initialize(_In_ BOOL bAppIsInteractive);

VOID Print(_In_ Console::eColor nColor, _In_ LPCWSTR szFormatW, ...);
VOID PrintError(_In_ HRESULT hRes);

}; //namespace Console

}; //namespace MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_CONSOLE_H
