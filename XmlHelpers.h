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
#ifndef _MXLIBHLP_XML_H
#define _MXLIBHLP_XML_H

#include <Defines.h>
#include <Strings\Strings.h>
#include <tinyxml2.h>

//-----------------------------------------------------------

namespace MX {

namespace XmlHelpers {

HRESULT Parse(_In_ tinyxml2::XMLDocument &cDoc, _In_ LPCVOID lpData, _In_ SIZE_T nDataLen);

BOOL ToString(_In_ tinyxml2::XMLDocument &cDoc, _Inout_ MX::CStringA &cStrA, _In_opt_ BOOL bAppend=FALSE);

tinyxml2::XMLElement* NewElement(_In_ tinyxml2::XMLDocument &cDoc, _In_z_ LPCSTR szNameA);
tinyxml2::XMLText* NewText(_In_ tinyxml2::XMLDocument &cDoc, _In_z_ LPCSTR szValueA,
                           _In_opt_ SIZE_T nValueLen=(SIZE_T)-1);
tinyxml2::XMLText* NewText(_In_ tinyxml2::XMLDocument &cDoc, _In_z_ LPCWSTR szValueW,
                           _In_opt_ SIZE_T nValueLen=(SIZE_T)-1);

BOOL SetElementAttribute(_In_ tinyxml2::XMLElement &cElem, _In_ LPCSTR szNameA, _In_ LPCSTR szValueA);

int ParseBoolean(_In_ LPCSTR szValueA);

}; //namespace XmlHelpers

}; //namespace MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_XML_H
