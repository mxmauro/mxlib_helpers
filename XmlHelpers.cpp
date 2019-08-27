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
#include "XmlHelpers.h"
#include <Strings\Utf8.h>

//-----------------------------------------------------------

namespace MX {

namespace XmlHelpers {

HRESULT Parse(_In_ tinyxml2::XMLDocument &cDoc, _In_ LPCVOID lpData, _In_ SIZE_T nDataLen)
{
  try
  {
    if (cDoc.Parse((char*)lpData, nDataLen) != tinyxml2::XML_SUCCESS)
      return MX_E_InvalidData;
  }
  catch (...)
  {
    return MX_E_InvalidData;
  }
  return S_OK;
}

BOOL ToString(_In_ tinyxml2::XMLDocument &cDoc, _Inout_ MX::CStringA &cStrA, _In_opt_ BOOL bAppend)
{
  tinyxml2::XMLPrinter cStream(NULL, false);
  LPCSTR sA;

  try
  {
    cDoc.Print(&cStream);
  }
  catch (...)
  {
    return FALSE;
  }
  //get data
  sA = cStream.CStr();
  if (sA[0] == 0xEF && sA[1] == 0xBB && sA[2] == 0xBF)
    sA += 3;
  return (bAppend == FALSE) ? cStrA.Copy(sA) : cStrA.Concat(sA);
}

tinyxml2::XMLElement* NewElement(_In_ tinyxml2::XMLDocument &cDoc, _In_z_ LPCSTR szNameA)
{
  tinyxml2::XMLElement *lpXmlElem;

  if (szNameA == NULL || *szNameA == 0)
    return NULL;
  try
  {
    lpXmlElem = cDoc.NewElement(szNameA);
  }
  catch (...)
  {
    lpXmlElem = NULL;
  }
  return lpXmlElem;
}

tinyxml2::XMLText* NewText(_In_ tinyxml2::XMLDocument &cDoc, _In_z_ LPCSTR szValueA, _In_opt_ SIZE_T nValueLen)
{
  tinyxml2::XMLText *lpXmlText = NULL;

  if (szValueA == NULL)
    return NULL;
  try
  {
    if (nValueLen == (SIZE_T)-1)
    {
      lpXmlText = cDoc.NewText(szValueA);
    }
    else
    {
      MX::CStringA cStrTempA;

      if (cStrTempA.CopyN(szValueA, nValueLen) != FALSE)
        lpXmlText = cDoc.NewText((LPCSTR)cStrTempA);
    }
  }
  catch (...)
  {
    lpXmlText = NULL;
  }
  return lpXmlText;
}

tinyxml2::XMLText* NewText(_In_ tinyxml2::XMLDocument &cDoc, _In_z_ LPCWSTR szValueW, _In_opt_ SIZE_T nValueLen)
{
  MX::CStringA cStrTempA;
  HRESULT hRes;

  if (szValueW == NULL)
    return NULL;
  if (nValueLen == (SIZE_T)-1)
    nValueLen = MX::StrLenW(szValueW);
  hRes = MX::Utf8_Encode(cStrTempA, szValueW, nValueLen);
  return (SUCCEEDED(hRes)) ? NewText(cDoc, (LPCSTR)cStrTempA) : NULL;
}

BOOL SetElementAttribute(_In_ tinyxml2::XMLElement &cElem, _In_ LPCSTR szNameA, _In_ LPCSTR szValueA)
{
  if (szNameA == NULL || *szNameA == 0)
    return FALSE;
  if (szValueA == NULL)
    szValueA = "";
  try
  {
    cElem.SetAttribute(szNameA, szValueA);
  }
  catch (...)
  {
    return FALSE;
  }
  return TRUE;
}

int ParseBoolean(_In_ LPCSTR szValueA)
{
  if (szValueA == NULL || *szValueA == 0)
    return 0;
  if (strcmp(szValueA, "0") == 0 || _stricmp(szValueA, "false") == 0 || _stricmp(szValueA, "no") == 0)
    return 0;
  if (strcmp(szValueA, "1") == 0 || _stricmp(szValueA, "true") == 0 || _stricmp(szValueA, "yes") == 0)
    return 1;
  return -1;
}

}; //namespace XmlHelpers

}; //namespace MX
