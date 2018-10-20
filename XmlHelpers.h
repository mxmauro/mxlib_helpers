/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#ifndef _MXLIBHLP_XML_H
#define _MXLIBHLP_XML_H

#include <Defines.h>
#include <Strings\Strings.h>
#include <tinyxml2.h>

//-----------------------------------------------------------

namespace MXHelpers {

namespace Xml {

HRESULT Parse(_In_ tinyxml2::XMLDocument &cDoc, _In_ LPCVOID lpData, _In_ SIZE_T nDataLen);

BOOL ToString(_In_ tinyxml2::XMLDocument &cDoc, _Inout_ MX::CStringA &cStrA, _In_opt_ BOOL bAppend=FALSE);

tinyxml2::XMLElement* NewElement(_In_ tinyxml2::XMLDocument &cDoc, _In_z_ LPCSTR szNameA);
tinyxml2::XMLText* NewText(_In_ tinyxml2::XMLDocument &cDoc, _In_z_ LPCSTR szValueA,
                           _In_opt_ SIZE_T nValueLen=(SIZE_T)-1);
tinyxml2::XMLText* NewText(_In_ tinyxml2::XMLDocument &cDoc, _In_z_ LPCWSTR szValueW,
                           _In_opt_ SIZE_T nValueLen=(SIZE_T)-1);

BOOL SetElementAttribute(_In_ tinyxml2::XMLElement &cElem, _In_ LPCSTR szNameA, _In_ LPCSTR szValueA);

int ParseBoolean(_In_ LPCSTR szValueA);

}; //namespace Xml

}; //namespace MXHelpers

//-----------------------------------------------------------

#endif //_MXLIBHLP_XML_H
