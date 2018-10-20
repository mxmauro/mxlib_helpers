/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#ifndef _MXLIBHLP_MISCELLANEOUS_H
#define _MXLIBHLP_MISCELLANEOUS_H

#include <Defines.h>
#include <Strings\Strings.h>

//-----------------------------------------------------------

namespace MXHelpers {

BOOL WildcardMatch(_In_ LPCWSTR szTextW, _In_ SIZE_T nTextLen, _In_ LPCWSTR szPatternW, _In_ SIZE_T nPatternLen);

BOOL String2Guid(_Out_ GUID &sGuid, _In_z_ LPCSTR szGuidA);
BOOL String2Guid(_Out_ GUID &sGuid, _In_z_ LPCWSTR szGuidW);

HRESULT SelfDeleteApp();

}; //MXHelpers

//-----------------------------------------------------------

#endif //_MXLIBHLP_MISCELLANEOUS_H
