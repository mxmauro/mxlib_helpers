/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#ifndef _MXLIBHLP_SYSTEM_H
#define _MXLIBHLP_SYSTEM_H

#include <Defines.h>
#include <Strings\Strings.h>
#include <ArrayList.h>

//-----------------------------------------------------------

namespace MX {

namespace System {

HRESULT GetOpSystemInfo(_Out_ CStringW &cStrOpSystemW);

HRESULT _GetComputerNameEx(_In_ COMPUTER_NAME_FORMAT NameType, _Out_ CStringW &cStrNameW);

HRESULT LoadSystem32Dll(_In_z_ LPCWSTR szLibraryNameW, _Out_ HINSTANCE *lphInst);

VOID RegisterAppInRestartManager();

HRESULT GetAllUsers(_Inout_ TArrayListWithFree<LPWSTR> &aUsersList);
HRESULT GetAllGroups(_Inout_ TArrayListWithFree<LPWSTR> &aGroupsList);

}; //System

}; //MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_SYSTEM_H
