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

namespace MXHelpers {

HRESULT GetOpSystemInfo(_Out_ MX::CStringW &cStrOpSystemW);

HRESULT _GetComputerNameEx(_In_ COMPUTER_NAME_FORMAT NameType, _Out_ MX::CStringW &cStrNameW);

VOID RegisterAppInRestartManager();

HRESULT GetAllUsers(_Inout_ MX::TArrayListWithFree<LPWSTR> &aUsersList);
HRESULT GetAllGroups(_Inout_ MX::TArrayListWithFree<LPWSTR> &aGroupsList);

}; //MXHelpers

//-----------------------------------------------------------

#endif //_MXLIBHLP_SYSTEM_H
