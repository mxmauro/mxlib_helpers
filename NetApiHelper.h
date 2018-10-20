/*
* Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
* All rights reserved.
*
**/

#ifndef _NETAPI_HELPER_H
#define _NETAPI_HELPER_H

#include <Defines.h>
#include <Windows.h>
#include <objbase.h>
#include <lm.h>
#include "Sid.h"
#include <ArrayList.h>

//-----------------------------------------------------------

namespace NetApiHelper {

HRESULT GetAllUsers(_Inout_ MX::TArrayListWithFree<LPWSTR> &aUsersList);
HRESULT GetAllGroups(_Inout_ MX::TArrayListWithFree<LPWSTR> &aGroupsList);

}; //namespace NetApiHelper

//-----------------------------------------------------------

#endif //_NETAPI_HELPER_H
