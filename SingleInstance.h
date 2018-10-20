/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#ifndef _SINGLEINSTANCE_H
#define _SINGLEINSTANCE_H

#include <Defines.h>

//-----------------------------------------------------------

namespace SingleInstance {

HRESULT Check(_In_z_ LPCWSTR szNameW);

}; //namespace SingleInstance

//-----------------------------------------------------------

#endif //_SINGLEINSTANCE_H
