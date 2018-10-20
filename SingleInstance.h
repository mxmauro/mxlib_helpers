/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#ifndef _MXLIBHLP_SINGLEINSTANCE_H
#define _MXLIBHLP_SINGLEINSTANCE_H

#include <Defines.h>

//-----------------------------------------------------------

namespace MXHelpers {

HRESULT SingleInstanceCheck(_In_z_ LPCWSTR szNameW);

}; //namespace MXHelpers

//-----------------------------------------------------------

#endif //_MXLIBHLP_SINGLEINSTANCE_H
