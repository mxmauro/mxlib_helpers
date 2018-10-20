/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#ifndef _MXLIBHLP_CRASH_REPORT_H
#define _MXLIBHLP_CRASH_REPORT_H

#include <Defines.h>

//-----------------------------------------------------------

namespace MXHelpers {

namespace CrashReport {

VOID Initialize();
BOOL HandleCrashDump(_In_z_ LPCWSTR szModuleNameW);

}; //namespace CrashReport

}; //namespace MXHelpers

//-----------------------------------------------------------

#endif //_MXLIBHLP_CRASH_REPORT_H
