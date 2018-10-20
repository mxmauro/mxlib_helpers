/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#ifndef _CRASH_REPORT_H
#define _CRASH_REPORT_H

#include <Defines.h>

//-----------------------------------------------------------

namespace CrashReport {

VOID Initialize();
BOOL HandleCrashDump(_In_z_ LPCWSTR szModuleNameW);

}; //namespace CrashReport

//-----------------------------------------------------------

#endif //_CRASH_REPORT_H
