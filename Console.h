/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#ifndef _MXLIBHLP_CONSOLE_H
#define _MXLIBHLP_CONSOLE_H

#include <Defines.h>

//-----------------------------------------------------------

namespace MXHelpers {

typedef enum {
  ccNormal, ccError, ccSuccess, ccYellow, ccBlue
} eConsoleColor;

}; //namespace MXHelpers

//-----------------------------------------------------------

namespace MXHelpers {

namespace Console {

VOID Initialize(_In_ BOOL bAppIsInteractive);

VOID Print(_In_ eConsoleColor nColor, _In_ LPCWSTR szFormatW, ...);
VOID PrintError(_In_ HRESULT hRes);

}; //namespace Console

}; //namespace MXHelpers

//-----------------------------------------------------------

#endif //_MXLIBHLP_CONSOLE_H
