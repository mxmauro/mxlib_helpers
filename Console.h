/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#ifndef _MXLIBHLP_CONSOLE_H
#define _MXLIBHLP_CONSOLE_H

#include <Defines.h>

//-----------------------------------------------------------

namespace MX {

namespace Console {

typedef enum {
  ColorNormal, ColorError, ColorSuccess, ColorYellow, ColorBlue
} eColor;

}; //namespace Console

}; //namespace MX

//-----------------------------------------------------------

namespace MX {

namespace Console {

VOID Initialize(_In_ BOOL bAppIsInteractive);

VOID Print(_In_ eColor nColor, _In_ LPCWSTR szFormatW, ...);
VOID PrintError(_In_ HRESULT hRes);

}; //namespace Console

}; //namespace MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_CONSOLE_H
