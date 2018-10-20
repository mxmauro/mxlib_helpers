/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#ifndef _CONSOLE_H
#define _CONSOLE_H

#include <Defines.h>

//-----------------------------------------------------------

typedef enum {
  ccNormal, ccError, ccSuccess, ccYellow, ccBlue
} eConsoleColor;

//-----------------------------------------------------------

namespace Console {

VOID Initialize(_In_ BOOL bAppIsInteractive);

VOID Print(_In_ eConsoleColor nColor, _In_ LPCWSTR szFormatW, ...);
VOID PrintError(_In_ HRESULT hRes);

}; //namespace Console

//-----------------------------------------------------------

#endif //_CONSOLE_H
