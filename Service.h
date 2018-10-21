/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#ifndef _MXLIBHLP_SERVICE_H
#define _MXLIBHLP_SERVICE_H

#include <Defines.h>
#include <Callbacks.h>

//-----------------------------------------------------------

namespace MX {

namespace Service {

typedef Callback<HRESULT (_In_ HANDLE hShutdownEvent, _In_ int argc, _In_ WCHAR* argv[],
                          _In_ BOOL bIsInteractiveApp)> OnStartCallback;
typedef Callback<HRESULT ()> OnStopCallback;

}; //namespace Service

}; //namespace MX

//-----------------------------------------------------------

namespace MX {

namespace Service {

HRESULT Run(_In_opt_z_ LPCWSTR szServiceNameW, _In_ OnStartCallback cStartCallback, _In_ OnStopCallback cStopCallback,
            _In_ int argc, _In_ WCHAR* argv[]);

VOID SignalStarting();
VOID SignalStopping();

VOID EnableStop();
VOID DisableStop();

}; //namespace Service

}; //namespace MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_SERVICE_H
