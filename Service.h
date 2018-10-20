/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#ifndef _SERVICE_H
#define _SERVICE_H

#include <Defines.h>
#include <Callbacks.h>

//-----------------------------------------------------------

namespace Service {

typedef MX::Callback<HRESULT (_In_ HANDLE hShutdownEvent, _In_ int argc, _In_ WCHAR* argv[],
                              _In_ BOOL bIsInteractiveApp)> OnStartCallback;
typedef MX::Callback<HRESULT ()> OnStopCallback;

HRESULT Run(_In_opt_z_ LPCWSTR szServiceNameW, _In_ OnStartCallback cStartCallback, _In_ OnStopCallback cStopCallback,
            _In_ int argc, _In_ WCHAR* argv[]);

VOID SignalStarting();
VOID SignalStopping();

VOID EnableStop();
VOID DisableStop();

}; //namespace Service

//-----------------------------------------------------------

#endif //_SERVICE_H
