/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#ifndef _MXLIBHLP_REGISTRY_CHANGE_MONITOR_H
#define _MXLIBHLP_REGISTRY_CHANGE_MONITOR_H

#include <Defines.h>
#include <Windows.h>
#include <Threads.h>
#include <Callbacks.h>
#include <Strings\Strings.h>

//-----------------------------------------------------------

namespace MX {

class CRegistryChangeMonitor : public CBaseMemObj
{
public:
  typedef Callback<VOID(_In_ LPVOID lpUserParam)> OnRegistryChangedCallback;

public:
  CRegistryChangeMonitor();
  ~CRegistryChangeMonitor();

  HRESULT Start(_In_ HKEY hRootKey, _In_z_ LPCWSTR szSubkeyW, _In_ BOOL bWatchSubtree,
                _In_ OnRegistryChangedCallback cCallback, _In_opt_ LPVOID lpUserParam = NULL);
  VOID Stop();

private:
  VOID WorkerThread();

private:
  HKEY hRootKey;
  CStringW cStrSubKeyW;
  BOOL bWatchSubtree;
  HANDLE hEvent;
  OnRegistryChangedCallback cCallback;
  LPVOID lpUserParam;
  TClassWorkerThread<CRegistryChangeMonitor> cWorkerThread;
};

}; //namespace MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_REGISTRY_CHANGE_MONITOR_H
