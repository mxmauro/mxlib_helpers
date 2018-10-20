/*
* Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
* All rights reserved.
*
**/

#ifndef _MXLIBHLP_AUTO_COM_INITIALIZE_H
#define _MXLIBHLP_AUTO_COM_INITIALIZE_H

#include <Windows.h>
#include <Ole2.h>

//-----------------------------------------------------------

namespace MXHelpers {

class CAutoComInit
{
public:
  CAutoComInit()
    {
    hRes = ::CoInitializeEx(NULL, COINIT_MULTITHREADED);
    return;
    };

  ~CAutoComInit()
    {
    if (SUCCEEDED(hRes))
      ::CoUninitialize();
    return;
    };

  HRESULT InitResult() const
    {
    return (SUCCEEDED(hRes) || hRes == RPC_E_CHANGED_MODE) ? S_OK : hRes;
    };

private:
  HRESULT hRes;
};

}; //namespace MXHelpers

//-----------------------------------------------------------

#endif //_MXLIBHLP_AUTO_COM_INITIALIZE_H
