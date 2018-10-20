/*
* Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
* All rights reserved.
*
**/

#ifndef _AUTO_COM_INITIALIZE_H
#define _AUTO_COM_INITIALIZE_H

#include <Windows.h>
#include <Ole2.h>

//-----------------------------------------------------------

class CAutoComInit
{
public:
  CAutoComInit();
  ~CAutoComInit();

  HRESULT InitResult() const;

private:
  HRESULT hRes;
};

//-----------------------------------------------------------

#endif //_AUTO_COM_INITIALIZE_H
