#include "AutoComInit.h"

//-----------------------------------------------------------

CAutoComInit::CAutoComInit()
{
  hRes = ::CoInitializeEx(NULL, COINIT_MULTITHREADED);
  return;
}

CAutoComInit::~CAutoComInit()
{
  if (SUCCEEDED(hRes))
    ::CoUninitialize();
  return;
}

HRESULT CAutoComInit::InitResult() const
{
  return (SUCCEEDED(hRes) || hRes == RPC_E_CHANGED_MODE) ? S_OK : hRes;
}
