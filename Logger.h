/*
* Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
* All rights reserved.
*
**/

#ifndef _MXLIBHLP_EVENT_LOGGER_H
#define _MXLIBHLP_EVENT_LOGGER_H

#include <Defines.h>
#include <Windows.h>
#include <AutoHandle.h>
#include <Strings\Strings.h>

//-----------------------------------------------------------

namespace MX {

namespace EventLogger {

HRESULT Initialize(_In_z_ LPCWSTR szModuleNameW, _In_z_ LPCWSTR szRegistryKeyW, _In_z_ LPCWSTR szRegistryValueW,
                   _In_ DWORD dwDefaultKeepDays);

HRESULT Log(_Printf_format_string_ LPCWSTR szFormatW, ...);
HRESULT LogIfError(_In_ HRESULT hResError, _Printf_format_string_ LPCWSTR szFormatW, ...);
HRESULT LogAlways(_In_ HRESULT hResError, _Printf_format_string_ LPCWSTR szFormatW, ...);
HRESULT LogRaw(_In_z_ LPCWSTR szTextW);

HRESULT GetLogFolder(_Out_ CStringW &cStrLogFolderW);

}; //namespace EventLogger

}; //namespace MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_EVENT_LOGGER_H
