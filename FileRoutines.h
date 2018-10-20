/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#ifndef _MXLIBHLP_FILE_ROUTINES_H
#define _MXLIBHLP_FILE_ROUTINES_H

#include <Defines.h>
#include <Strings\Strings.h>
#include <ArrayList.h>

//-----------------------------------------------------------

namespace MXHelpers {

typedef enum {
  DontTryDeleteOnReboot,
  DeleteOnRebootOnFailure,
  WaitUntilReboot
} eDelayedDelete;

HRESULT GetAppFileName(_Inout_ MX::CStringW &cStrDestW);
HRESULT GetAppFolderPath(_Inout_ MX::CStringW &cStrDestW);

//IMPORTANT: Passed parameter should exists in entire app's life.
VOID SetAppDataFolder(_In_z_ LPCWSTR szSubFolderW);
HRESULT GetAppDataFolderPath(_Inout_ MX::CStringW &cStrDestW);

HRESULT GetCommonAppDataFolderPath(_Inout_ MX::CStringW &cStrDestW);
HRESULT GetWindowsPath(_Inout_ MX::CStringW &cStrDestW);
HRESULT GetWindowsSystemPath(_Inout_ MX::CStringW &cStrDestW);
HRESULT _GetTempPath(_Inout_ MX::CStringW &cStrDestW);

HRESULT CreateDirectoryRecursive(_In_ LPCWSTR szFolderNameW);
HRESULT RemoveDirectoryRecursive(_In_ LPCWSTR szFolderNameW, _In_opt_ eDelayedDelete nDD=DontTryDeleteOnReboot);

HRESULT _DeleteFile(_In_ LPCWSTR szFileNameW, _In_opt_ eDelayedDelete nDD=DontTryDeleteOnReboot);
HRESULT DeleteDirectoryFiles(_In_ LPCWSTR szFolderNameW, _In_opt_ eDelayedDelete nDD=DontTryDeleteOnReboot);

VOID NormalizePath(_Inout_ MX::CStringW &cStrPathW);

HRESULT ConvertToLongPath(_Inout_ MX::CStringW &cStrPathW);

HRESULT ConvertToNative(_Inout_ MX::CStringW &cStrPathW);
HRESULT ConvertToWin32(_Inout_ MX::CStringW &cStrPathW);
HRESULT DeviceName2DosName(_Inout_ MX::CStringW &cStrPathW);

HRESULT ResolveSymbolicLink(_Inout_ MX::CStringW &cStrPathW);

//Returned filename is in NT format
HRESULT GetFileNameFromHandle(_In_ HANDLE hFile, _Inout_ MX::CStringW &cStrFileNameW);

HRESULT OpenFileWithEscalatingSharing(_In_z_ LPCWSTR szFileNameW, _Out_ HANDLE *lphFile);

}; //MXHelpers

//-----------------------------------------------------------

#endif //_MXLIBHLP_FILE_ROUTINES_H
