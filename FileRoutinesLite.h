/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#ifndef _FILE_ROUTINES_LITE_H
#define _FILE_ROUTINES_LITE_H

#include <Defines.h>
#include <Strings\Strings.h>
#include <ArrayList.h>

//-----------------------------------------------------------

namespace FileRoutinesLite {

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

HRESULT ResolveSymbolicLink(_Inout_ MX::CStringW &cStrPathW);

HRESULT ResolveChildProcessFileName(_Inout_ MX::CStringW &cStrFullNameW, _In_ LPCWSTR szApplicationNameW,
                                    _In_ LPCWSTR szCommandLineW);

HRESULT QueryEnvVariable(_In_z_ LPCWSTR szVarNameW, _Inout_ MX::CStringW &cStrDestW);

//Returned filename is in NT format
HRESULT GetFileNameFromHandle(_In_ HANDLE hFile, _Inout_ MX::CStringW &cStrFileNameW);

HRESULT OpenFileWithEscalatingSharing(_In_z_ LPCWSTR szFileNameW, _Out_ HANDLE *lphFile);

}; //FileRoutinesLite

//-----------------------------------------------------------

#endif //_FILE_ROUTINES_LITE_H
