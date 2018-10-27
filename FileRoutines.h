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

namespace MX {

namespace FileRoutines {

typedef enum {
  DontTryDeleteOnReboot,
  DeleteOnRebootOnFailure,
  WaitUntilReboot
} eDelayedDelete;

}; //namespace FileRoutines

}; //namespace MX

//-----------------------------------------------------------

namespace MX {

namespace FileRoutines {

HRESULT GetAppFileName(_Out_ CStringW &cStrDestW);
HRESULT GetAppFolderPath(_Out_ CStringW &cStrDestW);

//IMPORTANT: Passed parameter should exists in entire app's life.
VOID SetAppDataFolder(_In_z_ LPCWSTR szSubFolderW);
HRESULT GetAppDataFolderPath(_Out_ CStringW &cStrDestW);

HRESULT GetCommonAppDataFolderPath(_Out_ CStringW &cStrDestW);
HRESULT GetProgramFilesFolderPath(_Out_ CStringW &cStrDestW);

HRESULT GetWindowsPath(_Out_ CStringW &cStrDestW);
HRESULT GetWindowsSystemPath(_Out_ CStringW &cStrDestW);
HRESULT _GetTempPath(_Out_ CStringW &cStrDestW);

HRESULT CreateDirectoryRecursive(_In_ LPCWSTR szFolderNameW);
HRESULT RemoveDirectoryRecursive(_In_ LPCWSTR szFolderNameW, _In_opt_ eDelayedDelete nDD=DontTryDeleteOnReboot);

HRESULT _DeleteFile(_In_ LPCWSTR szFileNameW, _In_opt_ eDelayedDelete nDD=DontTryDeleteOnReboot);
HRESULT DeleteDirectoryFiles(_In_ LPCWSTR szFolderNameW, _In_opt_ eDelayedDelete nDD=DontTryDeleteOnReboot);

VOID NormalizePath(_Inout_ CStringW &cStrPathW);

HRESULT ConvertToLongPath(_Inout_ CStringW &cStrPathW);

HRESULT ConvertToNative(_Inout_ CStringW &cStrPathW);
HRESULT ConvertToWin32(_Inout_ CStringW &cStrPathW);
HRESULT DeviceName2DosName(_Inout_ CStringW &cStrPathW);

HRESULT ResolveSymbolicLink(_Inout_ CStringW &cStrPathW);

//Returned filename is in NT format
HRESULT GetFileNameFromHandle(_In_ HANDLE hFile, _Out_ CStringW &cStrFileNameW);

HRESULT OpenFileWithEscalatingSharing(_In_z_ LPCWSTR szFileNameW, _Out_ HANDLE *lphFile);

}; //namespace FileRoutines

}; //namespace MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_FILE_ROUTINES_H
