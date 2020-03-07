/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the LICENSE file distributed with
 * this work for additional information regarding copyright ownership.
 *
 * Also, if exists, check the Licenses directory for information about
 * third-party modules.
 *
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
#if defined(_M_X64)
HRESULT GetProgramFilesX86FolderPath(_Out_ CStringW &cStrDestW);
#endif //_M_X64

HRESULT GetWindowsPath(_Out_ CStringW &cStrDestW);
HRESULT GetWindowsSystemPath(_Out_ CStringW &cStrDestW);
#if defined(_M_X64)
HRESULT GetWindowsSysWow64Path(_Out_ CStringW &cStrDestW);
#endif //_M_X64

HRESULT _GetTempPath(_Out_ CStringW &cStrDestW);

HRESULT CreateDirectoryRecursive(_In_ LPCWSTR szFolderNameW);
HRESULT RemoveDirectoryRecursive(_In_ LPCWSTR szFolderNameW,
                                 _In_opt_ FileRoutines::eDelayedDelete nDD = FileRoutines::DontTryDeleteOnReboot);

HRESULT _DeleteFile(_In_ LPCWSTR szFileNameW,
                    _In_opt_ FileRoutines::eDelayedDelete nDD = FileRoutines::DontTryDeleteOnReboot);
HRESULT DeleteDirectoryFiles(_In_ LPCWSTR szFolderNameW,
                             _In_opt_ FileRoutines::eDelayedDelete nDD = FileRoutines::DontTryDeleteOnReboot);

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
