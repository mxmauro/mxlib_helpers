/*
 * Copyright (C) 2014-2015 Mauro H. Leggieri, Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

#ifndef _RESOURCE_EXTRACT_H
#define _RESOURCE_EXTRACT_H

#include <Defines.h>
#include <Windows.h>
#include <MemoryStream.h>
#include <Strings\Strings.h>

//-----------------------------------------------------------

HRESULT ExtractResourceToFile(_In_ HINSTANCE hInst, _In_ LPCWSTR szResNameW, _In_ LPCWSTR szResTypeW,
                              _In_ HANDLE hFile);
HRESULT ExtractResourceToMemory(_In_ HINSTANCE hInst, _In_ LPCWSTR szResNameW, _In_ LPCWSTR szResTypeW,
                                _Outptr_result_maybenull_ LPBYTE *lplpDest, _Out_ SIZE_T *lpnDestSize);
HRESULT ExtractResourceToStream(_In_ HINSTANCE hInst, _In_ LPCWSTR szResNameW, _In_ LPCWSTR szResTypeW,
                                _COM_Outptr_opt_result_maybenull_ MX::CMemoryStream **lplpStream);

//-----------------------------------------------------------

#endif //_RESOURCE_EXTRACT_H
