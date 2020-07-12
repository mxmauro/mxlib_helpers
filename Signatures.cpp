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
#include "Signatures.h"
#include "FileRoutines.h"
#include "System.h"
#include <Strings\Strings.h>
#include <Crypto\MessageDigest.h>
#include <appmodel.h>
#include <WinTrust.h>
#include <mscat.h>
#include <VersionHelpers.h>
#include <Finalizer.h>
#include <AutoHandle.h>
#include <AutoPtr.h>
#include "FileVersionInfo.h"

//-----------------------------------------------------------

#define READ_RETRIES_COUNT                               200
#define READ_RETRIES_DELAY_MS                             15

#define MAX_FILE_SIZE_FOR_CATALOG_CHECK  100ui64*1048576ui64

#define MAX_CACHED_ITEMS                                8192

#define X_CHAR_ENC(_x,_y)   (CHAR)((  (BYTE)(_x)) ^ (  (BYTE)_y+0xB3))
#define X_WCHAR_ENC(_x,_y) (WCHAR)(((USHORT)(_x)) ^ ((USHORT)_y+0x2CE3))

#define _EXPAND_A(str)                       \
    i = 0; do                                \
    { szTempA[i] = X_CHAR_ENC(str[i], i); }  \
    while (szTempA[i++] != 0)
#define _EXPAND_W(str)                       \
    i = 0; do                                \
    { szTempW[i] = X_WCHAR_ENC(str[i], i); } \
    while (szTempW[i++] != 0)

#define __ALLOCATION_GRANULARITY                       65536

#define ViewShare 1

//-----------------------------------------------------------

#pragma pack(8)
typedef struct {
  DWORD           cbStruct;               // = sizeof(WINTRUST_CATALOG_INFO)
  DWORD           dwCatalogVersion;       // optional: Catalog version number
  LPCWSTR         pcwszCatalogFilePath;   // required: path/name to Catalog file
  LPCWSTR         pcwszMemberTag;         // optional: tag to member in Catalog
  LPCWSTR         pcwszMemberFilePath;    // required: path/name to member file
  HANDLE          hMemberFile;            // optional: open handle to pcwszMemberFilePath
  _Field_size_(cbCalculatedFileHash) BYTE            *pbCalculatedFileHash;  // optional: pass in the calculated hash
  DWORD           cbCalculatedFileHash;   // optional: pass in the count bytes of the calc hash
  PCCTL_CONTEXT   pcCatalogContext;       // optional: pass in to use instead of CatalogFilePath.
  HCATADMIN       hCatAdmin;              // optional for SHA-1 hashes, required for all other hash types.
} ___WINTRUST_CATALOG_INFO;
#pragma pack()

typedef struct {
  WORD wFileVersion[4];
  WORD wProductVersion[4];
} __DLL_VERSION;

//-----------------------------------------------------------

typedef LONG (WINAPI *lpfnWinVerifyTrustEx)(_In_ HWND hwnd, _In_ GUID *pgActionID, _In_ LPVOID pWVTData);
typedef CRYPT_PROVIDER_DATA* (WINAPI *lpfnWTHelperProvDataFromStateData)(_In_ HANDLE hStateData);
typedef CRYPT_PROVIDER_SGNR* (WINAPI *lpfnWTHelperGetProvSignerFromChain)(_In_ CRYPT_PROVIDER_DATA *pProvData,
                                                  _In_ DWORD idxSigner, _In_ BOOL fCounterSigner,
                                                  _In_ DWORD idxCounterSigner);
typedef DWORD (WINAPI *lpfnCertGetNameStringW)(_In_ PCCERT_CONTEXT pCertContext, _In_ DWORD dwType, _In_ DWORD dwFlags,
                                               _In_opt_ void *pvTypePara, _Out_ LPWSTR pszNameString,
                                               _In_ DWORD cchNameString);
typedef PCCERT_CONTEXT (WINAPI *lpfnCertDuplicateCertificateContext)(_In_opt_ PCCERT_CONTEXT pCertContext);
typedef BOOL (WINAPI *lpfnCertFreeCertificateContext)(_In_opt_ PCCERT_CONTEXT pCertContext);
typedef LONG (WINAPI *lpfnGetPackageFullName)(_In_ HANDLE hProcess, _Inout_ UINT32 *packageFullNameLength,
                                              _Out_opt_ PWSTR packageFullName);
typedef LONG (WINAPI *lpfnGetPackagePath)(_In_ PACKAGE_ID *packageId, _Reserved_ UINT32 reserved,
                                          _Inout_ UINT32 *pathLength, _Out_opt_ PWSTR path);
typedef LONG (WINAPI *lpfnPackageIdFromFullName)(_In_ PCWSTR packageFullName, _In_ UINT32 flags,
                                                 _Inout_ UINT32 *bufferLength, _Out_opt_ BYTE *buffer);
typedef BOOL (WINAPI *lpfnCryptCATAdminAcquireContext)(_Out_ HCATADMIN *phCatAdmin, _In_opt_ const GUID *pgSubsystem,
                                                       _Reserved_ DWORD dwFlags);
typedef BOOL (WINAPI *lpfnCryptCATAdminAcquireContext2)(_Out_ HCATADMIN *phCatAdmin, _In_opt_ const GUID *pgSubsystem,
                                                        _In_opt_ PCWSTR pwszHashAlgorithm,
                                                        _In_opt_ PCCERT_STRONG_SIGN_PARA pStrongHashPolicy,
                                                        _Reserved_ DWORD dwFlags);
typedef BOOL (WINAPI *lpfnCryptCATAdminCalcHashFromFileHandle)(_In_ HANDLE hFile, _Inout_ DWORD *pcbHash,
                                                       _Out_writes_bytes_to_opt_(*pcbHash, *pcbHash) BYTE *pbHash,
                                                       _Reserved_ DWORD dwFlags);
typedef BOOL (WINAPI *lpfnCryptCATAdminCalcHashFromFileHandle2)(_In_ HCATADMIN hCatAdmin, _In_ HANDLE hFile,
                                                       _Inout_ DWORD *pcbHash,
                                                       _Out_writes_bytes_to_opt_(*pcbHash, *pcbHash) BYTE *pbHash,
                                                       _Reserved_ DWORD dwFlags);
typedef HCATINFO (WINAPI *lpfnCryptCATAdminEnumCatalogFromHash)(_In_ HCATADMIN hCatAdmin,
                                                                _In_reads_bytes_(cbHash) BYTE *pbHash,
                                                                _In_ DWORD cbHash, _Reserved_ DWORD dwFlags,
                                                                _Inout_opt_ HCATINFO *phPrevCatInfo);
typedef BOOL (WINAPI *lpfnCryptCATAdminReleaseContext)(_In_ HCATADMIN hCatAdmin, _In_ DWORD dwFlags);
typedef BOOL (WINAPI *lpfnCryptCATCatalogInfoFromContext)(_In_ HCATINFO hCatInfo, _Inout_ CATALOG_INFO *psCatInfo,
                                                          _In_ DWORD dwFlags);
typedef BOOL (WINAPI *lpfnCryptCATAdminReleaseCatalogContext)(_In_ HCATADMIN hCatAdmin, _In_ HCATINFO hCatInfo,
                                                              _In_ DWORD dwFlags);

//-----------------------------------------------------------

static GUID sWVTPolicyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
static GUID sDriverActionVerify = DRIVER_ACTION_VERIFY;

static HINSTANCE hCrypt32Dll = NULL;
static HINSTANCE hWinTrustDll = NULL;
static __DLL_VERSION sCrypt32DllVersion = { 0 };
static __DLL_VERSION sWinTrustDllVersion = { 0 };

static lpfnWinVerifyTrustEx fnWinVerifyTrustEx = NULL;
static lpfnWTHelperProvDataFromStateData fnWTHelperProvDataFromStateData = NULL;
static lpfnWTHelperGetProvSignerFromChain fnWTHelperGetProvSignerFromChain = NULL;
static lpfnCertGetNameStringW fnCertGetNameStringW = NULL;
static lpfnCertDuplicateCertificateContext fnCertDuplicateCertificateContext = NULL;
static lpfnCertFreeCertificateContext fnCertFreeCertificateContext = NULL;
static lpfnGetPackageFullName fnGetPackageFullName = NULL;
static lpfnGetPackagePath fnGetPackagePath = NULL;
static lpfnPackageIdFromFullName fnPackageIdFromFullName = NULL;
static lpfnCryptCATAdminAcquireContext fnCryptCATAdminAcquireContext = NULL;
static lpfnCryptCATAdminAcquireContext2 fnCryptCATAdminAcquireContext2 = NULL;
static lpfnCryptCATAdminCalcHashFromFileHandle fnCryptCATAdminCalcHashFromFileHandle = NULL;
static lpfnCryptCATAdminCalcHashFromFileHandle2 fnCryptCATAdminCalcHashFromFileHandle2 = NULL;
static lpfnCryptCATAdminEnumCatalogFromHash fnCryptCATAdminEnumCatalogFromHash = NULL;
static lpfnCryptCATAdminReleaseContext fnCryptCATAdminReleaseContext = NULL;
static lpfnCryptCATCatalogInfoFromContext fnCryptCATCatalogInfoFromContext = NULL;
static lpfnCryptCATAdminReleaseCatalogContext fnCryptCATAdminReleaseCatalogContext = NULL;

//-----------------------------------------------------------

static BOOL IsWinVistaPlus();

static VOID EndSignaturesAndInfo();

static HRESULT DoTrustVerification(_In_opt_z_ LPCWSTR szPeFileNameW, _In_opt_ HANDLE hFile, _In_ LPGUID lpActionId,
                                   _In_opt_ PWINTRUST_CATALOG_INFO lpCatalogInfo, _Out_ PCERT_CONTEXT *lplpCertCtx,
                                   _Out_ PFILETIME lpTimeStamp);

static HRESULT CheckKnownExploits(_In_ PCCERT_CONTEXT pCert, _In_ HRESULT hOriginalRes);
static int CompareVersion(_In_ LPWORD lpwVersion, _In_ WORD wMajor, _In_ WORD wMinor, _In_ WORD wRelease,
                          _In_ WORD wBuild);

//-----------------------------------------------------------

namespace MX {

namespace Signatures {

HRESULT Initialize()
{
  static const WCHAR strW_WinTrustDll[] = {
    X_WCHAR_ENC(L'w',  0), X_WCHAR_ENC(L'i',  1), X_WCHAR_ENC(L'n',  2), X_WCHAR_ENC(L't',  3),
    X_WCHAR_ENC(L'r',  4), X_WCHAR_ENC(L'u',  5), X_WCHAR_ENC(L's',  6), X_WCHAR_ENC(L't',  7),
    X_WCHAR_ENC(L'.',  8), X_WCHAR_ENC(L'd',  9), X_WCHAR_ENC(L'l', 10), X_WCHAR_ENC(L'l', 11),
    X_WCHAR_ENC(0,    12)
  };
  static const CHAR strA_WinVerifyTrustEx[] = {
    X_CHAR_ENC('W',  0), X_CHAR_ENC('i',  1), X_CHAR_ENC('n',  2), X_CHAR_ENC('V',  3),
    X_CHAR_ENC('e',  4), X_CHAR_ENC('r',  5), X_CHAR_ENC('i',  6), X_CHAR_ENC('f',  7),
    X_CHAR_ENC('y',  8), X_CHAR_ENC('T',  9), X_CHAR_ENC('r', 10), X_CHAR_ENC('u', 11),
    X_CHAR_ENC('s', 12), X_CHAR_ENC('t', 13), X_CHAR_ENC('E', 14), X_CHAR_ENC('x', 15),
    X_CHAR_ENC(0,   16)
  };
  static const CHAR strA_WTHelperProvDataFromStateData[] = {
    X_CHAR_ENC('W',  0), X_CHAR_ENC('T',  1), X_CHAR_ENC('H',  2), X_CHAR_ENC('e',  3),
    X_CHAR_ENC('l',  4), X_CHAR_ENC('p',  5), X_CHAR_ENC('e',  6), X_CHAR_ENC('r',  7),
    X_CHAR_ENC('P',  8), X_CHAR_ENC('r',  9), X_CHAR_ENC('o', 10), X_CHAR_ENC('v', 11),
    X_CHAR_ENC('D', 12), X_CHAR_ENC('a', 13), X_CHAR_ENC('t', 14), X_CHAR_ENC('a', 15),
    X_CHAR_ENC('F', 16), X_CHAR_ENC('r', 17), X_CHAR_ENC('o', 18), X_CHAR_ENC('m', 19),
    X_CHAR_ENC('S', 20), X_CHAR_ENC('t', 21), X_CHAR_ENC('a', 22), X_CHAR_ENC('t', 23),
    X_CHAR_ENC('e', 24), X_CHAR_ENC('D', 25), X_CHAR_ENC('a', 26), X_CHAR_ENC('t', 27),
    X_CHAR_ENC('a', 28), X_CHAR_ENC(0,   29)
  };
  static const CHAR strA_WTHelperGetProvSignerFromChain[] = {
    X_CHAR_ENC('W',  0), X_CHAR_ENC('T',  1), X_CHAR_ENC('H',  2), X_CHAR_ENC('e',  3),
    X_CHAR_ENC('l',  4), X_CHAR_ENC('p',  5), X_CHAR_ENC('e',  6), X_CHAR_ENC('r',  7),
    X_CHAR_ENC('G',  8), X_CHAR_ENC('e',  9), X_CHAR_ENC('t', 10), X_CHAR_ENC('P', 11),
    X_CHAR_ENC('r', 12), X_CHAR_ENC('o', 13), X_CHAR_ENC('v', 14), X_CHAR_ENC('S', 15),
    X_CHAR_ENC('i', 16), X_CHAR_ENC('g', 17), X_CHAR_ENC('n', 18), X_CHAR_ENC('e', 19),
    X_CHAR_ENC('r', 20), X_CHAR_ENC('F', 21), X_CHAR_ENC('r', 22), X_CHAR_ENC('o', 23),
    X_CHAR_ENC('m', 24), X_CHAR_ENC('C', 25), X_CHAR_ENC('h', 26), X_CHAR_ENC('a', 27),
    X_CHAR_ENC('i', 28), X_CHAR_ENC('n', 29), X_CHAR_ENC(0,   30)
  };
  static const WCHAR strW_Crypt32Dll[] = {
    X_WCHAR_ENC(L'c',  0), X_WCHAR_ENC(L'r',  1), X_WCHAR_ENC(L'y',  2), X_WCHAR_ENC(L'p',  3),
    X_WCHAR_ENC(L't',  4), X_WCHAR_ENC(L'3',  5), X_WCHAR_ENC(L'2',  6), X_WCHAR_ENC(L'.',  7),
    X_WCHAR_ENC(L'd',  8), X_WCHAR_ENC(L'l',  9), X_WCHAR_ENC(L'l', 10), X_WCHAR_ENC(0,    11)
  };
  static const WCHAR strW_KernelbaseDll[] = {
    X_WCHAR_ENC(L'k',  0), X_WCHAR_ENC(L'e',  1), X_WCHAR_ENC(L'r',  2), X_WCHAR_ENC(L'n',  3),
    X_WCHAR_ENC(L'e',  4), X_WCHAR_ENC(L'l',  5), X_WCHAR_ENC(L'b',  6), X_WCHAR_ENC(L'a',  7),
    X_WCHAR_ENC(L's',  8), X_WCHAR_ENC(L'e',  9), X_WCHAR_ENC(L'.', 10), X_WCHAR_ENC(L'd', 11),
    X_WCHAR_ENC(L'l', 12), X_WCHAR_ENC(L'l', 13), X_WCHAR_ENC(0, 14)
  };
  static const WCHAR strW_Kernel32Dll[] = {
    X_WCHAR_ENC(L'k',  0), X_WCHAR_ENC(L'e',  1), X_WCHAR_ENC(L'r',  2), X_WCHAR_ENC(L'n',  3),
    X_WCHAR_ENC(L'e',  4), X_WCHAR_ENC(L'l',  5), X_WCHAR_ENC(L'3',  6), X_WCHAR_ENC(L'2',  7),
    X_WCHAR_ENC(L'.',  8), X_WCHAR_ENC(L'd',  9), X_WCHAR_ENC(L'l', 10), X_WCHAR_ENC(L'l', 11),
    X_WCHAR_ENC(0, 12)
  };
  static const CHAR strA_CertGetNameStringW[] = {
    X_CHAR_ENC('C',  0), X_CHAR_ENC('e',  1), X_CHAR_ENC('r',  2), X_CHAR_ENC('t',  3),
    X_CHAR_ENC('G',  4), X_CHAR_ENC('e',  5), X_CHAR_ENC('t',  6), X_CHAR_ENC('N',  7),
    X_CHAR_ENC('a',  8), X_CHAR_ENC('m',  9), X_CHAR_ENC('e', 10), X_CHAR_ENC('S', 11),
    X_CHAR_ENC('t', 12), X_CHAR_ENC('r', 13), X_CHAR_ENC('i', 14), X_CHAR_ENC('n', 15),
    X_CHAR_ENC('g', 16), X_CHAR_ENC('W', 17), X_CHAR_ENC(0,   18)
  };
  static const CHAR strA_CertDuplicateCertificateContext[] = {
    X_CHAR_ENC('C',  0), X_CHAR_ENC('e',  1), X_CHAR_ENC('r',  2), X_CHAR_ENC('t',  3),
    X_CHAR_ENC('D',  4), X_CHAR_ENC('u',  5), X_CHAR_ENC('p',  6), X_CHAR_ENC('l',  7),
    X_CHAR_ENC('i',  8), X_CHAR_ENC('c',  9), X_CHAR_ENC('a', 10), X_CHAR_ENC('t', 11),
    X_CHAR_ENC('e', 12), X_CHAR_ENC('C', 13), X_CHAR_ENC('e', 14), X_CHAR_ENC('r', 15),
    X_CHAR_ENC('t', 16), X_CHAR_ENC('i', 17), X_CHAR_ENC('f', 18), X_CHAR_ENC('i', 19),
    X_CHAR_ENC('c', 20), X_CHAR_ENC('a', 21), X_CHAR_ENC('t', 22), X_CHAR_ENC('e', 23),
    X_CHAR_ENC('C', 24), X_CHAR_ENC('o', 25), X_CHAR_ENC('n', 26), X_CHAR_ENC('t', 27),
    X_CHAR_ENC('e', 28), X_CHAR_ENC('x', 29), X_CHAR_ENC('t', 30), X_CHAR_ENC(0, 31)
  };
  static const CHAR strA_CertFreeCertificateContext[] = {
    X_CHAR_ENC('C',  0), X_CHAR_ENC('e',  1), X_CHAR_ENC('r',  2), X_CHAR_ENC('t',  3),
    X_CHAR_ENC('F',  4), X_CHAR_ENC('r',  5), X_CHAR_ENC('e',  6), X_CHAR_ENC('e',  7),
    X_CHAR_ENC('C',  8), X_CHAR_ENC('e',  9), X_CHAR_ENC('r', 10), X_CHAR_ENC('t', 11),
    X_CHAR_ENC('i', 12), X_CHAR_ENC('f', 13), X_CHAR_ENC('i', 14), X_CHAR_ENC('c', 15),
    X_CHAR_ENC('a', 16), X_CHAR_ENC('t', 17), X_CHAR_ENC('e', 18), X_CHAR_ENC('C', 19),
    X_CHAR_ENC('o', 20), X_CHAR_ENC('n', 21), X_CHAR_ENC('t', 22), X_CHAR_ENC('e', 23),
    X_CHAR_ENC('x', 24), X_CHAR_ENC('t', 25), X_CHAR_ENC(0, 26)
  };
  static const CHAR strA_GetPackageFullName[] = {
    X_CHAR_ENC('G',  0), X_CHAR_ENC('e',  1), X_CHAR_ENC('t',  2), X_CHAR_ENC('P',  3),
    X_CHAR_ENC('a',  4), X_CHAR_ENC('c',  5), X_CHAR_ENC('k',  6), X_CHAR_ENC('a',  7),
    X_CHAR_ENC('g',  8), X_CHAR_ENC('e',  9), X_CHAR_ENC('F', 10), X_CHAR_ENC('u', 11),
    X_CHAR_ENC('l', 12), X_CHAR_ENC('l', 13), X_CHAR_ENC('N', 14), X_CHAR_ENC('a', 15),
    X_CHAR_ENC('m', 16), X_CHAR_ENC('e', 17), X_CHAR_ENC(0, 18)
  };
  static const CHAR strA_GetPackagePath[] = {
    X_CHAR_ENC('G',  0), X_CHAR_ENC('e',  1), X_CHAR_ENC('t',  2), X_CHAR_ENC('P',  3),
    X_CHAR_ENC('a',  4), X_CHAR_ENC('c',  5), X_CHAR_ENC('k',  6), X_CHAR_ENC('a',  7),
    X_CHAR_ENC('g',  8), X_CHAR_ENC('e',  9), X_CHAR_ENC('P', 10), X_CHAR_ENC('a', 11),
    X_CHAR_ENC('t', 12), X_CHAR_ENC('h', 13), X_CHAR_ENC(0, 14)
  };
  static const CHAR strA_PackageIdFromFullName[] = {
    X_CHAR_ENC('P',  0), X_CHAR_ENC('a',  1), X_CHAR_ENC('c',  2), X_CHAR_ENC('k',  3),
    X_CHAR_ENC('a',  4), X_CHAR_ENC('g',  5), X_CHAR_ENC('e',  6), X_CHAR_ENC('I',  7),
    X_CHAR_ENC('d',  8), X_CHAR_ENC('F',  9), X_CHAR_ENC('r', 10), X_CHAR_ENC('o', 11),
    X_CHAR_ENC('m', 12), X_CHAR_ENC('F', 13), X_CHAR_ENC('u', 14), X_CHAR_ENC('l', 15),
    X_CHAR_ENC('l', 16), X_CHAR_ENC('N', 17), X_CHAR_ENC('a', 18), X_CHAR_ENC('m', 19),
    X_CHAR_ENC('e', 20), X_CHAR_ENC(0, 21)
  };
  static const CHAR strA_CryptCATAdminAcquireContext[] = {
    X_CHAR_ENC('C',  0), X_CHAR_ENC('r',  1), X_CHAR_ENC('y',  2), X_CHAR_ENC('p',  3),
    X_CHAR_ENC('t',  4), X_CHAR_ENC('C',  5), X_CHAR_ENC('A',  6), X_CHAR_ENC('T',  7),
    X_CHAR_ENC('A',  8), X_CHAR_ENC('d',  9), X_CHAR_ENC('m', 10), X_CHAR_ENC('i', 11),
    X_CHAR_ENC('n', 12), X_CHAR_ENC('A', 13), X_CHAR_ENC('c', 14), X_CHAR_ENC('q', 15),
    X_CHAR_ENC('u', 16), X_CHAR_ENC('i', 17), X_CHAR_ENC('r', 18), X_CHAR_ENC('e', 19),
    X_CHAR_ENC('C', 20), X_CHAR_ENC('o', 21), X_CHAR_ENC('n', 22), X_CHAR_ENC('t', 23),
    X_CHAR_ENC('e', 24), X_CHAR_ENC('x', 25), X_CHAR_ENC('t', 26), X_CHAR_ENC(0, 27)
  };
  static const CHAR strA_CryptCATAdminAcquireContext2[] = {
    X_CHAR_ENC('C',  0), X_CHAR_ENC('r',  1), X_CHAR_ENC('y',  2), X_CHAR_ENC('p',  3),
    X_CHAR_ENC('t',  4), X_CHAR_ENC('C',  5), X_CHAR_ENC('A',  6), X_CHAR_ENC('T',  7),
    X_CHAR_ENC('A',  8), X_CHAR_ENC('d',  9), X_CHAR_ENC('m', 10), X_CHAR_ENC('i', 11),
    X_CHAR_ENC('n', 12), X_CHAR_ENC('A', 13), X_CHAR_ENC('c', 14), X_CHAR_ENC('q', 15),
    X_CHAR_ENC('u', 16), X_CHAR_ENC('i', 17), X_CHAR_ENC('r', 18), X_CHAR_ENC('e', 19),
    X_CHAR_ENC('C', 20), X_CHAR_ENC('o', 21), X_CHAR_ENC('n', 22), X_CHAR_ENC('t', 23),
    X_CHAR_ENC('e', 24), X_CHAR_ENC('x', 25), X_CHAR_ENC('t', 26), X_CHAR_ENC('2', 27),
    X_CHAR_ENC(0, 28)
  };
  static const CHAR strA_CryptCATAdminCalcHashFromFileHandle[] = {
    X_CHAR_ENC('C',  0), X_CHAR_ENC('r',  1), X_CHAR_ENC('y',  2), X_CHAR_ENC('p',  3),
    X_CHAR_ENC('t',  4), X_CHAR_ENC('C',  5), X_CHAR_ENC('A',  6), X_CHAR_ENC('T',  7),
    X_CHAR_ENC('A',  8), X_CHAR_ENC('d',  9), X_CHAR_ENC('m', 10), X_CHAR_ENC('i', 11),
    X_CHAR_ENC('n', 12), X_CHAR_ENC('C', 13), X_CHAR_ENC('a', 14), X_CHAR_ENC('l', 15),
    X_CHAR_ENC('c', 16), X_CHAR_ENC('H', 17), X_CHAR_ENC('a', 18), X_CHAR_ENC('s', 19),
    X_CHAR_ENC('h', 20), X_CHAR_ENC('F', 21), X_CHAR_ENC('r', 22), X_CHAR_ENC('o', 23),
    X_CHAR_ENC('m', 24), X_CHAR_ENC('F', 25), X_CHAR_ENC('i', 26), X_CHAR_ENC('l', 27),
    X_CHAR_ENC('e', 28), X_CHAR_ENC('H', 29), X_CHAR_ENC('a', 30), X_CHAR_ENC('n', 31),
    X_CHAR_ENC('d', 32), X_CHAR_ENC('l', 33), X_CHAR_ENC('e', 34), X_CHAR_ENC(0, 35)
  };
  static const CHAR strA_CryptCATAdminCalcHashFromFileHandle2[] = {
    X_CHAR_ENC('C',  0), X_CHAR_ENC('r',  1), X_CHAR_ENC('y',  2), X_CHAR_ENC('p',  3),
    X_CHAR_ENC('t',  4), X_CHAR_ENC('C',  5), X_CHAR_ENC('A',  6), X_CHAR_ENC('T',  7),
    X_CHAR_ENC('A',  8), X_CHAR_ENC('d',  9), X_CHAR_ENC('m', 10), X_CHAR_ENC('i', 11),
    X_CHAR_ENC('n', 12), X_CHAR_ENC('C', 13), X_CHAR_ENC('a', 14), X_CHAR_ENC('l', 15),
    X_CHAR_ENC('c', 16), X_CHAR_ENC('H', 17), X_CHAR_ENC('a', 18), X_CHAR_ENC('s', 19),
    X_CHAR_ENC('h', 20), X_CHAR_ENC('F', 21), X_CHAR_ENC('r', 22), X_CHAR_ENC('o', 23),
    X_CHAR_ENC('m', 24), X_CHAR_ENC('F', 25), X_CHAR_ENC('i', 26), X_CHAR_ENC('l', 27),
    X_CHAR_ENC('e', 28), X_CHAR_ENC('H', 29), X_CHAR_ENC('a', 30), X_CHAR_ENC('n', 31),
    X_CHAR_ENC('d', 32), X_CHAR_ENC('l', 33), X_CHAR_ENC('e', 34), X_CHAR_ENC('2', 35),
    X_CHAR_ENC(0, 36)
  };
  static const CHAR strA_CryptCATAdminEnumCatalogFromHash[] = {
    X_CHAR_ENC('C',  0), X_CHAR_ENC('r',  1), X_CHAR_ENC('y',  2), X_CHAR_ENC('p',  3),
    X_CHAR_ENC('t',  4), X_CHAR_ENC('C',  5), X_CHAR_ENC('A',  6), X_CHAR_ENC('T',  7),
    X_CHAR_ENC('A',  8), X_CHAR_ENC('d',  9), X_CHAR_ENC('m', 10), X_CHAR_ENC('i', 11),
    X_CHAR_ENC('n', 12), X_CHAR_ENC('E', 13), X_CHAR_ENC('n', 14), X_CHAR_ENC('u', 15),
    X_CHAR_ENC('m', 16), X_CHAR_ENC('C', 17), X_CHAR_ENC('a', 18), X_CHAR_ENC('t', 19),
    X_CHAR_ENC('a', 20), X_CHAR_ENC('l', 21), X_CHAR_ENC('o', 22), X_CHAR_ENC('g', 23),
    X_CHAR_ENC('F', 24), X_CHAR_ENC('r', 25), X_CHAR_ENC('o', 26), X_CHAR_ENC('m', 27),
    X_CHAR_ENC('H', 28), X_CHAR_ENC('a', 29), X_CHAR_ENC('s', 30), X_CHAR_ENC('h', 31),
    X_CHAR_ENC(0, 32)
  };
  static const CHAR strA_CryptCATAdminReleaseContext[] = {
    X_CHAR_ENC('C',  0), X_CHAR_ENC('r',  1), X_CHAR_ENC('y',  2), X_CHAR_ENC('p',  3),
    X_CHAR_ENC('t',  4), X_CHAR_ENC('C',  5), X_CHAR_ENC('A',  6), X_CHAR_ENC('T',  7),
    X_CHAR_ENC('A',  8), X_CHAR_ENC('d',  9), X_CHAR_ENC('m', 10), X_CHAR_ENC('i', 11),
    X_CHAR_ENC('n', 12), X_CHAR_ENC('R', 13), X_CHAR_ENC('e', 14), X_CHAR_ENC('l', 15),
    X_CHAR_ENC('e', 16), X_CHAR_ENC('a', 17), X_CHAR_ENC('s', 18), X_CHAR_ENC('e', 19),
    X_CHAR_ENC('C', 20), X_CHAR_ENC('o', 21), X_CHAR_ENC('n', 22), X_CHAR_ENC('t', 23),
    X_CHAR_ENC('e', 24), X_CHAR_ENC('x', 25), X_CHAR_ENC('t', 26), X_CHAR_ENC(0, 27)
  };
  static const CHAR strA_CryptCATCatalogInfoFromContext[] = {
    X_CHAR_ENC('C',  0), X_CHAR_ENC('r',  1), X_CHAR_ENC('y',  2), X_CHAR_ENC('p',  3),
    X_CHAR_ENC('t',  4), X_CHAR_ENC('C',  5), X_CHAR_ENC('A',  6), X_CHAR_ENC('T',  7),
    X_CHAR_ENC('C',  8), X_CHAR_ENC('a',  9), X_CHAR_ENC('t', 10), X_CHAR_ENC('a', 11),
    X_CHAR_ENC('l', 12), X_CHAR_ENC('o', 13), X_CHAR_ENC('g', 14), X_CHAR_ENC('I', 15),
    X_CHAR_ENC('n', 16), X_CHAR_ENC('f', 17), X_CHAR_ENC('o', 18), X_CHAR_ENC('F', 19),
    X_CHAR_ENC('r', 20), X_CHAR_ENC('o', 21), X_CHAR_ENC('m', 22), X_CHAR_ENC('C', 23),
    X_CHAR_ENC('o', 24), X_CHAR_ENC('n', 25), X_CHAR_ENC('t', 26), X_CHAR_ENC('e', 27),
    X_CHAR_ENC('x', 28), X_CHAR_ENC('t', 29), X_CHAR_ENC(0, 30)
  };
  static const CHAR strA_CryptCATAdminReleaseCatalogContext[] = {
    X_CHAR_ENC('C',  0), X_CHAR_ENC('r',  1), X_CHAR_ENC('y',  2), X_CHAR_ENC('p',  3),
    X_CHAR_ENC('t',  4), X_CHAR_ENC('C',  5), X_CHAR_ENC('A',  6), X_CHAR_ENC('T',  7),
    X_CHAR_ENC('A',  8), X_CHAR_ENC('d',  9), X_CHAR_ENC('m', 10), X_CHAR_ENC('i', 11),
    X_CHAR_ENC('n', 12), X_CHAR_ENC('R', 13), X_CHAR_ENC('e', 14), X_CHAR_ENC('l', 15),
    X_CHAR_ENC('e', 16), X_CHAR_ENC('a', 17), X_CHAR_ENC('s', 18), X_CHAR_ENC('e', 19),
    X_CHAR_ENC('C', 20), X_CHAR_ENC('a', 21), X_CHAR_ENC('t', 22), X_CHAR_ENC('a', 23),
    X_CHAR_ENC('l', 24), X_CHAR_ENC('o', 25), X_CHAR_ENC('g', 26), X_CHAR_ENC('C', 27),
    X_CHAR_ENC('o', 28), X_CHAR_ENC('n', 29), X_CHAR_ENC('t', 30), X_CHAR_ENC('e', 31),
    X_CHAR_ENC('x', 32), X_CHAR_ENC('t', 33), X_CHAR_ENC(0, 34)
  };
  CHAR szTempA[128];
  WCHAR szTempW[128];
  SIZE_T i;
  HRESULT hRes = S_OK;

  _EXPAND_W(strW_WinTrustDll);
  if (SUCCEEDED(System::LoadSystem32Dll(szTempW, &hWinTrustDll)))
  {
    _EXPAND_A(strA_WinVerifyTrustEx);
    fnWinVerifyTrustEx = (lpfnWinVerifyTrustEx)::GetProcAddress(hWinTrustDll, szTempA);
    _EXPAND_A(strA_WTHelperProvDataFromStateData);
    fnWTHelperProvDataFromStateData = (lpfnWTHelperProvDataFromStateData)::GetProcAddress(hWinTrustDll, szTempA);
    _EXPAND_A(strA_WTHelperGetProvSignerFromChain);
    fnWTHelperGetProvSignerFromChain = (lpfnWTHelperGetProvSignerFromChain)::GetProcAddress(hWinTrustDll, szTempA);

    _EXPAND_A(strA_CryptCATAdminAcquireContext);
    fnCryptCATAdminAcquireContext = (lpfnCryptCATAdminAcquireContext)::GetProcAddress(hWinTrustDll, szTempA);
    _EXPAND_A(strA_CryptCATAdminAcquireContext2);
    fnCryptCATAdminAcquireContext2 = (lpfnCryptCATAdminAcquireContext2)::GetProcAddress(hWinTrustDll, szTempA);
    _EXPAND_A(strA_CryptCATAdminCalcHashFromFileHandle);
    fnCryptCATAdminCalcHashFromFileHandle = (lpfnCryptCATAdminCalcHashFromFileHandle)::GetProcAddress(hWinTrustDll,
                                                                                                      szTempA);
    _EXPAND_A(strA_CryptCATAdminCalcHashFromFileHandle2);
    fnCryptCATAdminCalcHashFromFileHandle2 = (lpfnCryptCATAdminCalcHashFromFileHandle2)::GetProcAddress(hWinTrustDll,
                                                                                                        szTempA);
    _EXPAND_A(strA_CryptCATAdminEnumCatalogFromHash);
    fnCryptCATAdminEnumCatalogFromHash = (lpfnCryptCATAdminEnumCatalogFromHash)::GetProcAddress(hWinTrustDll, szTempA);
    _EXPAND_A(strA_CryptCATAdminReleaseContext);
    fnCryptCATAdminReleaseContext = (lpfnCryptCATAdminReleaseContext)::GetProcAddress(hWinTrustDll, szTempA);
    _EXPAND_A(strA_CryptCATCatalogInfoFromContext);
    fnCryptCATCatalogInfoFromContext = (lpfnCryptCATCatalogInfoFromContext)::GetProcAddress(hWinTrustDll, szTempA);
    _EXPAND_A(strA_CryptCATAdminReleaseCatalogContext);
    fnCryptCATAdminReleaseCatalogContext = (lpfnCryptCATAdminReleaseCatalogContext)::GetProcAddress(hWinTrustDll,
                                                                                                    szTempA);

    if (fnCryptCATAdminAcquireContext2 == NULL || fnCryptCATAdminCalcHashFromFileHandle2 == NULL)
    {
      fnCryptCATAdminAcquireContext2 = NULL;
      fnCryptCATAdminCalcHashFromFileHandle2 = NULL;
    }
    if (fnCryptCATAdminAcquireContext == NULL || fnCryptCATAdminCalcHashFromFileHandle == NULL ||
        fnCryptCATAdminEnumCatalogFromHash == NULL || fnCryptCATAdminReleaseContext == NULL ||
        fnCryptCATCatalogInfoFromContext == NULL || fnCryptCATAdminReleaseCatalogContext == NULL)
    {
      fnCryptCATAdminAcquireContext = NULL;
      fnCryptCATAdminAcquireContext2 = NULL;
      fnCryptCATAdminCalcHashFromFileHandle = NULL;
      fnCryptCATAdminCalcHashFromFileHandle2 = NULL;
      fnCryptCATAdminEnumCatalogFromHash = NULL;
      fnCryptCATAdminReleaseContext = NULL;
      fnCryptCATCatalogInfoFromContext = NULL;
      fnCryptCATAdminReleaseCatalogContext = NULL;
    }
  }
  _EXPAND_W(strW_Crypt32Dll);
  if (SUCCEEDED(System::LoadSystem32Dll(szTempW, &hCrypt32Dll)))
  {
    _EXPAND_A(strA_CertGetNameStringW);
    fnCertGetNameStringW = (lpfnCertGetNameStringW)::GetProcAddress(hCrypt32Dll, szTempA);

    _EXPAND_A(strA_CertDuplicateCertificateContext);
    fnCertDuplicateCertificateContext = (lpfnCertDuplicateCertificateContext)::GetProcAddress(hCrypt32Dll, szTempA);
    _EXPAND_A(strA_CertFreeCertificateContext);
    fnCertFreeCertificateContext = (lpfnCertFreeCertificateContext)::GetProcAddress(hCrypt32Dll, szTempA);
  }
  if (fnWinVerifyTrustEx == NULL || fnCertGetNameStringW == NULL ||
      fnWTHelperProvDataFromStateData == NULL || fnWTHelperGetProvSignerFromChain == NULL ||
      fnCertDuplicateCertificateContext == NULL || fnCertFreeCertificateContext == NULL)
  {
    hRes = MX_HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
  }
  if (SUCCEEDED(hRes))
  {
    CFileVersionInfo cFileVersion;

    hRes = cFileVersion.InitializeFromMemory((LPCVOID)hCrypt32Dll, 0x80000000, TRUE);
    if (SUCCEEDED(hRes))
    {
      sCrypt32DllVersion.wFileVersion[0] = (WORD)(cFileVersion->dwFileVersionMS >> 16);
      sCrypt32DllVersion.wFileVersion[1] = (WORD)(cFileVersion->dwFileVersionMS & 0xFFFF);
      sCrypt32DllVersion.wFileVersion[2] = (WORD)(cFileVersion->dwFileVersionLS >> 16);
      sCrypt32DllVersion.wFileVersion[3] = (WORD)(cFileVersion->dwFileVersionLS & 0xFFFF);

      sCrypt32DllVersion.wProductVersion[0] = (WORD)(cFileVersion->dwProductVersionMS >> 16);
      sCrypt32DllVersion.wProductVersion[1] = (WORD)(cFileVersion->dwProductVersionMS & 0xFFFF);
      sCrypt32DllVersion.wProductVersion[2] = (WORD)(cFileVersion->dwProductVersionLS >> 16);
      sCrypt32DllVersion.wProductVersion[3] = (WORD)(cFileVersion->dwProductVersionLS & 0xFFFF);

      hRes = cFileVersion.InitializeFromMemory((LPCVOID)hWinTrustDll, 0x80000000, TRUE);
      if (SUCCEEDED(hRes))
      {
        sWinTrustDllVersion.wFileVersion[0] = (WORD)(cFileVersion->dwFileVersionMS >> 16);
        sWinTrustDllVersion.wFileVersion[1] = (WORD)(cFileVersion->dwFileVersionMS & 0xFFFF);
        sWinTrustDllVersion.wFileVersion[2] = (WORD)(cFileVersion->dwFileVersionLS >> 16);
        sWinTrustDllVersion.wFileVersion[3] = (WORD)(cFileVersion->dwFileVersionLS & 0xFFFF);

        sWinTrustDllVersion.wProductVersion[0] = (WORD)(cFileVersion->dwProductVersionMS >> 16);
        sWinTrustDllVersion.wProductVersion[1] = (WORD)(cFileVersion->dwProductVersionMS & 0xFFFF);
        sWinTrustDllVersion.wProductVersion[2] = (WORD)(cFileVersion->dwProductVersionLS >> 16);
        sWinTrustDllVersion.wProductVersion[3] = (WORD)(cFileVersion->dwProductVersionLS & 0xFFFF);
      }
    }
  }
  if (SUCCEEDED(hRes))
  {
    HINSTANCE hDll[2];

    _EXPAND_W(strW_KernelbaseDll);
    hDll[0] = ::GetModuleHandleW(szTempW);
    _EXPAND_W(strW_Kernel32Dll);
    hDll[1] = ::GetModuleHandleW(szTempW);
    if (hDll[0] != NULL && hDll[1] != NULL)
    {
      _EXPAND_A(strA_GetPackageFullName);
      fnGetPackageFullName = (lpfnGetPackageFullName)::GetProcAddress(hDll[0], szTempA);
      if (fnGetPackageFullName == NULL)
        fnGetPackageFullName = (lpfnGetPackageFullName)::GetProcAddress(hDll[1], szTempA);
      _EXPAND_A(strA_GetPackagePath);
      fnGetPackagePath = (lpfnGetPackagePath)::GetProcAddress(hDll[0], szTempA);
      if (fnGetPackagePath == NULL)
        fnGetPackagePath = (lpfnGetPackagePath)::GetProcAddress(hDll[1], szTempA);
      _EXPAND_A(strA_PackageIdFromFullName);
      fnPackageIdFromFullName = (lpfnPackageIdFromFullName)::GetProcAddress(hDll[0], szTempA);
      if (fnPackageIdFromFullName == NULL)
        fnPackageIdFromFullName = (lpfnPackageIdFromFullName)::GetProcAddress(hDll[1], szTempA);
    }
    if (fnGetPackageFullName == NULL || fnGetPackagePath == NULL || fnPackageIdFromFullName == NULL)
    {
      fnGetPackageFullName = NULL;
      fnGetPackagePath = NULL;
      fnPackageIdFromFullName = NULL;
    }
  }
  //register finalizer
  if (SUCCEEDED(hRes))
  {
    hRes = RegisterFinalizer(&EndSignaturesAndInfo, 3);
  }
  //done
  if (FAILED(hRes))
    EndSignaturesAndInfo();
  ::MxMemSet(szTempA, 0, sizeof(szTempA));
  ::MxMemSet(szTempW, 0, sizeof(szTempW));
  return hRes;
}

HRESULT GetPeSignature(_In_z_ LPCWSTR szPeFileNameW, _In_opt_ HANDLE hFile, _In_opt_ HANDLE hProcess,
                       _In_opt_ HANDLE hCancelEvent, _Out_ PCERT_CONTEXT *lplpCertCtx, _Out_ PFILETIME lpTimeStamp)
{
  static const WCHAR strW_AppxMetadata_CodeIntegrity_cat[] = {
    X_WCHAR_ENC(L'A',  0), X_WCHAR_ENC(L'p',  1), X_WCHAR_ENC(L'p',  2), X_WCHAR_ENC(L'x',  3),
    X_WCHAR_ENC(L'M',  4), X_WCHAR_ENC(L'e',  5), X_WCHAR_ENC(L't',  6), X_WCHAR_ENC(L'a',  7),
    X_WCHAR_ENC(L'd',  8), X_WCHAR_ENC(L'a',  9), X_WCHAR_ENC(L't', 10), X_WCHAR_ENC(L'a', 11),
    X_WCHAR_ENC(L'\\', 12), X_WCHAR_ENC(L'C', 13), X_WCHAR_ENC(L'o', 14), X_WCHAR_ENC(L'd', 15),
    X_WCHAR_ENC(L'e', 16), X_WCHAR_ENC(L'I', 17), X_WCHAR_ENC(L'n', 18), X_WCHAR_ENC(L't', 19),
    X_WCHAR_ENC(L'e', 20), X_WCHAR_ENC(L'g', 21), X_WCHAR_ENC(L'r', 22), X_WCHAR_ENC(L'i', 23),
    X_WCHAR_ENC(L't', 24), X_WCHAR_ENC(L'y', 25), X_WCHAR_ENC(L'.', 26), X_WCHAR_ENC(L'c', 27),
    X_WCHAR_ENC(L'a', 28), X_WCHAR_ENC(L't', 29)
  };
  CStringW cStrPackageFullPathW;
  CWindowsHandle cFileH;
  HRESULT hRes;

  if (lplpCertCtx != NULL)
    *lplpCertCtx = NULL;
  if (lpTimeStamp != NULL)
    lpTimeStamp->dwLowDateTime = lpTimeStamp->dwHighDateTime = 0;
  if (lplpCertCtx == NULL || lpTimeStamp == NULL)
    return E_POINTER;
  if (szPeFileNameW == NULL)
    return E_POINTER;
  if (*szPeFileNameW == 0)
    return E_INVALIDARG;

  if (fnWinVerifyTrustEx == NULL)
    return MX_E_Cancelled;

  //open file if none provided
  if (hFile == NULL)
  {
    hRes = FileRoutines::OpenFileWithEscalatingSharing(szPeFileNameW, &cFileH);
    if (FAILED(hRes))
      return hRes;
    hFile = cFileH.Get();
  }

  if (hCancelEvent != NULL && ::WaitForSingleObject(hCancelEvent, 0) == WAIT_OBJECT_0)
    return MX_E_Cancelled;

  //if we reach here, cache is not valid or does not contains the certificate
  if (hProcess != NULL && fnGetPackageFullName != NULL)
  {
    TAutoFreePtr<PACKAGE_ID> aPackageId;
    UINT32 dwLen;

    if (cStrPackageFullPathW.EnsureBuffer(1024 + 4) == FALSE)
      return E_OUTOFMEMORY;

    dwLen = 1024;
    hRes = MX_HRESULT_FROM_WIN32(fnGetPackageFullName(hProcess, &dwLen, (LPWSTR)cStrPackageFullPathW));
    if (hRes == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER))
    {
      if (cStrPackageFullPathW.EnsureBuffer((SIZE_T)dwLen + 4) != FALSE)
        hRes = MX_HRESULT_FROM_WIN32(fnGetPackageFullName(hProcess, &dwLen, (LPWSTR)cStrPackageFullPathW));
      else
        hRes = E_OUTOFMEMORY;
    }
    if (SUCCEEDED(hRes))
    {
      ((LPWSTR)cStrPackageFullPathW)[dwLen] = 0;
      cStrPackageFullPathW.Refresh();

      aPackageId.Attach((PACKAGE_ID*)MX_MALLOC(1024));
      if (!aPackageId)
      {
        hRes = E_OUTOFMEMORY;
        goto done;
      }
      dwLen = 1024;
      hRes = MX_HRESULT_FROM_WIN32(fnPackageIdFromFullName((LPCWSTR)cStrPackageFullPathW, PACKAGE_INFORMATION_BASIC,
                                   &dwLen, (PBYTE)(aPackageId.Get())));
      if (hRes == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER))
      {
        aPackageId.Attach((PACKAGE_ID*)MX_MALLOC((SIZE_T)dwLen));
        hRes = MX_HRESULT_FROM_WIN32(fnPackageIdFromFullName((LPCWSTR)cStrPackageFullPathW, PACKAGE_INFORMATION_BASIC,
                                     &dwLen, (PBYTE)(aPackageId.Get())));
      }
      if (SUCCEEDED(hRes))
      {
        if (cStrPackageFullPathW.EnsureBuffer(1024 + 4) == FALSE)
        {
          hRes = E_OUTOFMEMORY;
          goto done;
        }
        dwLen = 1024;
        hRes = MX_HRESULT_FROM_WIN32(fnGetPackagePath(aPackageId.Get(), 0, &dwLen, (LPWSTR)cStrPackageFullPathW));
        if (hRes == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER))
        {
          if (cStrPackageFullPathW.EnsureBuffer((SIZE_T)dwLen + 4) == FALSE)
          {
            hRes = E_OUTOFMEMORY;
            goto done;
          }
          hRes = MX_HRESULT_FROM_WIN32(fnGetPackagePath(aPackageId.Get(), 0, &dwLen, (LPWSTR)cStrPackageFullPathW));
        }
        if (SUCCEEDED(hRes))
        {
          SIZE_T nLen;

          ((LPWSTR)cStrPackageFullPathW)[dwLen] = 0;
          cStrPackageFullPathW.Refresh();
          nLen = cStrPackageFullPathW.GetLength();
          if (nLen > 0 && ((LPCWSTR)cStrPackageFullPathW)[nLen - 1] != L'\\')
          {
            if (cStrPackageFullPathW.ConcatN(L"\\", 1) == FALSE)
            {
              hRes = E_OUTOFMEMORY;
              goto done;
            }
          }
          for (nLen = 0; nLen < MX_ARRAYLEN(strW_AppxMetadata_CodeIntegrity_cat); nLen++)
          {
            WCHAR chW = X_WCHAR_ENC(strW_AppxMetadata_CodeIntegrity_cat[nLen], nLen);
            if (cStrPackageFullPathW.ConcatN(&chW, 1) == FALSE)
            {
              hRes = E_OUTOFMEMORY;
              goto done;
            }
          }
        }
        else if (hRes == E_OUTOFMEMORY)
        {
          goto done;
        }
      }
    }
    else if (hRes == E_OUTOFMEMORY)
    {
      goto done;
    }
  }

  if (hCancelEvent != NULL && ::WaitForSingleObject(hCancelEvent, 0) == WAIT_OBJECT_0)
    return MX_E_Cancelled;

  //verify PE's signature
  if (::SetFilePointer(hFile, 0, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER)
  {
    hRes = DoTrustVerification(szPeFileNameW, hFile, &sWVTPolicyGuid, NULL, lplpCertCtx, lpTimeStamp);
    if (hRes == E_OUTOFMEMORY)
      return hRes;

    if (hCancelEvent != NULL && ::WaitForSingleObject(hCancelEvent, 0) == WAIT_OBJECT_0)
      return MX_E_Cancelled;
  }
  else
  {
    hRes = MX_HRESULT_FROM_LASTERROR();
  }

  if (hRes == TRUST_E_NOSIGNATURE && fnCryptCATAdminAcquireContext != NULL)
  {
    TAutoFreePtr<BYTE> aFileHash;
    ULONG nFileHashLength;
    HCATADMIN hCatAdmin = NULL;
    int nPass;
    ULARGE_INTEGER uliFileSize;

    if (::GetFileSizeEx(hFile, (PLARGE_INTEGER)&uliFileSize) != FALSE &&
        uliFileSize.QuadPart < MAX_FILE_SIZE_FOR_CATALOG_CHECK)
    {
      for (nPass = 1; nPass <= 2; nPass++)
      {
        if (hCancelEvent != NULL && ::WaitForSingleObject(hCancelEvent, 0) == WAIT_OBJECT_0)
        {
          hRes = MX_E_Cancelled;
          break;
        }

        hRes = S_OK;
        if (nPass == 1)
        {
          //CERT_STRONG_SIGN_PARA sSigningPolicy = {};

          if (fnCryptCATAdminAcquireContext2 == NULL)
            continue;
          //::MxMemSet(&sSigningPolicy, 0, sizeof(sSigningPolicy));
          //sSigningPolicy.cbSize = (DWORD)sizeof(sSigningPolicy);
          //sSigningPolicy.dwInfoChoice = CERT_STRONG_SIGN_OID_INFO_CHOICE;
          //sSigningPolicy.pszOID = szOID_CERT_STRONG_SIGN_OS_CURRENT;
          if (fnCryptCATAdminAcquireContext2(&hCatAdmin, &sDriverActionVerify, BCRYPT_SHA256_ALGORITHM,
                                             NULL, 0) == FALSE)
          {
            hRes = MX_HRESULT_FROM_LASTERROR();
          }
        }
        else
        {
          if (fnCryptCATAdminAcquireContext(&hCatAdmin, &sDriverActionVerify, 0) == FALSE)
            hRes = MX_HRESULT_FROM_LASTERROR();
        }
        if (SUCCEEDED(hRes))
        {
          nFileHashLength = 32;
          aFileHash.Attach((LPBYTE)MX_MALLOC((SIZE_T)nFileHashLength));
          if (aFileHash)
          {
            if (fnCryptCATAdminCalcHashFromFileHandle2 != NULL)
            {
              if (::SetFilePointer(hFile, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER ||
                  fnCryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, &nFileHashLength, aFileHash.Get(),
                                                         0) == FALSE)
              {
                aFileHash.Attach((LPBYTE)MX_MALLOC((SIZE_T)nFileHashLength));
                if (aFileHash)
                {
                  if (::SetFilePointer(hFile, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER ||
                      fnCryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, &nFileHashLength,
                                                             aFileHash.Get(), 0) == FALSE)
                  {
                    hRes = MX_HRESULT_FROM_LASTERROR();
                  }
                }
                else
                {
                  hRes = E_OUTOFMEMORY;
                }
              }
            }
            else
            {
              if (::SetFilePointer(hFile, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER ||
                  fnCryptCATAdminCalcHashFromFileHandle(hFile, &nFileHashLength, aFileHash.Get(), 0) == FALSE)
              {
                aFileHash.Attach((LPBYTE)MX_MALLOC((SIZE_T)nFileHashLength));
                if (aFileHash)
                {
                  if (::SetFilePointer(hFile, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER ||
                      fnCryptCATAdminCalcHashFromFileHandle(hFile, &nFileHashLength, aFileHash.Get(), 0) == FALSE)
                  {
                    hRes = MX_HRESULT_FROM_LASTERROR();
                  }
                }
                else
                {
                  hRes = E_OUTOFMEMORY;
                }
              }
            }
          }
          else
          {
            hRes = E_OUTOFMEMORY;
          }
        }
        if (SUCCEEDED(hRes))
        {
          CStringW cStrFileHashHexW;

          for (ULONG i = 0; i < nFileHashLength; i++)
          {
            if (cStrFileHashHexW.AppendFormat(L"%02X", aFileHash.Get()[i]) == FALSE)
            {
              hRes = E_OUTOFMEMORY;
              break;
            }
          }
          if (SUCCEEDED(hRes))
          {
            ___WINTRUST_CATALOG_INFO sCatInfo;
            HCATINFO hCatInfo;

            hCatInfo = fnCryptCATAdminEnumCatalogFromHash(hCatAdmin, aFileHash.Get(), nFileHashLength, 0, NULL);
            if (hCatInfo != NULL)
            {
              CATALOG_INFO sCi;
              DRIVER_VER_INFO sDrvVerInfo;

              ::MxMemSet(&sCi, 0, sizeof(sCi));
              if (fnCryptCATCatalogInfoFromContext(hCatInfo, &sCi, 0) != FALSE)
              {
                ::MxMemSet(&sDrvVerInfo, 0, sizeof(sDrvVerInfo));
                sDrvVerInfo.cbStruct = (DWORD)sizeof(DRIVER_VER_INFO);

                ::MxMemSet(&sCatInfo, 0, sizeof(sCatInfo));
                sCatInfo.cbStruct = (DWORD)sizeof(sCatInfo);
                sCatInfo.pcwszCatalogFilePath = sCi.wszCatalogFile;
                sCatInfo.pcwszMemberFilePath = szPeFileNameW;
                sCatInfo.pcwszMemberTag = (LPCWSTR)cStrFileHashHexW;
                sCatInfo.hMemberFile = hFile;
                sCatInfo.pbCalculatedFileHash = aFileHash.Get();
                sCatInfo.cbCalculatedFileHash = nFileHashLength;
                sCatInfo.hCatAdmin = hCatAdmin;
                if (::SetFilePointer(hFile, 0, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER)
                {
                  hRes = DoTrustVerification(NULL, NULL, &sDriverActionVerify, (PWINTRUST_CATALOG_INFO)&sCatInfo,
                                             lplpCertCtx, lpTimeStamp);
                }
                else
                {
                  hRes = MX_HRESULT_FROM_LASTERROR();
                }
              }
              else
              {
                hRes = TRUST_E_NOSIGNATURE;
              }
              fnCryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            }
            else if (cStrPackageFullPathW.IsEmpty() == FALSE)
            {
              ::MxMemSet(&sCatInfo, 0, sizeof(sCatInfo));
              sCatInfo.cbStruct = sizeof(sCatInfo);
              sCatInfo.pcwszCatalogFilePath = (LPCWSTR)cStrPackageFullPathW;
              sCatInfo.pcwszMemberFilePath = szPeFileNameW;
              sCatInfo.pcwszMemberTag = (LPCWSTR)cStrFileHashHexW;
              sCatInfo.hMemberFile = hFile;
              sCatInfo.pbCalculatedFileHash = aFileHash.Get();
              sCatInfo.cbCalculatedFileHash = nFileHashLength;
              sCatInfo.hCatAdmin = hCatAdmin;
              if (::SetFilePointer(hFile, 0, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER)
              {
                hRes = DoTrustVerification(NULL, NULL, &sWVTPolicyGuid, (PWINTRUST_CATALOG_INFO)&sCatInfo, lplpCertCtx,
                                           lpTimeStamp);
              }
              else
              {
                hRes = MX_HRESULT_FROM_LASTERROR();
              }
            }
            else
            {
              hRes = TRUST_E_NOSIGNATURE;
            }
          }
        }

        if (hCatAdmin != NULL)
          fnCryptCATAdminReleaseContext(hCatAdmin, 0);

        //break only if a certificate is found or a hard error
        if (hRes != TRUST_E_NOSIGNATURE)
          break;
      }
    }
  }

  //done
done:
  return hRes;
}

VOID FreeCertificate(_In_opt_ PCCERT_CONTEXT lpCertCtx)
{
  if (lpCertCtx != NULL && fnCertFreeCertificateContext != NULL)
  {
    fnCertFreeCertificateContext(lpCertCtx);
  }
  return;
}

PCCERT_CONTEXT DuplicateCertificate(_In_ PCCERT_CONTEXT lpCertCtx)
{
  return (lpCertCtx != NULL && fnCertDuplicateCertificateContext != NULL)
         ? fnCertDuplicateCertificateContext(lpCertCtx) : NULL;
}

HRESULT GetCertificateName(_In_ PCCERT_CONTEXT lpCertCtx, DWORD dwType, _Inout_ CStringW &cStrNameW,
                           _In_opt_ BOOL bFromIssuer)
{
  DWORD dwFlags;
  SIZE_T i, nLen;
  LPWSTR sW;

  cStrNameW.Empty();
  if (lpCertCtx == NULL)
    return E_POINTER;
  dwFlags = (bFromIssuer != FALSE) ? CERT_NAME_ISSUER_FLAG : 0;
#pragma warning(suppress: 6387)
  nLen = (SIZE_T)fnCertGetNameStringW(lpCertCtx, dwType, dwFlags, NULL, NULL, 0);
  if (cStrNameW.EnsureBuffer(nLen + 4) == FALSE)
    return E_OUTOFMEMORY;
  nLen = (SIZE_T)fnCertGetNameStringW(lpCertCtx, dwType, dwFlags, NULL, (LPWSTR)cStrNameW, (DWORD)nLen + 2);
  ((LPWSTR)cStrNameW)[nLen] = 0;
  cStrNameW.Refresh();

  sW = (LPWSTR)cStrNameW;
  for (i=0; i<nLen; i++)
  {
    if (sW[i] < 32)
      sW[i] = 32;
  }
  for (i=0; i<nLen && sW[i]==32; i++);
  if (i > 0)
  {
    cStrNameW.Delete(0, i);
    sW = (LPWSTR)cStrNameW;
    nLen = cStrNameW.GetLength();
  }
  i = nLen;
  while (i>0 && sW[i-1] == 32)
    i--;
  if (i < nLen)
    cStrNameW.Delete(i, nLen - i);
  //done
  return S_OK;
}

HRESULT GetCertificateSerialNumber(_In_ PCCERT_CONTEXT lpCertCtx, _Out_ LPBYTE *lplpSerialNumber,
                                   _Out_ PSIZE_T lpnSerialNumberLength)
{
  if (lplpSerialNumber != NULL)
    *lplpSerialNumber = NULL;
  if (lpnSerialNumberLength != NULL)
    *lpnSerialNumberLength = 0;
  if (lpCertCtx == NULL || lplpSerialNumber == NULL || lpnSerialNumberLength == NULL)
    return E_POINTER;
  *lplpSerialNumber = (LPBYTE)MX_MALLOC((SIZE_T)(lpCertCtx->pCertInfo->SerialNumber.cbData));
  if ((*lplpSerialNumber) == NULL)
    return E_OUTOFMEMORY;
  ::MxMemCopy(*lplpSerialNumber, lpCertCtx->pCertInfo->SerialNumber.pbData,
          (SIZE_T)(lpCertCtx->pCertInfo->SerialNumber.cbData));
  *lpnSerialNumberLength = (SIZE_T)(lpCertCtx->pCertInfo->SerialNumber.cbData);
  return S_OK;
}

HRESULT CalculateHashes(_In_z_ LPCWSTR szFileNameW, _In_opt_ HANDLE hFile, _In_opt_ HANDLE hCancelEvent,
                        _Out_ LPHASHES lpHashes)
{
  CWindowsHandle cFileH, cReadCompletedEventH;
  CMessageDigest cHashSha256, cHashSha1, cHashMd5;
  HRESULT hRes;

  if (lpHashes != NULL)
    ::MxMemSet(lpHashes, 0, sizeof(HASHES));
  if (szFileNameW == NULL || lpHashes == NULL)
    return E_POINTER;
  if (*szFileNameW == 0)
    return E_INVALIDARG;

  cReadCompletedEventH.Attach(::CreateEventW(NULL, FALSE, FALSE, NULL));
  if (!cReadCompletedEventH)
    return MX_HRESULT_FROM_LASTERROR();

  if (hFile == NULL)
  {
    hRes = FileRoutines::OpenFileWithEscalatingSharing(szFileNameW, &cFileH);
    if (FAILED(hRes))
      return hRes;
    hFile = cFileH.Get();
  }

  hRes = cHashSha256.BeginDigest(CMessageDigest::AlgorithmSHA256);
  if (SUCCEEDED(hRes))
  {
    hRes = cHashSha1.BeginDigest(CMessageDigest::AlgorithmSHA1);
    if (SUCCEEDED(hRes))
      hRes = cHashMd5.BeginDigest(CMessageDigest::AlgorithmMD5);
  }

  if (SUCCEEDED(hRes))
  {
    BYTE aBlock[8192];
    DWORD dwCancelCheckCounter;
    MX_IO_STATUS_BLOCK sIoStatus;
    ULARGE_INTEGER uliOffset;
    HANDLE hEvents[2];
    NTSTATUS nNtStatus;

    hEvents[0] = cReadCompletedEventH.Get();
    hEvents[1] = hCancelEvent;

    dwCancelCheckCounter = 0;
    uliOffset.QuadPart = 0ui64;
    do
    {
      if ((++dwCancelCheckCounter) >= 16)
      {
        dwCancelCheckCounter = 0;
        if (::WaitForSingleObject(hCancelEvent, 0) == WAIT_OBJECT_0)
        {
          hRes = MX_E_Cancelled;
          break;
        }
      }

      ::MxMemSet(&sIoStatus, 0, sizeof(sIoStatus));
      nNtStatus = ::MxNtReadFile(hFile, hEvents[0], NULL, NULL, &sIoStatus, aBlock, (ULONG)sizeof(aBlock),
                                 (PLARGE_INTEGER)&uliOffset, NULL);
      if (nNtStatus == STATUS_PENDING)
      {
        if (hCancelEvent != NULL)
        {
          nNtStatus = ::MxNtWaitForMultipleObjects(2, hEvents, 1/*WaitAnyObject*/, FALSE, NULL);
          if (nNtStatus == STATUS_WAIT_0)
          {
            nNtStatus = sIoStatus.Status;
          }
          else if (nNtStatus == STATUS_WAIT_0 + 1)
          {
            hRes = MX_E_Cancelled;
            break;
          }
          else if (NT_SUCCESS(nNtStatus))
          {
            hRes = E_FAIL;
            break;
          }
        }
        else
        {
          nNtStatus = ::MxNtWaitForSingleObject(hEvents[0], FALSE, NULL);
          if (NT_SUCCESS(nNtStatus))
            nNtStatus = sIoStatus.Status;
        }
      }
      if (nNtStatus == STATUS_END_OF_FILE)
      {
        hRes = MX_E_EndOfFileReached;
        break;
      }
      if (!NT_SUCCESS(nNtStatus))
      {
        hRes = MX_HRESULT_FROM_WIN32(::MxRtlNtStatusToDosError(nNtStatus));
        break;
      }

      if (sIoStatus.Information > 0)
      {
        uliOffset.QuadPart += (ULONGLONG)(sIoStatus.Information);

        hRes = cHashSha256.DigestStream(aBlock, (DWORD)(sIoStatus.Information));
        if (SUCCEEDED(hRes))
        {
          hRes = cHashSha1.DigestStream(aBlock, (DWORD)(sIoStatus.Information));
          if (SUCCEEDED(hRes))
            hRes = cHashMd5.DigestStream(aBlock, (DWORD)(sIoStatus.Information));
        }
        if (FAILED(hRes))
          break;
      }
    }
    while (sIoStatus.Information > 0);
    if (hRes == MX_E_EndOfFileReached)
      hRes = S_OK;

    if (SUCCEEDED(hRes))
      hRes = cHashSha256.EndDigest();
    if (SUCCEEDED(hRes))
      hRes = cHashSha1.EndDigest();
    if (SUCCEEDED(hRes))
      hRes = cHashMd5.EndDigest();
  }

  if (SUCCEEDED(hRes))
  {
    ::MxMemCopy(lpHashes->aSha256, cHashSha256.GetResult(), 32);
    ::MxMemCopy(lpHashes->aSha1, cHashSha1.GetResult(), 20);
    ::MxMemCopy(lpHashes->aMd5, cHashMd5.GetResult(), 16);
  }

  //done
  return hRes;
}

}; //namespace Signatures

}; //namespace MX

//-----------------------------------------------------------

static BOOL IsWinVistaPlus()
{
  static LONG volatile nIsWinVistaPlus = -1;
  LONG nIsWinVistaPlusLocal;

  nIsWinVistaPlusLocal = __InterlockedRead(&nIsWinVistaPlus);
  if (nIsWinVistaPlusLocal < 0)
  {
    nIsWinVistaPlusLocal = ::IsWindowsVistaOrGreater() ? 1 : 0;
    _InterlockedCompareExchange(&nIsWinVistaPlus, nIsWinVistaPlusLocal, -1);
  }
  return (nIsWinVistaPlusLocal == 1) ? TRUE : FALSE;
}

static VOID EndSignaturesAndInfo()
{
  if (hWinTrustDll != NULL)
  {
    ::FreeLibrary(hWinTrustDll);
    hWinTrustDll = NULL;
  }
  if (hCrypt32Dll != NULL)
  {
    ::FreeLibrary(hCrypt32Dll);
    hCrypt32Dll = NULL;
  }
  fnWinVerifyTrustEx = NULL;
  fnWTHelperProvDataFromStateData = NULL;
  fnWTHelperGetProvSignerFromChain = NULL;
  fnCertGetNameStringW = NULL;
  fnCertDuplicateCertificateContext = NULL;
  fnCertFreeCertificateContext = NULL;
  fnGetPackageFullName = NULL;
  fnGetPackagePath = NULL;
  fnPackageIdFromFullName = NULL;
  fnCryptCATAdminAcquireContext = NULL;
  fnCryptCATAdminAcquireContext2 = NULL;
  fnCryptCATAdminCalcHashFromFileHandle = NULL;
  fnCryptCATAdminCalcHashFromFileHandle2 = NULL;
  fnCryptCATAdminEnumCatalogFromHash = NULL;
  fnCryptCATAdminReleaseContext = NULL;
  fnCryptCATCatalogInfoFromContext = NULL;
  fnCryptCATAdminReleaseCatalogContext = NULL;
  //done
  return;
}

static HRESULT DoTrustVerification(_In_opt_z_ LPCWSTR szPeFileNameW, _In_opt_ HANDLE hFile, _In_ LPGUID lpActionId,
                                   _In_opt_ PWINTRUST_CATALOG_INFO lpCatalogInfo, _Out_ PCERT_CONTEXT *lplpCertCtx,
                                   _Out_ PFILETIME lpTimeStamp)
{
  WINTRUST_DATA sWtData;
  WINTRUST_FILE_INFO sWtFileInfo;
  DWORD dwRetryCount = 0;
  HRESULT hRes;

  *lplpCertCtx = NULL;
  lpTimeStamp->dwLowDateTime = lpTimeStamp->dwHighDateTime = 0;

restart:
  //verify PE's signature
  ::MxMemSet(&sWtData, 0, sizeof(sWtData));
  sWtData.cbStruct = (DWORD)sizeof(sWtData);
  sWtData.dwUIContext = WTD_UICONTEXT_EXECUTE;
  sWtData.dwUIChoice = WTD_UI_NONE;
  sWtData.fdwRevocationChecks = WTD_REVOKE_NONE; //no revocation checking.
  sWtData.dwStateAction = WTD_STATEACTION_VERIFY; //verify action
  sWtData.hWVTStateData = NULL; //verification sets this value
  sWtData.dwProvFlags = (IsWinVistaPlus() != FALSE) ? WTD_CACHE_ONLY_URL_RETRIEVAL : WTD_REVOCATION_CHECK_NONE;
  if (lpCatalogInfo != NULL)
  {
    sWtData.dwUnionChoice = WTD_CHOICE_CATALOG;
    sWtData.pCatalog = lpCatalogInfo;
  }
  else
  {
    sWtData.dwUnionChoice = WTD_CHOICE_FILE;
    sWtData.pFile = &sWtFileInfo;

    ::MxMemSet(&sWtFileInfo, 0, sizeof(sWtFileInfo));
    sWtFileInfo.cbStruct = (DWORD)sizeof(sWtFileInfo);
    sWtFileInfo.pcwszFilePath = szPeFileNameW;
    sWtFileInfo.hFile = hFile;
  }

  hRes = MX_HRESULT_FROM_WIN32(fnWinVerifyTrustEx((HWND)INVALID_HANDLE_VALUE, lpActionId, &sWtData));
  if (hRes == E_OUTOFMEMORY)
    goto done;
  if (sWtData.hWVTStateData != NULL)
  {
    PCRYPT_PROVIDER_DATA lpProvData = NULL;
    PCRYPT_PROVIDER_SGNR lpProvSigner = NULL;
    DWORD dw;

    lpProvData = fnWTHelperProvDataFromStateData(sWtData.hWVTStateData);
    if (lpProvData != NULL)
    {
      for (dw = 0; ; dw++)
      {
        lpProvSigner = fnWTHelperGetProvSignerFromChain(lpProvData, dw, FALSE, 0);
        if (lpProvSigner == NULL)
          break;
        if (lpProvSigner->pasCertChain != NULL && lpProvSigner->pasCertChain->pCert != NULL)
        {
          HRESULT hResKnownExploit;

          hResKnownExploit = CheckKnownExploits(lpProvSigner->pasCertChain->pCert, hRes);
          if (hResKnownExploit != S_FALSE)
          {
            hRes = hResKnownExploit;
            goto done;
          }

          *lplpCertCtx = (PCERT_CONTEXT)fnCertDuplicateCertificateContext(lpProvSigner->pasCertChain->pCert);
          if ((*lplpCertCtx) == NULL)
          {
            hRes = E_OUTOFMEMORY;
            goto done;
          }

          if (lpProvSigner->sftVerifyAsOf.dwHighDateTime != 0 || lpProvSigner->sftVerifyAsOf.dwLowDateTime != 0)
            *lpTimeStamp = lpProvSigner->sftVerifyAsOf;
          else
            ::GetSystemTimeAsFileTime(lpTimeStamp);
          break;
        }
      }
    }
  }

  if ((*lplpCertCtx) == NULL)
    hRes = TRUST_E_NOSIGNATURE;

done:
  //close the verifier
  sWtData.dwStateAction = WTD_STATEACTION_CLOSE;
  fnWinVerifyTrustEx((HWND)INVALID_HANDLE_VALUE, lpActionId, &sWtData);

  if (hRes == HRESULT_FROM_WIN32(ERROR_LOCK_VIOLATION) && dwRetryCount < READ_RETRIES_COUNT)
  {
    if ((*lplpCertCtx) != NULL)
    {
      fnCertFreeCertificateContext(*lplpCertCtx);
      *lplpCertCtx = NULL;
    }
    dwRetryCount++;
    ::Sleep(READ_RETRIES_DELAY_MS);
    goto restart;
  }
  return hRes;
}

static HRESULT CheckKnownExploits(_In_ PCCERT_CONTEXT pCert, _In_ HRESULT hOriginalRes)
{
  //CHECK CVE-2020-0601
  if (pCert->pCertInfo != NULL && pCert->pCertInfo->SignatureAlgorithm.pszObjId != NULL &&
      (MX::StrNCompareA(pCert->pCertInfo->SignatureAlgorithm.pszObjId, "1.2.840.10045.", 14) == 0 || //szOID_ECDSA_###
       MX::StrNCompareA(pCert->pCertInfo->SignatureAlgorithm.pszObjId, "1.3.132.0.", 10) == 0)) //szOID_ECC_CURVE_###
  {
    if (::IsWindows10OrGreater() != FALSE)
    {
      if (CompareVersion(sWinTrustDllVersion.wProductVersion, 10, 0, 18362, 592) < 0)
      {
        return MX_E_TRUST_FAILED_CVE_2020_0601;
      }
      else if (hOriginalRes == CERT_E_UNTRUSTEDROOT)
      {
        return MX_E_TRUST_FAILED_CVE_2020_0601;
      }
    }
    else
    {
      if (hOriginalRes == CERT_E_UNTRUSTEDROOT)
      {
        return MX_E_TRUST_FAILED_CVE_2020_0601;
      }
    }
  }
  return S_FALSE;
}

static int CompareVersion(_In_ LPWORD lpwVersion, _In_ WORD wMajor, _In_ WORD wMinor, _In_ WORD wRelease,
                          _In_ WORD wBuild)
{
  if (lpwVersion[0] < wMajor)
    return -1;
  if (lpwVersion[0] > wMajor)
    return 1;
  //---
  if (lpwVersion[1] < wMinor)
    return -1;
  if (lpwVersion[1] > wMinor)
    return 1;
  //---
  if (lpwVersion[2] < wRelease)
    return -1;
  if (lpwVersion[2] > wRelease)
    return 1;
  //---
  if (lpwVersion[3] < wBuild)
    return -1;
  if (lpwVersion[3] > wBuild)
    return 1;
  //---
  return 0;
}
