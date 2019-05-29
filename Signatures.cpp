#include "Signatures.h"
#include "FileRoutines.h"
#include <AutoPtr.h>
#include <LinkedList.h>
#include <FnvHash.h>
#include <Strings\Strings.h>
#include <Crypto\DigestAlgorithmSHAx.h>
#include <Crypto\DigestAlgorithmMDx.h>
#include <appmodel.h>
#include <WinTrust.h>
#include <mscat.h>
#include <VersionHelpers.h>
#include <Finalizer.h>

//-----------------------------------------------------------

#define READ_RETRIES_COUNT                               200
#define READ_RETRIES_DELAY_MS                             15

#define MAX_FILE_SIZE_FOR_CATALOG_CHECK  100ui64*1048576ui64

#define MAX_CACHED_ITEMS                                4096

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

namespace MX {

namespace Signatures {

namespace Internals {

class CCachedItem : public CBaseMemObj, public TLnkLstNode<CCachedItem>
{
public:
  CCachedItem() :  CBaseMemObj(), TLnkLstNode<CCachedItem>()
    {
    nFileNameHash = 0ui64;
    MemSet(&sFtLastCreated, 0, sizeof(sFtLastCreated));
    MemSet(&sFtLastModified, 0, sizeof(sFtLastModified));
    liFileSize.QuadPart = 0ui64;
    MemSet(&sCertificate, 0, sizeof(sCertificate));
    MemSet(&sHashes, 0, sizeof(sHashes));
    return;
    };

  ~CCachedItem()
    {
    Reset();
    return;
    };

  VOID Reset()
    {
    if (sCertificate.lpCertCtx != NULL)
      fnCertFreeCertificateContext(sCertificate.lpCertCtx);
    nFileNameHash = 0ui64;
    MemSet(&sFtLastCreated, 0, sizeof(sFtLastCreated));
    MemSet(&sFtLastModified, 0, sizeof(sFtLastModified));
    liFileSize.QuadPart = 0ui64;
    MemSet(&sCertificate, 0, sizeof(sCertificate));
    MemSet(&sHashes, 0, sizeof(sHashes));
    return;
    };

public:
  Fnv64_t nFileNameHash;
  FILETIME sFtLastCreated;
  FILETIME sFtLastModified;
  LARGE_INTEGER liFileSize;
  struct {
    BOOL bHasValues;
    FILETIME sFtTimeStamp;
    PCERT_CONTEXT lpCertCtx;
    HRESULT hRes;
  } sCertificate;
  struct {
    BOOL bHasValues;
    HASHES sValues;
  } sHashes;
};

static struct {
  LONG volatile nMutex = 0;
  TLnkLst<CCachedItem> aInUseList, aFreeList;
  SIZE_T nCreatedItemsCount = 0;
  struct {
    CCachedItem** lpList;
    SIZE_T nCount;
  } sInUseSortedByName = { NULL, 0 };
} sCachedItems;

}; //namespace Internals

}; //namespace Signatures

}; //namespace MX

//-----------------------------------------------------------

static BOOL IsWinVistaPlus();

static VOID EndSignaturesAndInfo();

static HRESULT DoTrustVerification(_In_opt_z_ LPCWSTR szPeFileNameW, _In_opt_ HANDLE hFile, _In_ LPGUID lpActionId,
                                   _In_opt_ PWINTRUST_CATALOG_INFO lpCatalogInfo, _Out_ PCERT_CONTEXT *lplpCertCtx,
                                   _Out_ PFILETIME lpTimeStamp);

namespace MX {

namespace Signatures {

namespace Internals {

static CCachedItem* AddCachedItem(_In_z_ LPCWSTR szPeFileNameW, _In_ HANDLE hFile);

static VOID RemoveCachedItem(_In_z_ LPCWSTR szPeFileNameW);
static VOID RemoveCachedItemByHash(_In_ Fnv64_t nFileNameHash);
static VOID RemoveCachedItemByIndex(_In_ SIZE_T nIndex);

static CCachedItem* FindCachedItem(_In_z_ LPCWSTR szPeFileNameW, _In_ HANDLE hFile);

static SIZE_T GetCachedItemIndex(_In_ Fnv64_t nFileNameHash);

}; //namespace Internals

}; //namespace Signatures

}; //namespace MX

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

  _InterlockedExchange(&(Internals::sCachedItems.nMutex), 0);

  _EXPAND_W(strW_WinTrustDll);
  hWinTrustDll = ::LoadLibraryW(szTempW);
  _EXPAND_W(strW_Crypt32Dll);
  hCrypt32Dll = ::LoadLibraryW(szTempW);
  if (hWinTrustDll != NULL)
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
  if (hCrypt32Dll != NULL)
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
  //----
  if (SUCCEEDED(hRes))
  {
    Internals::sCachedItems.sInUseSortedByName.lpList = (Internals::CCachedItem**)MX_MALLOC(MAX_CACHED_ITEMS *
                                                                                  sizeof(Internals::CCachedItem*));
    if (Internals::sCachedItems.sInUseSortedByName.lpList == NULL)
      hRes = E_OUTOFMEMORY;
  }
  //register finalizer
  if (SUCCEEDED(hRes))
  {
    hRes = RegisterFinalizer(&EndSignaturesAndInfo, 3);
  }
  //done
  if (FAILED(hRes))
    EndSignaturesAndInfo();
  MemSet(szTempA, 0, sizeof(szTempA));
  MemSet(szTempW, 0, sizeof(szTempW));
  return hRes;
}

HRESULT GetPeSignature(_In_z_ LPCWSTR szPeFileNameW, _In_opt_ HANDLE hFile, _In_opt_ HANDLE hProcess,
                       _Out_ PCERT_CONTEXT *lplpCertCtx, _Out_ PFILETIME lpTimeStamp, _In_opt_ BOOL bIgnoreCache)
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

  if (bIgnoreCache == FALSE)
  {
    CFastLock cLock(&(Internals::sCachedItems.nMutex));
    Internals::CCachedItem *lpCachedItem;

    lpCachedItem = Internals::FindCachedItem(szPeFileNameW, hFile);
    if (lpCachedItem != NULL)
    {
      if (lpCachedItem->sCertificate.bHasValues != FALSE)
      {
        if (lpCachedItem->sCertificate.lpCertCtx != NULL)
        {
          *lplpCertCtx = (PCERT_CONTEXT)fnCertDuplicateCertificateContext(lpCachedItem->sCertificate.lpCertCtx);
          if ((*lplpCertCtx) == NULL)
            return E_OUTOFMEMORY;
        }
        MemCopy(lpTimeStamp, &(lpCachedItem->sCertificate.sFtTimeStamp),
                sizeof(lpCachedItem->sCertificate.sFtTimeStamp));
        return lpCachedItem->sCertificate.hRes;
      }
    }
  }

  //if we reach here, cache is not valid or does not contains the certificate
  if (hProcess != NULL && fnGetPackageFullName != NULL)
  {
    TAutoFreePtr<PACKAGE_ID> aPackageId;
    UINT32 dwLen;

    if (cStrPackageFullPathW.EnsureBuffer(1024 + 4) == FALSE)
    {
      hRes = E_OUTOFMEMORY;
      goto done;
    }
    dwLen = 1024;
    hRes = MX_HRESULT_FROM_WIN32(fnGetPackageFullName(hProcess, &dwLen, (LPWSTR)cStrPackageFullPathW));
    if (hRes == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER))
    {
      if (cStrPackageFullPathW.EnsureBuffer((SIZE_T)dwLen + 4) == FALSE)
      {
        hRes = E_OUTOFMEMORY;
        goto done;
      }
      hRes = MX_HRESULT_FROM_WIN32(fnGetPackageFullName(hProcess, &dwLen, (LPWSTR)cStrPackageFullPathW));
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

  //verify PE's signature
  if (::SetFilePointer(hFile, 0, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER)
  {
    hRes = DoTrustVerification(szPeFileNameW, hFile, &sWVTPolicyGuid, NULL, lplpCertCtx, lpTimeStamp);
    if (hRes == E_OUTOFMEMORY)
      goto done;
  }
  else
  {
    hRes = MX_HRESULT_FROM_LASTERROR();
  }

  if (hRes == S_FALSE && fnCryptCATAdminAcquireContext != NULL)
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
        hRes = S_OK;
        if (nPass == 1)
        {
          //CERT_STRONG_SIGN_PARA sSigningPolicy = {};

          if (fnCryptCATAdminAcquireContext2 == NULL)
            continue;
          //MemSet(&sSigningPolicy, 0, sizeof(sSigningPolicy));
          //sSigningPolicy.cbSize = (DWORD)sizeof(sSigningPolicy);
          //sSigningPolicy.dwInfoChoice = CERT_STRONG_SIGN_OID_INFO_CHOICE;
          //sSigningPolicy.pszOID = szOID_CERT_STRONG_SIGN_OS_CURRENT;
          if (fnCryptCATAdminAcquireContext2(&hCatAdmin, &sDriverActionVerify, BCRYPT_SHA256_ALGORITHM, NULL, 0) == FALSE)
            hRes = MX_HRESULT_FROM_LASTERROR();
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

              if (fnCryptCATCatalogInfoFromContext(hCatInfo, &sCi, 0) != FALSE)
              {
                MemSet(&sDrvVerInfo, 0, sizeof(sDrvVerInfo));
                sDrvVerInfo.cbStruct = (DWORD)sizeof(DRIVER_VER_INFO);

                MemSet(&sCatInfo, 0, sizeof(sCatInfo));
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
                hRes = S_FALSE;
              }
              fnCryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            }
            else if (cStrPackageFullPathW.IsEmpty() == FALSE)
            {
              MemSet(&sCatInfo, 0, sizeof(sCatInfo));
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
              hRes = S_FALSE;
            }
          }
        }

        if (hCatAdmin != NULL)
          fnCryptCATAdminReleaseContext(hCatAdmin, 0);

        //break only if a certificate is found or a hard error
        if (hRes != S_FALSE)
          break;
      }
    }
  }

  //when we get here, we have to add the certificate to the cache store
  if (hRes != E_OUTOFMEMORY)
  {
    if (hRes == S_FALSE)
      hRes = TRUST_E_NOSIGNATURE;

    if (bIgnoreCache == FALSE)
    {
      CFastLock cLock(&(Internals::sCachedItems.nMutex));
      Internals::CCachedItem *lpCachedItem;

      lpCachedItem = Internals::FindCachedItem(szPeFileNameW, hFile);
      if (lpCachedItem != NULL)
      {
        //another thread (re)created a cached item in parallel
        if (lpCachedItem->sCertificate.bHasValues == FALSE)
        {
          if ((*lplpCertCtx) != NULL)
          {
            lpCachedItem->sCertificate.lpCertCtx = (PCERT_CONTEXT)fnCertDuplicateCertificateContext(*lplpCertCtx);
            if (lpCachedItem->sCertificate.lpCertCtx == NULL)
            {
              fnCertFreeCertificateContext(*lplpCertCtx);
              *lplpCertCtx = NULL;
              MemSet(lpTimeStamp, 0, sizeof(FILETIME));
              hRes = E_OUTOFMEMORY;
              goto done;
            }
          }
          MemCopy(&(lpCachedItem->sCertificate.sFtTimeStamp), lpTimeStamp, sizeof(FILETIME));
          lpCachedItem->sCertificate.hRes = hRes;

          lpCachedItem->sCertificate.bHasValues = TRUE;
        }
      }
      else
      {
        lpCachedItem = Internals::AddCachedItem(szPeFileNameW, hFile);
        if (lpCachedItem == NULL)
        {
          //couldn't create a new item??? Give up with an error
          fnCertFreeCertificateContext(*lplpCertCtx);
          *lplpCertCtx = NULL;
          MemSet(lpTimeStamp, 0, sizeof(FILETIME));
          hRes = E_OUTOFMEMORY;
          goto done;
        }

        if ((*lplpCertCtx) != NULL)
        {
          lpCachedItem->sCertificate.lpCertCtx = (PCERT_CONTEXT)fnCertDuplicateCertificateContext(*lplpCertCtx);
          if (lpCachedItem->sCertificate.lpCertCtx == NULL)
          {
            Internals::RemoveCachedItemByHash(lpCachedItem->nFileNameHash);

            fnCertFreeCertificateContext(*lplpCertCtx);
            *lplpCertCtx = NULL;
            MemSet(lpTimeStamp, 0, sizeof(FILETIME));
            hRes = E_OUTOFMEMORY;
            goto done;
          }
        }
        MemCopy(&(lpCachedItem->sCertificate.sFtTimeStamp), lpTimeStamp, sizeof(FILETIME));
        lpCachedItem->sCertificate.hRes = hRes;

        lpCachedItem->sCertificate.bHasValues = TRUE;
      }
    }
  }

  //done
done:
  return hRes;
}

VOID FreeCertificate(_In_opt_ PCERT_CONTEXT lpCertCtx)
{
  if (lpCertCtx != NULL && fnCertFreeCertificateContext != NULL)
  {
    fnCertFreeCertificateContext(lpCertCtx);
  }
  return;
}

HRESULT GetCertificateName(_In_ PCERT_CONTEXT lpCertCtx, DWORD dwType, _Inout_ CStringW &cStrNameW,
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

HRESULT GetCertificateSerialNumber(_In_ PCERT_CONTEXT lpCertCtx, _Out_ LPBYTE *lplpSerialNumber,
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
  MemCopy(*lplpSerialNumber, lpCertCtx->pCertInfo->SerialNumber.pbData,
          (SIZE_T)(lpCertCtx->pCertInfo->SerialNumber.cbData));
  *lpnSerialNumberLength = (SIZE_T)(lpCertCtx->pCertInfo->SerialNumber.cbData);
  return S_OK;
}

HRESULT CalculateHashes(_In_z_ LPCWSTR szFileNameW, _In_opt_ HANDLE hFile, _Out_ LPHASHES lpHashes,
                        _In_opt_ BOOL bIgnoreCache)
{
  CWindowsHandle cFileH;
  CDigestAlgorithmSecureHash cHashSha256, cHashSha1;
  CDigestAlgorithmMessageDigest cHashMd5;
  HRESULT hRes;

  if (lpHashes != NULL)
    MemSet(lpHashes, 0, sizeof(HASHES));
  if (szFileNameW == NULL || lpHashes == NULL)
    return E_POINTER;
  if (*szFileNameW == 0)
    return E_INVALIDARG;

  if (hFile == NULL)
  {
    hRes = FileRoutines::OpenFileWithEscalatingSharing(szFileNameW, &cFileH);
    if (FAILED(hRes))
      return hRes;
    hFile = cFileH.Get();
  }

  if (bIgnoreCache == FALSE)
  {
    CFastLock cLock(&(Internals::sCachedItems.nMutex));
    Internals::CCachedItem *lpCachedItem;

    lpCachedItem = Internals::FindCachedItem(szFileNameW, cFileH);
    if (lpCachedItem != NULL)
    {
      if (lpCachedItem->sHashes.bHasValues != FALSE)
      {
        MemCopy(lpHashes, &(lpCachedItem->sHashes.sValues), sizeof(lpCachedItem->sHashes.sValues));
        return S_OK;
      }
    }
  }

  hRes = cHashSha256.BeginDigest(CDigestAlgorithmSecureHash::AlgorithmSHA256);
  if (SUCCEEDED(hRes))
    hRes = cHashSha1.BeginDigest(CDigestAlgorithmSecureHash::AlgorithmSHA1);
  if (SUCCEEDED(hRes))
    hRes = cHashMd5.BeginDigest(CDigestAlgorithmMessageDigest::AlgorithmMD5);

  if (SUCCEEDED(hRes))
  {
    if (::SetFilePointer(hFile, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
      hRes = MX_HRESULT_FROM_LASTERROR();
  }
  if (SUCCEEDED(hRes))
  {
    BYTE aBlock[8192];
    DWORD dwRead;

    do
    {
      dwRead = 0;
      if (::ReadFile(hFile, aBlock, (DWORD)sizeof(aBlock), &dwRead, NULL) == FALSE)
      {
        hRes = MX_HRESULT_FROM_LASTERROR();
        break;
      }
      if (dwRead > 0)
      {
        hRes = cHashSha256.DigestStream(aBlock, dwRead);
        if (SUCCEEDED(hRes))
        {
          hRes = cHashSha1.DigestStream(aBlock, dwRead);
          if (SUCCEEDED(hRes))
            hRes = cHashMd5.DigestStream(aBlock, dwRead);
        }
        if (FAILED(hRes))
          break;
      }
    }
    while (dwRead > 0);
    if (hRes == HRESULT_FROM_WIN32(ERROR_HANDLE_EOF))
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
    MemCopy(lpHashes->aSha256, cHashSha256.GetResult(), 32);
    MemCopy(lpHashes->aSha1, cHashSha1.GetResult(), 20);
    MemCopy(lpHashes->aMd5, cHashMd5.GetResult(), 16);

    if (bIgnoreCache == FALSE)
    {
      CFastLock cLock(&(Internals::sCachedItems.nMutex));
      Internals::CCachedItem *lpCachedItem;

      //when we get here, we have to add the certificate to the cache store
      lpCachedItem = Internals::FindCachedItem(szFileNameW, hFile);
      if (lpCachedItem != NULL)
      {
        //another thread (re)created a cached item in parallel
        if (lpCachedItem->sHashes.bHasValues == FALSE)
        {
          MemCopy(&(lpCachedItem->sHashes.sValues), lpHashes, sizeof(lpCachedItem->sHashes.sValues));

          lpCachedItem->sHashes.bHasValues = TRUE;
        }
      }
      else
      {
        lpCachedItem = Internals::AddCachedItem(szFileNameW, hFile);
        if (lpCachedItem != NULL)
        {
          MemCopy(&(lpCachedItem->sHashes.sValues), lpHashes, sizeof(lpCachedItem->sHashes.sValues));

          lpCachedItem->sHashes.bHasValues = TRUE;
        }
        else
        {
          MemSet(lpHashes, 0, sizeof(HASHES));
          hRes = E_OUTOFMEMORY;
        }
      }
    }
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
    _InterlockedCompareExchange(&nIsWinVistaPlusLocal, nIsWinVistaPlusLocal, -1);
  }
  return (nIsWinVistaPlusLocal == 1) ? TRUE : FALSE;
}

static VOID EndSignaturesAndInfo()
{
  MX::CFastLock cLock(&(MX::Signatures::Internals::sCachedItems.nMutex));
  MX::Signatures::Internals::CCachedItem *lpItem;

  MX_FREE(MX::Signatures::Internals::sCachedItems.sInUseSortedByName.lpList);
  while ((lpItem = MX::Signatures::Internals::sCachedItems.aFreeList.PopHead()) != NULL)
  {
    delete lpItem;
  }
  while ((lpItem = MX::Signatures::Internals::sCachedItems.aInUseList.PopHead()) != NULL)
  {
    delete lpItem;
  }
  MX::Signatures::Internals::sCachedItems.nCreatedItemsCount = 0;
  //----
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
  MX::MemSet(&sWtData, 0, sizeof(sWtData));
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

    MX::MemSet(&sWtFileInfo, 0, sizeof(sWtFileInfo));
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
    hRes = S_FALSE;

done:
  //close the verifier
  sWtData.dwStateAction = WTD_STATEACTION_CLOSE;
  fnWinVerifyTrustEx((HWND)INVALID_HANDLE_VALUE, lpActionId, &sWtData);

  if (hRes == HRESULT_FROM_WIN32(ERROR_LOCK_VIOLATION) && dwRetryCount < READ_RETRIES_COUNT)
  {
    dwRetryCount++;
    ::Sleep(READ_RETRIES_DELAY_MS);
    goto restart;
  }
  return hRes;
}

namespace MX {

namespace Signatures {

namespace Internals {

static CCachedItem* AddCachedItem(_In_z_ LPCWSTR szPeFileNameW, _In_ HANDLE hFile)
{
  CCachedItem *lpNewItem, *lpCachedItem;
  SIZE_T nIndex, nMin, nMax;

  lpNewItem = sCachedItems.aFreeList.PopHead();
  if (lpNewItem == NULL && sCachedItems.nCreatedItemsCount < MAX_CACHED_ITEMS)
  {
    //no free items but still room to create entries
    lpNewItem = MX_DEBUG_NEW CCachedItem();
    if (lpNewItem != NULL)
      (sCachedItems.nCreatedItemsCount)++;
  }
  if (lpNewItem == NULL)
  {
    //no free items, then take the less recently used one
    lpNewItem = sCachedItems.aInUseList.GetTail();
    if (lpNewItem == NULL)
      return NULL;
    RemoveCachedItemByHash(lpNewItem->nFileNameHash);

    lpNewItem = sCachedItems.aFreeList.PopHead();
    MX_ASSERT(lpNewItem != NULL);
  }

  //set the item key
  lpNewItem->nFileNameHash = fnv_64a_buf(szPeFileNameW, StrLenW(szPeFileNameW) * 2, FNV1A_64_INIT);

  //insert the item in the in-use list
  sCachedItems.aInUseList.PushHead(lpNewItem);

  //insert the item in the sorted by name in-use list
  nMin = 1; //shifted by one to avoid problems with negative indexes
  nMax = sCachedItems.sInUseSortedByName.nCount; //if count == 0, loop will not enter
  MX_ASSERT(nMax < MAX_CACHED_ITEMS);
  while (nMin <= nMax)
  {
    nIndex = nMin + (nMax - nMin) / 2;
    
    lpCachedItem = sCachedItems.sInUseSortedByName.lpList[nIndex - 1];
    if (lpNewItem->nFileNameHash == lpCachedItem->nFileNameHash)
    {
      nMin = nIndex;
      break;
    }
    if (lpNewItem->nFileNameHash < lpCachedItem->nFileNameHash)
      nMax = nIndex - 1;
    else
      nMin = nIndex + 1;
  }
  nIndex = nMin - 1;

  MemMove(&(sCachedItems.sInUseSortedByName.lpList[nIndex+1]), &(sCachedItems.sInUseSortedByName.lpList[nIndex]),
          (sCachedItems.sInUseSortedByName.nCount - nIndex) * sizeof(CCachedItem*));
  sCachedItems.sInUseSortedByName.lpList[nIndex] = lpNewItem;
  (sCachedItems.sInUseSortedByName.nCount)++;

  //set file times
  if (::GetFileTime(hFile, &(lpNewItem->sFtLastCreated), NULL, &(lpNewItem->sFtLastModified)) == FALSE)
  {
    MemSet(&(lpNewItem->sFtLastCreated), 0, sizeof(lpNewItem->sFtLastCreated));
    MemSet(&(lpNewItem->sFtLastModified), 0, sizeof(lpNewItem->sFtLastModified));
  }
  if (::GetFileSizeEx(hFile, &(lpNewItem->liFileSize)) == FALSE)
  {
    lpNewItem->liFileSize.QuadPart = 0ui64;
  }

  //done
  return lpNewItem;
}

static VOID RemoveCachedItem(_In_z_ LPCWSTR szPeFileNameW)
{
  RemoveCachedItemByHash(fnv_64a_buf(szPeFileNameW, StrLenW(szPeFileNameW) * 2, FNV1A_64_INIT));
  return;
}

static VOID RemoveCachedItemByHash(_In_ Fnv64_t nFileNameHash)
{
  SIZE_T nIndex;

  nIndex = GetCachedItemIndex(nFileNameHash);
  if (nIndex != (SIZE_T)-1)
  {
    RemoveCachedItemByIndex(nIndex);
  }
  return;
}

static VOID RemoveCachedItemByIndex(_In_ SIZE_T nIndex)
{
  CCachedItem *lpFoundItem = sCachedItems.sInUseSortedByName.lpList[nIndex];

  //remove from sorted by name list
  (sCachedItems.sInUseSortedByName.nCount)--;
  MemMove(&(sCachedItems.sInUseSortedByName.lpList[nIndex]), &(sCachedItems.sInUseSortedByName.lpList[nIndex + 1]),
          (sCachedItems.sInUseSortedByName.nCount - nIndex) * sizeof(CCachedItem*));

  //move from in-use list to the free list
  MX_ASSERT(lpFoundItem->GetLinkedList() == &(sCachedItems.aInUseList));
  lpFoundItem->RemoveNode();
  sCachedItems.aFreeList.PushTail(lpFoundItem);

  lpFoundItem->Reset();
  return;
}

static CCachedItem* FindCachedItem(_In_z_ LPCWSTR szPeFileNameW, _In_ HANDLE hFile)
{
  CCachedItem *lpFoundItem = NULL;
  SIZE_T nIndex;
  FILETIME sFtCreationTime, sFtLastWriteTime;
  LARGE_INTEGER liFileSize;

  //get cached item
  nIndex =  GetCachedItemIndex(fnv_64a_buf(szPeFileNameW, StrLenW(szPeFileNameW) * 2, FNV1A_64_INIT));
  if (nIndex != (SIZE_T)-1)
  {
    lpFoundItem = sCachedItems.sInUseSortedByName.lpList[nIndex];

    //check if file was changed
    if (::GetFileTime(hFile, &sFtCreationTime, NULL, &sFtLastWriteTime) != FALSE &&
        ::GetFileSizeEx(hFile, &liFileSize) != FALSE &&
        sFtCreationTime.dwHighDateTime == lpFoundItem->sFtLastCreated.dwHighDateTime &&
        sFtCreationTime.dwLowDateTime == lpFoundItem->sFtLastCreated.dwLowDateTime &&
        sFtLastWriteTime.dwHighDateTime == lpFoundItem->sFtLastModified.dwHighDateTime &&
        sFtLastWriteTime.dwLowDateTime == lpFoundItem->sFtLastModified.dwLowDateTime &&
        liFileSize.QuadPart == lpFoundItem->liFileSize.QuadPart)
    {
      //cached item is valid, move to top of the in-use list
      lpFoundItem->RemoveNode();
      sCachedItems.aInUseList.PushHead(lpFoundItem);
    }
    else
    {
      //invalid, remove from the list
      RemoveCachedItemByIndex(nIndex);
      lpFoundItem = NULL;
    }
  }
  return lpFoundItem;
}

static SIZE_T GetCachedItemIndex(_In_ Fnv64_t nFileNameHash)
{
  CCachedItem *lpCachedItem;
  SIZE_T nMid, nMin, nMax;

  nMin = 1; //shifted by one to avoid problems with negative indexes
  nMax = sCachedItems.sInUseSortedByName.nCount; //if count == 0, loop will not enter
  while (nMin <= nMax)
  {
    nMid = nMin + (nMax - nMin) / 2;

    lpCachedItem = sCachedItems.sInUseSortedByName.lpList[nMid - 1];
    if (nFileNameHash == lpCachedItem->nFileNameHash)
      return nMid - 1;
    if (nFileNameHash < lpCachedItem->nFileNameHash)
      nMax = nMid - 1;
    else
      nMin = nMid + 1;
  }
  return (SIZE_T)-1;
}

}; //namespace Internals

}; //namespace Signatures

}; //namespace MX
