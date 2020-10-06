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
#ifndef _MXLIBHLP_CLOCK_CACHE_H
#define _MXLIBHLP_CLOCK_CACHE_H

#include <Defines.h>
#include <Windows.h>
#include <Strings\Strings.h>
#include <RedBlackTree.h>
#include <RefCounted.h>

#define MX_CLOCKCACHE_ENTRY_FLAG_Referenced           0x0001
#define MX_CLOCKCACHE_ENTRY_FLAG_Evicted              0x0002

#define MX_CLOCKCACHE_ENTRY_OFFSET_NotOnList     0x7FFFFFFFL

//-----------------------------------------------------------

namespace MX {

class CClockCache : public virtual CBaseMemObj, public CNonCopyableObj
{
public:
  class CValue : public TRefCounted<CBaseMemObj>, public CNonCopyableObj
  {
  private:
    CValue(_In_ LPCVOID lpData, _In_ SIZE_T nDataSize) : TRefCounted<CBaseMemObj>(), CNonCopyableObj()
      {
      this->nDataSize = 0;
      if (nDataSize > 0)
      {
        this->lpData = MX_MALLOC(nDataSize);
        if (this->lpData != NULL)
        {
          ::MxMemCopy(this->lpData, lpData, nDataSize);
          this->nDataSize = nDataSize;
        }
      }
      return;
      };

  public:
    ~CValue()
      {
      MX_FREE(lpData);
      return;
      };

    LPVOID GetData() const
      {
      return lpData;
      };

    SIZE_T GetDataSize() const
      {
      return nDataSize;
      };

  private:
    friend class CClockCache;

    LPVOID lpData;
    SIZE_T nDataSize;
  };

private:
  class CEntry : public TRefCounted<CBaseMemObj>, public CNonCopyableObj
  {
  private:
    CEntry(_In_ LPCSTR szKeyA, _In_ SIZE_T nKeyLen, _In_ DWORD dwExpireTimeMs) : TRefCounted<CBaseMemObj>(),
                                                                                 CNonCopyableObj()
      {
      SlimRWL_Initialize(&sRwValueLock);

      this->szKeyA = (LPCSTR)MX_MALLOC((nKeyLen + 1) * sizeof(CHAR));
      if (this->szKeyA != NULL)
      {
        ::MxMemCopy((LPSTR)(this->szKeyA), szKeyA, nKeyLen);
        ((LPSTR)(this->szKeyA))[nKeyLen] = 0;
      }
      this->dwExpireTimeMs = dwExpireTimeMs;
      _InterlockedExchange(&nFlags, 0);
      nEntryOffset = MX_CLOCKCACHE_ENTRY_OFFSET_NotOnList;
      return;
      };

  public:
    ~CEntry()
      {
      MX_FREE(szKeyA);
      return;
      };

    VOID SetValue(_In_ CValue *lpValue)
      {
      CAutoSlimRWLExclusive cLock(&sRwValueLock);

      cValue = lpValue;
      return;
      };

    CValue* GetValue() const
      {
      CAutoSlimRWLShared cLock(const_cast<LPRWLOCK>(&sRwValueLock));

      CValue *lpValue = cValue.Get();
      if (lpValue != NULL)
        lpValue->AddRef();
      return lpValue;
      };

  private:
    BOOL IsEvicted()
      {
      if ((__InterlockedRead(&nFlags) & MX_CLOCKCACHE_ENTRY_FLAG_Evicted) != 0)
        return TRUE;

      //check expiration time if it has any
      if (dwExpireTimeMs > 0 && ::GetTickCount() >= dwExpireTimeMs)
      {
        //evict entry
        _InterlockedOr(&nFlags, MX_CLOCKCACHE_ENTRY_FLAG_Evicted);

        return TRUE;
      }
      return FALSE;
      };

  private:
    friend class CClockCache;

    CRedBlackTreeNode cTreeNode;
    DWORD dwExpireTimeMs;
    LPCSTR szKeyA;

    RWLOCK sRwValueLock;
    TAutoRefCounted<CValue> cValue;

    LONG volatile nFlags;
    ULONG nEntryOffset;
  };

public:
  CClockCache()
    {
    nMaxEntries = 0;
    lplpEntries = NULL;
    SlimRWL_Initialize(&sRwLock);
    ::MxMemSet(&sStats, 0, sizeof(sStats));
    return;
    };

  ~CClockCache()
    {
    Finalize();
    return;
    };

  HRESULT Initialize(_In_ ULONG _nMaxEntries)
    {
    if (_nMaxEntries < 1 || (_nMaxEntries & (_nMaxEntries - 1)) != 0 || _nMaxEntries > (1 << 24))
      return E_INVALIDARG;

    lplpEntries = (CEntry**)MX_MALLOC((SIZE_T)_nMaxEntries * sizeof(CEntry*));
    if (lplpEntries == NULL)
      return E_OUTOFMEMORY;
    ::MxMemSet(lplpEntries, 0, (SIZE_T)_nMaxEntries * sizeof(CEntry*));
    nMaxEntries = _nMaxEntries;

    nClockHand = 0;

    //done
    return S_OK;
    };

  VOID Finalize()
    {
    CAutoSlimRWLExclusive cLock(&sRwLock);

    cTree.RemoveAll();
    if (lplpEntries != NULL)
    {
      for (ULONG i = 0; i < nMaxEntries; i++)
      {
        if (lplpEntries[i] != NULL)
          lplpEntries[i]->Release();
      }
    }
    MX_FREE(lplpEntries);
    nMaxEntries = 0;
    ::MxMemSet(&sStats, 0, sizeof(sStats));

    //done
    return;
    };

  CValue* Get(_In_z_ LPCSTR szKeyA)
    {
    TAutoRefCounted<CEntry> cEntry;

    MX_ASSERT(szKeyA != NULL);

    {
      CAutoSlimRWLShared cLock(&sRwLock);
      CRedBlackTreeNode *lpTreeNode;

      //find value
      lpTreeNode = cTree.Find(szKeyA, &CClockCache::SearchValue);
      if (lpTreeNode != NULL)
      {
        //keep a reference to the found value
        cEntry = CONTAINING_RECORD(lpTreeNode, CEntry, cTreeNode);
      }
    }

    //check expiration time if it has any
    if (cEntry && cEntry->IsEvicted() == FALSE)
    {
      _InterlockedOr(&(cEntry->nFlags), MX_CLOCKCACHE_ENTRY_FLAG_Referenced);

      _InterlockedIncrement(&(sStats.nHit));
      //return value
      return cEntry->GetValue();
    }

    //if we reach here, the key was not found or it was evicted
    _InterlockedIncrement(&(sStats.nMiss));
    return NULL;
    };

  HRESULT Put(_In_z_ LPCSTR szKeyA, _In_ LPCVOID lpValue, _In_ SIZE_T nValueSize, _In_opt_ DWORD dwExpireTimeMs = 0,
              _In_opt_ BOOL bOverwrite = TRUE)
    {
    TAutoRefCounted<CEntry> cNewEntry, cEvictedEntry;
    TAutoRefCounted<CValue> cNewValue;

    MX_ASSERT(szKeyA != NULL);

    MX_ASSERT(lpValue != NULL || nValueSize == 0);

    if (dwExpireTimeMs > 0)
    {
      dwExpireTimeMs += ::GetTickCount();
    }

    //create new item
    cNewEntry.Attach(MX_DEBUG_NEW CEntry(szKeyA, StrLenA(szKeyA), dwExpireTimeMs));
    if ((!cNewEntry) || cNewEntry->szKeyA == NULL)
      return E_OUTOFMEMORY;

    cNewValue.Attach(MX_DEBUG_NEW CValue(lpValue, nValueSize));
    if ((!cNewValue) || (nValueSize > 0 && cNewValue->lpData == NULL))
      return E_OUTOFMEMORY;

    {
      CAutoSlimRWLExclusive cLock(&sRwLock);
      CRedBlackTreeNode *lpMatchingTreeNode;

      //try to insert the new value
      if (cTree.Insert(&(cNewEntry->cTreeNode), &CClockCache::InsertValue, FALSE, &lpMatchingTreeNode) != FALSE)
      {
        //the item was added to the tree (didn't exist before) so find a free slot to add it
        cNewEntry->SetValue(cNewValue);
        _InterlockedIncrement(&(sStats.nInserted));

        while (lplpEntries[nClockHand] != NULL)
        {
          if ((_InterlockedAnd(&(lplpEntries[nClockHand]->nFlags), ~MX_CLOCKCACHE_ENTRY_FLAG_Referenced) &
               MX_CLOCKCACHE_ENTRY_FLAG_Referenced) == 0 ||
              lplpEntries[nClockHand]->IsEvicted() != FALSE)
          {
            cEvictedEntry.Attach(lplpEntries[nClockHand]);
            cEvictedEntry->cTreeNode.Remove();
            _InterlockedOr(&(cEvictedEntry->nFlags), MX_CLOCKCACHE_ENTRY_FLAG_Evicted);
            break;
          }

          nClockHand = (nClockHand + 1) & (nMaxEntries - 1);
        }

        cNewEntry->nEntryOffset = nClockHand;
        lplpEntries[nClockHand] = cNewEntry.Detach();

        nClockHand = (nClockHand + 1) & (nMaxEntries - 1);
      }
      else
      {
        CEntry *lpMatchingEntry = CONTAINING_RECORD(lpMatchingTreeNode, CEntry, cTreeNode);

        if (lpMatchingEntry->IsEvicted() == FALSE)
        {
          if (bOverwrite == FALSE)
            return MX_E_AlreadyExists;
        }

        _InterlockedIncrement(&(sStats.nReplaced));

        //just replace the value
        lpMatchingEntry->SetValue(cNewValue.Get());
      }
    }

    //done
    return S_OK;
    }

  HRESULT Delete(_In_z_ LPCSTR szKeyA)
    {
    CAutoSlimRWLShared cLock(&sRwLock);
    CRedBlackTreeNode *lpTreeNode;
    CEntry *lpEntry;

    MX_ASSERT(szKeyA != NULL);

    //find value
    lpTreeNode = cTree.Find(szKeyA, &CClockCache::SearchValue);
    if (lpTreeNode == NULL)
      return MX_E_NotFound;

    lpEntry = CONTAINING_RECORD(lpTreeNode, CEntry, cTreeNode);

    if ((_InterlockedOr(&(lpEntry->nFlags), MX_CLOCKCACHE_ENTRY_FLAG_Evicted) & MX_CLOCKCACHE_ENTRY_FLAG_Evicted) != 0)
    {
      //already evicted
      return MX_E_NotFound;
    }

    _InterlockedIncrement(&(sStats.nDeleted));

    //done
    return S_OK;
    };

  VOID Flush()
    {
    CAutoSlimRWLShared cLock(&sRwLock);
    CRedBlackTree::Iterator it;

    for (CRedBlackTreeNode *lpTreeNode = it.Begin(cTree); lpTreeNode != NULL; lpTreeNode = it.Next())
    {
      CEntry *lpEntry = CONTAINING_RECORD(lpTreeNode, CEntry, cTreeNode);

      _InterlockedOr(&(lpEntry->nFlags), MX_CLOCKCACHE_ENTRY_FLAG_Evicted);
    }

    //done
    return;
    };

private:
  static int InsertValue(_In_ LPVOID lpContext, _In_ CRedBlackTreeNode *lpNode1, _In_ CRedBlackTreeNode *lpNode2)
    {
    CEntry *lpEntry1 = CONTAINING_RECORD(lpNode1, CEntry, cTreeNode);
    CEntry *lpEntry2 = CONTAINING_RECORD(lpNode2, CEntry, cTreeNode);

    return StrCompareA(lpEntry1->szKeyA, lpEntry2->szKeyA);
    };

  static int SearchValue(_In_ LPVOID lpContext, _In_z_ LPCSTR szKeyA, _In_ CRedBlackTreeNode *lpNode)
    {
    CEntry *lpEntry = CONTAINING_RECORD(lpNode, CEntry, cTreeNode);

    return StrCompareA(szKeyA, lpEntry->szKeyA);
    };

private:
  ULONG nMaxEntries;
  CEntry **lplpEntries;
  ULONG nClockHand;
  RWLOCK sRwLock;
  CRedBlackTree cTree;
  struct {
    LONG volatile nInserted;
    LONG volatile nReplaced;
    LONG volatile nHit;
    LONG volatile nMiss;
    LONG volatile nDeleted;
  } sStats;
};

}; //namespace MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_CLOCK_CACHE_H
