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
#ifndef _MXLIBHLP_SIMPLE_CACHE_H
#define _MXLIBHLP_SIMPLE_CACHE_H

#include <Defines.h>
#include <Windows.h>
#include <RefCounted.h>

//-----------------------------------------------------------

namespace MX {

class CSimpleCache : public virtual CBaseMemObj, public CNonCopyableObj
{
public:
  class CValue : public TRefCounted<CBaseMemObj>, public CNonCopyableObj
  {
  private:
    CValue(_In_ LPCVOID _lpData, _In_ SIZE_T _nDataSize, _In_ DWORD _dwExpireTimeMs,
           _In_ DWORD _dwId) : TRefCounted<CBaseMemObj>(), CNonCopyableObj()
      {
      if (_nDataSize > 0)
      {
        lpData = MX_MALLOC(_nDataSize);
        if (lpData != NULL)
          ::MxMemCopy(lpData, _lpData, _nDataSize);
      }
      else
      {
        lpData = NULL;
      }
      nDataSize = _nDataSize;
      dwExpireTimeMs = _dwExpireTimeMs;
      dwId = _dwId;
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
    friend class CSimpleCache;

    LPVOID lpData;
    SIZE_T nDataSize;
    DWORD dwExpireTimeMs;
    DWORD dwId;
  };

public:
  CSimpleCache()
    {
    SlimRWL_Initialize(&sRwMutex);
    _InterlockedExchange(&nNextId, 0);
    return;
    };

  ~CSimpleCache()
    {
    Delete();
    return;
    };

  CValue* Get()
    {
    TAutoRefCounted<CValue> cValue, cValueToDelete;

    {
      CAutoSlimRWLShared cLock(&sRwMutex);

      //find value
      cValue = cStoredValue;
    }

    if (cValue)
    {
      if (cValue->dwExpireTimeMs > 0)
      {
        DWORD dwCurrentTimeMs = ::GetTickCount();

        if (dwCurrentTimeMs >= cValue->dwExpireTimeMs)
        {
          {
            CAutoSlimRWLExclusive cLock(&sRwMutex);

            if (cStoredValue->dwId == cValue->dwId)
            {
              //the stored object is the same we retrieved
              cValueToDelete.Attach(cStoredValue.Detach());
            }
          }

          //expired
          return NULL;
        }
      }
    }

    //done
    return cValue.Detach();
    };

  HRESULT Put(_In_ LPCVOID lpValue, _In_ SIZE_T nValueSize, _In_opt_ DWORD dwExpireTimeMs = 0)
    {
    TAutoRefCounted<CValue> cNewValue, cValueToDelete;

    MX_ASSERT(lpValue != NULL || nValueSize == 0);

    if (dwExpireTimeMs > 0)
    {
      dwExpireTimeMs = ::GetTickCount() + dwExpireTimeMs;
    }

    //create new item
    cNewValue.Attach(MX_DEBUG_NEW CValue(lpValue, nValueSize, dwExpireTimeMs, (DWORD)_InterlockedIncrement(&nNextId)));
    if ((!cNewValue) || (nValueSize > 0 && cNewValue->lpData == NULL))
      return E_OUTOFMEMORY;

    {
      CAutoSlimRWLExclusive cLock(&sRwMutex);

      cValueToDelete.Attach(cStoredValue.Detach());

      cStoredValue.Attach(cNewValue.Detach());
    }

    //done
    return S_OK;
    }

  HRESULT Delete()
    {
    TAutoRefCounted<CValue> cValueToDelete;

    {
      CAutoSlimRWLExclusive cLock(&sRwMutex);

      cValueToDelete.Attach(cStoredValue.Detach());
    }

    //done
    return (cValueToDelete) ? S_OK : MX_E_NotFound;
    };

private:
  RWLOCK sRwMutex;
  TAutoRefCounted<CValue> cStoredValue;
  LONG volatile nNextId;
};

}; //namespace MX

//-----------------------------------------------------------

#endif //_MXLIBHLP_SIMPLE_CACHE_H
