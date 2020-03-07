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
#include "Console.h"
#include <WaitableObjects.h>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>

//-----------------------------------------------------------

static LONG volatile nEnabled = 0;

//-----------------------------------------------------------

namespace MX {

namespace Console {

VOID Initialize(_In_ BOOL bAppIsInteractive)
{
#pragma warning(suppress: 6031)
  _setmode(_fileno(stdout), _O_U16TEXT);
  _InterlockedExchange(&nEnabled, (bAppIsInteractive != FALSE) ? 1 : 0);
  return;
}

VOID Print(_In_ Console::eColor nColor, _In_ LPCWSTR szFormatW, ...)
{
  static LONG volatile nMutex = 0;
  static HANDLE hConsoleOut = NULL;
  CONSOLE_SCREEN_BUFFER_INFO sCsbi;
  va_list args;

  if (__InterlockedRead(&nEnabled) != 0)
  {
    CFastLock cLock(&nMutex);

    if (__InterlockedRead(&nEnabled) != 0)
    {
      if (hConsoleOut == NULL)
        hConsoleOut = ::GetStdHandle(STD_OUTPUT_HANDLE);
      if (nColor != ColorNormal)
      {
        ::GetConsoleScreenBufferInfo(hConsoleOut, &sCsbi);
        switch (nColor)
        {
          case ColorError:
            ::SetConsoleTextAttribute(hConsoleOut, FOREGROUND_RED|FOREGROUND_INTENSITY);
            break;
          case ColorSuccess:
            ::SetConsoleTextAttribute(hConsoleOut, FOREGROUND_GREEN|FOREGROUND_INTENSITY);
            break;
          case ColorYellow:
            ::SetConsoleTextAttribute(hConsoleOut, FOREGROUND_GREEN|FOREGROUND_RED|FOREGROUND_INTENSITY);
            break;
          case ColorBlue:
            ::SetConsoleTextAttribute(hConsoleOut, FOREGROUND_BLUE|FOREGROUND_INTENSITY);
            break;
        }
      }
      va_start(args, szFormatW);
      vwprintf_s(szFormatW, args);
      va_end(args);
      if (nColor != ColorNormal)
      {
        ::SetConsoleTextAttribute(hConsoleOut, sCsbi.wAttributes);
      }
    }
  }
  return;
}

VOID PrintError(_In_ HRESULT hRes)
{
  if (SUCCEEDED(hRes))
    Console::Print(ColorSuccess, L"OK");
  else
    Console::Print(ColorError, L"ERROR: 0x%08X", hRes);
  return;
}

}; //namespace Console

}; //namespace MX
