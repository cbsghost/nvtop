/*
 *
 * Copyright (C) 2019 Chung-Yu Liao <cbsghost@itri.org.tw>
 *
 * This file is part of Nvtop.
 *
 * Nvtop is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Nvtop is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with nvtop.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "nvtop/get_process_info.h"

#include <stdio.h>
#include <string.h>
#include <winbase.h>

void get_username_from_pid(pid_t pid, size_t size_buffer, char *buffer) {
  HANDLE hProc       = NULL;
  HANDLE hProcToken  = NULL;
  DWORD  dwTokenSize = 0u;

  PTOKEN_USER  pTokenUser                = NULL;
  LPSTR        lpName                    = NULL;
  DWORD        dwCchName                 = 0u;
  LPSTR        lpReferencedDomainName    = NULL;
  DWORD        dwCchReferencedDomainName = 0u;
  SID_NAME_USE eUse                      = 0;

  buffer[0] = '\0';

  hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

  if (hProc == NULL) {
    return;
  }

  if (!OpenProcessToken(hProc, TOKEN_QUERY, &hProcToken)) {
    return;
  }

  GetTokenInformation(hProcToken, TokenUser, NULL, dwTokenSize, &dwTokenSize);
  pTokenUser = (PTOKEN_USER)LocalAlloc(LMEM_FIXED, dwTokenSize);
  if (!GetTokenInformation(hProcToken, TokenUser, pTokenUser, dwTokenSize, &dwTokenSize)){
    LocalFree(pTokenUser);
    CloseHandle(hProcToken);
    return;
  }

  LookupAccountSidA(NULL, pTokenUser->User.Sid, lpName, &dwCchName, lpReferencedDomainName, &dwCchReferencedDomainName, &eUse);
  lpName = (LPSTR)LocalAlloc(LMEM_FIXED, dwCchName);
  lpReferencedDomainName = (LPSTR)LocalAlloc(LMEM_FIXED, dwCchReferencedDomainName);
  if (!LookupAccountSidA(NULL, pTokenUser->User.Sid, lpName, &dwCchName, lpReferencedDomainName, &dwCchReferencedDomainName, &eUse)) {
    LocalFree(lpName);
    LocalFree(lpReferencedDomainName);
    LocalFree(pTokenUser);
    CloseHandle(hProcToken);
    CloseHandle(hProc);
    return;
  }
  strncpy(buffer, lpName, size_buffer);

  LocalFree(lpName);
  LocalFree(lpReferencedDomainName);
  LocalFree(pTokenUser);
  CloseHandle(hProcToken);
  CloseHandle(hProc);
}
