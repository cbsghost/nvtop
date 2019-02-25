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
#include <sddl.h>

void get_username_from_pid(pid_t pid, size_t size_buffer, char *buffer) {
  HANDLE hProc       = NULL;
  HANDLE hProcToken  = NULL;
  DWORD  dwTokenSize = 0u;
  
  PTOKEN_USER pTokenUser  = NULL;
  LPSTR       lpStringSid = NULL;
  
  buffer[0] = '\0';
  
  hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
  
  if (!OpenProcessToken(hProc, TOKEN_QUERY, hProcToken)) {
    return;
  }

  if (!GetTokenInformation(hProcToken, TokenUser, NULL, dwTokenSize, &dwTokenSize)){
    CloseHandle(hProcToken);
    return;
  }
  pTokenUser = (TOKEN_USER *)LocalAlloc(LMEM_FIXED, dwTokenSize);
  if (!GetTokenInformation(hProcToken, TokenUser, pTokenUser, dwTokenSize, &dwTokenSize)){
    LocalFree(pTokenUser);
    CloseHandle(hProcToken);
    return;
  }
  
  if (!ConvertSidToStringSid(pTokenUser->User.Sid, &lpStringSid)) {
    LocalFree(pTokenUser);
    CloseHandle(hProcToken);
    CloseHandle(hProc);
    return;
  }
  strncpy(buffer, lpStringSid, size_buffer);
  
  LocalFree(lpStringSid);
  LocalFree(pTokenUser);
  CloseHandle(hProcToken);
  CloseHandle(hProc);
}
