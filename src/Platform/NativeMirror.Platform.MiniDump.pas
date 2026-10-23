{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Platform.MiniDump;

interface

uses
  Winapi.Windows;

function MakeMiniDump(Pid: DWORD; const OutFile: string): Boolean;

implementation

uses
  NativeMirror.Platform.Process;

type
  TMiniDumpType = DWORD;
  TMiniDumpWriteDump = function(
    hProcess: THandle;
    ProcessId: DWORD;
    hFile: THandle;
    DumpType: TMiniDumpType;
    ExceptionParam: Pointer;
    UserStreamParam: Pointer;
    CallbackParam: Pointer): BOOL; stdcall;

const
  MiniDumpWithFullMemory = $00000002;

var
  GMiniDumpWriteDump: TMiniDumpWriteDump = nil;

function LoadMiniDumpWriteDump: Boolean;
var
  Lib: HMODULE;
begin
  if Assigned(GMiniDumpWriteDump) then Exit(True);
  Lib := LoadLibraryA('dbghelp.dll');
  if Lib = 0 then Exit(False);
  GMiniDumpWriteDump := TMiniDumpWriteDump(GetProcAddress(Lib, 'MiniDumpWriteDump'));
  if not Assigned(GMiniDumpWriteDump) then
    FreeLibrary(Lib);
  Result := Assigned(GMiniDumpWriteDump);
end;

function MakeMiniDump(Pid: DWORD; const OutFile: string): Boolean;
var
  ProcHandle, FileHandle: THandle;
begin
  Result := False;
  if not LoadMiniDumpWriteDump then Exit;
  ProcHandle := OpenProcess(PROCESS_ALL_ACCESS, False, Pid);
  if ProcHandle = 0 then
  begin
    if GetLastError = ERROR_ACCESS_DENIED then
    begin
      NativeMirror.Platform.Process.SetDebugPrivilege;
      ProcHandle := OpenProcess(PROCESS_ALL_ACCESS, False, Pid);
    end;
  end;
  if ProcHandle = 0 then Exit;
  try
    FileHandle := CreateFile(PChar(OutFile), GENERIC_ALL, 0, nil,
      CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if FileHandle = INVALID_HANDLE_VALUE then Exit;
    try
      Result := GMiniDumpWriteDump(ProcHandle, Pid, FileHandle,
        MiniDumpWithFullMemory, nil, nil, nil);
    finally
      CloseHandle(FileHandle);
    end;
  finally
    CloseHandle(ProcHandle);
  end;
end;

end.
