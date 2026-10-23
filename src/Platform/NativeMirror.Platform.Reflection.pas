{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Platform.Reflection;

interface

uses
  Winapi.Windows,
  System.SysUtils;

type
  TNativeMirrorProcessReflection = class
  private
    FReflHandle: THandle;
    FSnapshot: THandle;
    procedure ReleaseSnapshot;
  public
    constructor Create(AReflHandle: THandle; ASnapshot: THandle = 0);
    destructor Destroy; override;
    function ReleaseReflectedHandle: Boolean;
    property ReflHandle: THandle read FReflHandle;
    property Snapshot: THandle read FSnapshot;
  end;

function CanMakeProcessReflection: Boolean;
function MakeProcessReflection(OrigHandle: THandle): TNativeMirrorProcessReflection;

implementation

const
  RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES = $00000002;
  PSS_CAPTURE_VA_CLONE             = $00000001;
  PSS_CREATE_BREAKAWAY             = $08000000;
  PSS_CREATE_BREAKAWAY_OPTIONAL    = $04000000;
  PSS_CREATE_USE_VM_ALLOCATIONS    = $20000000;
  PSS_QUERY_VA_CLONE_INFORMATION   = 1;
  ReflectionAccess1 = PROCESS_CREATE_THREAD or PROCESS_VM_OPERATION or PROCESS_DUP_HANDLE;
  ReflectionAccess2 = ReflectionAccess1 or PROCESS_CREATE_PROCESS;

type
  TClientId = record
    UniqueProcess: THandle;
    UniqueThread: THandle;
  end;
  TRtlpProcessReflectionInfo = record
    ReflectionProcessHandle: THandle;
    ReflectionThreadHandle: THandle;
    ReflectionClientId: TClientId;
  end;
  PRtlpProcessReflectionInfo = ^TRtlpProcessReflectionInfo;
  PNmHandle = ^THandle;
  TRtlCreateProcessReflection = function(
    ProcessHandle: THandle;
    Flags: ULONG;
    StartRoutine: Pointer;
    StartContext: Pointer;
    EventHandle: THandle;
    ReflectionInfo: PRtlpProcessReflectionInfo): LONG; stdcall;

  TPssCaptureSnapshot = function(
    ProcessHandle: THandle;
    CaptureFlags: DWORD;
    ThreadContextFlags: DWORD;
    SnapshotHandle: PNmHandle): DWORD; stdcall;
  TPssFreeSnapshot = function(
    ProcessHandle: THandle;
    SnapshotHandle: THandle): DWORD; stdcall;
  TPssQuerySnapshot = function(
    SnapshotHandle: THandle;
    InformationClass: DWORD;
    Buffer: Pointer;
    BufferLength: DWORD): DWORD; stdcall;

  TPssVaCloneInfo = record
    VaCloneHandle: THandle;
  end;

  TReflCreatorArgs = record
    OrigHandle: THandle;
    ReturnedHandle: THandle;
    IsOk: Boolean;
  end;
  PReflCreatorArgs = ^TReflCreatorArgs;

var
  GRtlCreateProcessReflection: TRtlCreateProcessReflection = nil;
  GPssCaptureSnapshot: TPssCaptureSnapshot = nil;
  GPssFreeSnapshot: TPssFreeSnapshot = nil;
  GPssQuerySnapshot: TPssQuerySnapshot = nil;

function LoadPssApis: Boolean;
var
  Lib: HMODULE;
begin
  Result := Assigned(GPssCaptureSnapshot) and Assigned(GPssFreeSnapshot)
    and Assigned(GPssQuerySnapshot);
  if Result then Exit;
  Lib := LoadLibraryA('kernel32.dll');
  if Lib = 0 then Exit(False);
  GPssCaptureSnapshot := TPssCaptureSnapshot(GetProcAddress(Lib, 'PssCaptureSnapshot'));
  GPssFreeSnapshot := TPssFreeSnapshot(GetProcAddress(Lib, 'PssFreeSnapshot'));
  GPssQuerySnapshot := TPssQuerySnapshot(GetProcAddress(Lib, 'PssQuerySnapshot'));
  Result := Assigned(GPssCaptureSnapshot) and Assigned(GPssFreeSnapshot)
    and Assigned(GPssQuerySnapshot);
end;

function LoadRtlReflection: Boolean;
var
  Lib: HMODULE;
begin
  Result := Assigned(GRtlCreateProcessReflection);
  if Result then Exit;
  Lib := LoadLibraryA('ntdll.dll');
  if Lib = 0 then Exit(False);
  GRtlCreateProcessReflection := TRtlCreateProcessReflection(
    GetProcAddress(Lib, 'RtlCreateProcessReflection'));
  Result := Assigned(GRtlCreateProcessReflection);
end;

function ReleaseProcessSnapshot(Snapshot: THandle): Boolean;
begin
  Result := False;
  if (Snapshot = 0) or not Assigned(GPssFreeSnapshot) then Exit;
  Result := GPssFreeSnapshot(GetCurrentProcess, Snapshot) = ERROR_SUCCESS;
end;

function MakeProcessSnapshot(OrigHandle: THandle): THandle;
var
  CaptureFlags: DWORD;
  Snap: THandle;
begin
  Result := 0;
  if not LoadPssApis then Exit;
  CaptureFlags := PSS_CAPTURE_VA_CLONE or PSS_CREATE_BREAKAWAY
    or PSS_CREATE_BREAKAWAY_OPTIONAL or PSS_CREATE_USE_VM_ALLOCATIONS;
  Snap := 0;
  if GPssCaptureSnapshot(OrigHandle, CaptureFlags, 0, @Snap) <> ERROR_SUCCESS then Exit;
  Result := Snap;
end;

function MakeReflectionFromSnapshot(Snapshot: THandle): THandle;
var
  Info: TPssVaCloneInfo;
begin
  Result := 0;
  if (Snapshot = 0) or not Assigned(GPssQuerySnapshot) then Exit;
  FillChar(Info, SizeOf(Info), 0);
  if GPssQuerySnapshot(Snapshot, PSS_QUERY_VA_CLONE_INFORMATION, @Info, SizeOf(Info)) <> ERROR_SUCCESS then Exit;
  Result := Info.VaCloneHandle;
end;

function ReflCreatorThread(Param: Pointer): DWORD; stdcall;
var
  Args: PReflCreatorArgs;
  Info: TRtlpProcessReflectionInfo;
  Ret: LONG;
begin
  Args := PReflCreatorArgs(Param);
  Args^.IsOk := False;
  FillChar(Info, SizeOf(Info), 0);
  Ret := GRtlCreateProcessReflection(Args^.OrigHandle,
    RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES, nil, nil, 0, @Info);
  if Ret = 0 then
  begin
    Args^.IsOk := True;
    Args^.ReturnedHandle := Info.ReflectionProcessHandle;
  end;
  Result := DWORD(Ret);
end;

function MakeReflectionViaRtl(OrigHandle: THandle): THandle;
const
  MaxWait = 1000;
var
  Args: TReflCreatorArgs;
  hThread: THandle;
  ThreadId: DWORD;
  WaitRes: DWORD;
begin
  Result := 0;
  if not LoadRtlReflection then Exit;
  FillChar(Args, SizeOf(Args), 0);
  Args.OrigHandle := OrigHandle;
  ThreadId := 0;
  hThread := CreateThread(nil, 0, @ReflCreatorThread, @Args, 0, ThreadId);
  if hThread = 0 then Exit;
  WaitRes := WaitForSingleObject(hThread, MaxWait);
  if WaitRes = WAIT_TIMEOUT then
  begin
    TerminateThread(hThread, 0);
    CloseHandle(hThread);
    Exit;
  end;
  CloseHandle(hThread);
  if Args.IsOk and (Args.ReturnedHandle <> 0)
    and (Args.ReturnedHandle <> INVALID_HANDLE_VALUE) then
    Result := Args.ReturnedHandle;
end;

function CanMakeProcessReflection: Boolean;
begin
  Result := LoadPssApis or LoadRtlReflection;
end;

function MakeProcessReflection(OrigHandle: THandle): TNativeMirrorProcessReflection;
var
  Snapshot, Clone: THandle;
begin
  Result := nil;
  if OrigHandle = 0 then Exit;
  if LoadPssApis then
  begin
    Snapshot := MakeProcessSnapshot(OrigHandle);
    if Snapshot <> 0 then
    begin
      Clone := MakeReflectionFromSnapshot(Snapshot);
      if Clone <> 0 then
      begin
        Result := TNativeMirrorProcessReflection.Create(Clone, Snapshot);
        Exit;
      end;
      ReleaseProcessSnapshot(Snapshot);
    end;
  end;
  if LoadRtlReflection then
  begin
    Clone := MakeReflectionViaRtl(OrigHandle);
    if Clone <> 0 then
      Result := TNativeMirrorProcessReflection.Create(Clone);
  end;
end;

{ TNativeMirrorProcessReflection }

constructor TNativeMirrorProcessReflection.Create(AReflHandle, ASnapshot: THandle);
begin
  inherited Create;
  FReflHandle := AReflHandle;
  FSnapshot := ASnapshot;
end;

destructor TNativeMirrorProcessReflection.Destroy;
begin
  ReleaseReflectedHandle;
  ReleaseSnapshot;
  inherited;
end;

procedure TNativeMirrorProcessReflection.ReleaseSnapshot;
begin
  if FSnapshot <> 0 then
  begin
    ReleaseProcessSnapshot(FSnapshot);
    FSnapshot := 0;
  end;
end;

function TNativeMirrorProcessReflection.ReleaseReflectedHandle: Boolean;
begin
  Result := False;
  if FReflHandle = 0 then Exit;
  Result := TerminateProcess(FReflHandle, 0);
  CloseHandle(FReflHandle);
  FReflHandle := 0;
end;

end.
