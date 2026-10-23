{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Platform.Process;

interface

uses
  Winapi.Windows,
  NativeMirror.Core.Memory,
  NativeMirror.Core.Types;

type
  TNativeMirrorProcessMemoryReader = class(TInterfacedObject, INativeMirrorMemoryReader)
  private
    FHandle: THandle;
    FOwnsHandle: Boolean;
    FArchitecture: TNativeMirrorArchitecture;
    function DetectArchitecture: TNativeMirrorArchitecture;
  public
    constructor Create(ProcessHandle: THandle; OwnsHandle: Boolean); overload;
    constructor Create(ProcessId: DWORD; Access: DWORD = PROCESS_QUERY_INFORMATION or PROCESS_VM_READ); overload;
    destructor Destroy; override;
    function ReadMemory(Address: UInt64; Buffer: Pointer; Size: NativeUInt; ForceAccess: Boolean = False): NativeUInt;
    function QueryRegion(Address: UInt64; out Region: TNativeMirrorMemoryRegion): Boolean;
    function GetArchitecture: TNativeMirrorArchitecture;
    function GetProcessHandle: THandle;
  end;

function IsProcess64Bit(ProcessHandle: THandle): Boolean;
function IsProcessWow64(ProcessHandle: THandle; out IsWow64: Boolean): Boolean;
function IsCurrentWow64: Boolean;
function DisableWow64FsRedirection(out OldValue: Pointer): Boolean;
function RevertWow64FsRedirection(OldValue: Pointer): Boolean;
function GetWow64ThreadContext(ThreadHandle: THandle; Context: Pointer): Boolean;
function SetDebugPrivilege: Boolean;
function IsDepEnabled(ProcessHandle: THandle): Boolean;
function GetProcessIntegrityLevel(ProcessHandle: THandle): TNativeMirrorProcessIntegrity;

implementation

uses
  System.SysUtils,
  NativePe.RemotePeReader;

type
  TWow64DisableFsRedirection = function(var OldValue: Pointer): BOOL; stdcall;
  TWow64RevertFsRedirection = function(OldValue: Pointer): BOOL; stdcall;
  TWow64GetThreadContext = function(hThread: THandle; lpContext: Pointer): BOOL; stdcall;
  TNmSidAndAttributes = record
    Sid: PSID;
    Attributes: DWORD;
  end;
  TNmTokenMandatoryLabel = record
    Label_: TNmSidAndAttributes;
  end;
  PNmTokenMandatoryLabel = ^TNmTokenMandatoryLabel;

function IsProcessWow64(ProcessHandle: THandle; out IsWow64: Boolean): Boolean;
var
  Value: BOOL;
begin
  Value := False;
  Result := IsWow64Process(ProcessHandle, Value);
  IsWow64 := Value;
end;

function IsProcess64Bit(ProcessHandle: THandle): Boolean;
var
  ProcessWow64: Boolean;
  System64: Boolean;
{$IFNDEF WIN64}
  ScannerWow64: Boolean;
{$ENDIF}
begin
{$IFDEF WIN64}
  System64 := True;
{$ELSE}
  ScannerWow64 := False;
  IsProcessWow64(GetCurrentProcess, ScannerWow64);
  System64 := ScannerWow64;
{$ENDIF}
  if not System64 then
    Exit(False);
  ProcessWow64 := False;
  IsProcessWow64(ProcessHandle, ProcessWow64);
  Result := not ProcessWow64;
end;

function IsCurrentWow64: Boolean;
{$IFNDEF WIN64}
var
  Wow64: Boolean;
{$ENDIF}
begin
{$IFDEF WIN64}
  Result := False;
{$ELSE}
  Wow64 := False;
  Result := IsProcessWow64(GetCurrentProcess, Wow64) and Wow64;
{$ENDIF}
end;

function DisableWow64FsRedirection(out OldValue: Pointer): Boolean;
var
  Kernel: HMODULE;
  Proc: TWow64DisableFsRedirection;
begin
  OldValue := nil;
  Result := False;
  Kernel := GetModuleHandle('kernel32.dll');
  if Kernel = 0 then Exit;
  Proc := TWow64DisableFsRedirection(GetProcAddress(Kernel, 'Wow64DisableWow64FsRedirection'));
  if Assigned(Proc) then
    Result := Proc(OldValue);
end;

function RevertWow64FsRedirection(OldValue: Pointer): Boolean;
var
  Kernel: HMODULE;
  Proc: TWow64RevertFsRedirection;
begin
  Result := False;
  Kernel := GetModuleHandle('kernel32.dll');
  if Kernel = 0 then Exit;
  Proc := TWow64RevertFsRedirection(GetProcAddress(Kernel, 'Wow64RevertWow64FsRedirection'));
  if Assigned(Proc) then
    Result := Proc(OldValue);
end;

function GetWow64ThreadContext(ThreadHandle: THandle; Context: Pointer): Boolean;
var
  Kernel: HMODULE;
  Proc: TWow64GetThreadContext;
begin
  Result := False;
{$IFDEF WIN64}
  if (ThreadHandle = 0) or (Context = nil) then Exit;
  Kernel := GetModuleHandle('kernel32.dll');
  if Kernel = 0 then Exit;
  Proc := TWow64GetThreadContext(GetProcAddress(Kernel, 'Wow64GetThreadContext'));
  if Assigned(Proc) then
    Result := Proc(ThreadHandle, Context);
{$ENDIF}
end;

function SetDebugPrivilege: Boolean;
var
  Token: THandle;
  LuidValue: TLargeInteger;
  Tp: TTokenPrivileges;
  ReturnLength: DWORD;
begin
  Result := False;
  Token := 0;
  if not OpenProcessToken(GetCurrentProcess, TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, Token) then
    Exit;
  try
    if not LookupPrivilegeValue(nil, 'SeDebugPrivilege', LuidValue) then
      Exit;
    FillChar(Tp, SizeOf(Tp), 0);
    Tp.PrivilegeCount := 1;
    Tp.Privileges[0].Luid := LuidValue;
    Tp.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
    ReturnLength := 0;
    if not AdjustTokenPrivileges(Token, False, Tp, SizeOf(Tp), nil, ReturnLength) then
      Exit;
    Result := GetLastError = ERROR_SUCCESS;
  finally
    CloseHandle(Token);
  end;
end;

function IsDepEnabled(ProcessHandle: THandle): Boolean;
const
  DepPolicyAlwaysOff = 0;
  DepPolicyAlwaysOn = 1;
type
  TGetSystemDepPolicy = function: Integer; stdcall;
  TGetProcessDepPolicy = function(hProcess: THandle; var lpFlags: DWORD; var lpPermanent: BOOL): BOOL; stdcall;
var
  Kernel: HMODULE;
  GetSystemDepPolicy: TGetSystemDepPolicy;
  GetProcessDepPolicy: TGetProcessDepPolicy;
  GlobalPolicy: Integer;
  Flags: DWORD;
  Permanent: BOOL;
  Wow64: Boolean;
begin
  Result := False;
  Kernel := GetModuleHandle('kernel32.dll');
  if Kernel = 0 then
    Kernel := LoadLibrary('kernel32.dll');
  if Kernel = 0 then
    Exit;
  GetSystemDepPolicy := TGetSystemDepPolicy(GetProcAddress(Kernel, 'GetSystemDEPPolicy'));
  if not Assigned(GetSystemDepPolicy) then
    Exit;
  GlobalPolicy := GetSystemDepPolicy;
  if GlobalPolicy = DepPolicyAlwaysOff then
    Exit(False);
  if GlobalPolicy = DepPolicyAlwaysOn then
    Exit(True);
  GetProcessDepPolicy := TGetProcessDepPolicy(GetProcAddress(Kernel, 'GetProcessDEPPolicy'));
  Flags := 0;
  Permanent := False;
  if Assigned(GetProcessDepPolicy) then
    if GetProcessDepPolicy(ProcessHandle, Flags, Permanent) then
      Exit((Flags and (PROCESS_DEP_ENABLE or PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION)) <> 0);
{$IFDEF WIN64}
  Wow64 := False;
  IsProcessWow64(ProcessHandle, Wow64);
  if not Wow64 then
    Exit(True);
{$ENDIF}
  Result := False;
end;

function GetProcessIntegrityLevel(ProcessHandle: THandle): TNativeMirrorProcessIntegrity;
const
  MandatoryUntrustedRid = $00000000;
  MandatoryLowRid = $00001000;
  MandatoryMediumRid = $00002000;
  MandatoryHighRid = $00003000;
  MandatorySystemRid = $00004000;
  MandatoryProtectedRid = $00005000;
var
  Token: THandle;
  Needed: DWORD;
  Buffer: Pointer;
  LabelInfo: PNmTokenMandatoryLabel;
  Count: PUCHAR;
  Rid: PDWORD;
begin
  Result := nmIntegrityUnknown;
  if ProcessHandle = 0 then Exit;
  Token := 0;
  if not OpenProcessToken(ProcessHandle, TOKEN_QUERY, Token) then Exit;
  try
    Needed := 0;
    GetTokenInformation(Token, TokenIntegrityLevel, nil, 0, Needed);
    if (Needed = 0) or (GetLastError <> ERROR_INSUFFICIENT_BUFFER) then Exit;
    GetMem(Buffer, Needed);
    try
      FillChar(Buffer^, Needed, 0);
      if not GetTokenInformation(Token, TokenIntegrityLevel, Buffer, Needed, Needed) then Exit;
      LabelInfo := PNmTokenMandatoryLabel(Buffer);
      if (LabelInfo^.Label_.Sid = nil) or not IsValidSid(LabelInfo^.Label_.Sid) then Exit;
      Count := GetSidSubAuthorityCount(LabelInfo^.Label_.Sid);
      if (Count = nil) or (Count^ = 0) then Exit;
      Rid := GetSidSubAuthority(LabelInfo^.Label_.Sid, Count^ - 1);
      if Rid = nil then Exit;
      if Rid^ >= MandatoryProtectedRid then
        Result := nmIntegrityProtected
      else if Rid^ >= MandatorySystemRid then
        Result := nmIntegritySystem
      else if Rid^ >= MandatoryHighRid then
        Result := nmIntegrityHigh
      else if Rid^ >= MandatoryMediumRid then
        Result := nmIntegrityMedium
      else if Rid^ >= MandatoryLowRid then
        Result := nmIntegrityLow
      else
        Result := nmIntegrityUntrusted;
    finally
      FreeMem(Buffer);
    end;
  finally
    CloseHandle(Token);
  end;
end;

constructor TNativeMirrorProcessMemoryReader.Create(ProcessHandle: THandle; OwnsHandle: Boolean);
begin
  inherited Create;
  FHandle := ProcessHandle;
  FOwnsHandle := OwnsHandle;
  FArchitecture := DetectArchitecture;
end;

constructor TNativeMirrorProcessMemoryReader.Create(ProcessId: DWORD; Access: DWORD);
begin
  inherited Create;
  FHandle := OpenProcess(Access, False, ProcessId);
  if FHandle = 0 then
    RaiseLastOSError;
  FOwnsHandle := True;
  FArchitecture := DetectArchitecture;
end;

destructor TNativeMirrorProcessMemoryReader.Destroy;
begin
  if FOwnsHandle and (FHandle <> 0) then
    CloseHandle(FHandle);
  inherited;
end;

function TNativeMirrorProcessMemoryReader.DetectArchitecture: TNativeMirrorArchitecture;
begin
  if FHandle = 0 then
    Exit(nmaUnknown);
  if IsProcess64Bit(FHandle) then
    Result := nmaX64
  else
    Result := nmaX86;
end;

function TNativeMirrorProcessMemoryReader.ReadMemory(Address: UInt64; Buffer: Pointer; Size: NativeUInt; ForceAccess: Boolean): NativeUInt;
begin
  if (FHandle = 0) or (Buffer = nil) or (Size = 0) then
    Exit(0);
  Result := ReadRemoteArea(FHandle, Pointer(NativeUInt(Address)), PByte(Buffer), Size, ForceAccess);
end;

function TNativeMirrorProcessMemoryReader.QueryRegion(Address: UInt64; out Region: TNativeMirrorMemoryRegion): Boolean;
var
  Info: TMemoryBasicInformation;
begin
  FillChar(Region, SizeOf(Region), 0);
  Result := FetchRegionInfo(FHandle, Pointer(NativeUInt(Address)), Info);
  if not Result then
    Exit;
  Region.BaseAddress := UInt64(NativeUInt(Info.BaseAddress));
  Region.AllocationBase := UInt64(NativeUInt(Info.AllocationBase));
  Region.RegionSize := Info.RegionSize;
  Region.State := Info.State;
  Region.Protect := Info.Protect;
  Region.AllocationProtect := Info.AllocationProtect;
  Region.MappingType := Info.Type_9;
end;

function TNativeMirrorProcessMemoryReader.GetArchitecture: TNativeMirrorArchitecture;
begin
  Result := FArchitecture;
end;

function TNativeMirrorProcessMemoryReader.GetProcessHandle: THandle;
begin
  Result := FHandle;
end;

end.
