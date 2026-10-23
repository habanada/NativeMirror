{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Platform.Enumeration;

interface

uses
  Winapi.Windows,
  System.Generics.Collections,
  NativeMirror.Core.Memory,
  NativeMirror.Core.Types;

function EnumerateProcessModules(ProcessHandle: THandle; Modules: TList<UInt64>): NativeUInt;
function EnumerateMemoryRegions(const Reader: INativeMirrorMemoryReader; Regions: TList<TNativeMirrorMemoryRegion>): NativeUInt;
function EnumerateWorkingSetRegions(ProcessHandle: THandle; Regions: TList<TNativeMirrorMemoryRegion>): NativeUInt;
function CountWorkingSetEntries(ProcessHandle: THandle): DWORD;
function IsProcessRunning(ProcessHandle: THandle): Boolean;
function GetProcessImagePath(ProcessHandle: THandle): string;

implementation

uses
  Winapi.PsAPI,
  System.SysUtils,
  NativeMirror.Platform.Paths;

const
  NativeMirrorListModulesAll = $03;

type
  TNativeMirrorWorkingSetInformation = record
    NumberOfEntries: NativeUInt;
    WorkingSetInfo: array[0..0] of NativeUInt;
  end;
  PNativeMirrorWorkingSetInformation = ^TNativeMirrorWorkingSetInformation;

function NativeMirrorEnumProcessModulesEx(hProcess: THandle; lphModule: Pointer; cb: DWORD; var lpcbNeeded: DWORD; dwFilterFlag: DWORD): BOOL; stdcall; external 'psapi.dll' name 'EnumProcessModulesEx';
function NativeMirrorGetProcessImageFileNameW(hProcess: THandle; lpImageFileName: PWideChar; nSize: DWORD): DWORD; stdcall; external 'psapi.dll' name 'GetProcessImageFileNameW';

function EnumerateProcessModules(ProcessHandle: THandle; Modules: TList<UInt64>): NativeUInt;
const
  MaxCount = 3072;
var
  Buffer: TArray<HMODULE>;
  Needed, Capacity, Count, I: DWORD;
begin
  Result := 0;
  if (ProcessHandle = 0) or (Modules = nil) then
    Exit;
  Modules.Clear;
  Capacity := 1024;
  while Capacity <= MaxCount do
  begin
    SetLength(Buffer, Capacity);
    Needed := 0;
{$IFDEF WIN64}
    if not NativeMirrorEnumProcessModulesEx(ProcessHandle, @Buffer[0], Capacity * SizeOf(HMODULE), Needed, NativeMirrorListModulesAll) then
      raise Exception.Create('Could not enumerate modules.');
{$ELSE}
    if not EnumProcessModules(ProcessHandle, @Buffer[0], Capacity * SizeOf(HMODULE), Needed) then
      raise Exception.Create('Could not enumerate modules.');
{$ENDIF}
    Count := Needed div SizeOf(HMODULE);
    if Count <= Capacity then
    begin
      if Count <> 0 then
        for I := 0 to Count - 1 do
          Modules.Add(UInt64(NativeUInt(Buffer[I])));
      Exit(Modules.Count);
    end;
    if Count > MaxCount then
      raise Exception.Create('Too many modules to enumerate safely.');
    Capacity := Count;
  end;
end;

function EnumerateMemoryRegions(const Reader: INativeMirrorMemoryReader; Regions: TList<TNativeMirrorMemoryRegion>): NativeUInt;
var
  Address, NextAddress: UInt64;
  Region: TNativeMirrorMemoryRegion;
begin
  Result := 0;
  if (Reader = nil) or (Regions = nil) then
    Exit;
  Regions.Clear;
  Address := 0;
  while Reader.QueryRegion(Address, Region) do
  begin
    if ((Region.State and MEM_COMMIT) <> 0) and ((Region.State and MEM_FREE) = 0) and (Region.RegionSize <> 0) then
      Regions.Add(Region);
    if Region.RegionSize = 0 then
      NextAddress := Address + $1000
    else
      NextAddress := Region.BaseAddress + Region.RegionSize;
    if NextAddress <= Address then
      Break;
    Address := NextAddress;
{$IFNDEF WIN64}
    if Address > High(DWORD) then
      Break;
{$ENDIF}
  end;
  Result := Regions.Count;
end;

function EnumerateWorkingSetRegions(ProcessHandle: THandle; Regions: TList<TNativeMirrorMemoryRegion>): NativeUInt;
const
  PageSize = UInt64($1000);
{$IFDEF WIN64}
  MaxAddress = High(UInt64);
{$ELSE}
  MaxAddress = UInt64(High(DWORD));
{$ENDIF}
var
  Address, NextAddress, BaseAddress, LastBase: UInt64;
  Info: TMemoryBasicInformation;
  Region: TNativeMirrorMemoryRegion;
  QuerySize: NativeUInt;
  ErrorCode: DWORD;
  HasLastBase: Boolean;
begin
  Result := 0;
  if (ProcessHandle = 0) or (Regions = nil) then
    Exit;
  Regions.Clear;
  Address := 0;
  LastBase := 0;
  HasLastBase := False;
  while Address < MaxAddress do
  begin
    FillChar(Info, SizeOf(Info), 0);
    SetLastError(ERROR_SUCCESS);
    QuerySize := VirtualQueryEx(ProcessHandle, Pointer(NativeUInt(Address)), Info, SizeOf(Info));
    if QuerySize <> SizeOf(Info) then
    begin
      ErrorCode := GetLastError;
      if (ErrorCode = ERROR_INVALID_PARAMETER) or (ErrorCode = ERROR_ACCESS_DENIED) then
        Break;
      if Address > MaxAddress - PageSize then
        Break;
      Inc(Address, PageSize);
      Continue;
    end;
    if Info.RegionSize = 0 then
    begin
      if Address > MaxAddress - PageSize then
        Break;
      Inc(Address, PageSize);
      Continue;
    end;
    if ((Info.State and MEM_FREE) <> 0) or ((Info.State and MEM_COMMIT) = 0) then
    begin
      if UInt64(Info.RegionSize) > MaxAddress - Address then
        Break;
      Inc(Address, UInt64(Info.RegionSize));
      Continue;
    end;
    BaseAddress := UInt64(NativeUInt(Info.BaseAddress));
    if HasLastBase and (BaseAddress = LastBase) then
      Break;
    if UInt64(Info.RegionSize) > MaxAddress - BaseAddress then
      Break;
    NextAddress := BaseAddress + UInt64(Info.RegionSize);
    Region.BaseAddress := BaseAddress;
    Region.AllocationBase := UInt64(NativeUInt(Info.AllocationBase));
    Region.RegionSize := UInt64(Info.RegionSize);
    Region.State := Info.State;
    Region.Protect := Info.Protect;
    Region.AllocationProtect := Info.AllocationProtect;
    Region.MappingType := Info.Type_9;
    Regions.Add(Region);
    LastBase := BaseAddress;
    HasLastBase := True;
    Address := NextAddress;
  end;
  Result := Regions.Count;
end;

function CountWorkingSetEntries(ProcessHandle: THandle): DWORD;
var
  Size: DWORD;
  Buffer: PNativeMirrorWorkingSetInformation;
  Success: BOOL;
begin
  Result := 0;
  if ProcessHandle = 0 then
    Exit;
  Size := SizeOf(TNativeMirrorWorkingSetInformation);
  GetMem(Buffer, Size);
  try
    FillChar(Buffer^, Size, 0);
    Success := QueryWorkingSet(ProcessHandle, Buffer, Size);
    if not Success and (GetLastError = ERROR_BAD_LENGTH) then
      Success := True;
    if Success then
      if Buffer^.NumberOfEntries > High(DWORD) then
        Result := High(DWORD)
      else
        Result := DWORD(Buffer^.NumberOfEntries);
  finally
    FreeMem(Buffer);
  end;
end;

function IsProcessRunning(ProcessHandle: THandle): Boolean;
var
  ExitCode: DWORD;
begin
  Result := ProcessHandle <> 0;
  if not Result then
    Exit;
  ExitCode := 0;
  if GetExitCodeProcess(ProcessHandle, ExitCode) then
    Result := ExitCode = STILL_ACTIVE;
end;

function GetProcessImagePath(ProcessHandle: THandle): string;
var
  Buffer: array[0..32767] of Char;
  Len: DWORD;
begin
  Result := '';
  if ProcessHandle = 0 then
    Exit;
  FillChar(Buffer, SizeOf(Buffer), 0);
  Len := NativeMirrorGetProcessImageFileNameW(ProcessHandle, @Buffer[0], DWORD(Length(Buffer)));
  if Len <> 0 then
    Result := NormalizeModulePath(Buffer);
end;

end.
