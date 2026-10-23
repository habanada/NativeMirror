{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Core.Memory;

interface

uses
  Winapi.Windows,
  NativeMirror.Core.Types;

type
  INativeMirrorReader = interface
    ['{DC459255-7DDA-4E23-BA70-222429A0CD06}']
    function ReadAt(Offset: UInt64; Buffer: Pointer; Size: NativeUInt): NativeUInt;
    function GetSize: UInt64;
    property Size: UInt64 read GetSize;
  end;

  INativeMirrorMemoryReader = interface
    ['{B64DFD55-021C-40C5-9C58-4081A7747450}']
    function ReadMemory(Address: UInt64; Buffer: Pointer; Size: NativeUInt; ForceAccess: Boolean = False): NativeUInt;
    function QueryRegion(Address: UInt64; out Region: TNativeMirrorMemoryRegion): Boolean;
    function GetArchitecture: TNativeMirrorArchitecture;
    function GetProcessHandle: THandle;
    property Architecture: TNativeMirrorArchitecture read GetArchitecture;
    property ProcessHandle: THandle read GetProcessHandle;
  end;

function NativeMirrorRegionSize(const Reader: INativeMirrorMemoryReader; Address: UInt64): NativeUInt;

implementation

function NativeMirrorRegionSize(const Reader: INativeMirrorMemoryReader; Address: UInt64): NativeUInt;
var
  Region: TNativeMirrorMemoryRegion;
  Delta, Remaining: UInt64;
begin
  Result := 0;
  if (Reader = nil) or not Reader.QueryRegion(Address, Region) then
    Exit;
  if (Region.MappingType = 0) or (Address < Region.BaseAddress) then
    Exit;
  Delta := Address - Region.BaseAddress;
  if Delta > Region.RegionSize then
    Exit;
  Remaining := Region.RegionSize - Delta;
  if Remaining <= High(NativeUInt) then
    Result := NativeUInt(Remaining);
end;

end.
