{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Scanner.Modules;

interface

uses
  Winapi.Windows,
  System.Generics.Collections,
  NativeMirror.Core.Types,
  NativeMirror.Scanner.Reports;

type
  TNativeMirrorScannedModule = class
  private
    FStart: UInt64;
    FSize: NativeUInt;
    FSuspicious: Boolean;
    FModuleName: string;
  public
    constructor Create(Start: UInt64; ModuleSize: NativeUInt);
    function EndAddress: UInt64;
    function Resize(NewSize: NativeUInt): Boolean;
    property Start: UInt64 read FStart;
    property Size: NativeUInt read FSize;
    property Suspicious: Boolean read FSuspicious write FSuspicious;
    property ModuleName: string read FModuleName write FModuleName;
  end;

  TNativeMirrorModulesInfo = class
  private
    FPid: DWORD;
    FModules: TObjectDictionary<UInt64, TNativeMirrorScannedModule>;
  public
    constructor Create(Pid: DWORD);
    destructor Destroy; override;
    function AppendReport(Report: TNativeMirrorModuleScanReport): Boolean;
    function Count: NativeUInt;
    function GetScannedSize(Address: UInt64): NativeUInt;
    function FindModuleContaining(Address: UInt64; Size: NativeUInt = 0): TNativeMirrorScannedModule;
    function GetModuleAt(Address: UInt64): TNativeMirrorScannedModule;
    function ToArray: TArray<TNativeMirrorScannedModule>;
    property Pid: DWORD read FPid;
  end;

implementation

uses
  System.SysUtils;

constructor TNativeMirrorScannedModule.Create(Start: UInt64; ModuleSize: NativeUInt);
begin
  inherited Create;
  FStart := Start;
  FSize := ModuleSize;
end;

function TNativeMirrorScannedModule.EndAddress: UInt64;
begin
  Result := FStart + FSize;
end;

function TNativeMirrorScannedModule.Resize(NewSize: NativeUInt): Boolean;
begin
  Result := NewSize > FSize;
  if Result then
    FSize := NewSize;
end;

constructor TNativeMirrorModulesInfo.Create(Pid: DWORD);
begin
  inherited Create;
  FPid := Pid;
  FModules := TObjectDictionary<UInt64, TNativeMirrorScannedModule>.Create([doOwnsValues]);
end;

destructor TNativeMirrorModulesInfo.Destroy;
begin
  FModules.Free;
  inherited;
end;

function TNativeMirrorModulesInfo.AppendReport(Report: TNativeMirrorModuleScanReport): Boolean;
var
  Module: TNativeMirrorScannedModule;
begin
  Result := False;
  if (Report = nil) or (Report.ModuleSize = 0) then
    Exit;
  if not FModules.TryGetValue(Report.ModuleBase, Module) then
  begin
    Module := TNativeMirrorScannedModule.Create(Report.ModuleBase, Report.ModuleSize);
    FModules.Add(Report.ModuleBase, Module);
  end;
  if Module.ModuleName = '' then
    Module.ModuleName := ExtractFileName(Report.ModuleFile);
  Module.Resize(Report.ModuleSize);
  if not Module.Suspicious then
    Module.Suspicious := Report.Status = NM_SCAN_SUSPICIOUS;
  Result := True;
end;

function TNativeMirrorModulesInfo.Count: NativeUInt;
begin
  Result := FModules.Count;
end;

function TNativeMirrorModulesInfo.GetScannedSize(Address: UInt64): NativeUInt;
var
  Pair: TPair<UInt64, TNativeMirrorScannedModule>;
  Diff: UInt64;
begin
  Result := 0;
  for Pair in FModules do
    if (Address >= Pair.Value.Start) and (Address < Pair.Value.EndAddress) then
    begin
      Diff := Pair.Value.EndAddress - Address;
      if Diff > Result then
        Result := NativeUInt(Diff);
    end;
end;

function TNativeMirrorModulesInfo.FindModuleContaining(Address: UInt64; Size: NativeUInt): TNativeMirrorScannedModule;
var
  Pair: TPair<UInt64, TNativeMirrorScannedModule>;
  FieldEnd: UInt64;
begin
  Result := nil;
  FieldEnd := Address + Size;
  for Pair in FModules do
    if (Address >= Pair.Value.Start) and (FieldEnd <= Pair.Value.EndAddress) then
      if (Result = nil) or (Pair.Value.Start < Result.Start) then
        Result := Pair.Value;
end;

function TNativeMirrorModulesInfo.GetModuleAt(Address: UInt64): TNativeMirrorScannedModule;
begin
  if not FModules.TryGetValue(Address, Result) then
    Result := nil;
end;

function TNativeMirrorModulesInfo.ToArray: TArray<TNativeMirrorScannedModule>;
var
  Pair: TPair<UInt64, TNativeMirrorScannedModule>;
  I: Integer;
begin
  SetLength(Result, FModules.Count);
  I := 0;
  for Pair in FModules do
  begin
    Result[I] := Pair.Value;
    Inc(I);
  end;
end;

end.
