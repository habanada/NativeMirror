{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Dumper.Reports;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.JSON,
  System.Generics.Collections;

type
  TNativeMirrorModuleDumpReport = class
  public
    ModuleStart: UInt64;
    ModuleSize: NativeUInt;
    RebasedTo: UInt64;
    IsCorruptPe: Boolean;
    IsShellcode: Boolean;
    ImportRecoveryMode: string;
    IsReportDumped: Boolean;
    IsDumped: Boolean;
    ModeInfo: string;
    DumpFileName: string;
    HooksTagFileName: string;
    PatternsTagFileName: string;
    ImportListFileName: string;
    NotRecoveredFileName: string;
    IatHooksFileName: string;
    constructor Create(AModuleStart: UInt64; AModuleSize: NativeUInt);
  end;

  TNativeMirrorProcessDumpReport = class
  private
    FPid: DWORD;
    FModuleReports: TObjectList<TNativeMirrorModuleDumpReport>;
  public
    OutputDirectory: string;
    MiniDumpPath: string;
    constructor Create(APid: DWORD);
    destructor Destroy; override;
    procedure AppendReport(Report: TNativeMirrorModuleDumpReport);
    function CountTotal: NativeUInt;
    function CountDumped: NativeUInt;
    function IsFilled: Boolean;
    function HasModule(ModuleBase: UInt64; ModuleSize: NativeUInt): Boolean;
    function ToJson: TJSONObject;
    property Pid: DWORD read FPid;
    property ModuleReports: TObjectList<TNativeMirrorModuleDumpReport> read FModuleReports;
  end;

implementation

constructor TNativeMirrorModuleDumpReport.Create(AModuleStart: UInt64; AModuleSize: NativeUInt);
begin
  inherited Create;
  ModuleStart := AModuleStart;
  ModuleSize := AModuleSize;
  RebasedTo := AModuleStart;
end;

constructor TNativeMirrorProcessDumpReport.Create(APid: DWORD);
begin
  inherited Create;
  FPid := APid;
  FModuleReports := TObjectList<TNativeMirrorModuleDumpReport>.Create(True);
end;

destructor TNativeMirrorProcessDumpReport.Destroy;
begin
  FModuleReports.Free;
  inherited;
end;

procedure TNativeMirrorProcessDumpReport.AppendReport(Report: TNativeMirrorModuleDumpReport);
begin
  if Report <> nil then
    FModuleReports.Add(Report);
end;

function TNativeMirrorProcessDumpReport.CountTotal: NativeUInt;
begin
  Result := FModuleReports.Count;
end;

function TNativeMirrorProcessDumpReport.CountDumped: NativeUInt;
var
  Report: TNativeMirrorModuleDumpReport;
begin
  Result := 0;
  for Report in FModuleReports do
    if Report.IsDumped then
      Inc(Result);
end;

function TNativeMirrorProcessDumpReport.IsFilled: Boolean;
begin
  Result := (FModuleReports.Count > 0) or (MiniDumpPath <> '');
end;

function TNativeMirrorProcessDumpReport.HasModule(ModuleBase: UInt64; ModuleSize: NativeUInt): Boolean;
var
  Report: TNativeMirrorModuleDumpReport;
begin
  Result := False;
  if ModuleBase = 0 then
    Exit;
  for Report in FModuleReports do
    if Report.IsDumped and (Report.ModuleStart = ModuleBase) and (Report.ModuleSize = ModuleSize) then
      Exit(True);
end;

function TNativeMirrorProcessDumpReport.ToJson: TJSONObject;
var
  Modules: TJSONArray;
  ModuleReport: TNativeMirrorModuleDumpReport;
  ModObj, Dumped: TJSONObject;
begin
  Result := TJSONObject.Create;
  Result.AddPair('pid', TJSONNumber.Create(FPid));
  Result.AddPair('output_dir', OutputDirectory);
  if MiniDumpPath <> '' then
    Result.AddPair('minidump_path', MiniDumpPath);
  Dumped := TJSONObject.Create;
  Dumped.AddPair('total', TJSONNumber.Create(CountTotal));
  Dumped.AddPair('dumped', TJSONNumber.Create(CountDumped));
  Result.AddPair('dumped', Dumped);
  Modules := TJSONArray.Create;
  Result.AddPair('dumps', Modules);
  for ModuleReport in FModuleReports do
  begin
    if not ModuleReport.IsDumped and not ModuleReport.IsReportDumped then Continue;
    ModObj := TJSONObject.Create;
    ModObj.AddPair('module', IntToHex(ModuleReport.ModuleStart, 1).ToLower);
    ModObj.AddPair('module_size', IntToHex(ModuleReport.ModuleSize, 1).ToLower);
    if ModuleReport.RebasedTo <> ModuleReport.ModuleStart then
      ModObj.AddPair('dump_base', IntToHex(ModuleReport.RebasedTo, 1).ToLower);
    if ModuleReport.DumpFileName <> '' then
      ModObj.AddPair('dump_file', ExtractFileName(ModuleReport.DumpFileName));
    if ModuleReport.HooksTagFileName <> '' then
      ModObj.AddPair('tags_file', ExtractFileName(ModuleReport.HooksTagFileName));
    if ModuleReport.PatternsTagFileName <> '' then
      ModObj.AddPair('pattern_tags_file', ExtractFileName(ModuleReport.PatternsTagFileName));
    if ModuleReport.ImportListFileName <> '' then
      ModObj.AddPair('imports_file', ExtractFileName(ModuleReport.ImportListFileName));
    if ModuleReport.ImportRecoveryMode <> '' then
    begin
      ModObj.AddPair('imp_rec_result', ModuleReport.ImportRecoveryMode);
      if ModuleReport.NotRecoveredFileName <> '' then
        ModObj.AddPair('imp_not_recovered_file', ExtractFileName(ModuleReport.NotRecoveredFileName));
    end;
    if ModuleReport.IatHooksFileName <> '' then
      ModObj.AddPair('iat_hooks_file', ExtractFileName(ModuleReport.IatHooksFileName));
    if ModuleReport.ModeInfo <> '' then
      ModObj.AddPair('dump_mode', ModuleReport.ModeInfo);
    ModObj.AddPair('is_shellcode', TJSONNumber.Create(Ord(ModuleReport.IsShellcode)));
    if ModuleReport.IsCorruptPe then
      ModObj.AddPair('is_corrupt_pe', TJSONNumber.Create(1));
    ModObj.AddPair('status', TJSONNumber.Create(Ord(ModuleReport.IsDumped)));
    Modules.Add(ModObj);
  end;
end;

end.
