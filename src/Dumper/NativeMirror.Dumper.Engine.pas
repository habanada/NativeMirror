{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Dumper.Engine;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.DateUtils,
  System.IOUtils,
  System.Classes,
  System.JSON,
  System.Generics.Collections,
  NativeMirror.Core.Types,
  NativeMirror.Core.Memory,
  NativeMirror.Core.Buffer,
  NativeMirror.Scanner.Reports,
  NativeMirror.Scanner.Modules,
  NativeMirror.Scanner.ProcessReport,
  NativeMirror.Scanner.WorkingSet,
  NativeMirror.Scanner.Artefacts,
  NativeMirror.Scanner.Code,
  NativeMirror.Scanner.IAT,
  NativeMirror.Dumper.Buffer,
  NativeMirror.Dumper.Reports,
  NativeMirror.Dumper.Reconstructor,
  NativeMirror.Dumper.Imports.Reconstructor,
  NativeMirror.Dumper.Imports.Blocks,
  NativePe.ExportsMapper,
  NativePe.ImportsUneraser;

type
  TNativeMirrorDumperMessageEvent = reference to procedure(const Text: string; IsError: Boolean);

  TNativeMirrorResultsDumper = class
  private
    FBaseDir: string;
    FDumpDir: string;
    FQuiet: Boolean;
    FOnMessage: TNativeMirrorDumperMessageEvent;
    procedure Emit(const Text: string; IsError: Boolean = False);
    function FillModuleCopy(
      ModReport: TNativeMirrorModuleScanReport;
      Buffer: TNativeMirrorDumpBuffer): Boolean;
    function DumpModule(
      const Reader: INativeMirrorMemoryReader;
      IsRefl: Boolean;
      ModulesInfo: TNativeMirrorModulesInfo;
      ModReport: TNativeMirrorModuleScanReport;
      ExportsMap: TExportsMapper;
      DumpMode: TNativeMirrorDumpMode;
      ImprecMode: TNativeMirrorImportRecoveryMode;
      Rebase: Boolean;
      DumpReport: TNativeMirrorProcessDumpReport): Boolean;
    function MakeModuleDumpPath(
      ModBase: UInt64;
      const Fname: string;
      const DefaultExt: string): string;
    function MakeDirName(Pid: DWORD): string;
    procedure MakeAndJoinDirectories(out OutPath: string);
    function SaveNotRecovered(
      const FileName: string;
      const Reader: INativeMirrorMemoryReader;
      ModulesInfo: TNativeMirrorModulesInfo;
      NotCovered: TImpsNotCovered;
      ExportsMap: TExportsMapper): Boolean;
    function WriteJsonToFile(const Path: string; Json: TJSONObject): Boolean;
  public
    constructor Create(const BaseDir: string; Quiet: Boolean);
    function DumpDetectedModules(
      const Reader: INativeMirrorMemoryReader;
      IsRefl: Boolean;
      ProcessReport: TNativeMirrorProcessScanReport;
      DumpMode: TNativeMirrorDumpMode;
      ImprecMode: TNativeMirrorImportRecoveryMode;
      Rebase: Boolean): TNativeMirrorProcessDumpReport;
    function DumpJsonScanReport(
      ProcessReport: TNativeMirrorProcessScanReport;
      Filter: TNativeMirrorResultsFilter;
      Level: TNativeMirrorJsonLevel): Boolean;
    function DumpJsonDumpReport(
      DumpReport: TNativeMirrorProcessDumpReport): Boolean;
    function DumpJsonErrorReport(Pid: DWORD; const MessageText: string; Filter: TNativeMirrorResultsFilter): Boolean;
    function MakeOutPath(
      const Fname: string;
      const DefaultExt: string = ''): string;
    property OutputDir: string read FDumpDir;
    property OnMessage: TNativeMirrorDumperMessageEvent read FOnMessage write FOnMessage;
  end;

implementation

uses
  NativePe.ExportedFunc;

function GetPayloadExt(Report: TNativeMirrorArtefactScanReport): string;
begin
  if not Report.HasPe then Exit('shc');
  if Report.Artefacts.IsDll then Exit('dll');
  Result := 'exe';
end;

constructor TNativeMirrorResultsDumper.Create(const BaseDir: string;
  Quiet: Boolean);
begin
  inherited Create;
  FBaseDir := BaseDir;
  FQuiet := Quiet;
end;

procedure TNativeMirrorResultsDumper.Emit(const Text: string; IsError: Boolean);
begin
  if FQuiet then Exit;
  if Assigned(FOnMessage) then FOnMessage(Text, IsError)
  else if IsError then Writeln(ErrOutput, Text)
  else Writeln(Text);
end;

function TNativeMirrorResultsDumper.MakeDirName(Pid: DWORD): string;
begin
  Result := Format('process_%d', [Pid]);
end;

procedure TNativeMirrorResultsDumper.MakeAndJoinDirectories(out OutPath: string);
var
  InnerDir: string;
begin
  OutPath := '';
  if FBaseDir <> '' then
  begin
    if not TDirectory.Exists(FBaseDir) then
    begin
      try
        TDirectory.CreateDirectory(FBaseDir);
      except
        FBaseDir := '';
      end;
    end;
  end;
  if FDumpDir <> '' then
  begin
    InnerDir := FDumpDir;
    if FBaseDir <> '' then
      InnerDir := FBaseDir + PathDelim + FDumpDir;
    if not TDirectory.Exists(InnerDir) then
    begin
      try
        TDirectory.CreateDirectory(InnerDir);
      except
        FDumpDir := '';
        InnerDir := '';
      end;
    end;
  end;
  if FBaseDir <> '' then
    OutPath := FBaseDir + PathDelim;
  if FDumpDir <> '' then
    OutPath := OutPath + FDumpDir + PathDelim;
end;

function TNativeMirrorResultsDumper.MakeModuleDumpPath(ModBase: UInt64;
  const Fname: string; const DefaultExt: string): string;
var
  Prefix: string;
begin
  MakeAndJoinDirectories(Prefix);
  if Fname <> '' then
    Result := Prefix + IntToHex(ModBase, 1).ToLower + '.' + Fname
  else
    Result := Prefix + IntToHex(ModBase, 1).ToLower + '.' + DefaultExt;
end;

function TNativeMirrorResultsDumper.MakeOutPath(const Fname: string;
  const DefaultExt: string): string;
var
  Prefix: string;
begin
  MakeAndJoinDirectories(Prefix);
  if Fname <> '' then
    Result := Prefix + Fname
  else
    Result := Format('%s%d%s', [Prefix, DateTimeToUnix(TTimeZone.Local.ToUniversalTime(Now)), DefaultExt]);
end;

function TNativeMirrorResultsDumper.FillModuleCopy(
  ModReport: TNativeMirrorModuleScanReport;
  Buffer: TNativeMirrorDumpBuffer): Boolean;
var
  WsReport: TNativeMirrorWorkingSetScanReport;
begin
  Result := False;
  if ModReport = nil then Exit;
  WsReport := nil;
  if ModReport is TNativeMirrorWorkingSetScanReport then
    WsReport := TNativeMirrorWorkingSetScanReport(ModReport);
  if (WsReport <> nil) and (WsReport.DataCache.Size > 0) then
    Result := Buffer.FillFromBuffer(ModReport.ModuleBase,
      WsReport.DataCache.Data, WsReport.DataCache.Size);
  if not Result then
    Result := Buffer.ReadRemote(ModReport.ModuleBase, ModReport.ModuleSize);
end;

function TNativeMirrorResultsDumper.SaveNotRecovered(
  const FileName: string;
  const Reader: INativeMirrorMemoryReader;
  ModulesInfo: TNativeMirrorModulesInfo;
  NotCovered: TImpsNotCovered;
  ExportsMap: TExportsMapper): Boolean;
var
  Lines: TStringList;
  Pair: TPair<DWORD, UInt64>;
  Module: TNativeMirrorScannedModule;
  Region: TNativeMirrorMemoryRegion;
  ExportedFunction: TExportedFunc;
  ModuleStart, Offset: UInt64;
  Suspicious: Boolean;
  TargetName: string;
begin
  Result := False;
  if (NotCovered = nil) or (NotCovered.Count = 0) then Exit;
  Lines := TStringList.Create;
  try
    Lines.WriteBOM := False;
    for Pair in NotCovered.ThunkToAddr do
    begin
      Module := nil;
      if ModulesInfo <> nil then Module := ModulesInfo.FindModuleContaining(Pair.Value);
      if Module <> nil then ModuleStart := Module.Start
      else if (Reader <> nil) and Reader.QueryRegion(Pair.Value, Region) then ModuleStart := Region.AllocationBase
      else ModuleStart := 0;
      Offset := Pair.Value - ModuleStart;
      Suspicious := (Module = nil) or Module.Suspicious;
      if Pair.Value = 0 then TargetName := '(invalid)'
      else if ExportsMap = nil then TargetName := ''
      else
      begin
        ExportedFunction := ExportsMap.FindExportByVa(Pair.Value);
        if ExportedFunction <> nil then TargetName := ExportedFunction.ToStringFull
        else if Module <> nil then TargetName := ChangeFileExt(ExtractFileName(Module.ModuleName), '') + '.(unknown_func)'
        else if ModuleStart = 0 then TargetName := '(invalid)'
        else TargetName := '(unknown)';
      end;
      Lines.Add(IntToHex(Pair.Key, 1).ToLower + ';' + IntToHex(Pair.Value, 1).ToLower + '[' + IntToHex(ModuleStart, 1).ToLower + '+' + IntToHex(Offset, 1).ToLower + ':' + TargetName + ':' + IntToStr(Ord(Suspicious)) + ']');
    end;
    try
      Lines.SaveToFile(FileName, TEncoding.UTF8);
      Result := True;
    except
      Result := False;
    end;
  finally
    Lines.Free;
  end;
end;

function TNativeMirrorResultsDumper.WriteJsonToFile(const Path: string;
  Json: TJSONObject): Boolean;
var
  Content: string;
  Bytes: TBytes;
  FS: TFileStream;
begin
  Result := False;
  if Json = nil then Exit;
  Content := Json.ToJSON;
  if Content = '' then Exit;
  Bytes := TEncoding.UTF8.GetBytes(Content);
  if Length(Bytes) = 0 then Exit;
  try
    FS := TFileStream.Create(Path, fmCreate);
    try
      FS.Write(Bytes[0], Length(Bytes));
      Result := True;
    finally
      FS.Free;
    end;
  except
    Result := False;
  end;
end;

function TNativeMirrorResultsDumper.DumpModule(
  const Reader: INativeMirrorMemoryReader;
  IsRefl: Boolean;
  ModulesInfo: TNativeMirrorModulesInfo;
  ModReport: TNativeMirrorModuleScanReport;
  ExportsMap: TExportsMapper;
  DumpMode: TNativeMirrorDumpMode;
  ImprecMode: TNativeMirrorImportRecoveryMode;
  Rebase: Boolean;
  DumpReport: TNativeMirrorProcessDumpReport): Boolean;
const
  SaveImpReport = True;
var
  ModuleBuf: TNativeMirrorDumpBuffer;
  IsCorruptPe: Boolean;
  DumpShellcode: Boolean;
  PayloadExt: string;
  CurrDumpMode: TNativeMirrorDumpMode;
  ModuleName: string;
  ModDumpReport: TNativeMirrorModuleDumpReport;
  ArtefactReport: TNativeMirrorArtefactScanReport;
  PeRec: TNativeMirrorReconstructor;
  ImpRec: TNativeMirrorImportReconstructor;
  NotCovered: TImpsNotCovered;
  ImprecRes: TNativeMirrorImportRecoveryResult;
  OutBase: UInt64;
  IatNotRebuilt: Boolean;
  DumpFile: string;
  ImportsFile: string;
  NotRecFile: string;
  TagsFile: string;
  TagCount: NativeUInt;
  CodeReport: TNativeMirrorCodeScanReport;
  WsScanReport: TNativeMirrorWorkingSetScanReport;
  IatHooksReport: TNativeMirrorIatScanReport;
  ScannedModule: TNativeMirrorScannedModule;
  ModeInfo: string;
begin
  Result := False;
  if ModReport = nil then Exit;

  CurrDumpMode := DumpMode;
  IsCorruptPe := False;
  DumpShellcode := False;
  PayloadExt := '';

  ModuleBuf := TNativeMirrorDumpBuffer.Create(Reader, IsRefl);
  try
    ArtefactReport := nil;
    if ModReport is TNativeMirrorArtefactScanReport then
      ArtefactReport := TNativeMirrorArtefactScanReport(ModReport);

    if ArtefactReport <> nil then
    begin
      PayloadExt := GetPayloadExt(ArtefactReport);
      if ArtefactReport.HasShellcode then DumpShellcode := True;
      if ArtefactReport.HasPe then
      begin
        PeRec := TNativeMirrorReconstructor.Create(ArtefactReport.Artefacts, ModuleBuf);
        try
          if not PeRec.Reconstruct then
          begin
            IsCorruptPe := True;
            PayloadExt := 'corrupt_' + PayloadExt;
            if not FQuiet then
              Emit('[-] Reconstructing PE at: ' + IntToHex(ArtefactReport.Artefacts.PeImageBase, 1).ToLower + ' failed.');
          end;
        finally
          PeRec.Free;
        end;
      end;
    end;

    // Kein Artefakt-Report oder PE-Rekonstruktion gescheitert: Rohkopie lesen
    if (ArtefactReport = nil) or IsCorruptPe then
      FillModuleCopy(ModReport, ModuleBuf);

    if PayloadExt = '' then
    begin
      if ModuleBuf.IsValidPe then PayloadExt := 'dll'
      else PayloadExt := 'shc';
    end;

    ModuleName := TPath.GetFileName(ModReport.ModuleFile);
    if (ModuleName = '') and (ModulesInfo <> nil) then
    begin
      ScannedModule := ModulesInfo.GetModuleAt(ModReport.ModuleBase);
      if ScannedModule <> nil then ModuleName := TPath.GetFileName(ScannedModule.ModuleName);
    end;

    ModDumpReport := TNativeMirrorModuleDumpReport.Create(
      ModuleBuf.ModuleBase, ModuleBuf.Size);
    DumpReport.AppendReport(ModDumpReport);

    DumpFile := MakeModuleDumpPath(ModuleBuf.ModuleBase, ModuleName, PayloadExt);
    ModDumpReport.DumpFileName := DumpFile;
    ModDumpReport.IsCorruptPe := IsCorruptPe;
    ModDumpReport.IsShellcode := (not ModuleBuf.IsValidPe) and ModuleBuf.IsCode;

    if ModuleBuf.IsFilled then
    begin
      NotCovered := TImpsNotCovered.Create;
      try
        ImpRec := TNativeMirrorImportReconstructor.Create(ModuleBuf);
        try
          ImprecRes := ImpRec.RebuildImportTable(ExportsMap, ImprecMode);
          ModDumpReport.ImportRecoveryMode := ImportRecoveryResultName(ImprecRes);

          ModuleBuf.RelocBase := ModReport.GetRelocBase;
          OutBase := 0;
          if Rebase then
          begin
            OutBase := ModReport.OriginalBase;
            if OutBase = 0 then OutBase := NATIVE_MIRROR_DEFAULT_REBASE;
            ModuleBuf.RelocBase := OutBase;
          end;

          if ImprecMode = nmImportNone then
            ModDumpReport.IsDumped := ModuleBuf.DumpPeToFile(DumpFile, CurrDumpMode)
          else
            ModDumpReport.IsDumped := ModuleBuf.DumpPeToFile(DumpFile, CurrDumpMode,
              ExportsMap, NotCovered);

          if not ModDumpReport.IsDumped then
          begin
            ModDumpReport.IsDumped := ModuleBuf.DumpToFile(DumpFile);
            CurrDumpMode := nmDumpVirtual;
          end;

          if (CurrDumpMode <> nmDumpVirtual) and (OutBase <> 0) then
            ModDumpReport.RebasedTo := OutBase;

          ModDumpReport.ModeInfo := DumpModeName(CurrDumpMode);

          IatNotRebuilt := (ImprecRes = nmImportRecoveryError) or
                           (ImprecRes = nmImportRecoveryNotApplicable);
          if IatNotRebuilt or SaveImpReport then
          begin
            ImportsFile := DumpFile + '.imports.txt';
            if ImpRec.PrintFoundIats(ImportsFile) then
              ModDumpReport.ImportListFileName := ImportsFile;
          end;

          NotRecFile := DumpFile + '.not_fixed_imports.txt';
          if SaveNotRecovered(NotRecFile, Reader, ModulesInfo, NotCovered, ExportsMap) then
            ModDumpReport.NotRecoveredFileName := NotRecFile;
        finally
          ImpRec.Free;
        end;
      finally
        NotCovered.Free;
      end;
    end;

    // Nicht gedumpt oder Shellcode explizit: Rohkopie als .shc
    if (not ModDumpReport.IsDumped) or DumpShellcode then
    begin
      if DumpShellcode then PayloadExt := 'shc';
      FillModuleCopy(ModReport, ModuleBuf);
      ModDumpReport := TNativeMirrorModuleDumpReport.Create(
        ModuleBuf.ModuleBase, ModuleBuf.Size);
      DumpReport.AppendReport(ModDumpReport);
      ModDumpReport.IsShellcode := DumpShellcode;
      DumpFile := MakeModuleDumpPath(ModuleBuf.ModuleBase, ModuleName, PayloadExt);
      ModDumpReport.DumpFileName := DumpFile;
      ModDumpReport.IsDumped := ModuleBuf.DumpToFile(DumpFile);
      CurrDumpMode := nmDumpVirtual;
      ModDumpReport.ModeInfo := DumpModeName(nmDumpVirtual);
    end;

    if ModDumpReport.IsDumped then
    begin
      Result := True;
      if not FQuiet then
      begin
        ModeInfo := ModDumpReport.ModeInfo;
        if ModeInfo <> '' then ModeInfo := ' as ' + ModeInfo;
        Emit('[*] Dumped module to: ' + DumpFile + ModeInfo);
      end;
    end
    else
    begin
      if not FQuiet then
        Emit('[-] Failed dumping module!', True);
    end;

    // Code-Patches → .tag
    CodeReport := nil;
    if ModReport is TNativeMirrorCodeScanReport then
      CodeReport := TNativeMirrorCodeScanReport(ModReport);
    if CodeReport <> nil then
    begin
      TagsFile := ModDumpReport.DumpFileName + '.tag';
      TagCount := CodeReport.GenerateTags(TagsFile);
      if TagCount > 0 then
      begin
        ModDumpReport.HooksTagFileName := TagsFile;
        ModDumpReport.IsReportDumped := True;
      end;
    end;

    // Working-Set-Pattern → .pattern.tag
    WsScanReport := nil;
    if ModReport is TNativeMirrorWorkingSetScanReport then
      WsScanReport := TNativeMirrorWorkingSetScanReport(ModReport);
    if WsScanReport <> nil then
    begin
      TagsFile := ModDumpReport.DumpFileName + '.pattern.tag';
      TagCount := WsScanReport.GenerateTags(TagsFile);
      if TagCount > 0 then
      begin
        ModDumpReport.PatternsTagFileName := TagsFile;
        ModDumpReport.IsReportDumped := True;
      end;
    end;

    // IAT-Hooks → .iat_hooks.txt
    IatHooksReport := nil;
    if ModReport is TNativeMirrorIatScanReport then
      IatHooksReport := TNativeMirrorIatScanReport(ModReport);
    if IatHooksReport <> nil then
    begin
      TagsFile := ModDumpReport.DumpFileName + '.iat_hooks.txt';
      if IatHooksReport.GenerateList(TagsFile, Reader, ModulesInfo, ExportsMap) then
      begin
        ModDumpReport.IatHooksFileName := TagsFile;
        ModDumpReport.IsReportDumped := True;
      end;
    end;
  finally
    ModuleBuf.Free;
  end;
end;

function TNativeMirrorResultsDumper.DumpDetectedModules(
  const Reader: INativeMirrorMemoryReader;
  IsRefl: Boolean;
  ProcessReport: TNativeMirrorProcessScanReport;
  DumpMode: TNativeMirrorDumpMode;
  ImprecMode: TNativeMirrorImportRecoveryMode;
  Rebase: Boolean): TNativeMirrorProcessDumpReport;
var
  ModuleReport: TNativeMirrorModuleScanReport;
begin
  if (Reader = nil) or (ProcessReport = nil) then Exit(nil);
  Result := TNativeMirrorProcessDumpReport.Create(ProcessReport.Pid);
  FDumpDir := MakeDirName(ProcessReport.Pid);
  for ModuleReport in ProcessReport.Reports do
  begin
    if ModuleReport.Status <> NM_SCAN_SUSPICIOUS then Continue;
    if Result.HasModule(ModuleReport.ModuleBase, ModuleReport.ModuleSize) then Continue;
    DumpModule(Reader, IsRefl, ProcessReport.ModulesInfo, ModuleReport,
      ProcessReport.ExportsMap, DumpMode, ImprecMode, Rebase, Result);
  end;
end;

function TNativeMirrorResultsDumper.DumpJsonScanReport(
  ProcessReport: TNativeMirrorProcessScanReport;
  Filter: TNativeMirrorResultsFilter;
  Level: TNativeMirrorJsonLevel): Boolean;
var
  Json: TJSONObject;
  OutPath: string;
  Summary: TNativeMirrorProcessSummary;
  ScanStatus, ErrorStatus: TNativeMirrorScanStatus;
begin
  Result := False;
  if ProcessReport = nil then Exit;
  Summary := ProcessReport.GenerateSummary;
  if Summary.Suspicious > 0 then ScanStatus := NM_SCAN_SUSPICIOUS
  else ScanStatus := NM_SCAN_NOT_SUSPICIOUS;
  if Summary.Errors > 0 then ErrorStatus := NM_SCAN_ERROR
  else ErrorStatus := NM_SCAN_NOT_SUSPICIOUS;
  if not NativePeIsShownStatus(ScanStatus, Filter) and
    not NativePeIsShownStatus(ErrorStatus, Filter) then Exit;
  FDumpDir := MakeDirName(ProcessReport.Pid);
  Json := ProcessReport.ToJson(Filter, Level);
  if Json = nil then Exit;
  try
    OutPath := MakeOutPath('scan_report.json');
    Result := WriteJsonToFile(OutPath, Json);
  finally
    Json.Free;
  end;
end;

function TNativeMirrorResultsDumper.DumpJsonDumpReport(
  DumpReport: TNativeMirrorProcessDumpReport): Boolean;
var
  Json: TJSONObject;
  OutPath: string;
begin
  Result := False;
  if (DumpReport = nil) or not DumpReport.IsFilled then Exit;
  FDumpDir := MakeDirName(DumpReport.Pid);
  Json := DumpReport.ToJson;
  if Json = nil then Exit;
  try
    OutPath := MakeOutPath('dump_report.json');
    Result := WriteJsonToFile(OutPath, Json);
  finally
    Json.Free;
  end;
end;

function TNativeMirrorResultsDumper.DumpJsonErrorReport(Pid: DWORD; const MessageText: string; Filter: TNativeMirrorResultsFilter): Boolean;
var
  Json: TJSONObject;
  OutPath: string;
begin
  Result := False;
  if (Filter and NM_SHOW_ERRORS) = 0 then Exit;
  FDumpDir := MakeDirName(Pid);
  Json := TJSONObject.Create;
  try
    Json.AddPair('pid', TJSONNumber.Create(Pid));
    Json.AddPair('err_message', MessageText);
    OutPath := MakeOutPath('error_report.json');
    Result := WriteJsonToFile(OutPath, Json);
  finally
    Json.Free;
  end;
end;

end.
