{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Scanner.WorkingSet;

interface

uses
  System.Classes,
  Winapi.Windows,
  System.JSON,
  System.Generics.Collections,
  NativeMirror.Core.Types,
  NativeMirror.Core.Options,
  NativeMirror.Core.Memory,
  NativeMirror.Core.Buffer,
  NativeMirror.Stats.Core,
  NativeMirror.Stats.Analyzer,
  NativeMirror.Scanner.Reports,
  NativeMirror.Scanner.MemPage,
  NativeMirror.Scanner.ProcessDetails,
  NativeMirror.Scanner.ProcessReport,
  NativeMirror.Scanner.Signatures;

type
  TNativeMirrorWorkingSetScanReport = class(TNativeMirrorModuleScanReport)
  private
    FMatchedRules: TStringList;
  private
    FIsExecutable: Boolean;
    FIsListedModule: Boolean;
    FHasPe: Boolean;
    FHasShellcode: Boolean;
    FProtection: DWORD;
    FMappingType: DWORD;
    FMappedName: string;
    FDataCache: TNativeMirrorBuffer;
    FCustomMatches: TList<TNativeMirrorSignatureMatch>;
    FAllMatchedCount: NativeUInt;
    FMatchAreaStart: NativeUInt;
    FStats: TNativeMirrorAreaMultiStats;
    FAreaInfo: TNativeMirrorAreaInfo;
  protected
    procedure AddBaseJson(Json: TJSONObject); override;
  public
    constructor Create(ModuleBase: UInt64; ModuleSize: NativeUInt; Status: TNativeMirrorScanStatus);
    destructor Destroy; override;
    function ReportType: TNativeMirrorScanReportType; override;
    function CacheData(Data: PByte; Size: NativeUInt): Boolean;
    procedure AddMatchedRule(const RuleId: string);
    function GenerateTags(const ReportPath: string): NativeUInt; override;
    property IsExecutable: Boolean read FIsExecutable write FIsExecutable;
    property IsListedModule: Boolean read FIsListedModule write FIsListedModule;
    property HasPe: Boolean read FHasPe write FHasPe;
    property HasShellcode: Boolean read FHasShellcode write FHasShellcode;
    property Protection: DWORD read FProtection write FProtection;
    property MappingType: DWORD read FMappingType write FMappingType;
    property MappedName: string read FMappedName write FMappedName;
    property DataCache: TNativeMirrorBuffer read FDataCache;
    property CustomMatches: TList<TNativeMirrorSignatureMatch> read FCustomMatches;
    property AllMatchedCount: NativeUInt read FAllMatchedCount write FAllMatchedCount;
    property MatchAreaStart: NativeUInt read FMatchAreaStart write FMatchAreaStart;
    property Stats: TNativeMirrorAreaMultiStats read FStats;
    property AreaInfo: TNativeMirrorAreaInfo read FAreaInfo;
  end;

  TNativeMirrorWorkingSetScanner = class
  private
    FReader: INativeMirrorMemoryReader;
    FDetails: TNativeMirrorProcessDetails;
    FRegion: TNativeMirrorMemoryRegion;
    FOptions: TNativeMirrorOptions;
    FProcessReport: TNativeMirrorProcessScanReport;
    FMatcher: TNativeMirrorPatternMatcher;
    function CheckAreaContent(Page: TNativeMirrorMemPageData; Report: TNativeMirrorWorkingSetScanReport): Boolean;
    function IsExecutable(Page: TNativeMirrorMemPageData): Boolean;
    function IsPotentiallyExecutable(Page: TNativeMirrorMemPageData; Mode: TNativeMirrorDataScanMode): Boolean;
    function IsScannedAsModule(Page: TNativeMirrorMemPageData): Boolean;
    function ScanImage(Page: TNativeMirrorMemPageData): Boolean;
    function ScanExecutableArea(Page: TNativeMirrorMemPageData): TNativeMirrorWorkingSetScanReport;
  public
    constructor Create(const Reader: INativeMirrorMemoryReader; const Details: TNativeMirrorProcessDetails; const Region: TNativeMirrorMemoryRegion; const Options: TNativeMirrorOptions; ProcessReport: TNativeMirrorProcessScanReport; Matcher: TNativeMirrorPatternMatcher);
    function ScanRemote: TNativeMirrorWorkingSetScanReport;
  end;

implementation

uses
  System.SysUtils,
  NativeMirror.Scanner.Patterns,
  NativeMirror.Scanner.Artefacts,
  NativeMirror.Scanner.ProcessScanner;

constructor TNativeMirrorWorkingSetScanReport.Create(ModuleBase: UInt64; ModuleSize: NativeUInt; Status: TNativeMirrorScanStatus);
begin
  inherited Create(ModuleBase, ModuleSize, Status);
  FHasShellcode := False;
  FDataCache := TNativeMirrorBuffer.Create;
  FCustomMatches := TList<TNativeMirrorSignatureMatch>.Create;
  FStats := TNativeMirrorAreaMultiStats.Create;
  FAreaInfo := TNativeMirrorAreaInfo.Create;
end;

destructor TNativeMirrorWorkingSetScanReport.Destroy;
begin
  FMatchedRules.Free;
  FAreaInfo.Free;
  FStats.Free;
  FCustomMatches.Free;
  FDataCache.Free;
  inherited;
end;

function TNativeMirrorWorkingSetScanReport.ReportType: TNativeMirrorScanReportType;
begin
  Result := nmReportMemPageScan;
end;

function TNativeMirrorWorkingSetScanReport.CacheData(Data: PByte; Size: NativeUInt): Boolean;
begin
  Result := FDataCache.Assign(Data, Size);
end;

function MappingTypeName(Value: DWORD): string;
begin
  case Value of
    MEM_PRIVATE: Result := 'MEM_PRIVATE';
    MEM_MAPPED: Result := 'MEM_MAPPED';
    MEM_IMAGE: Result := 'MEM_IMAGE';
  else
    Result := 'unknown';
  end;
end;

procedure TNativeMirrorWorkingSetScanReport.AddBaseJson(Json: TJSONObject);
var
  StatsJson, FullAreaJson, Verdict, Patterns: TJSONObject;
  Frequent: string;
begin
  inherited;
  Json.AddPair('has_pe', TJSONNumber.Create(Ord(FHasPe)));
  Json.AddPair('has_shellcode', TJSONNumber.Create(Ord(FHasShellcode)));
  if not FIsExecutable then
    Json.AddPair('is_executable', TJSONNumber.Create(0));
  Json.AddPair('is_listed_module', TJSONNumber.Create(Ord(FIsListedModule)));
  Json.AddPair('protection', IntToHex(FProtection, 1).ToLower);
  Json.AddPair('mapping_type', MappingTypeName(FMappingType));
  if (FMappingType = MEM_IMAGE) or (FMappingType = MEM_MAPPED) then
    Json.AddPair('mapped_name', FMappedName);
  if FAllMatchedCount <> 0 then
  begin
    Patterns := TJSONObject.Create;
    Patterns.AddPair('total_matched', TJSONNumber.Create(FAllMatchedCount));
    if FCustomMatches.Count <> 0 then
      Patterns.AddPair('custom_matched', TJSONNumber.Create(FCustomMatches.Count));
    Json.AddPair('patterns', Patterns);
  end;
  if FStats.IsFilled then
  begin
    StatsJson := TJSONObject.Create;
    FullAreaJson := TJSONObject.Create;
    FullAreaJson.AddPair('offset', IntToHex(FStats.Area.Offset, 1).ToLower);
    FullAreaJson.AddPair('size', IntToHex(FStats.Area.Size, 1).ToLower);
    FullAreaJson.AddPair('charset_size', TJSONNumber.Create(FStats.Area.PopulationSize));
    Frequent := FStats.Area.MostFrequentValuesHex(16, 8);
    if Frequent <> '' then
      FullAreaJson.AddPair('most_freq_vals', Frequent);
    FullAreaJson.AddPair('entropy', TJSONNumber.Create(FloatToStrF(FStats.Area.Entropy, ffGeneral, 6, 0, TFormatSettings.Invariant)));
    StatsJson.AddPair('full_area', FullAreaJson);
    Json.AddPair('stats', StatsJson);
    if FAreaInfo.HasAnyMatch then
    begin
      Verdict := FAreaInfo.ToJson;
      Json.AddPair('stats_verdict', Verdict);
    end;
  end;
end;

constructor TNativeMirrorWorkingSetScanner.Create(const Reader: INativeMirrorMemoryReader; const Details: TNativeMirrorProcessDetails; const Region: TNativeMirrorMemoryRegion; const Options: TNativeMirrorOptions; ProcessReport: TNativeMirrorProcessScanReport; Matcher: TNativeMirrorPatternMatcher);
begin
  inherited Create;
  FReader := Reader;
  FDetails := Details;
  FRegion := Region;
  FOptions := Options;
  FProcessReport := ProcessReport;
  FMatcher := Matcher;
end;

function TNativeMirrorWorkingSetScanner.IsPotentiallyExecutable(Page: TNativeMirrorMemPageData; Mode: TNativeMirrorDataScanMode): Boolean;
var
  Readable: Boolean;
begin
  Result := False;
  if Mode = nmDataNoScan then
    Exit;
  if (Mode = nmDataNoDep) and FDetails.IsDep and not FProcessReport.IsManaged then
    Exit;
  if (Mode = nmDataDotNet) and not FProcessReport.IsManaged then
    Exit;
  Readable := IsReadableProtection(Page.MappingType, Page.Protection);
  if (Mode <> nmDataInaccessibleOnly) and Readable then
    Exit(True);
  if (Mode >= nmDataInaccessible) or (Mode = nmDataInaccessibleOnly) then
    Result := FDetails.IsReflection and ((Page.Protection and PAGE_NOACCESS) <> 0);
end;

function TNativeMirrorWorkingSetScanner.IsExecutable(Page: TNativeMirrorMemPageData): Boolean;
begin
  Result := IsExecutableProtection(Page.MappingType, Page.Protection) or IsPotentiallyExecutable(Page, FOptions.DataScanMode);
end;

function TNativeMirrorWorkingSetScanner.IsScannedAsModule(Page: TNativeMirrorMemPageData): Boolean;
begin
  Result := (Page.MappingType = MEM_IMAGE) and FProcessReport.HasModule(Page.AllocationBase);
end;

function TNativeMirrorWorkingSetScanner.CheckAreaContent(Page: TNativeMirrorMemPageData; Report: TNativeMirrorWorkingSetScanReport): Boolean;
var
  ByStats, Code, CodePatterns, CodeStats, Obfuscated: Boolean;
  AllMatches: TList<TNativeMirrorSignatureMatch>;
  Settings: TNativeMirrorMultiStatsSettings;
  CustomCount: NativeUInt;
  Rules: Cardinal;
  Data: PByte;
  Size, StartOffset: NativeUInt;
begin
  Result := False;
  if not Page.Load then
    Exit;
  Data := Page.GetLoadedData(True);
  Size := Page.GetLoadedSize(True);
  StartOffset := Page.GetStartOffset(True);
  ByStats := FOptions.ShellcodeMode in [nmShellcodeStats, nmShellcodePatternsOrStats, nmShellcodePatternsAndStats];
  Code := False;
  CodePatterns := False;
  CodeStats := False;
  Obfuscated := False;
  CustomCount := 0;
  if (FMatcher <> nil) and FMatcher.IsReady then
  begin
    AllMatches := TList<TNativeMirrorSignatureMatch>.Create;
    try
      Report.AllMatchedCount := FMatcher.FindAll(Data, Size, AllMatches);
      CustomCount := FMatcher.FilterCustom(AllMatches, Report.CustomMatches);
      if Report.AllMatchedCount <> 0 then
      begin
        Report.MatchAreaStart := StartOffset;
        CodePatterns := True;
        Code := True;
        if FOptions.ShellcodeMode = nmShellcodePatternsOrStats then
          ByStats := False;
      end
      else if FOptions.ShellcodeMode = nmShellcodePatternsAndStats then
        ByStats := False;
    finally
      AllMatches.Free;
    end;
  end;
  if ByStats or (FOptions.ObfuscationMode <> nmObfuscationNone) then
  begin
    Settings := TNativeMirrorMultiStatsSettings.Create;
    try
      TNativeMirrorStatsAnalyzer.FillCodeStrings(Settings);
      Report.Stats.Fill(Data, Size, StartOffset, Settings);
      if TNativeMirrorStatsAnalyzer.FindMatches(Report.Stats, NM_RULE_CODE, Report.AreaInfo) <> 0 then
      begin
        CodeStats := True;
        Code := True;
      end;
      if not CodeStats and (FOptions.ObfuscationMode <> nmObfuscationNone) then
      begin
        Rules := 0;
        case FOptions.ObfuscationMode of
          nmObfuscationAny: Rules := NM_RULE_OBFUSCATED or NM_RULE_ENCRYPTED;
          nmObfuscationStrong: Rules := NM_RULE_ENCRYPTED;
          nmObfuscationWeak: Rules := NM_RULE_OBFUSCATED;
        end;
        Obfuscated := TNativeMirrorStatsAnalyzer.FindMatches(Report.Stats, Rules, Report.AreaInfo) <> 0;
        if Obfuscated and (Page.MappingType = MEM_MAPPED) and not IsExecutableProtection(Page.MappingType, Page.Protection) and Page.LoadMappedName then
          Obfuscated := False;
      end;
    finally
      Settings.Free;
    end;
  end;
  if FOptions.ShellcodeMode = nmShellcodePatternsAndStats then
    Code := CodePatterns and CodeStats
  else if FOptions.ShellcodeMode = nmShellcodePatternsOrStats then
    Code := CodePatterns or CodeStats;
  Report.HasShellcode := Code;
  if (Obfuscated and (FOptions.ObfuscationMode <> nmObfuscationNone)) or (Code and ((FOptions.ShellcodeMode <> nmShellcodeNone) or (CustomCount <> 0))) then
    Report.Status := NM_SCAN_SUSPICIOUS;
  if Report.Status = NM_SCAN_SUSPICIOUS then
    Report.CacheData(Page.GetLoadedData(False), Page.GetLoadedSize(False));
  Result := True;
end;

function TNativeMirrorWorkingSetScanner.ScanExecutableArea(Page: TNativeMirrorMemPageData): TNativeMirrorWorkingSetScanReport;
var
  ArtefactScanner: TNativeMirrorArtefactScanner;
  ArtefactReport: TNativeMirrorArtefactScanReport;
  RegionSize: NativeUInt;
begin
  Result := nil;
  if not Page.Load then
    Exit;
  if not IsScannedAsModule(Page) then
  begin
    ArtefactScanner := TNativeMirrorArtefactScanner.Create(FReader, FDetails, Page, FProcessReport);
    try
      ArtefactReport := ArtefactScanner.ScanRemote;
      if ArtefactReport <> nil then
        Exit(ArtefactReport);
    finally
      ArtefactScanner.Free;
    end;
  end;
  if ((FMatcher = nil) or not FMatcher.IsReady) and (FOptions.ObfuscationMode = nmObfuscationNone) then
    Exit;
  if Page.RegionEnd <= Page.RegionStart then
    Exit;
  RegionSize := NativeUInt(Page.RegionEnd - Page.RegionStart);
  Result := TNativeMirrorWorkingSetScanReport.Create(Page.RegionStart, RegionSize, NM_SCAN_NOT_SUSPICIOUS);
  if not CheckAreaContent(Page, Result) then
    Result.Status := NM_SCAN_ERROR;
  if Result.Status = NM_SCAN_NOT_SUSPICIOUS then
  begin
    Result.Free;
    Exit(nil);
  end;
  Result.HasPe := IsScannedAsModule(Page) and FProcessReport.HasModule(Page.RegionStart);
end;

function TNativeMirrorWorkingSetScanner.ScanImage(Page: TNativeMirrorMemPageData): Boolean;
begin
  Result := TNativeMirrorProcessScanner.ScanDetachedImage(FReader, FDetails, Page, FOptions, FProcessReport);
end;

function TNativeMirrorWorkingSetScanner.ScanRemote: TNativeMirrorWorkingSetScanReport;
var
  Page: TNativeMirrorMemPageData;
  RegionSize: UInt64;
begin
  Result := nil;
  Page := TNativeMirrorMemPageData.Create(FReader, FDetails.IsReflection, FRegion.BaseAddress, 0);
  try
    Page.IsListedModule := FProcessReport.HasModule(FRegion.BaseAddress);
    if not Page.IsInfoFilled and not Page.FillInfo then
      Exit;
    if Page.AllocationBase <> FRegion.AllocationBase then
      Exit;
    RegionSize := Page.RegionEnd - Page.RegionStart;
    if RegionSize <> FRegion.RegionSize then
      Exit;
    if not IsExecutable(Page) then
      Exit;
    if (Page.MappingType = MEM_MAPPED) and Page.IsRealMapping then
      Exit;
    if Page.MappingType = MEM_IMAGE then
    begin
      Page.LoadModuleName;
      Page.LoadMappedName;
      if not IsScannedAsModule(Page) then
        ScanImage(Page);
      if FProcessReport.HasModuleContaining(Page.RegionStart, NativeUInt(RegionSize)) then
        Exit;
    end;
    Result := ScanExecutableArea(Page);
    if Result <> nil then
    begin
      Result.IsExecutable := True;
      Result.IsListedModule := Page.IsListedModule;
      Result.Protection := Page.Protection;
      Result.MappingType := Page.MappingType;
      Result.MappedName := Page.MappedName;
    end;
  finally
    Page.Free;
  end;
end;

procedure TNativeMirrorWorkingSetScanReport.AddMatchedRule(const RuleId: string);
begin
  if FMatchedRules = nil then
    FMatchedRules := TStringList.Create;
  if FMatchedRules.IndexOf(RuleId) < 0 then
    FMatchedRules.Add(RuleId);
end;

function TNativeMirrorWorkingSetScanReport.GenerateTags(const ReportPath: string): NativeUInt;
var
  Bytes: TBytes;
  FS: TFileStream;
  Match: TNativeMirrorSignatureMatch;
  SB: TStringBuilder;
begin
  Result := 0;
  if FCustomMatches.Count = 0 then
    Exit;
  SB := TStringBuilder.Create;
  try
    for Match in FCustomMatches do
      if Match.Signature <> nil then
      begin
        SB.Append(IntToHex(FMatchAreaStart + Match.Offset, 1).ToLower);
        SB.Append(';');
        SB.Append(Match.Signature.Name);
        SB.Append(';');
        SB.Append(IntToHex(Match.Signature.Length, 1).ToLower);
        SB.AppendLine;
        Inc(Result);
      end;
    Bytes := TEncoding.UTF8.GetBytes(SB.ToString);
  finally
    SB.Free;
  end;
  if (Result = 0) or (Length(Bytes) = 0) then
  begin
    Result := 0;
    Exit;
  end;
  try
    FS := TFileStream.Create(ReportPath, fmCreate);
    try
      FS.WriteBuffer(Bytes[0], Length(Bytes));
    finally
      FS.Free;
    end;
  except
    Result := 0;
  end;
end;

end.
