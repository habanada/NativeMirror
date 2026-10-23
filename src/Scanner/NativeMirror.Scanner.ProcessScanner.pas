{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Scanner.ProcessScanner;

interface

uses
  Winapi.Windows,
  System.Generics.Collections,
  NativeMirror.Core.Memory,
  NativeMirror.Core.Options,
  NativeMirror.Core.Types,
  NativeMirror.Scanner.MemPage,
  NativeMirror.Scanner.ModuleData,
  NativeMirror.Scanner.ProcessDetails,
  NativeMirror.Scanner.ProcessReport,
  NativeMirror.Scanner.Reports,
  NativeMirror.Platform.Symbols,
  NativeMirror.Layer,
  NativeMirror.Scanner.Signatures;

type
  TNativeMirrorScannerMessageEvent = reference to procedure(const Text: string; IsError: Boolean);

  TNativeMirrorProcessScanner = class
  private
    FReader: INativeMirrorMemoryReader;
    FProcessHandle: THandle;
    FIsDep: Boolean;
    FIsReflection: Boolean;
    FOptions: TNativeMirrorOptions;
    FDisasm: IDisassembler;
    FCodeGen: ICodeGen;
    FSectionCompare: TNativeMirrorSectionCompareFunc;
    FSymbols: TNativeMirrorSymbolsManager;
    FIgnoredModules: TList<string>;
    FMatcher: TNativeMirrorPatternMatcher;
    FOnMessage: TNativeMirrorScannerMessageEvent;
    procedure Emit(const Text: string; IsError: Boolean = False);
    procedure EmitScanTime(const ScannedElement: string; StartTick: DWORD);
    procedure Initialize(const Reader: INativeMirrorMemoryReader; IsReflection: Boolean; const Options: TNativeMirrorOptions);
    function IsIgnoredModule(const ModuleName: string): Boolean;
    function NeedsExportsMap: Boolean;
    function ScanForMappingMismatch(ModuleData: TNativeMirrorModuleData; ProcessReport: TNativeMirrorProcessScanReport): TNativeMirrorModuleScanReport;
    function ScanModules(ProcessReport: TNativeMirrorProcessScanReport): NativeUInt;
    function ScanModulesIats(ProcessReport: TNativeMirrorProcessScanReport): NativeUInt;
    function ScanWorkingSet(ProcessReport: TNativeMirrorProcessScanReport): NativeUInt;
    function ScanThreads(ProcessReport: TNativeMirrorProcessScanReport): NativeUInt;
    function ResolveHookTargets(ProcessReport: TNativeMirrorProcessScanReport): Boolean;
    function FilterDotNetReport(ProcessReport: TNativeMirrorProcessScanReport): Boolean;
    class function SetNonSuspicious(Reports: TObjectList<TNativeMirrorModuleScanReport>; ReportType: TNativeMirrorScanReportType; DotNetModulesOnly: Boolean): Boolean; static;
  public
    constructor Create(const Reader: INativeMirrorMemoryReader; IsReflection: Boolean; const Options: TNativeMirrorOptions); overload;
    constructor Create(ProcessHandle: THandle; IsReflection: Boolean; const Options: TNativeMirrorOptions); overload;
    destructor Destroy; override;
    function ScanRemote: TNativeMirrorProcessScanReport;
    class function ScanForHollows(ModuleData: TNativeMirrorModuleData; RemoteData: TNativeMirrorRemoteModuleData; ProcessReport: TNativeMirrorProcessScanReport): TNativeMirrorScanStatus; static;
    class function ScanForHooks(ModuleData: TNativeMirrorModuleData; RemoteData: TNativeMirrorRemoteModuleData; ProcessReport: TNativeMirrorProcessScanReport; ScanData, ScanInaccessible: Boolean; SectionCompare: TNativeMirrorSectionCompareFunc = nil): TNativeMirrorScanStatus; static;
    class function ScanForIatHooks(ModuleData: TNativeMirrorModuleData; RemoteData: TNativeMirrorRemoteModuleData; ProcessReport: TNativeMirrorProcessScanReport; Filter: TNativeMirrorIatScanMode): TNativeMirrorScanStatus; static;
    class function ScanDetachedImage(const Reader: INativeMirrorMemoryReader; const Details: TNativeMirrorProcessDetails; Page: TNativeMirrorMemPageData; const Options: TNativeMirrorOptions; ProcessReport: TNativeMirrorProcessScanReport): Boolean; static;
    procedure SetLayer(Disasm: IDisassembler; CodeGen: ICodeGen = nil);
    property OnMessage: TNativeMirrorScannerMessageEvent read FOnMessage write FOnMessage;
    property Reader: INativeMirrorMemoryReader read FReader;
    property ProcessHandle: THandle read FProcessHandle;
    property IsReflection: Boolean read FIsReflection;
    property IsDep: Boolean read FIsDep;
  end;

implementation

uses
  System.SysUtils,
  NativeMirror.Core.Text,
  NativeMirror.Platform.Enumeration,
  NativeMirror.Platform.Process,
  NativeMirror.Platform.Threads,
  NativeMirror.Scanner.Threads,
  NativeMirror.Scanner.Code,
  NativeMirror.Scanner.Headers,
  NativeMirror.Scanner.HookTargets,
  NativeMirror.Scanner.IAT,
  NativeMirror.Scanner.Mapping,
  NativeMirror.Scanner.WorkingSet;

procedure TNativeMirrorProcessScanner.Emit(const Text: string; IsError: Boolean);
begin
  if FOptions.Quiet then Exit;
  if Assigned(FOnMessage) then FOnMessage(Text, IsError)
  else if IsError then Writeln(ErrOutput, Text)
  else Writeln(Text);
end;

procedure TNativeMirrorProcessScanner.EmitScanTime(const ScannedElement: string; StartTick: DWORD);
var
  Elapsed: DWORD;
begin
  if FOptions.Quiet then Exit;
  Elapsed := DWORD((UInt64(GetTickCount) + $100000000 - StartTick) and $FFFFFFFF);
  Emit(FormatScanTime(ScannedElement, Elapsed));
end;

procedure TNativeMirrorProcessScanner.Initialize(const Reader: INativeMirrorMemoryReader; IsReflection: Boolean; const Options: TNativeMirrorOptions);
begin
  if Reader = nil then
    raise EArgumentException.Create('Reader must not be nil.');
  FReader := Reader;
  FProcessHandle := Reader.ProcessHandle;
  FIsReflection := IsReflection;
  FOptions := Options;
  FSectionCompare := NativeMirrorScalarSectionCompare;
  FIgnoredModules := TList<string>.Create;
  if FOptions.ScanThreads then
  begin
    FSymbols := TNativeMirrorSymbolsManager.Create;
    FSymbols.InitSymbols(FProcessHandle, FOptions.DownloadSymbols, False);
  end;
  if FOptions.IgnoredModules <> '' then
    StringToList(FOptions.IgnoredModules, ';', FIgnoredModules, True);
  FMatcher := NativeMirrorSharedPatternMatcher;
  NativeMirrorInitializePatterns(FOptions.PatternFile,
    FOptions.ShellcodeMode in [nmShellcodePatterns, nmShellcodePatternsOrStats, nmShellcodePatternsAndStats]);
end;

constructor TNativeMirrorProcessScanner.Create(const Reader: INativeMirrorMemoryReader; IsReflection: Boolean; const Options: TNativeMirrorOptions);
begin
  inherited Create;
  Initialize(Reader, IsReflection, Options);
end;

constructor TNativeMirrorProcessScanner.Create(ProcessHandle: THandle; IsReflection: Boolean; const Options: TNativeMirrorOptions);
var
  ProcessReader: INativeMirrorMemoryReader;
begin
  inherited Create;
  ProcessReader := TNativeMirrorProcessMemoryReader.Create(ProcessHandle, False);
  Initialize(ProcessReader, IsReflection, Options);
end;

destructor TNativeMirrorProcessScanner.Destroy;
begin
  FSymbols.Free;
  FIgnoredModules.Free;
  inherited;
end;

function TNativeMirrorProcessScanner.IsIgnoredModule(const ModuleName: string): Boolean;
begin
  Result := IsStringInList(ExtractFileName(ModuleName), FIgnoredModules, True);
end;

function TNativeMirrorProcessScanner.NeedsExportsMap: Boolean;
begin
  Result := (FOptions.ImportRecoveryMode <> nmImportNone) or (FOptions.IatScanMode <> nmIatNone) or FOptions.ScanThreads;
end;

class function TNativeMirrorProcessScanner.ScanForHollows(ModuleData: TNativeMirrorModuleData; RemoteData: TNativeMirrorRemoteModuleData; ProcessReport: TNativeMirrorProcessScanReport): TNativeMirrorScanStatus;
var
  Scanner: TNativeMirrorHeadersScanner;
  Report: TNativeMirrorHeadersScanReport;
{$IFDEF WIN64}
  IsWow64: Boolean;
{$ENDIF}
begin
  Result := NM_SCAN_ERROR;
  if (ModuleData = nil) or (RemoteData = nil) or (ProcessReport = nil) then
    Exit;
  Scanner := TNativeMirrorHeadersScanner.Create(ModuleData, RemoteData);
  try
    Report := Scanner.ScanRemote;
    if Report = nil then
      Exit;
{$IFDEF WIN64}
    if Report.ArchitectureMismatch and IsProcessWow64(ModuleData.ProcessHandle, IsWow64) and IsWow64 and ModuleData.ReloadWow64 then
    begin
      Report.Free;
      Report := Scanner.ScanRemote;
      if Report = nil then
        Exit;
    end;
{$ENDIF}
    Report.ModuleFile := ModuleData.ModuleName;
    Report.IsInPeb := ModuleData.IsPebConnected;
    Result := Report.Status;
    if (Result <> NM_SCAN_NOT_SUSPICIOUS) and not Report.IsHeaderReplaced then
      Result := NM_SCAN_NOT_SUSPICIOUS;
    ProcessReport.AppendReport(Report);
  finally
    Scanner.Free;
  end;
end;

class function TNativeMirrorProcessScanner.ScanForHooks(ModuleData: TNativeMirrorModuleData; RemoteData: TNativeMirrorRemoteModuleData; ProcessReport: TNativeMirrorProcessScanReport; ScanData, ScanInaccessible: Boolean; SectionCompare: TNativeMirrorSectionCompareFunc = nil): TNativeMirrorScanStatus;
var
  Scanner: TNativeMirrorCodeScanner;
  Report: TNativeMirrorCodeScanReport;
begin
  Result := NM_SCAN_ERROR;
  if (ModuleData = nil) or (RemoteData = nil) or (ProcessReport = nil) then
    Exit;
  Scanner := TNativeMirrorCodeScanner.Create(ModuleData, RemoteData, SectionCompare);
  try
    Scanner.ScanData := ScanData;
    Scanner.ScanInaccessible := ScanInaccessible;
    Report := Scanner.ScanRemote;
    if Report = nil then
      Exit;
    Report.ModuleFile := ModuleData.ModuleName;
    Result := Report.Status;
    ProcessReport.AppendReport(Report);
  finally
    Scanner.Free;
  end;
end;

class function TNativeMirrorProcessScanner.ScanForIatHooks(ModuleData: TNativeMirrorModuleData; RemoteData: TNativeMirrorRemoteModuleData; ProcessReport: TNativeMirrorProcessScanReport; Filter: TNativeMirrorIatScanMode): TNativeMirrorScanStatus;
var
  Scanner: TNativeMirrorIatScanner;
  Report: TNativeMirrorIatScanReport;
begin
  Result := NM_SCAN_ERROR;
  if (ModuleData = nil) or (RemoteData = nil) or (ProcessReport = nil) or (ProcessReport.ExportsMap = nil) then
    Exit;
  if ProcessReport.IsModuleReplaced(ModuleData.ModuleBase) then
    Exit;
  Scanner := TNativeMirrorIatScanner.Create(ModuleData, RemoteData, ProcessReport.ExportsMap, ProcessReport.ModulesInfo, Filter);
  try
    Report := Scanner.ScanRemote;
    if Report = nil then
      Exit;
    Report.ModuleFile := ModuleData.ModuleName;
    Result := Report.Status;
    ProcessReport.AppendReport(Report);
  finally
    Scanner.Free;
  end;
end;

class function TNativeMirrorProcessScanner.ScanDetachedImage(const Reader: INativeMirrorMemoryReader; const Details: TNativeMirrorProcessDetails; Page: TNativeMirrorMemPageData; const Options: TNativeMirrorOptions; ProcessReport: TNativeMirrorProcessScanReport): Boolean;
var
  ModuleBase: UInt64;
  ModuleData: TNativeMirrorModuleData;
  RemoteData: TNativeMirrorRemoteModuleData;
  Status: TNativeMirrorScanStatus;
  ScanData, ScanInaccessible: Boolean;
begin
  Result := False;
  if (Reader = nil) or (Page = nil) or (ProcessReport = nil) then
    Exit;
  if (Page.MappedName = '') and not Page.LoadMappedName then
    Exit;
  ModuleBase := Page.AllocationBase;
  RemoteData := TNativeMirrorRemoteModuleData.Create(Reader, Details.IsReflection, ModuleBase);
  try
    if not RemoteData.Initialize then
      Exit;
    ModuleData := TNativeMirrorModuleData.Create(Reader.ProcessHandle, ModuleBase, False, Options.UseCache, Page.MappedName);
    try
      if not ModuleData.LoadOriginal then
      begin
        ProcessReport.AppendReport(TNativeMirrorUnreachableModuleReport.Create(ModuleBase, 0, Page.MappedName));
        Exit;
      end;
      Status := ScanForHollows(ModuleData, RemoteData, ProcessReport);
      if Status = NM_SCAN_ERROR then
        Exit;
      if Status = NM_SCAN_SUSPICIOUS then
        Exit(True);
      if not Options.NoHooks then
      begin
        ScanData := ((Options.DataScanMode >= nmDataAlways) and (Options.DataScanMode <> nmDataInaccessibleOnly)) or (not Details.IsDep and (Options.DataScanMode = nmDataNoDep));
        ScanInaccessible := Details.IsReflection and (Options.DataScanMode >= nmDataInaccessible);
        ScanForHooks(ModuleData, RemoteData, ProcessReport, ScanData, ScanInaccessible);
      end;
      Result := True;
    finally
      ModuleData.Free;
    end;
  finally
    RemoteData.Free;
  end;
end;

function TNativeMirrorProcessScanner.ScanForMappingMismatch(ModuleData: TNativeMirrorModuleData; ProcessReport: TNativeMirrorProcessScanReport): TNativeMirrorModuleScanReport;
var
  Scanner: TNativeMirrorMappingScanner;
begin
  Result := nil;
  Scanner := TNativeMirrorMappingScanner.Create(ModuleData);
  try
    Result := Scanner.ScanRemote;
    ProcessReport.AppendReport(Result);
  finally
    Scanner.Free;
  end;
end;

function TNativeMirrorProcessScanner.ScanModules(ProcessReport: TNativeMirrorProcessScanReport): NativeUInt;
var
  Modules: TList<UInt64>;
  ModuleBase: UInt64;
  ModuleData: TNativeMirrorModuleData;
  RemoteData: TNativeMirrorRemoteModuleData;
  MappingReport: TNativeMirrorModuleScanReport;
  Hollowed: TNativeMirrorScanStatus;
  ScanData, ScanInaccessible: Boolean;
begin
  Result := 0;
  Modules := TList<UInt64>.Create;
  try
    if EnumerateProcessModules(FProcessHandle, Modules) = 0 then
      Exit;
    if NeedsExportsMap then
      ProcessReport.EnsureExportsMap;
    for ModuleBase in Modules do
    begin
      if not IsProcessRunning(FProcessHandle) then
        Break;
      Inc(Result);
      ModuleData := TNativeMirrorModuleData.Create(FProcessHandle, ModuleBase, True, FOptions.UseCache);
      try
        MappingReport := ScanForMappingMismatch(ModuleData, ProcessReport);
        if not ModuleData.LoadOriginal then
        begin
          Emit('[!][' + UIntToStr(FOptions.Pid) + '] Suspicious: could not read the module file!');
          ProcessReport.AppendReport(TNativeMirrorUnreachableModuleReport.Create(ModuleBase, 0, ModuleData.ModuleName));
          Continue;
        end;
        if ModuleData.IsDotNet then
          ProcessReport.IsManaged := True;
        if IsIgnoredModule(ModuleData.ModuleName) then
        begin
          if ProcessReport.ExportsMap <> nil then
            ProcessReport.ExportsMap.AddToLookup(ModuleData.ModuleName, HMODULE(NativeUInt(ModuleData.OriginalModule)), ModuleData.OriginalSize, ModuleData.ModuleBase);
          Emit('[*] Skipping ignored: ' + IntToHex(ModuleData.ModuleBase, 1).ToLower + ' : ' + ModuleData.ModuleName);
          ProcessReport.AppendReport(TNativeMirrorSkippedModuleReport.Create(ModuleData.ModuleBase, ModuleData.OriginalSize, ModuleData.ModuleName));
          Continue;
        end;
        if ModuleData.IsDotNet then
          Emit('[*] Scanning: ' + ModuleData.ModuleName + ' (.NET) ')
        else
          Emit('[*] Scanning: ' + ModuleData.ModuleName);
        RemoteData := TNativeMirrorRemoteModuleData.Create(FReader, FIsReflection, ModuleBase);
        try
          if not RemoteData.Initialize then
          begin
            if not IsProcessRunning(FProcessHandle) then
            begin
              Dec(Result);
              Break;
            end;
            ProcessReport.AppendReport(TNativeMirrorMalformedHeaderReport.Create(ModuleBase, 0, ModuleData.ModuleName));
            Continue;
          end;
          Hollowed := ScanForHollows(ModuleData, RemoteData, ProcessReport);
          if Hollowed = NM_SCAN_ERROR then
            Continue;
          if (Hollowed = NM_SCAN_NOT_SUSPICIOUS) and (MappingReport <> nil) then
            MappingReport.Status := NM_SCAN_NOT_SUSPICIOUS;
          if ProcessReport.ExportsMap <> nil then
            ProcessReport.ExportsMap.AddToLookup(ModuleData.ModuleName, HMODULE(NativeUInt(ModuleData.OriginalModule)), ModuleData.OriginalSize, ModuleData.ModuleBase);
          if not FOptions.NoHooks and (Hollowed = NM_SCAN_NOT_SUSPICIOUS) then
          begin
            ScanData := ((FOptions.DataScanMode >= nmDataAlways) and (FOptions.DataScanMode <> nmDataInaccessibleOnly)) or (not FIsDep and (FOptions.DataScanMode = nmDataNoDep));
            ScanInaccessible := FIsReflection and (FOptions.DataScanMode >= nmDataInaccessible);
            ScanForHooks(ModuleData, RemoteData, ProcessReport, ScanData, ScanInaccessible, FSectionCompare);
          end;
        finally
          RemoteData.Free;
        end;
      finally
        ModuleData.Free;
      end;
    end;
  finally
    Modules.Free;
  end;
end;

function TNativeMirrorProcessScanner.ScanModulesIats(ProcessReport: TNativeMirrorProcessScanReport): NativeUInt;
var
  Modules: TList<UInt64>;
  ModuleBase: UInt64;
  ModuleData: TNativeMirrorModuleData;
  RemoteData: TNativeMirrorRemoteModuleData;
  StartTick: DWORD;
begin
  Result := 0;
  if (ProcessReport = nil) or (ProcessReport.ExportsMap = nil) then
    Exit;
  Modules := TList<UInt64>.Create;
  try
    if EnumerateProcessModules(FProcessHandle, Modules) = 0 then
      Exit;
    Emit('Scanning for IAT hooks: ' + IntToStr(Modules.Count) + ' modules.');
    StartTick := GetTickCount;
    for ModuleBase in Modules do
    begin
      if not IsProcessRunning(FProcessHandle) then
        Break;
      Inc(Result);
      ModuleData := TNativeMirrorModuleData.Create(FProcessHandle, ModuleBase, True, FOptions.UseCache);
      try
        if IsIgnoredModule(ModuleData.ModuleName) then
          Continue;
        RemoteData := TNativeMirrorRemoteModuleData.Create(FReader, FIsReflection, ModuleBase);
        try
          if not RemoteData.Initialize then
          begin
            ProcessReport.AppendReport(TNativeMirrorMalformedHeaderReport.Create(ModuleBase, 0, ModuleData.ModuleName));
            Continue;
          end;
          ScanForIatHooks(ModuleData, RemoteData, ProcessReport, FOptions.IatScanMode);
        finally
          RemoteData.Free;
        end;
      finally
        ModuleData.Free;
      end;
    end;
    EmitScanTime('IATs', StartTick);
  finally
    Modules.Free;
  end;
end;

function TNativeMirrorProcessScanner.ScanWorkingSet(ProcessReport: TNativeMirrorProcessScanReport): NativeUInt;
var
  Regions: TList<TNativeMirrorMemoryRegion>;
  Region: TNativeMirrorMemoryRegion;
  Details: TNativeMirrorProcessDetails;
  Scanner: TNativeMirrorWorkingSetScanner;
  Report: TNativeMirrorWorkingSetScanReport;
  StartTick: DWORD;
begin
  Result := 0;
  if CountWorkingSetEntries(FProcessHandle) = 0 then
    raise Exception.Create('Could not query the working set.');
  StartTick := GetTickCount;
  Details := TNativeMirrorProcessDetails.Create(FIsReflection, FIsDep);
  Regions := TList<TNativeMirrorMemoryRegion>.Create;
  try
    EnumerateWorkingSetRegions(FProcessHandle, Regions);
    Emit('Scanning workingset: ' + IntToStr(Regions.Count) + ' memory regions.');
    for Region in Regions do
    begin
      if not IsProcessRunning(FProcessHandle) then
        Break;
      Inc(Result);
      Scanner := TNativeMirrorWorkingSetScanner.Create(FReader, Details, Region, FOptions, ProcessReport, FMatcher);
      try
        Report := Scanner.ScanRemote;
      finally
        Scanner.Free;
      end;
      if Report = nil then
        Continue;
      Report.IsListedModule := ProcessReport.HasModule(Report.ModuleBase);
      if not Report.HasPe and ProcessReport.HasModuleContaining(Report.ModuleBase, Report.ModuleSize) then
        Report.Status := NM_SCAN_NOT_SUSPICIOUS;
      ProcessReport.AppendReport(Report);
    end;
    EmitScanTime('Workingset', StartTick);
  finally
    Regions.Free;
  end;
end;

function TNativeMirrorProcessScanner.ScanThreads(ProcessReport: TNativeMirrorProcessScanReport): NativeUInt;
var
  Threads: TNativeMirrorThreadMap;
  ThreadIds: TList<DWORD>;
  Tid: DWORD;
  Info: TNativeMirrorThreadInfo;
  Scanner: TNativeMirrorThreadScanner;
  Report: TNativeMirrorThreadScanReport;
  Fetched: Boolean;
  StartTick: DWORD;
begin
  Result := 0;
  if ProcessReport = nil then Exit;
{$IFNDEF WIN64}
  if IsProcess64Bit(FProcessHandle) then Exit;
{$ENDIF}
  Emit('Scanning threads.');
  StartTick := GetTickCount;
  Threads := TNativeMirrorThreadMap.Create;
  ThreadIds := TList<DWORD>.Create;
  try
    Fetched := FetchThreadsInfo(ProcessReport.Pid, Threads);
    if not Fetched then Fetched := FetchThreadsBySnapshot(ProcessReport.Pid, Threads);
    if not Fetched then
    begin
      Emit('[-] Failed enumerating threads or no live threads found.', True);
      Exit;
    end;
    if QueryThreadsDetails(Threads) = 0 then
      Emit('[-] Failed quering thread details.');
    for Tid in Threads.Keys do ThreadIds.Add(Tid);
    ThreadIds.Sort;
    for Tid in ThreadIds do
    begin
      if not IsProcessRunning(FProcessHandle) then Break;
      Info := Threads[Tid];
      if not Info.IsFilled then Continue;
      Scanner := TNativeMirrorThreadScanner.Create(FProcessHandle, FIsReflection, ProcessReport.IsManaged, Info, ProcessReport.ModulesInfo, ProcessReport.ExportsMap, FSymbols);
      try
        Report := Scanner.ScanRemote;
        if Report <> nil then
        begin
          ProcessReport.AppendReport(Report);
          Inc(Result);
        end;
      finally
        Scanner.Free;
      end;
    end;
    EmitScanTime('Threads', StartTick);
  finally
    ThreadIds.Free;
    Threads.Free;
  end;
end;

function TNativeMirrorProcessScanner.ResolveHookTargets(ProcessReport: TNativeMirrorProcessScanReport): Boolean;
var
  Resolver: TNativeMirrorHookTargetResolver;
begin
  Result := False;
  if ProcessReport = nil then
    Exit;
  Resolver := TNativeMirrorHookTargetResolver.Create(ProcessReport);
  try
    Result := Resolver.ResolveAll <> 0;
  finally
    Resolver.Free;
  end;
end;

class function TNativeMirrorProcessScanner.SetNonSuspicious(Reports: TObjectList<TNativeMirrorModuleScanReport>; ReportType: TNativeMirrorScanReportType; DotNetModulesOnly: Boolean): Boolean;
var
  Report: TNativeMirrorModuleScanReport;
begin
  Result := False;
  if Reports = nil then
    Exit;
  for Report in Reports do
  begin
    if Report.ReportType <> ReportType then
      Continue;
    if DotNetModulesOnly and not Report.IsDotNetModule then
      Continue;
    if Report.Status = NM_SCAN_SUSPICIOUS then
    begin
      Report.Status := NM_SCAN_NOT_SUSPICIOUS;
      Result := True;
    end;
  end;
end;

function TNativeMirrorProcessScanner.FilterDotNetReport(ProcessReport: TNativeMirrorProcessScanReport): Boolean;
var
  Changed1, Changed2: Boolean;
begin
  Result := False;
  if (ProcessReport = nil) or not ProcessReport.IsManaged or (FOptions.DotNetPolicy = nmDotNetNone) then
    Exit;
  if FOptions.DotNetPolicy in [nmDotNetSkipMapping, nmDotNetSkipAll] then
    Result := SetNonSuspicious(ProcessReport.Reports, nmReportMappingScan, True);
  if FOptions.DotNetPolicy in [nmDotNetSkipHooks, nmDotNetSkipAll] then
    Result := SetNonSuspicious(ProcessReport.Reports, nmReportCodeScan, False);
  if FOptions.DotNetPolicy in [nmDotNetSkipShellcode, nmDotNetSkipAll] then
  begin
    Changed1 := SetNonSuspicious(ProcessReport.Reports, nmReportMemPageScan, False);
    Changed2 := SetNonSuspicious(ProcessReport.Reports, nmReportThreadsScan, False);
    Result := Changed1 or Changed2;
  end;
end;

function TNativeMirrorProcessScanner.ScanRemote: TNativeMirrorProcessScanReport;
var
  ModulesScanned, RegionsScanned, IatsScanned, ThreadsScanned: NativeUInt;
  Errors: string;
  Pid: DWORD;

  procedure AppendError(const StageName, MessageText: string);
  begin
    if Errors <> '' then
      Errors := Errors + ' ';
    Errors := Errors + StageName + ': ' + MessageText;
  end;

begin
  if FProcessHandle = 0 then
    raise Exception.Create('Invalid process handle.');
  FIsDep := IsDepEnabled(FProcessHandle);
  Pid := FOptions.Pid;
  if Pid = 0 then
    Pid := GetProcessId(FProcessHandle);
  Result := TNativeMirrorProcessScanReport.Create(Pid, IsProcess64Bit(FProcessHandle), FIsReflection);
  try
    Result.MainImagePath := GetProcessImagePath(FProcessHandle);
    ModulesScanned := 0;
    RegionsScanned := 0;
    IatsScanned := 0;
    ThreadsScanned := 0;
    Errors := '';
    try
      ModulesScanned := ScanModules(Result);
    except
      on E: Exception do
      begin
        ModulesScanned := 0;
        AppendError('modules', E.Message);
      end;
    end;
    try
      RegionsScanned := ScanWorkingSet(Result);
    except
      on E: Exception do
      begin
        RegionsScanned := 0;
        AppendError('working set', E.Message);
      end;
    end;
    if FOptions.IatScanMode <> nmIatNone then
    begin
      try
        IatsScanned := ScanModulesIats(Result);
      except
        on E: Exception do
        begin
          IatsScanned := 0;
          AppendError('IATs', E.Message);
        end;
      end;
    end;
    if FOptions.ScanThreads then
    begin
      try
        ThreadsScanned := ScanThreads(Result);
      except
        on E: Exception do
        begin
          ThreadsScanned := 0;
          AppendError('threads', E.Message);
        end;
      end;
    end;
    if (ModulesScanned = 0) and (RegionsScanned = 0) and (IatsScanned = 0) and (ThreadsScanned = 0) then
    begin
      if Errors = '' then
        Errors := 'No scan stage completed successfully.';
      raise Exception.Create(Errors);
    end;
    ResolveHookTargets(Result);
    FilterDotNetReport(Result);
  except
    Result.Free;
    raise;
  end;
end;

procedure TNativeMirrorProcessScanner.SetLayer(Disasm: IDisassembler; CodeGen: ICodeGen = nil);
begin
  FDisasm := Disasm;
  FCodeGen := CodeGen;
  if Assigned(CodeGen) then
    FSectionCompare := CodeGen.EmitSectionCompare
  else
    FSectionCompare := NativeMirrorScalarSectionCompare;
end;

end.
