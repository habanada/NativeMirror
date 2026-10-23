{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Scanner.IAT;

interface

uses
  Winapi.Windows,
  System.JSON,
  NativePe.ExportsMapper,
  NativePe.ImportsLoader,
  NativePe.ImportsUneraser,
  NativePe.ExportedFunc,
  NativeMirror.Core.Types,
  NativeMirror.Core.Memory,
  NativeMirror.Scanner.Reports,
  NativeMirror.Scanner.ModuleData,
  NativeMirror.Scanner.Modules;

type
  TNativeMirrorIatScanReport = class(TNativeMirrorModuleScanReport)
  private
    FStoredFunctions: TImportsCollection;
    FNotCovered: TImpsNotCovered;
    function FormatHookedFunction(ThunkRva: DWORD): string;
    function FormatTargetName(ExportsMap: TExportsMapper; ModulesInfo: TNativeMirrorModulesInfo; ModuleStart, Address: UInt64): string;
  protected
    procedure AddBaseJson(Json: TJSONObject); override;
  public
    constructor Create(ModuleBase: UInt64; ModuleSize: NativeUInt; const ModuleFile: string);
    destructor Destroy; override;
    function ReportType: TNativeMirrorScanReportType; override;
    function ToJson(Level: TNativeMirrorJsonLevel = nmJsonBasic): TJSONObject; override;
    function CountHooked: NativeUInt;
    function GenerateList(const FileName: string; const Reader: INativeMirrorMemoryReader; ModulesInfo: TNativeMirrorModulesInfo; ExportsMap: TExportsMapper): Boolean;
    property StoredFunctions: TImportsCollection read FStoredFunctions;
    property NotCovered: TImpsNotCovered read FNotCovered;
  end;

  TNativeMirrorIatScanner = class
  private
    FModuleData: TNativeMirrorModuleData;
    FRemoteData: TNativeMirrorRemoteModuleData;
    FExportsMap: TExportsMapper;
    FModulesInfo: TNativeMirrorModulesInfo;
    FHooksFilter: TNativeMirrorIatScanMode;
    FSystem32Path: string;
    FSysWow64Path: string;
    procedure InitExcludedPaths;
    function IsInSystemDir(const ModuleName: string): Boolean;
    function IsValidFunctionFilled(FilledValue: UInt64; DefinedFunction, PossibleFunction: TExportedFunc): Boolean;
    function ScanByOriginalTable(NotCovered: TImpsNotCovered): Boolean;
    function FilterResults(NotCovered: TImpsNotCovered; Report: TNativeMirrorIatScanReport): Boolean;
    function ListAllImports(Collection: TImportsCollection): Boolean;
  public
    constructor Create(ModuleData: TNativeMirrorModuleData; RemoteData: TNativeMirrorRemoteModuleData; ExportsMap: TExportsMapper; ModulesInfo: TNativeMirrorModulesInfo; HooksFilter: TNativeMirrorIatScanMode);
    function ScanRemote: TNativeMirrorIatScanReport;
  end;

implementation

uses
  System.Classes,
  System.SysUtils,
  System.Generics.Collections,
  System.IOUtils,
  NativePe.BufferUtil;

function ReadThunk(Buffer: PByte; BufferSize: NativeUInt; Rva: DWORD; Is64Bit: Boolean): UInt64;
begin
  Result := 0;
  if Buffer = nil then
    Exit;
  if Is64Bit then
  begin
    if ValidatePtr(Buffer, BufferSize, PByte(NativeUInt(Buffer) + Rva), SizeOf(UInt64)) then
      Result := PUInt64(NativeUInt(Buffer) + Rva)^;
  end
  else if ValidatePtr(Buffer, BufferSize, PByte(NativeUInt(Buffer) + Rva), SizeOf(DWORD)) then
    Result := PDWORD(NativeUInt(Buffer) + Rva)^;
end;

constructor TNativeMirrorIatScanReport.Create(ModuleBase: UInt64; ModuleSize: NativeUInt; const ModuleFile: string);
begin
  inherited Create(ModuleBase, ModuleSize, NM_SCAN_SUSPICIOUS);
  Self.ModuleFile := ModuleFile;
  FStoredFunctions := TImportsCollection.Create;
  FNotCovered := TImpsNotCovered.Create;
end;

destructor TNativeMirrorIatScanReport.Destroy;
begin
  FNotCovered.Free;
  FStoredFunctions.Free;
  inherited;
end;

function TNativeMirrorIatScanReport.ReportType: TNativeMirrorScanReportType;
begin
  Result := nmReportIatScan;
end;

function TNativeMirrorIatScanReport.CountHooked: NativeUInt;
begin
  Result := FNotCovered.Count;
end;

procedure TNativeMirrorIatScanReport.AddBaseJson(Json: TJSONObject);
begin
  inherited;
  Json.AddPair('hooks', TJSONNumber.Create(CountHooked));
end;

function TNativeMirrorIatScanReport.ToJson(Level: TNativeMirrorJsonLevel): TJSONObject;
var
  Details, Entry: TJSONObject;
  Hooks: TJSONArray;
  Pair: TPair<DWORD, UInt64>;
  Func: TExportedFunc;
begin
  Details := TJSONObject.Create;
  AddBaseJson(Details);
  if (Level >= nmJsonDetails) and (CountHooked <> 0) then
  begin
    Hooks := TJSONArray.Create;
    for Pair in FNotCovered.ThunkToAddr do
    begin
      Entry := TJSONObject.Create;
      Entry.AddPair('thunk_rva', IntToHex(Pair.Key, 1).ToLower);
      if FStoredFunctions.ThunkToFunc.TryGetValue(Pair.Key, Func) and (Func <> nil) then
        Entry.AddPair('func_name', Func.ToStringFull);
      Entry.AddPair('target_va', IntToHex(Pair.Value, 1).ToLower);
      Hooks.AddElement(Entry);
    end;
    Details.AddPair('hooks_list', Hooks);
  end;
  Result := TJSONObject.Create;
  Result.AddPair('iat_scan', Details);
end;

function TNativeMirrorIatScanReport.FormatHookedFunction(ThunkRva: DWORD): string;
var
  Func: TExportedFunc;
begin
  Result := '(unknown)';
  if FStoredFunctions.ThunkToFunc.TryGetValue(ThunkRva, Func) and (Func <> nil) then
    Result := Func.ToStringFull;
end;

function TNativeMirrorIatScanReport.FormatTargetName(ExportsMap: TExportsMapper; ModulesInfo: TNativeMirrorModulesInfo; ModuleStart, Address: UInt64): string;
var
  Func: TExportedFunc;
  Module: TNativeMirrorScannedModule;
begin
  if Address = 0 then
    Exit('(invalid)');
  if ExportsMap = nil then
    Exit('');
  Func := ExportsMap.FindExportByVa(Address);
  if Func <> nil then
    Exit(Func.ToStringFull);
  Module := ModulesInfo.FindModuleContaining(Address);
  if Module = nil then
  begin
    if ModuleStart = 0 then
      Exit('(invalid)');
    Exit('(unknown)');
  end;
  Result := NativePe.ExportedFunc.GetDllShortName(Module.ModuleName) + '.(unknown_func)';
end;

function TNativeMirrorIatScanReport.GenerateList(const FileName: string; const Reader: INativeMirrorMemoryReader; ModulesInfo: TNativeMirrorModulesInfo; ExportsMap: TExportsMapper): Boolean;
var
  Lines: TStringList;
  Pair: TPair<DWORD, UInt64>;
  Module: TNativeMirrorScannedModule;
  Region: TNativeMirrorMemoryRegion;
  ModuleStart: UInt64;
  Offset: UInt64;
  Suspicious: Boolean;
  Line: string;
begin
  Result := False;
  if CountHooked = 0 then
    Exit;
  Lines := TStringList.Create;
  try
    Lines.WriteBOM := False;
    for Pair in FNotCovered.ThunkToAddr do
    begin
      Module := ModulesInfo.FindModuleContaining(Pair.Value);
      if Module <> nil then
        ModuleStart := Module.Start
      else if (Reader <> nil) and Reader.QueryRegion(Pair.Value, Region) then
        ModuleStart := Region.AllocationBase
      else
        ModuleStart := 0;
      Offset := Pair.Value - ModuleStart;
      Suspicious := (Module = nil) or Module.Suspicious;
      Line := IntToHex(Pair.Key, 1).ToLower + ';[' + FormatHookedFunction(Pair.Key) + ']->' + IntToHex(Pair.Value, 1).ToLower + '[' + IntToHex(ModuleStart, 1).ToLower + '+' + IntToHex(Offset, 1).ToLower + ':' + FormatTargetName(ExportsMap, ModulesInfo, ModuleStart, Pair.Value) + ':' + IntToStr(Ord(Suspicious)) + ']';
      Lines.Add(Line);
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

constructor TNativeMirrorIatScanner.Create(ModuleData: TNativeMirrorModuleData; RemoteData: TNativeMirrorRemoteModuleData; ExportsMap: TExportsMapper; ModulesInfo: TNativeMirrorModulesInfo; HooksFilter: TNativeMirrorIatScanMode);
begin
  inherited Create;
  FModuleData := ModuleData;
  FRemoteData := RemoteData;
  FExportsMap := ExportsMap;
  FModulesInfo := ModulesInfo;
  FHooksFilter := HooksFilter;
  InitExcludedPaths;
end;

procedure TNativeMirrorIatScanner.InitExcludedPaths;
var
  WindowsDir: array[0..MAX_PATH - 1] of Char;
begin
  FillChar(WindowsDir, SizeOf(WindowsDir), 0);
  GetWindowsDirectory(WindowsDir, Length(WindowsDir));
  FSystem32Path := LowerCase(IncludeTrailingPathDelimiter(WindowsDir) + 'system32');
  FSysWow64Path := LowerCase(IncludeTrailingPathDelimiter(WindowsDir) + 'SysWoW64');
end;

function TNativeMirrorIatScanner.IsInSystemDir(const ModuleName: string): Boolean;
var
  DirName: string;
begin
  DirName := LowerCase(ExcludeTrailingPathDelimiter(ExtractFileDir(ModuleName)));
  Result := SameText(DirName, FSystem32Path) or SameText(DirName, FSysWow64Path);
end;

function TNativeMirrorIatScanner.IsValidFunctionFilled(FilledValue: UInt64; DefinedFunction, PossibleFunction: TExportedFunc): Boolean;
var
  DllBase: UInt64;
  FullName: string;
begin
  Result := False;
  if (DefinedFunction = nil) or (PossibleFunction = nil) then
    Exit;
  if not TExportedFunc.IsTheSameFuncName(PossibleFunction, DefinedFunction) then
    Exit;
  if TExportedFunc.IsTheSameDllName(PossibleFunction, DefinedFunction) then
    Exit(True);
  DllBase := FExportsMap.FindDllBaseByFuncVa(FilledValue);
  if DllBase = 0 then
    Exit;
  FullName := FExportsMap.GetDllPath(DllBase);
  Result := IsInSystemDir(FullName);
end;

function TNativeMirrorIatScanner.ListAllImports(Collection: TImportsCollection): Boolean;
begin
  Result := FModuleData.LoadImportsList(Collection);
end;

function TNativeMirrorIatScanner.ScanByOriginalTable(NotCovered: TImpsNotCovered): Boolean;
var
  Collection: TImportsCollection;
  Pair: TPair<DWORD, TExportedFunc>;
  FilledValue: UInt64;
  Possible: TExportedFuncSet;
  PossiblePair: TPair<string, TExportedFunc>;
  Covered: Boolean;
  ShortName: string;
begin
  Result := False;
  if not FRemoteData.Initialize then
    Exit;
  if (FModuleData.OriginalModule = nil) and not FModuleData.LoadOriginal then
    Exit;
  Collection := TImportsCollection.Create;
  try
    if not ListAllImports(Collection) then
      Exit;
    if Collection.ThunkToFunc.Count = 0 then
      Exit(True);
    if not FRemoteData.LoadFullImage then
      Exit;
    for Pair in Collection.ThunkToFunc do
    begin
      FilledValue := ReadThunk(FRemoteData.Image.Data, FRemoteData.Image.Size, Pair.Key, FModuleData.Is64Bit);
      if Pair.Value = nil then
        Continue;
      Possible := FExportsMap.FindExportsByVa(FilledValue);
      if (Possible = nil) or (Possible.Count = 0) then
      begin
        ShortName := ChangeFileExt(ExtractFileName(Pair.Value.LibName), '');
        if SameText(ShortName, 'mscoree') and (SameText(Pair.Value.FuncName, '_CorExeMain') or SameText(Pair.Value.FuncName, '_CorDllMain')) then
          Continue;
        NotCovered.Insert(Pair.Key, FilledValue);
        Continue;
      end;
      Covered := False;
      for PossiblePair in Possible do
        if IsValidFunctionFilled(FilledValue, Pair.Value, PossiblePair.Value) then
        begin
          Covered := True;
          Break;
        end;
      if not Covered then
        NotCovered.Insert(Pair.Key, FilledValue);
    end;
    Result := True;
  finally
    Collection.Free;
  end;
end;

function TNativeMirrorIatScanner.FilterResults(NotCovered: TImpsNotCovered; Report: TNativeMirrorIatScanReport): Boolean;
var
  Pair: TPair<DWORD, UInt64>;
  Module: TNativeMirrorScannedModule;
  Region: TNativeMirrorMemoryRegion;
  ModuleStart: UInt64;
  ModuleName: string;
begin
  for Pair in NotCovered.ThunkToAddr do
  begin
    Module := FModulesInfo.FindModuleContaining(Pair.Value);
    if Module <> nil then
      ModuleStart := Module.Start
    else if FRemoteData.Reader.QueryRegion(Pair.Value, Region) then
      ModuleStart := Region.AllocationBase
    else
      ModuleStart := 0;
    if ModuleStart = 0 then
    begin
      Report.NotCovered.Insert(Pair.Key, Pair.Value);
      Continue;
    end;
    if (FHooksFilter = nmIatCleanSystemFiltered) and (Module <> nil) and Module.Suspicious then
    begin
      Report.NotCovered.Insert(Pair.Key, Pair.Value);
      Continue;
    end;
    ModuleName := FExportsMap.GetDllPath(ModuleStart);
    if IsInSystemDir(ModuleName) then
      Continue;
    Report.NotCovered.Insert(Pair.Key, Pair.Value);
  end;
  Result := True;
end;

function TNativeMirrorIatScanner.ScanRemote: TNativeMirrorIatScanReport;
var
  NotCovered: TImpsNotCovered;
  Status: TNativeMirrorScanStatus;
  Pair: TPair<DWORD, UInt64>;
begin
  Result := nil;
  if not FRemoteData.Initialize then
    Exit;
  NotCovered := TImpsNotCovered.Create;
  try
    Status := NM_SCAN_NOT_SUSPICIOUS;
    if not ScanByOriginalTable(NotCovered) then
      Status := NM_SCAN_ERROR;
    if NotCovered.Count > 0 then
      Status := NM_SCAN_SUSPICIOUS;
    Result := TNativeMirrorIatScanReport.Create(FRemoteData.ModuleBase, FRemoteData.GetModuleSize, FModuleData.ModuleName);
    if NotCovered.Count > 0 then
      ListAllImports(Result.StoredFunctions);
    if FHooksFilter <> nmIatUnfiltered then
      FilterResults(NotCovered, Result)
    else
      for Pair in NotCovered.ThunkToAddr do
        Result.NotCovered.Insert(Pair.Key, Pair.Value);
    Result.Status := Status;
    if Result.CountHooked = 0 then
      Result.Status := NM_SCAN_NOT_SUSPICIOUS;
  finally
    NotCovered.Free;
  end;
end;

end.
