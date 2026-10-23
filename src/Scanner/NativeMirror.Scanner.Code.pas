{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Scanner.Code;

interface

uses
  Winapi.Windows,
  System.JSON,
  System.Generics.Collections,
  NativeMirror.Core.Types,
  NativeMirror.Layer,
  NativeMirror.Scanner.Reports,
  NativeMirror.Scanner.ModuleData,
  NativeMirror.Scanner.PeSection,
  NativeMirror.Scanner.Patches;

type
  TNativeMirrorCodeScanReport = class(TNativeMirrorModuleScanReport)
  private
    FSectionResults: TDictionary<DWORD, TNativeMirrorSectionStatus>;
    FPatches: TNativeMirrorPatchList;
  protected
    procedure AddBaseJson(Json: TJSONObject); override;
  public
    constructor Create(ModuleBase: UInt64; ModuleSize: NativeUInt);
    destructor Destroy; override;
    function ReportType: TNativeMirrorScanReportType; override;
    function ToJson(Level: TNativeMirrorJsonLevel = nmJsonBasic): TJSONObject; override;
    function GetRelocBase: UInt64; override;
    function CountSectionsWithStatus(Status: TNativeMirrorSectionStatus): NativeUInt;
    function CountUnpackedSections: NativeUInt;
    function CountInaccessibleSections: NativeUInt;
    function GenerateTags(const ReportPath: string): NativeUInt;
    procedure AssignSectionResults(Source: TDictionary<DWORD, TNativeMirrorSectionStatus>);
    property SectionResults: TDictionary<DWORD, TNativeMirrorSectionStatus> read FSectionResults;
    property Patches: TNativeMirrorPatchList read FPatches;
  end;

  TNativeMirrorCodeScanner = class
  private
    FModuleData: TNativeMirrorModuleData;
    FRemoteData: TNativeMirrorRemoteModuleData;
    FSectionCompare: TNativeMirrorSectionCompareFunc;
    FScanData: Boolean;
    FScanInaccessible: Boolean;
    function CollectExecutableSections(Sections: TObjectDictionary<NativeUInt, TNativeMirrorSection>; Report: TNativeMirrorCodeScanReport): NativeUInt;
    function ScanUsingBase(LoadBase: UInt64; RemoteSections: TObjectDictionary<NativeUInt, TNativeMirrorSection>; SectionResults: TDictionary<DWORD, TNativeMirrorSectionStatus>; Patches: TNativeMirrorPatchList): TNativeMirrorScanStatus;
    function ScanSection(OriginalSection, RemoteSection: TNativeMirrorSection; Patches: TNativeMirrorPatchList): TNativeMirrorSectionStatus;
    function ClearIat(OriginalSection, RemoteSection: TNativeMirrorSection): Boolean;
    function ClearExports(OriginalSection, RemoteSection: TNativeMirrorSection): Boolean;
    function ClearLoadConfig(OriginalSection, RemoteSection: TNativeMirrorSection): Boolean;
    function CollectPatches(SectionRva: DWORD; OriginalCode, PatchedCode: PByte; CodeSize: NativeUInt; Patches: TNativeMirrorPatchList): NativeUInt;
    function PostProcess(Report: TNativeMirrorCodeScanReport): Boolean;
  public
    constructor Create(ModuleData: TNativeMirrorModuleData; RemoteData: TNativeMirrorRemoteModuleData; SectionCompare: TNativeMirrorSectionCompareFunc = nil);
    function ScanRemote: TNativeMirrorCodeScanReport;
    property ScanData: Boolean read FScanData write FScanData;
    property ScanInaccessible: Boolean read FScanInaccessible write FScanInaccessible;
  end;

implementation

uses
  NativePe.BufferUtil,
  NativePe.Types,
  NativePe.PeHdrsHelper,
  NativePe.LoadConfig,
  NativePe.ExportsMapper,
  NativePe.Util,
  NativeMirror.Scanner.Patterns,
  NativeMirror.Scanner.PatchAnalyzer;

type
  PNativeMirrorImageLoadConfigDir32W8 = ^TImageLoadConfigDir32W8;
  PNativeMirrorImageLoadConfigDir64W8 = ^TImageLoadConfigDir64W8;

procedure ZeroRange(Data: PByte; Offset, Size: NativeUInt);
begin
  if (Data <> nil) and (Size > 0) then
    FillChar(PByte(NativeUInt(Data) + Offset)^, Size, 0);
end;

constructor TNativeMirrorCodeScanReport.Create(ModuleBase: UInt64; ModuleSize: NativeUInt);
begin
  inherited Create(ModuleBase, ModuleSize);
  FSectionResults := TDictionary<DWORD, TNativeMirrorSectionStatus>.Create;
  FPatches := TNativeMirrorPatchList.Create;
end;

destructor TNativeMirrorCodeScanReport.Destroy;
begin
  FPatches.Free;
  FSectionResults.Free;
  inherited;
end;

procedure TNativeMirrorCodeScanReport.AddBaseJson(Json: TJSONObject);
var
  Inaccessible: NativeUInt;
  Unpacked: NativeUInt;
  Scanned: NativeUInt;
begin
  inherited;
  Inaccessible := CountInaccessibleSections;
  Scanned := FSectionResults.Count - Inaccessible;
  if FSectionResults.Count > 0 then
    Json.AddPair('scanned_sections', TJSONNumber.Create(Scanned));
  if Inaccessible > 0 then
    Json.AddPair('inaccessible_sections', TJSONNumber.Create(Inaccessible));
  Unpacked := CountUnpackedSections;
  if Unpacked > 0 then
    Json.AddPair('unpacked_sections', TJSONNumber.Create(Unpacked));
  if FPatches.Count > 0 then
    Json.AddPair('patches', TJSONNumber.Create(FPatches.Count));
end;

function TNativeMirrorCodeScanReport.ToJson(Level: TNativeMirrorJsonLevel): TJSONObject;
var
  Details: TJSONObject;
begin
  Details := TJSONObject.Create;
  AddBaseJson(Details);
  if (Level >= nmJsonDetails) and (FPatches.Count > 0) then
    Details.AddPair('patches_list', FPatches.ToJson(Level < nmJsonDetails2));
  Result := TJSONObject.Create;
  Result.AddPair('code_scan', Details);
end;

function TNativeMirrorCodeScanReport.ReportType: TNativeMirrorScanReportType;
begin
  Result := nmReportCodeScan;
end;

function TNativeMirrorCodeScanReport.GetRelocBase: UInt64;
begin
  Result := RelocBase;
end;

function TNativeMirrorCodeScanReport.CountSectionsWithStatus(Status: TNativeMirrorSectionStatus): NativeUInt;
var
  Pair: TPair<DWORD, TNativeMirrorSectionStatus>;
begin
  Result := 0;
  for Pair in FSectionResults do
    if Pair.Value = Status then
      Inc(Result);
end;

function TNativeMirrorCodeScanReport.CountUnpackedSections: NativeUInt;
begin
  Result := CountSectionsWithStatus(nmSectionUnpacked);
end;

function TNativeMirrorCodeScanReport.CountInaccessibleSections: NativeUInt;
begin
  Result := CountSectionsWithStatus(nmSectionScanError);
end;

function TNativeMirrorCodeScanReport.GenerateTags(const ReportPath: string): NativeUInt;
begin
  if FPatches.Count = 0 then
    Exit(0);
  Result := FPatches.SaveTags(ReportPath, ';');
end;

procedure TNativeMirrorCodeScanReport.AssignSectionResults(Source: TDictionary<DWORD, TNativeMirrorSectionStatus>);
var
  Pair: TPair<DWORD, TNativeMirrorSectionStatus>;
begin
  FSectionResults.Clear;
  if Source = nil then
    Exit;
  for Pair in Source do
    FSectionResults.AddOrSetValue(Pair.Key, Pair.Value);
end;

constructor TNativeMirrorCodeScanner.Create(ModuleData: TNativeMirrorModuleData; RemoteData: TNativeMirrorRemoteModuleData; SectionCompare: TNativeMirrorSectionCompareFunc = nil);
begin
  inherited Create;
  FModuleData := ModuleData;
  FRemoteData := RemoteData;
  if Assigned(SectionCompare) then
    FSectionCompare := SectionCompare
  else
    FSectionCompare := NativeMirrorScalarSectionCompare;
end;

function TNativeMirrorCodeScanner.ClearIat(OriginalSection, RemoteSection: TNativeMirrorSection): Boolean;
var
  Thunks: TList<DWORD>;
  Rva: DWORD;
  ThunkSize: NativeUInt;
  Offset: NativeUInt;
begin
  Result := False;
  Thunks := TList<DWORD>.Create;
  try
    FModuleData.LoadImportThunks(Thunks);
    if Thunks.Count = 0 then
      Exit;
    if FModuleData.Is64Bit then
      ThunkSize := SizeOf(UInt64)
    else
      ThunkSize := SizeOf(DWORD);
    for Rva in Thunks do
      if OriginalSection.IsContained(Rva, ThunkSize) and RemoteSection.IsContained(Rva, ThunkSize) then
      begin
        Offset := Rva - OriginalSection.Rva;
        ZeroRange(OriginalSection.Data, Offset, ThunkSize);
        ZeroRange(RemoteSection.Data, Offset, ThunkSize);
      end;
    Result := True;
  finally
    Thunks.Free;
  end;
end;

function TNativeMirrorCodeScanner.ClearLoadConfig(OriginalSection, RemoteSection: TNativeMirrorSection): Boolean;
var
  Characteristics: Word;
  Config: PByte;
  Version: TLoadConfigVer;
  FieldVa: UInt64;
  FieldSize: NativeUInt;
  ModuleBase: UInt64;
  Rva: UInt64;
  Offset: NativeUInt;
begin
  Result := False;
  Characteristics := GetDllCharacteristics(FModuleData.OriginalModule);
  if (Characteristics and $4000) = 0 then
    Exit;
  Config := GetLoadConfigPtr(FModuleData.OriginalModule, FModuleData.OriginalSize);
  if Config = nil then
    Exit;
  Version := GetLoadConfigVersion(FModuleData.OriginalModule, FModuleData.OriginalSize, Config);
  if (Version <> LOAD_CONFIG_W8_VER) and (Version <> LOAD_CONFIG_W10_VER) then
    Exit;
  if FModuleData.Is64Bit then
  begin
    FieldVa := PNativeMirrorImageLoadConfigDir64W8(Config).GuardCFCheckFunctionPointer;
    FieldSize := SizeOf(UInt64);
  end
  else
  begin
    FieldVa := PNativeMirrorImageLoadConfigDir32W8(Config).GuardCFCheckFunctionPointer;
    FieldSize := SizeOf(DWORD);
  end;
  if FieldVa = 0 then
    Exit;
  ModuleBase := FModuleData.ModuleBase;
  if FieldVa < ModuleBase then
    Exit;
  Rva := FieldVa - ModuleBase;
  if not OriginalSection.IsContained(Rva, FieldSize) or not RemoteSection.IsContained(Rva, FieldSize) then
    Exit;
  Offset := Rva - OriginalSection.Rva;
  ZeroRange(OriginalSection.Data, Offset, FieldSize);
  ZeroRange(RemoteSection.Data, Offset, FieldSize);
  Result := True;
end;

function TNativeMirrorCodeScanner.ClearExports(OriginalSection, RemoteSection: TNativeMirrorSection): Boolean;
var
  Dir: NativePe.Types.PImageDataDirectory;
  Offset: DWORD;
  ExportDir: NativePe.Types.PImageExportDirectory;
  FunctionsOffset: DWORD;
  FunctionsSize: UInt64;
begin
  Result := False;
  Dir := GetDirectoryEntry(FModuleData.OriginalModule, IMAGE_DIRECTORY_ENTRY_EXPORT);
  if Dir = nil then
    Exit;
  if not OriginalSection.IsContained(Dir.VirtualAddress, Dir.Size) then
    Exit(True);
  Offset := Dir.VirtualAddress - OriginalSection.Rva;
  ExportDir := NativePe.Types.PImageExportDirectory(NativeUInt(OriginalSection.Data) + Offset);
  if not ValidatePtr(OriginalSection.Data, OriginalSection.LoadedSize, ExportDir, SizeOf(NativePe.Types.TImageExportDirectory)) then
    Exit;
  if ExportDir.AddressOfFunctions < OriginalSection.Rva then
    Exit;
  FunctionsOffset := ExportDir.AddressOfFunctions - OriginalSection.Rva;
  FunctionsSize := UInt64(ExportDir.NumberOfFunctions) * SizeOf(DWORD);
  if FunctionsSize = 0 then
    Exit(True);
  if FunctionsSize > High(NativeUInt) then
    Exit;
  if not OriginalSection.IsContained(ExportDir.AddressOfFunctions, NativeUInt(FunctionsSize)) or not RemoteSection.IsContained(ExportDir.AddressOfFunctions, NativeUInt(FunctionsSize)) then
    Exit;
  if not ValidatePtr(OriginalSection.Data, OriginalSection.LoadedSize, PByte(NativeUInt(OriginalSection.Data) + FunctionsOffset), NativeUInt(FunctionsSize)) then
    Exit;
  ZeroRange(OriginalSection.Data, FunctionsOffset, NativeUInt(FunctionsSize));
  ZeroRange(RemoteSection.Data, FunctionsOffset, NativeUInt(FunctionsSize));
  Result := True;
end;

function TNativeMirrorCodeScanner.CollectPatches(SectionRva: DWORD; OriginalCode, PatchedCode: PByte; CodeSize: NativeUInt; Patches: TNativeMirrorPatchList): NativeUInt;
var
  Analyzer: TNativeMirrorPatchAnalyzer;
  Current: TNativeMirrorPatch;
  I: NativeUInt;
  Parsed: NativeUInt;
begin
  Analyzer := TNativeMirrorPatchAnalyzer.Create(FModuleData, SectionRva, PatchedCode, CodeSize);
  try
    Current := nil;
    I := 0;
    while I < CodeSize do
    begin
      if PByte(NativeUInt(OriginalCode) + I)^ = PByte(NativeUInt(PatchedCode) + I)^ then
      begin
        if Current <> nil then
        begin
          Current.SetEnd(SectionRva + DWORD(I));
          Analyzer.AnalyzeOther(Current);
          Current := nil;
        end;
        Inc(I);
        Continue;
      end;
      if Current = nil then
      begin
        Current := TNativeMirrorPatch.Create(FModuleData.ModuleBase, Patches.Count, SectionRva + DWORD(I));
        Patches.Add(Current);
        Parsed := Analyzer.AnalyzeHook(Current);
        if Parsed > 0 then
        begin
          Current.SetEnd(SectionRva + DWORD(I + Parsed));
          Current := nil;
          Inc(I, Parsed);
          Continue;
        end;
      end;
      Inc(I);
    end;
    if Current <> nil then
      Current.SetEnd(SectionRva + DWORD(CodeSize));
    Result := Patches.Count;
  finally
    Analyzer.Free;
  end;
end;

function TNativeMirrorCodeScanner.ScanSection(OriginalSection, RemoteSection: TNativeMirrorSection; Patches: TNativeMirrorPatchList): TNativeMirrorSectionStatus;
var
  SmallerSize: NativeUInt;
  Equal: Boolean;
  CompareResult: NativeInt;
  DiffSize: NativeUInt;
  I: NativeUInt;
  FoundOffset: UInt64;
  Patch: TNativeMirrorPatch;
begin
  if not OriginalSection.IsInitialized or not RemoteSection.IsInitialized then
    Exit(nmSectionScanError);
  ClearIat(OriginalSection, RemoteSection);
  ClearExports(OriginalSection, RemoteSection);
  ClearLoadConfig(OriginalSection, RemoteSection);
  SmallerSize := OriginalSection.LoadedSize;
  if RemoteSection.LoadedSize < SmallerSize then
    SmallerSize := RemoteSection.LoadedSize;
  if SmallerSize = 0 then
    Equal := True
  else
  begin
    CompareResult := FSectionCompare(RemoteSection.Data, OriginalSection.Data, SmallerSize);
    Equal := (CompareResult = 0) and (RemoteSection.Data^ = OriginalSection.Data^);
  end;
  if ((OriginalSection.RawSize = 0) or IsPadding(OriginalSection.Data, SmallerSize, 0)) and not IsPadding(RemoteSection.Data, SmallerSize, 0) then
    Exit(nmSectionUnpacked);
  if not Equal then
    CollectPatches(OriginalSection.Rva, OriginalSection.Data, RemoteSection.Data, SmallerSize, Patches);
  if RemoteSection.LoadedSize > OriginalSection.LoadedSize then
  begin
    DiffSize := RemoteSection.LoadedSize - OriginalSection.LoadedSize;
    FoundOffset := NATIVE_MIRROR_INVALID_OFFSET;
    for I := 0 to DiffSize - 1 do
      if PByte(NativeUInt(RemoteSection.Data) + OriginalSection.LoadedSize + I)^ <> 0 then
      begin
        FoundOffset := OriginalSection.LoadedSize + I;
        Break;
      end;
    if FoundOffset <> NATIVE_MIRROR_INVALID_OFFSET then
    begin
      Patch := TNativeMirrorPatch.Create(FModuleData.ModuleBase, Patches.Count, RemoteSection.Rva + DWORD(FoundOffset));
      Patch.SetEnd(RemoteSection.Rva + DWORD(RemoteSection.LoadedSize));
      Patches.Add(Patch);
    end;
  end;
  if Patches.Count > 0 then
    Exit(nmSectionPatched);
  if Equal then
    Exit(nmSectionNotModified);
  Result := nmSectionUnpacked;
end;

function TNativeMirrorCodeScanner.CollectExecutableSections(Sections: TObjectDictionary<NativeUInt, TNativeMirrorSection>; Report: TNativeMirrorCodeScanReport): NativeUInt;
var
  Initial: Integer;
  Count: NativeUInt;
  I: NativeUInt;
  Header: NativePe.Types.PImageSectionHeader;
  IsEntry: Boolean;
  RemoteSection: TNativeMirrorSection;
begin
  Initial := Sections.Count;
  Count := GetSectionsCount(FRemoteData.HeaderData, FRemoteData.GetHeaderSize);
  if Count > 0 then
    for I := 0 to Count - 1 do
    begin
      Header := GetSectionHdr(FRemoteData.HeaderData, FRemoteData.GetHeaderSize, I);
      if Header = nil then
        Continue;
      IsEntry := FRemoteData.IsSectionEntry(I);
      if not IsEntry and ((Header.Characteristics and IMAGE_SCN_MEM_EXECUTE) = 0) and not FRemoteData.IsSectionExecutable(I, FScanData, FScanInaccessible) then
        Continue;
      RemoteSection := TNativeMirrorSection.CreateRemote(FRemoteData, I);
      if RemoteSection.IsInitialized then
      begin
        if IsEntry or IsCode(RemoteSection.Data, RemoteSection.LoadedSize) then
        begin
          Sections.Add(I, RemoteSection);
          Continue;
        end;
      end
      else
        Report.SectionResults.AddOrSetValue(DWORD(I), nmSectionScanError);
      RemoteSection.Free;
    end
  else
  begin
    RemoteSection := TNativeMirrorSection.CreateRemote(FRemoteData, 0);
    if RemoteSection.IsInitialized then
      Sections.Add(0, RemoteSection)
    else
    begin
      Report.SectionResults.AddOrSetValue(0, nmSectionScanError);
      RemoteSection.Free;
    end;
  end;
  Result := Sections.Count - Initial;
end;

function TNativeMirrorCodeScanner.ScanUsingBase(LoadBase: UInt64; RemoteSections: TObjectDictionary<NativeUInt, TNativeMirrorSection>; SectionResults: TDictionary<DWORD, TNativeMirrorSectionStatus>; Patches: TNativeMirrorPatchList): TNativeMirrorScanStatus;
var
  SectionIndexes: TList<NativeUInt>;
  SectionIndex: NativeUInt;
  RemoteSection: TNativeMirrorSection;
  OriginalSection: TNativeMirrorSection;
  SectionStatus: TNativeMirrorSectionStatus;
  Errors: NativeUInt;
  Modified: NativeUInt;
begin
  Result := NM_SCAN_NOT_SUSPICIOUS;
  if not FModuleData.RelocateToBase(LoadBase) then
    Exit(NM_SCAN_ERROR);
  Errors := 0;
  Modified := 0;
  SectionIndexes := TList<NativeUInt>.Create;
  try
    for SectionIndex in RemoteSections.Keys do
      SectionIndexes.Add(SectionIndex);
    SectionIndexes.Sort;
    for SectionIndex in SectionIndexes do
    begin
      RemoteSection := RemoteSections[SectionIndex];
      OriginalSection := TNativeMirrorSection.CreateOriginal(FModuleData, SectionIndex);
      try
        SectionStatus := ScanSection(OriginalSection, RemoteSection, Patches);
        SectionResults.AddOrSetValue(OriginalSection.Rva, SectionStatus);
        if SectionStatus = nmSectionScanError then
          Inc(Errors)
        else if SectionStatus <> nmSectionNotModified then
          Inc(Modified);
      finally
        OriginalSection.Free;
      end;
    end;
  finally
    SectionIndexes.Free;
  end;
  if Modified > 0 then
    Result := NM_SCAN_SUSPICIOUS
  else if Errors > 0 then
    Result := NM_SCAN_ERROR;
end;

function TNativeMirrorCodeScanner.PostProcess(Report: TNativeMirrorCodeScanReport): Boolean;
var
  Mapper: TExportsMapper;
begin
  Result := False;
  if Report.Patches.Count = 0 then
    Exit;
  Mapper := TExportsMapper.Create;
  try
    Mapper.AddToLookup(FModuleData.ModuleName, HMODULE(FModuleData.OriginalModule), FModuleData.OriginalSize, FModuleData.ModuleBase);
    Report.Patches.CheckForHookedExports(Mapper);
    Result := True;
  finally
    Mapper.Free;
  end;
end;

function TNativeMirrorCodeScanner.ScanRemote: TNativeMirrorCodeScanReport;
var
  Sections: TObjectDictionary<NativeUInt, TNativeMirrorSection>;
  Status: TNativeMirrorScanStatus;
  LoadBase: UInt64;
  HeaderBase: UInt64;
  Patches2: TNativeMirrorPatchList;
  Results2: TDictionary<DWORD, TNativeMirrorSectionStatus>;
  Status2: TNativeMirrorScanStatus;
begin
  Result := nil;
  if (FModuleData = nil) or (FRemoteData = nil) or (FModuleData.OriginalModule = nil) or not FRemoteData.Initialize then
    Exit;
  Result := TNativeMirrorCodeScanReport.Create(FModuleData.ModuleBase, FRemoteData.GetModuleSize);
  Result.IsDotNetModule := FModuleData.IsDotNet;
  Sections := TObjectDictionary<NativeUInt, TNativeMirrorSection>.Create([doOwnsValues]);
  try
    if CollectExecutableSections(Sections, Result) = 0 then
    begin
      Result.Status := NM_SCAN_NOT_SUSPICIOUS;
      if Result.CountInaccessibleSections > 0 then
        Result.Status := NM_SCAN_ERROR;
      Exit;
    end;
    LoadBase := FModuleData.ModuleBase;
    HeaderBase := FRemoteData.GetHeaderImageBase;
    Result.OriginalBase := GetImageBase(FModuleData.OriginalModule);
    Status := ScanUsingBase(LoadBase, Sections, Result.SectionResults, Result.Patches);
    if (LoadBase <> HeaderBase) and (Result.Patches.Count > 0) then
    begin
      Patches2 := TNativeMirrorPatchList.Create;
      Results2 := TDictionary<DWORD, TNativeMirrorSectionStatus>.Create;
      try
        Status2 := ScanUsingBase(HeaderBase, Sections, Results2, Patches2);
        if Patches2.Count < Result.Patches.Count then
        begin
          Result.RelocBase := HeaderBase;
          Result.Patches.Assign(Patches2);
          Result.AssignSectionResults(Results2);
          Status := Status2;
        end;
      finally
        Results2.Free;
        Patches2.Free;
      end;
    end;
    PostProcess(Result);
    Result.Status := Status;
  finally
    Sections.Free;
  end;
end;

end.
