{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-License-Identifier: BSD-2-Clause

  This file contains tests for NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Tests.Parity;

interface

uses
  DUnitX.TestFramework;

type
  [TestFixture]
  TNativeMirrorParityTests = class
  public
    [Test] procedure SectionIncludesAlignmentPadding;
    [Test] procedure SectionKeepsPartiallyReadBuffer;
    [Test] procedure SectionAccessFollowsReflection;
    [Test] procedure UniformFrequencyIsNotStrongEncryption;
    [Test] procedure WatchedStringsUseLexicalOrder;
    [Test] procedure FrequentValuesUseByteOrder;
    [Test] procedure PatchTagLengthIsHex;
    [Test] procedure RegionSizeStartsAtRequestedAddress;
    [Test] procedure FreeRegionHasNoReadableSize;
    [Test] procedure RemoteImageUsesRegionRemainder;
    [Test] procedure ArtefactImageUsesRegionRemainder;
    [Test] procedure OverlappingModulesUseLowestBase;
    [Test] procedure ImportListUsesHexLowercase;
    [Test] procedure ImportNameSpaceUsesFirstOrderedAlias;
    [Test] procedure IatUnknownTargetUsesLowercaseModule;
    [Test] procedure EntropyJsonUsesSixSignificantDigits;
    [Test] procedure MemoryPageKeepsPartialReadTail;
    [Test] procedure MemoryPagePartialReadRespectsStop;
    [Test] procedure MemoryPageRejectsEmptyRead;
    [Test] procedure ArtefactPatternExcludesFinalPosition;
    [Test] procedure ArtefactPatternIterationLimitIsInclusive;
    [Test] procedure CodePatternIncludesFinalPosition;
    [Test] procedure ScanTimeMatchesReferenceThresholds;
    [Test] procedure LibraryScannerEmitsProgress;
    [Test] procedure QuietLibraryScannerSuppressesProgress;
    [Test] procedure StandaloneMatchersKeepIndependentData;
    [Test] procedure StandaloneMatcherClearKeepsOtherInstances;
    [Test] procedure ArtefactPreviousPageMatchesReferenceStep;
    [Test] procedure ArtefactAdjacentHeaderRemainsDetected;
    [Test] procedure LibraryReportMessagesFollowEngine;
    [Test] procedure QuietLibraryReportMessagesAreSuppressed;
    [Test] procedure DumperCallbackReportsSuccess;
    [Test] procedure DumperCallbackReportsFailure;
    [Test] procedure QuietDumperSuppressesMessages;
    [Test] procedure DumperReconstructionFailureUsesReferenceText;
  end;

function RunNativeMirrorThreadProbe(Pid: Cardinal): Integer;
function RunNativeMirrorPatternProbe(const Mode, FirstFile, SecondFile: string): Integer;

implementation

uses
  Winapi.Windows,
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.JSON,
  System.Generics.Collections,
  NativePe.Types,
  NativePe.PeHdrsHelper,
  NativePe.ExportedFunc,
  NativePe.ExportsMapper,
  NativeMirror.Core.Types,
  NativeMirror.Core.Engine,
  NativeMirror.Scanner.Signatures,
  NativeMirror.Core.Options,
  NativeMirror.Core.Text,
  NativeMirror.Platform.Process,
  NativeMirror.Scanner.ProcessScanner,
  NativeMirror.Core.Memory,
  NativeMirror.Scanner.ModuleData,
  NativeMirror.Scanner.PeSection,
  NativeMirror.Scanner.Modules,
  NativeMirror.Scanner.Reports,
  NativeMirror.Scanner.Patterns,
  NativeMirror.Scanner.Patches,
  NativeMirror.Scanner.IAT,
  NativeMirror.Scanner.WorkingSet,
  NativeMirror.Scanner.Threads,
  NativeMirror.Scanner.Artefacts,
  NativeMirror.Scanner.MemPage,
  NativeMirror.Scanner.ProcessDetails,
  NativeMirror.Scanner.ProcessReport,
  NativeMirror.Stats.Core,
  NativeMirror.Stats.Analyzer,
  NativeMirror.Dumper.Imports.Blocks,
  NativeMirror.Dumper.Engine,
  NativeMirror.Dumper.Reports;

type
  TParityMemoryReader = class(TInterfacedObject, INativeMirrorMemoryReader)
  private
    FData: TBytes;
  public
    ReadLimit: NativeUInt;
    FailReads: Boolean;
    LastForceAccess: Boolean;
    MappingType: DWORD;
    RegionSpan: NativeUInt;
    ReadAddresses: TList<UInt64>;
    constructor Create;
    function ReadMemory(Address: UInt64; Buffer: Pointer; Size: NativeUInt; ForceAccess: Boolean = False): NativeUInt;
    function QueryRegion(Address: UInt64; out Region: TNativeMirrorMemoryRegion): Boolean;
    function GetArchitecture: TNativeMirrorArchitecture;
    function GetProcessHandle: THandle;
  end;

const
  TestBase = UInt64($100000);

constructor TParityMemoryReader.Create;
var
  Dos: NativePe.Types.PImageDosHeader;
  Nt: NativePe.Types.PImageNtHeaders64;
  Sec: NativePe.Types.PImageSectionHeader;
begin
  inherited Create;
  MappingType := MEM_PRIVATE;
  SetLength(FData, $4000);
  Dos := NativePe.Types.PImageDosHeader(@FData[0]);
  Dos.e_magic := IMAGE_DOS_SIGNATURE;
  Dos.e_lfanew := $80;
  Nt := NativePe.Types.PImageNtHeaders64(@FData[$80]);
  Nt.Signature := IMAGE_NT_SIGNATURE;
  Nt.FileHeader.Machine := IMAGE_FILE_MACHINE_AMD64;
  Nt.FileHeader.NumberOfSections := 2;
  Nt.FileHeader.SizeOfOptionalHeader := SizeOf(NativePe.Types.TImageOptionalHeader64);
  Nt.FileHeader.Characteristics := IMAGE_FILE_EXECUTABLE_IMAGE or IMAGE_FILE_LARGE_ADDRESS_AWARE;
  Nt.OptionalHeader.Magic := IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  Nt.OptionalHeader.ImageBase := TestBase;
  Nt.OptionalHeader.SectionAlignment := $1000;
  Nt.OptionalHeader.FileAlignment := $200;
  Nt.OptionalHeader.SizeOfImage := Length(FData);
  Nt.OptionalHeader.SizeOfHeaders := $400;
  Nt.OptionalHeader.AddressOfEntryPoint := $1000;
  Nt.OptionalHeader.NumberOfRvaAndSizes := 16;
  Sec := GetSectionHdr(@FData[0], Length(FData), 0);
  Sec.Name[0] := '.';
  Sec.Name[1] := 't';
  Sec.Name[2] := 'e';
  Sec.Name[3] := 'x';
  Sec.Name[4] := 't';
  Sec.VirtualAddress := $1000;
  Sec.Misc.VirtualSize := $1201;
  Sec.SizeOfRawData := $1400;
  Sec.PointerToRawData := $400;
  Sec.Characteristics := IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_EXECUTE or $20;
  Inc(Sec);
  Sec.VirtualAddress := $3000;
  Sec.Misc.VirtualSize := $1000;
  Sec.SizeOfRawData := $200;
  Sec.PointerToRawData := $1800;
  Sec.Characteristics := IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE or $40;
  FData[$1000] := $55;
  FData[$1001] := $8B;
  FData[$1002] := $EC;
  FData[$2FFF] := $77;
end;

function TParityMemoryReader.ReadMemory(Address: UInt64; Buffer: Pointer; Size: NativeUInt; ForceAccess: Boolean): NativeUInt;
var
  Offset: NativeUInt;
begin
  Result := 0;
  LastForceAccess := ForceAccess;
  if ReadAddresses <> nil then ReadAddresses.Add(Address);
  if FailReads then Exit;
  if (Address < TestBase) or (Address - TestBase >= UInt64(Length(FData))) then Exit;
  Offset := NativeUInt(Address - TestBase);
  Result := Length(FData) - Offset;
  if Result > Size then Result := Size;
  if (ReadLimit <> 0) and (Result > ReadLimit) then Result := ReadLimit;
  if Result <> 0 then Move(FData[Offset], Buffer^, Result);
end;

function TParityMemoryReader.QueryRegion(Address: UInt64; out Region: TNativeMirrorMemoryRegion): Boolean;
begin
  FillChar(Region, SizeOf(Region), 0);
  Result := (Address >= TestBase) and (Address < TestBase + UInt64(Length(FData)));
  if not Result then Exit;
  Region.BaseAddress := TestBase;
  Region.AllocationBase := TestBase;
  Region.RegionSize := Length(FData);
  if RegionSpan <> 0 then
  begin
    Region.BaseAddress := TestBase + ((Address - TestBase) div UInt64(RegionSpan)) * UInt64(RegionSpan);
    Region.RegionSize := UInt64(Length(FData)) - (Region.BaseAddress - TestBase);
    if Region.RegionSize > UInt64(RegionSpan) then Region.RegionSize := RegionSpan;
  end;
  Region.State := MEM_COMMIT;
  Region.Protect := PAGE_EXECUTE_READ;
  Region.AllocationProtect := PAGE_EXECUTE_READ;
  Region.MappingType := MappingType;
end;

function TParityMemoryReader.GetArchitecture: TNativeMirrorArchitecture;
begin
  Result := nmaX64;
end;

function TParityMemoryReader.GetProcessHandle: THandle;
begin
  Result := 0;
end;

procedure TNativeMirrorParityTests.SectionIncludesAlignmentPadding;
var
  Reader: INativeMirrorMemoryReader;
  Remote: TNativeMirrorRemoteModuleData;
  Section: TNativeMirrorSection;
begin
  Reader := TParityMemoryReader.Create;
  Remote := TNativeMirrorRemoteModuleData.Create(Reader, False, TestBase);
  try
    Section := TNativeMirrorSection.CreateRemote(Remote, 0);
    try
      Assert.IsTrue(Section.IsInitialized);
      Assert.AreEqual(8192, Integer(Section.LoadedSize));
      Assert.AreEqual($77, Integer(PByte(NativeUInt(Section.Data) + $1FFF)^));
    finally
      Section.Free;
    end;
  finally
    Remote.Free;
  end;
end;

procedure TNativeMirrorParityTests.SectionKeepsPartiallyReadBuffer;
var
  Stub: TParityMemoryReader;
  Reader: INativeMirrorMemoryReader;
  Remote: TNativeMirrorRemoteModuleData;
  Section: TNativeMirrorSection;
begin
  Stub := TParityMemoryReader.Create;
  Reader := Stub;
  Remote := TNativeMirrorRemoteModuleData.Create(Reader, False, TestBase);
  try
    Stub.ReadLimit := $1000;
    Section := TNativeMirrorSection.CreateRemote(Remote, 0);
    try
      Assert.IsTrue(Section.IsInitialized);
      Assert.AreEqual(8192, Integer(Section.LoadedSize));
      Assert.AreEqual(0, Integer(PByte(NativeUInt(Section.Data) + $1FFF)^));
    finally
      Section.Free;
    end;
  finally
    Remote.Free;
  end;
end;

procedure TNativeMirrorParityTests.SectionAccessFollowsReflection;
var
  Stub: TParityMemoryReader;
  Reader: INativeMirrorMemoryReader;
  Remote: TNativeMirrorRemoteModuleData;
  Section: TNativeMirrorSection;
  Reflection: Boolean;
begin
  Stub := TParityMemoryReader.Create;
  Reader := Stub;
  for Reflection := False to True do
  begin
    Remote := TNativeMirrorRemoteModuleData.Create(Reader, Reflection, TestBase);
    try
      Section := TNativeMirrorSection.CreateRemote(Remote, 0);
      try
        Assert.IsTrue(Section.IsInitialized);
        Assert.AreEqual(Reflection, Stub.LastForceAccess);
      finally
        Section.Free;
      end;
    finally
      Remote.Free;
    end;
  end;
end;

procedure TNativeMirrorParityTests.UniformFrequencyIsNotStrongEncryption;
var
  Data: TBytes;
  I: Integer;
  Stats: TNativeMirrorAreaMultiStats;
begin
  SetLength(Data, 4096);
  for I := 0 to High(Data) do Data[I] := $80 + (I mod 128);
  Stats := TNativeMirrorAreaMultiStats.Create;
  try
    Stats.Fill(@Data[0], Length(Data), 0, nil);
    Assert.IsFalse(TNativeMirrorStatsAnalyzer.IsEncrypted(Stats));
  finally
    Stats.Free;
  end;
end;

procedure TNativeMirrorParityTests.WatchedStringsUseLexicalOrder;
var
  Settings: TNativeMirrorMultiStatsSettings;
begin
  Settings := TNativeMirrorMultiStatsSettings.Create;
  try
    TNativeMirrorStatsAnalyzer.FillCodeStrings(Settings);
    Assert.AreEqual('AQ', Settings.Match('WVSAQ'));
  finally
    Settings.Free;
  end;
end;

procedure TNativeMirrorParityTests.FrequentValuesUseByteOrder;
var
  Stats: TNativeMirrorChunkStats;
begin
  Stats := TNativeMirrorChunkStats.Create;
  try
    Stats.AppendValue($FF);
    Stats.AppendValue($FF);
    Stats.AppendValue($FF);
    Stats.AppendValue($80);
    Stats.Summarize;
    Assert.AreEqual('\x80\xff', Stats.MostFrequentValuesHex(16, 8));
  finally
    Stats.Free;
  end;
end;

procedure TNativeMirrorParityTests.PatchTagLengthIsHex;
var
  Patch: TNativeMirrorPatch;
begin
  Patch := TNativeMirrorPatch.Create(TestBase, 0, $100);
  try
    Patch.SetEnd($110);
    Assert.AreEqual('100;patch_0;10', Patch.ToTag(';'));
  finally
    Patch.Free;
  end;
end;

procedure TNativeMirrorParityTests.RegionSizeStartsAtRequestedAddress;
var
  Reader: INativeMirrorMemoryReader;
begin
  Reader := TParityMemoryReader.Create;
  Assert.AreEqual($2000, Integer(NativeMirrorRegionSize(Reader, TestBase + $2000)));
end;

procedure TNativeMirrorParityTests.FreeRegionHasNoReadableSize;
var
  Stub: TParityMemoryReader;
  Reader: INativeMirrorMemoryReader;
begin
  Stub := TParityMemoryReader.Create;
  Reader := Stub;
  Stub.MappingType := 0;
  Assert.AreEqual(0, Integer(NativeMirrorRegionSize(Reader, TestBase + $2000)));
end;

procedure TNativeMirrorParityTests.RemoteImageUsesRegionRemainder;
var
  Reader: INativeMirrorMemoryReader;
  Remote: TNativeMirrorRemoteModuleData;
begin
  Reader := TParityMemoryReader.Create;
  Remote := TNativeMirrorRemoteModuleData.Create(Reader, False, TestBase);
  try
    Assert.AreEqual($4000, Integer(Remote.CalcImageSize));
  finally
    Remote.Free;
  end;
end;

procedure TNativeMirrorParityTests.ArtefactImageUsesRegionRemainder;
var
  Reader: INativeMirrorMemoryReader;
  Page: TNativeMirrorMemPageData;
  ProcessReport: TNativeMirrorProcessScanReport;
  Scanner: TNativeMirrorArtefactScanner;
  Report: TNativeMirrorArtefactScanReport;
begin
  Reader := TParityMemoryReader.Create;
  Page := TNativeMirrorMemPageData.Create(Reader, False, TestBase, 0);
  ProcessReport := TNativeMirrorProcessScanReport.Create(1, True, False);
  Scanner := TNativeMirrorArtefactScanner.Create(Reader, TNativeMirrorProcessDetails.Create(False, True), Page, ProcessReport);
  try
    Report := Scanner.ScanRemote;
    try
      Assert.IsNotNull(Report);
      Assert.AreEqual($4000, Integer(Report.Artefacts.CalculatedImageSize));
    finally
      Report.Free;
    end;
  finally
    Scanner.Free;
    ProcessReport.Free;
    Page.Free;
  end;
end;

procedure TNativeMirrorParityTests.OverlappingModulesUseLowestBase;
var
  Modules: TNativeMirrorModulesInfo;
  LowReport, HighReport: TNativeMirrorModuleScanReport;
  Found: TNativeMirrorScannedModule;
  I: Integer;
  Base: UInt64;
begin
  for I := 0 to 31 do
  begin
    Base := TestBase + UInt64(I) * $10000;
    Modules := TNativeMirrorModulesInfo.Create(1);
    LowReport := TNativeMirrorModuleScanReport.Create(Base, $4000);
    HighReport := TNativeMirrorModuleScanReport.Create(Base + $1000, $2000);
    try
      Modules.AppendReport(HighReport);
      Modules.AppendReport(LowReport);
      Found := Modules.FindModuleContaining(Base + $1800, 8);
      Assert.IsNotNull(Found);
      Assert.AreEqual<UInt64>(Base, Found.Start);
    finally
      HighReport.Free;
      LowReport.Free;
      Modules.Free;
    end;
  end;
end;

procedure TNativeMirrorParityTests.ImportListUsesHexLowercase;
var
  Block: TNativeMirrorIatBlock;
  Func: TExportedFunc;
  I: Integer;
begin
  Block := TNativeMirrorIatBlock.Create(True, $ABC);
  Func := TExportedFunc.Create('kernel32', 'Sleep', 1);
  try
    Block.IatSize := $88;
    for I := 0 to 15 do Block.Append($ABC + DWORD(I * 8), $1000 + UInt64(I), Func);
    Assert.IsTrue(Block.ToText.StartsWith('---' + sLineBreak + 'IAT at: abc, size: 88, thunks: 10, is_terminated: 0, in_main: 0' + sLineBreak));
  finally
    Block.Free;
    Func.Free;
  end;
end;

procedure TNativeMirrorParityTests.ImportNameSpaceUsesFirstOrderedAlias;
var
  Mapper: TExportsMapper;
  Series: TNativeMirrorIatThunkSeries;
  Functions: TExportedFuncSet;
  Func: TExportedFunc;
  Module: HMODULE;
  FunctionVa: UInt64;
  Buffer: TBytes;
  I: Integer;
begin
  Mapper := TExportsMapper.Create;
  Series := TNativeMirrorIatThunkSeries.Create($1000);
  try
    Module := GetModuleHandle('ntdll.dll');
    FunctionVa := UInt64(GetProcAddress(Module, 'NtClose'));
    Assert.IsTrue(FunctionVa <> 0);
    Assert.IsTrue(Mapper.AddToLookup('ntdll.dll', Module) <> 0);
    Series.Insert($1000, FunctionVa);
    Series.Insert($1004, FunctionVa);
    Assert.IsTrue(Series.MakeCoverage(Mapper));
    Functions := Series.Coverage.AddrToFunc[FunctionVa];
    Functions.Clear;
    for I := 0 to 31 do
    begin
      Func := TExportedFunc.Create('ntdll', 'LongAlias' + IntToStr(I), DWORD(I));
      Functions.Add(Func.MapKey, Func);
    end;
    Func := TExportedFunc.Create('ntdll', 'Foo', 100);
    Functions.Add(Func.MapKey, Func);
    Assert.AreEqual(38, Integer(Series.SizeOfNamesSpace(True)));
    SetLength(Buffer, 38);
    Assert.IsTrue(Series.FillNamesSpace(@Buffer[0], Length(Buffer), $2000, True));
    Assert.AreEqual<UInt64>($2018, PUInt64(@Buffer[0])^);
    Assert.AreEqual<UInt64>($201F, PUInt64(@Buffer[8])^);
  finally
    Series.Free;
    Mapper.Free;
  end;
end;

procedure TNativeMirrorParityTests.IatUnknownTargetUsesLowercaseModule;
var
  Modules: TNativeMirrorModulesInfo;
  ModuleReport: TNativeMirrorModuleScanReport;
  Report: TNativeMirrorIatScanReport;
  Mapper: TExportsMapper;
  FileName, Text: string;
begin
  Modules := TNativeMirrorModulesInfo.Create(1);
  ModuleReport := TNativeMirrorModuleScanReport.Create(TestBase, $4000);
  Report := TNativeMirrorIatScanReport.Create(TestBase, $4000, 'Target.exe');
  Mapper := TExportsMapper.Create;
  FileName := TPath.GetTempFileName;
  try
    ModuleReport.ModuleFile := 'MixedCaseTarget.EXE';
    Modules.AppendReport(ModuleReport);
    Report.NotCovered.Insert($123, TestBase + $20);
    Assert.IsTrue(Report.GenerateList(FileName, nil, Modules, Mapper));
    Text := TFile.ReadAllText(FileName, TEncoding.UTF8);
    Assert.IsTrue(Text.Contains(':mixedcasetarget.(unknown_func):0]'));
    Assert.AreEqual(Ord('1'), Integer(TFile.ReadAllBytes(FileName)[0]));
  finally
    TFile.Delete(FileName);
    Mapper.Free;
    Report.Free;
    ModuleReport.Free;
    Modules.Free;
  end;
end;

procedure TNativeMirrorParityTests.EntropyJsonUsesSixSignificantDigits;
var
  Report: TNativeMirrorWorkingSetScanReport;
  Area: TNativeMirrorSuspAddrReport;
  Data: TBytes;
  Json: TJSONObject;
  I: Integer;
begin
  SetLength(Data, 4096);
  for I := 0 to High(Data) do Data[I] := $80 + (I mod 128);
  Data[0] := $FF;
  Report := TNativeMirrorWorkingSetScanReport.Create(TestBase, Length(Data), NM_SCAN_SUSPICIOUS);
  Area := TNativeMirrorSuspAddrReport.Create(TestBase, Length(Data), PAGE_EXECUTE_READ);
  try
    Report.Stats.Fill(@Data[0], Length(Data), 0, nil);
    Json := Report.ToJson;
    try
      Assert.AreEqual('6.99999', Json.GetValue<TJSONObject>('workingset_scan').GetValue<TJSONObject>('stats').GetValue<TJSONObject>('full_area').GetValue('entropy').Value);
    finally
      Json.Free;
    end;
    Area.StatsSize := Length(Data);
    Area.Entropy := Report.Stats.Area.Entropy;
    Json := TJSONObject.Create;
    try
      Area.AddBaseJson(Json, nmJsonBasic);
      Assert.AreEqual('6.99999', Json.GetValue<TJSONObject>('stats').GetValue('entropy').Value);
    finally
      Json.Free;
    end;
  finally
    Area.Free;
    Report.Free;
  end;
end;

procedure TNativeMirrorParityTests.MemoryPageKeepsPartialReadTail;
var
  Stub: TParityMemoryReader;
  Reader: INativeMirrorMemoryReader;
  Page: TNativeMirrorMemPageData;
  Data: PByte;
  Reflection: Boolean;
begin
  for Reflection := False to True do
  begin
    Stub := TParityMemoryReader.Create;
    Reader := Stub;
    Stub.ReadLimit := 3;
    Page := TNativeMirrorMemPageData.Create(Reader, Reflection, TestBase + $1000, 0);
    try
      Assert.IsTrue(Page.Load);
      Assert.AreEqual($3000, Integer(Page.GetLoadedSize(False)));
      Assert.AreEqual(3, Integer(Page.GetLoadedSize(True)));
      Assert.AreEqual(0, Integer(Page.GetStartOffset(True)));
      Data := Page.GetLoadedData;
      Assert.AreEqual($55, Integer(Data[0]));
      Assert.AreEqual(0, Integer(Data[$2FFF]));
      Assert.IsTrue(Page.ValidatePtr(@Data[$2FFF], 1));
      Assert.AreEqual(Reflection, Stub.LastForceAccess);
    finally
      Page.Free;
    end;
  end;
end;

procedure TNativeMirrorParityTests.MemoryPagePartialReadRespectsStop;
var
  Stub: TParityMemoryReader;
  Reader: INativeMirrorMemoryReader;
  Page: TNativeMirrorMemPageData;
  Data: PByte;
begin
  Stub := TParityMemoryReader.Create;
  Reader := Stub;
  Stub.ReadLimit := 3;
  Page := TNativeMirrorMemPageData.Create(Reader, False, TestBase + $1000, TestBase + $2800);
  try
    Assert.IsTrue(Page.Load);
    Assert.AreEqual($1800, Integer(Page.GetLoadedSize(False)));
    Assert.AreEqual(3, Integer(Page.GetLoadedSize(True)));
    Data := Page.GetLoadedData;
    Assert.AreEqual(0, Integer(Data[$17FF]));
  finally
    Page.Free;
  end;
end;

procedure TNativeMirrorParityTests.MemoryPageRejectsEmptyRead;
var
  Stub: TParityMemoryReader;
  Reader: INativeMirrorMemoryReader;
  Page: TNativeMirrorMemPageData;
begin
  Stub := TParityMemoryReader.Create;
  Reader := Stub;
  Stub.FailReads := True;
  Page := TNativeMirrorMemPageData.Create(Reader, False, TestBase, 0);
  try
    Assert.IsFalse(Page.Load);
    Assert.AreEqual(0, Integer(Page.GetLoadedSize));
    Assert.IsTrue(Page.GetLoadedData = nil);
  finally
    Page.Free;
  end;
end;

procedure TNativeMirrorParityTests.ArtefactPatternExcludesFinalPosition;
var
  Data: array[0..7] of Byte;
  Pattern: array[0..1] of Byte;
begin
  FillChar(Data, SizeOf(Data), 0);
  Pattern[0] := $AA;
  Pattern[1] := $BB;
  Data[6] := $AA;
  Data[7] := $BB;
  Assert.IsTrue(FindPattern(@Data[0], SizeOf(Data), @Pattern[0], SizeOf(Pattern)) = nil);
  Assert.IsTrue(FindPattern(@Pattern[0], SizeOf(Pattern), @Pattern[0], SizeOf(Pattern)) = nil);
  Data[5] := $AA;
  Data[6] := $BB;
  Assert.IsTrue(FindPattern(@Data[0], SizeOf(Data), @Pattern[0], SizeOf(Pattern)) = @Data[5]);
end;

procedure TNativeMirrorParityTests.ArtefactPatternIterationLimitIsInclusive;
var
  Data: array[0..7] of Byte;
  Pattern: array[0..1] of Byte;
begin
  FillChar(Data, SizeOf(Data), 0);
  Pattern[0] := $AA;
  Pattern[1] := $BB;
  Data[3] := $AA;
  Data[4] := $BB;
  Assert.IsTrue(FindPattern(@Data[0], SizeOf(Data), @Pattern[0], SizeOf(Pattern), 2) = nil);
  Assert.IsTrue(FindPattern(@Data[0], SizeOf(Data), @Pattern[0], SizeOf(Pattern), 3) = @Data[3]);
end;

procedure TNativeMirrorParityTests.CodePatternIncludesFinalPosition;
var
  Data32: array[0..2] of Byte;
  Data64: array[0..3] of Byte;
begin
  Data32[0] := $55;
  Data32[1] := $8B;
  Data32[2] := $EC;
  Data64[0] := $48;
  Data64[1] := $83;
  Data64[2] := $E4;
  Data64[3] := $F0;
  Assert.AreEqual(0, Integer(Find32BitCode(@Data32[0], SizeOf(Data32))));
  Assert.AreEqual(0, Integer(Find64BitCode(@Data64[0], SizeOf(Data64))));
end;

procedure TNativeMirrorParityTests.ScanTimeMatchesReferenceThresholds;
begin
  Assert.AreEqual('[*] Workingset scanned in 0 ms.', FormatScanTime('Workingset', 0));
  Assert.AreEqual('[*] IATs scanned in 500 ms.', FormatScanTime('IATs', 500));
  Assert.AreEqual('[*] Threads scanned in 501 ms. = 0.501 sec.', FormatScanTime('Threads', 501));
  Assert.AreEqual('[*] IATs scanned in 30000 ms. = 30 sec.', FormatScanTime('IATs', 30000));
  Assert.AreEqual('[*] IATs scanned in 30001 ms. = 30.001 sec. = 0.500017 min.', FormatScanTime('IATs', 30001));
  Assert.AreEqual('[*] IATs scanned in 60000 ms. = 60 sec. = 1 min.', FormatScanTime('IATs', 60000));
  Assert.AreEqual('[*] IATs scanned in 4294967295 ms. = 4.29497e+06 sec. = 71582.8 min.', FormatScanTime('IATs', High(Cardinal)));
end;

procedure CheckLibraryScannerProgress(Quiet: Boolean);
var
  Options: TNativeMirrorOptions;
  Reader: INativeMirrorMemoryReader;
  Scanner: TNativeMirrorProcessScanner;
  Report: TNativeMirrorProcessScanReport;
  Lines: TStringList;
  Line: string;
  HasModule, HasWorkingSet, HasTiming: Boolean;
begin
  Options := TNativeMirrorOptions.Default;
  Options.Pid := GetCurrentProcessId;
  Options.Quiet := Quiet;
  Options.NoHooks := True;
  Reader := TNativeMirrorProcessMemoryReader.Create(GetCurrentProcess, False);
  Lines := TStringList.Create;
  Scanner := TNativeMirrorProcessScanner.Create(Reader, False, Options);
  try
    Scanner.OnMessage :=
      procedure(const Text: string; IsError: Boolean)
      begin
        Lines.Add(Text);
      end;
    Report := Scanner.ScanRemote;
    try
      Assert.IsNotNull(Report);
      Assert.IsTrue(Report.ModulesInfo.Count <> 0);
      if Quiet then
        Assert.AreEqual(0, Lines.Count)
      else
      begin
        HasModule := False;
        HasWorkingSet := False;
        HasTiming := False;
        for Line in Lines do
        begin
          HasModule := HasModule or Line.StartsWith('[*] Scanning: ');
          HasWorkingSet := HasWorkingSet or (Line.StartsWith('Scanning workingset: ') and Line.EndsWith(' memory regions.'));
          HasTiming := HasTiming or Line.StartsWith('[*] Workingset scanned in ');
        end;
        Assert.IsTrue(HasModule);
        Assert.IsTrue(HasWorkingSet);
        Assert.IsTrue(HasTiming);
      end;
    finally
      Report.Free;
    end;
  finally
    Scanner.Free;
    Lines.Free;
  end;
end;

procedure TNativeMirrorParityTests.LibraryScannerEmitsProgress;
begin
  CheckLibraryScannerProgress(False);
end;

procedure TNativeMirrorParityTests.QuietLibraryScannerSuppressesProgress;
begin
  CheckLibraryScannerProgress(True);
end;

procedure CheckStandaloneMatcherIsolation(ClearFirst: Boolean);
var
  First, Second: TNativeMirrorPatternMatcher;
  Stream: TStringStream;
  Matches: TList<TNativeMirrorSignatureMatch>;
  Bytes: array[0..3] of Byte;
begin
  Bytes[0] := $DE;
  Bytes[1] := $AD;
  Bytes[2] := $BE;
  Bytes[3] := $EF;
  First := TNativeMirrorPatternMatcher.Create;
  Second := TNativeMirrorPatternMatcher.Create;
  Stream := TStringStream.Create('standalone' + sLineBreak + '4' + sLineBreak + 'DE AD BE EF' + sLineBreak, TEncoding.UTF8);
  Matches := TList<TNativeMirrorSignatureMatch>.Create;
  try
    Assert.AreEqual(1, Integer(First.LoadFromStream(Stream)));
    if ClearFirst then
    begin
      Stream.Position := 0;
      Assert.AreEqual(1, Integer(Second.LoadFromStream(Stream)));
      First.Clear;
      Assert.IsFalse(First.IsReady);
      Assert.AreEqual(1, Integer(Second.FindAll(@Bytes[0], Length(Bytes), Matches)));
    end
    else
    begin
      Assert.IsFalse(Second.IsReady);
      Assert.AreEqual(1, Integer(First.FindAll(@Bytes[0], Length(Bytes), Matches)));
    end;
  finally
    Matches.Free;
    Stream.Free;
    Second.Free;
    First.Free;
  end;
end;

procedure TNativeMirrorParityTests.StandaloneMatchersKeepIndependentData;
begin
  CheckStandaloneMatcherIsolation(False);
end;

procedure TNativeMirrorParityTests.StandaloneMatcherClearKeepsOtherInstances;
begin
  CheckStandaloneMatcherIsolation(True);
end;

function RunNativeMirrorPatternProbe(const Mode, FirstFile, SecondFile: string): Integer;
var
  Root: TJSONObject;
  Scans, Messages: TJSONArray;
  Threads: TList<TThread>;
  Thread: TThread;
  I: Integer;
  Page: PByte;
  OldProtect: DWORD;
  ProbeFirstFile: string;

  function CountMatches(const Bytes: array of Byte): Integer;
  var
    Matches: TList<TNativeMirrorSignatureMatch>;
  begin
    Matches := TList<TNativeMirrorSignatureMatch>.Create;
    try
      Result := Integer(NativeMirrorSharedPatternMatcher.FindAll(@Bytes[0], Length(Bytes), Matches));
    finally
      Matches.Free;
    end;
  end;

  procedure AddCounts(Json: TJSONObject);
  begin
    Json.AddPair('a', TJSONNumber.Create(CountMatches([$DE, $AD, $BE, $EF])));
    Json.AddPair('b', TJSONNumber.Create(CountMatches([$CA, $FE, $BA, $BE])));
    Json.AddPair('prolog', TJSONNumber.Create(CountMatches([$55, $8B, $EC])));
  end;

  procedure Scan(const FileName: string; Patterns, Quiet: Boolean; ValidProcess: Boolean = False);
  var
    Options: TNativeMirrorOptions;
    Report: TNativeMirrorReportEx;
    Item: TJSONObject;
    Finding: TNativeMirrorModuleScanReport;
    TargetDetected: Boolean;
  begin
    Item := TJSONObject.Create;
    Scans.AddElement(Item);
    Messages := TJSONArray.Create;
    Item.AddPair('messages', Messages);
    Item.AddPair('file', FileName);
    Options := TNativeMirrorOptions.Default;
    Options.Quiet := Quiet;
    Options.OutputFilter := nmOutNoDir;
    Options.PatternFile := FileName;
    if ValidProcess then
    begin
      Options.Pid := GetCurrentProcessId;
      Options.NoHooks := True;
    end;
    if Patterns then Options.ShellcodeMode := nmShellcodePatterns;
    Report := ScanAndDump(Options,
      procedure(Kind: TNativeMirrorEngineMessageKind; const Text: string)
      begin
        if Kind = nmEngineError then Messages.Add('E:' + Text)
        else Messages.Add('I:' + Text);
      end);
    try
      Item.AddPair('open_failed', TJSONBool.Create(Report.ErrorReport <> nil));
      if ValidProcess then
      begin
        TargetDetected := False;
        if Report.ScanReport <> nil then
          for Finding in Report.ScanReport.Reports do
            if (Finding.ModuleBase = UInt64(NativeUInt(Page))) and (Finding.Status = NM_SCAN_SUSPICIOUS) and
              (Finding is TNativeMirrorWorkingSetScanReport) then
              TargetDetected := TNativeMirrorWorkingSetScanReport(Finding).CustomMatches.Count = 1;
        Item.AddPair('target_detected', TJSONBool.Create(TargetDetected));
      end;
    finally
      Report.Free;
    end;
    AddCounts(Item);
  end;

begin
  Result := 0;
  Root := TJSONObject.Create;
  try
    ProbeFirstFile := FirstFile;
    Root.AddPair('mode', Mode);
    Scans := TJSONArray.Create;
    Root.AddPair('scans', Scans);
    if Mode = 'valid_scans' then
    begin
      Page := VirtualAlloc(nil, $1000, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE);
      if Page = nil then RaiseLastOSError;
      try
        Page[0] := $DE;
        Page[1] := $AD;
        Page[2] := $BE;
        Page[3] := $EF;
        if not VirtualProtect(Page, $1000, PAGE_EXECUTE_READ, OldProtect) then RaiseLastOSError;
        Scan(FirstFile, False, True, True);
        Scan(SecondFile, False, True, True);
        Scan('', False, True, True);
      finally
        VirtualFree(Page, 0, MEM_RELEASE);
      end;
    end
    else if Mode = 'file_once' then
    begin
      Scan(FirstFile, False, True);
      Scan(SecondFile, False, True);
      Scan('', False, True);
    end
    else if Mode = 'missing_first' then
    begin
      Scan(FirstFile, False, True);
      Scan(SecondFile, False, True);
    end
    else if Mode = 'builtin_once' then
    begin
      Scan('', True, True);
      Scan('', True, True);
      Scan('', False, True);
    end
    else if Mode = 'builtin_then_file' then
    begin
      Scan('', True, True);
      Scan(FirstFile, False, True);
      Scan(SecondFile, False, True);
    end
    else if Mode = 'file_then_builtin' then
    begin
      Scan(FirstFile, False, True);
      Scan('', True, True);
    end
    else if Mode = 'verbose' then
    begin
      Scan(FirstFile, False, False);
      Scan(SecondFile, False, False);
    end
    else if Mode = 'concurrent' then
    begin
      Messages := TJSONArray.Create;
      Root.AddPair('messages', Messages);
      Threads := TList<TThread>.Create;
      try
        for I := 0 to 15 do
        begin
          Thread := TThread.CreateAnonymousThread(
            procedure
            begin
              NativeMirrorInitializePatterns(ProbeFirstFile, True,
                procedure(const Text: string; IsError: Boolean)
                begin
                  Messages.Add(Text);
                end);
            end);
          Thread.FreeOnTerminate := False;
          Threads.Add(Thread);
          Thread.Start;
        end;
        for Thread in Threads do Thread.WaitFor;
        for Thread in Threads do
          if Thread.FatalException <> nil then raise Exception.Create('Concurrent pattern initialization failed');
        AddCounts(Root);
      finally
        for Thread in Threads do Thread.Free;
        Threads.Free;
      end;
    end
    else
      raise Exception.Create('Unknown pattern probe mode');
    Writeln(Root.ToJSON);
  finally
    Root.Free;
  end;
end;

procedure CheckArtefactPreviousPage(Adjacent: Boolean);
var
  Stub: TParityMemoryReader;
  Reader: INativeMirrorMemoryReader;
  Reads: TList<UInt64>;
  Page: TNativeMirrorMemPageData;
  ProcessReport: TNativeMirrorProcessScanReport;
  Scanner: TNativeMirrorArtefactScanner;
  Report: TNativeMirrorArtefactScanReport;
  Start: UInt64;
begin
  Stub := TParityMemoryReader.Create;
  Reader := Stub;
  Reads := TList<UInt64>.Create;
  Stub.ReadAddresses := Reads;
  Stub.RegionSpan := $1000;
  if Adjacent then Start := TestBase + $1000 else Start := TestBase + $3000;
  Page := TNativeMirrorMemPageData.Create(Reader, False, Start, 0);
  ProcessReport := TNativeMirrorProcessScanReport.Create(1, True, False);
  Scanner := TNativeMirrorArtefactScanner.Create(Reader, TNativeMirrorProcessDetails.Create(False, True), Page, ProcessReport);
  try
    Report := Scanner.ScanRemote;
    try
      if Adjacent then
      begin
        Assert.IsNotNull(Report);
        Assert.AreEqual<UInt64>(TestBase, Report.ModuleBase);
        Assert.IsTrue(Reads.Contains(TestBase));
      end
      else
      begin
        Assert.IsTrue(Report = nil);
        Assert.IsTrue(Reads.Contains(TestBase + $2000));
        Assert.IsFalse(Reads.Contains(TestBase + $1000));
        Assert.IsFalse(Reads.Contains(TestBase));
      end;
    finally
      Report.Free;
    end;
  finally
    Scanner.Free;
    ProcessReport.Free;
    Page.Free;
    Stub.ReadAddresses := nil;
    Reads.Free;
  end;
end;

procedure TNativeMirrorParityTests.ArtefactPreviousPageMatchesReferenceStep;
begin
  CheckArtefactPreviousPage(False);
end;

procedure TNativeMirrorParityTests.ArtefactAdjacentHeaderRemainsDetected;
begin
  CheckArtefactPreviousPage(True);
end;

procedure CheckLibraryReportMessages(Quiet: Boolean);
var
  Options: TNativeMirrorOptions;
  Report: TNativeMirrorReportEx;
  Lines: TStringList;
  DirectoryName, ExpectedPath: string;
begin
  DirectoryName := TPath.Combine(ExtractFilePath(ParamStr(0)), 'report-messages-' + IntToStr(GetCurrentProcessId) + '-' + UIntToStr(GetTickCount64));
  Options := TNativeMirrorOptions.Default;
  Options.Pid := GetCurrentProcessId;
  Options.NoHooks := True;
  Options.Quiet := Quiet;
  Options.OutputFilter := nmOutNoDumps;
  Options.ResultsFilter := NM_SHOW_ALL;
  Options.OutputDirectory := DirectoryName;
  ExpectedPath := TPath.Combine(DirectoryName, 'process_' + IntToStr(Options.Pid));
  Lines := TStringList.Create;
  try
    Report := ScanAndDump(Options,
      procedure(Kind: TNativeMirrorEngineMessageKind; const Text: string)
      begin
        Lines.Add(Text);
      end);
    try
      Assert.IsNotNull(Report.ScanReport);
      Assert.IsTrue(TFile.Exists(TPath.Combine(ExpectedPath, 'scan_report.json')));
      if Quiet then Assert.AreEqual(0, Lines.Count)
      else Assert.IsTrue(Lines.IndexOf('[+] Report dumped to: process_' + IntToStr(Options.Pid)) >= 0);
    finally
      Report.Free;
    end;
  finally
    Lines.Free;
    if TDirectory.Exists(DirectoryName) then TDirectory.Delete(DirectoryName, True);
  end;
end;

procedure TNativeMirrorParityTests.LibraryReportMessagesFollowEngine;
begin
  CheckLibraryReportMessages(False);
end;

procedure TNativeMirrorParityTests.QuietLibraryReportMessagesAreSuppressed;
begin
  CheckLibraryReportMessages(True);
end;

procedure CheckDumperMessages(FailRead, Quiet, Artefact: Boolean);
var
  Stub: TParityMemoryReader;
  Reader: INativeMirrorMemoryReader;
  ProcessReport: TNativeMirrorProcessScanReport;
  ModuleReport: TNativeMirrorModuleScanReport;
  Dumper: TNativeMirrorResultsDumper;
  DumpReport: TNativeMirrorProcessDumpReport;
  Lines, Errors: TStringList;
  DirectoryName, DumpPath: string;
  PeArtefacts: TPeArtefacts;
begin
  DirectoryName := TPath.Combine(ExtractFilePath(ParamStr(0)), 'dumper-messages-' + IntToStr(GetCurrentProcessId) + '-' + UIntToStr(GetTickCount64));
  Stub := TParityMemoryReader.Create;
  Reader := Stub;
  Stub.FailReads := FailRead;
  ProcessReport := TNativeMirrorProcessScanReport.Create(1, True, False);
  if Artefact then
  begin
    PeArtefacts.Reset;
    PeArtefacts.RegionStart := TestBase;
    PeArtefacts.PeBaseOffset := 0;
    ModuleReport := TNativeMirrorArtefactScanReport.Create(TestBase, $4000, NM_SCAN_SUSPICIOUS, PeArtefacts);
    TNativeMirrorArtefactScanReport(ModuleReport).HasPe := True;
  end
  else
    ModuleReport := TNativeMirrorModuleScanReport.Create(TestBase, $4000, NM_SCAN_SUSPICIOUS);
  ModuleReport.ModuleFile := 'fixture.exe';
  ProcessReport.AppendReport(ModuleReport);
  Dumper := TNativeMirrorResultsDumper.Create(DirectoryName, Quiet);
  Lines := TStringList.Create;
  Errors := TStringList.Create;
  try
    Dumper.OnMessage :=
      procedure(const Text: string; IsError: Boolean)
      begin
        if IsError then Errors.Add(Text) else Lines.Add(Text);
      end;
    DumpReport := Dumper.DumpDetectedModules(Reader, False, ProcessReport, nmDumpVirtual, nmImportNone, False);
    try
      if Quiet then
      begin
        Assert.AreEqual(0, Lines.Count);
        Assert.AreEqual(0, Errors.Count);
      end
      else if FailRead then
      begin
        Assert.AreEqual(1, Errors.Count);
        Assert.AreEqual('[-] Failed dumping module!', Errors[0]);
        if Artefact then
        begin
          Assert.AreEqual(1, Lines.Count);
          Assert.AreEqual('[-] Reconstructing PE at: ' + IntToHex(TestBase, 1).ToLower + ' failed.', Lines[0]);
        end
        else Assert.AreEqual(0, Lines.Count);
      end
      else
      begin
        Assert.AreEqual(0, Errors.Count);
        Assert.AreEqual(1, Lines.Count);
        DumpPath := TPath.Combine(TPath.Combine(DirectoryName, 'process_1'), IntToHex(TestBase, 1).ToLower + '.fixture.exe');
        Assert.IsTrue(TFile.Exists(DumpPath));
        Assert.AreEqual('[*] Dumped module to: ' + DumpPath + ' as VIRTUAL', Lines[0]);
        Assert.AreEqual(1, Integer(DumpReport.CountDumped));
      end;
    finally
      DumpReport.Free;
    end;
  finally
    Errors.Free;
    Lines.Free;
    Dumper.Free;
    ProcessReport.Free;
    if TDirectory.Exists(DirectoryName) then TDirectory.Delete(DirectoryName, True);
  end;
end;

procedure TNativeMirrorParityTests.DumperCallbackReportsSuccess;
begin
  CheckDumperMessages(False, False, False);
end;

procedure TNativeMirrorParityTests.DumperCallbackReportsFailure;
begin
  CheckDumperMessages(True, False, False);
end;

procedure TNativeMirrorParityTests.QuietDumperSuppressesMessages;
begin
  CheckDumperMessages(False, True, False);
  CheckDumperMessages(True, True, True);
end;

procedure TNativeMirrorParityTests.DumperReconstructionFailureUsesReferenceText;
begin
  CheckDumperMessages(True, False, True);
end;

function RunNativeMirrorThreadProbe(Pid: Cardinal): Integer;
var
  Options: TNativeMirrorOptions;
  Report: TNativeMirrorReportEx;
  Finding: TNativeMirrorModuleScanReport;
  Thread: TNativeMirrorThreadScanReport;
  Root, Item: TJSONObject;
  Items: TJSONArray;
  ModuleInfo: TNativeMirrorScannedModule;
begin
  Options := TNativeMirrorOptions.Default;
  Options.Pid := Pid;
  Options.Quiet := True;
  Options.OutputFilter := nmOutNoDir;
  Options.ScanThreads := True;
  Options.ShellcodeMode := nmShellcodePatterns;
  Options.IatScanMode := nmIatCleanSystemFiltered;
  Report := ScanAndDump(Options);
  try
    Root := TJSONObject.Create;
    try
      Items := TJSONArray.Create;
      Root.AddPair('threads', Items);
      if Report.ScanReport = nil then Exit(1);
      for Finding in Report.ScanReport.Reports do
        if Finding is TNativeMirrorThreadScanReport then
        begin
          Thread := TNativeMirrorThreadScanReport(Finding);
          Item := TJSONObject.Create;
          Items.AddElement(Item);
          Item.AddPair('report', Thread.ToJson(nmJsonDetails));
          Item.AddPair('ret_on_stack', IntToHex(Thread.CDetails.RetOnStack, 1).ToLower);
          Item.AddPair('ret_in_frame', TJSONBool.Create(Thread.CDetails.IsRetInFrame));
          ModuleInfo := Report.ScanReport.ModulesInfo.FindModuleContaining(Thread.CDetails.RetOnStack);
          if ModuleInfo <> nil then Item.AddPair('ret_module', ModuleInfo.ModuleName);
        end;
      Writeln(Root.ToJSON);
    finally
      Root.Free;
    end;
  finally
    Report.Free;
  end;
  Result := 0;
end;

initialization
  TDUnitX.RegisterTestFixture(TNativeMirrorParityTests);

end.
