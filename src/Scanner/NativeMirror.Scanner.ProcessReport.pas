{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Scanner.ProcessReport;

interface

uses
  Winapi.Windows,
  System.JSON,
  System.Generics.Collections,
  NativePe.ExportsMapper,
  NativeMirror.Core.Types,
  NativeMirror.Scanner.Reports,
  NativeMirror.Scanner.Modules;

type
  TNativeMirrorProcessScanReport = class
  private
    FPid: DWORD;
    FIs64Bit: Boolean;
    FIsManaged: Boolean;
    FIsReflection: Boolean;
    FErrorsCount: NativeUInt;
    FMainImagePath: string;
    FReports: TObjectList<TNativeMirrorModuleScanReport>;
    FModulesInfo: TNativeMirrorModulesInfo;
    FExportsMap: TExportsMapper;
    function CountReports(ReportType: TNativeMirrorScanReportType): NativeUInt;
    function CountResults(ReportType: TNativeMirrorScanReportType; Status: TNativeMirrorScanStatus): NativeUInt;
    function CountHeaderReplaced: NativeUInt;
  public
    constructor Create(Pid: DWORD; Is64Bit, IsReflection: Boolean);
    destructor Destroy; override;
    procedure AppendReport(Report: TNativeMirrorModuleScanReport);
    function EnsureExportsMap: TExportsMapper;
    function HasModule(Address: UInt64): Boolean;
    function HasModuleContaining(Address: UInt64; Size: NativeUInt = 0): Boolean;
    function IsModuleReplaced(Address: UInt64): Boolean;
    function GetScannedSize(Address: UInt64): NativeUInt;
    function GetModuleContaining(Address: UInt64; Size: NativeUInt = 0): TNativeMirrorScannedModule;
    function GenerateSummary: TNativeMirrorProcessSummary;
    function ToJson(Filter: TNativeMirrorResultsFilter; Level: TNativeMirrorJsonLevel): TJSONObject;
    property Pid: DWORD read FPid;
    property Is64Bit: Boolean read FIs64Bit;
    property IsManaged: Boolean read FIsManaged write FIsManaged;
    property IsReflection: Boolean read FIsReflection;
    property MainImagePath: string read FMainImagePath write FMainImagePath;
    property Reports: TObjectList<TNativeMirrorModuleScanReport> read FReports;
    property ModulesInfo: TNativeMirrorModulesInfo read FModulesInfo;
    property ExportsMap: TExportsMapper read FExportsMap;
  end;

function NativePeIsShownStatus(Status: TNativeMirrorScanStatus; Filter: TNativeMirrorResultsFilter): Boolean;

implementation

uses
  System.SysUtils,
  NativeMirror.Scanner.Headers;

function NativePeIsShownStatus(Status: TNativeMirrorScanStatus; Filter: TNativeMirrorResultsFilter): Boolean;
begin
  if Filter = NM_SHOW_ALL then
    Exit(True);
  if ((Filter and NM_SHOW_ERRORS) <> 0) and (Status = NM_SCAN_ERROR) then
    Exit(True);
  if ((Filter and NM_SHOW_SUSPICIOUS) <> 0) and (Status = NM_SCAN_SUSPICIOUS) then
    Exit(True);
  Result := ((Filter and NM_SHOW_NOT_SUSPICIOUS) <> 0) and (Status = NM_SCAN_NOT_SUSPICIOUS);
end;

constructor TNativeMirrorProcessScanReport.Create(Pid: DWORD; Is64Bit, IsReflection: Boolean);
begin
  inherited Create;
  FPid := Pid;
  FIs64Bit := Is64Bit;
  FIsReflection := IsReflection;
  FReports := TObjectList<TNativeMirrorModuleScanReport>.Create(True);
  FModulesInfo := TNativeMirrorModulesInfo.Create(Pid);
  FExportsMap := nil;
end;

destructor TNativeMirrorProcessScanReport.Destroy;
begin
  FExportsMap.Free;
  FModulesInfo.Free;
  FReports.Free;
  inherited;
end;

procedure TNativeMirrorProcessScanReport.AppendReport(Report: TNativeMirrorModuleScanReport);
begin
  if Report = nil then
    Exit;
  FReports.Add(Report);
  if Report.Status = NM_SCAN_ERROR then
    Inc(FErrorsCount)
  else
    FModulesInfo.AppendReport(Report);
end;

function TNativeMirrorProcessScanReport.EnsureExportsMap: TExportsMapper;
begin
  if FExportsMap = nil then
    FExportsMap := TExportsMapper.Create;
  Result := FExportsMap;
end;

function TNativeMirrorProcessScanReport.HasModule(Address: UInt64): Boolean;
begin
  Result := FModulesInfo.GetModuleAt(Address) <> nil;
end;

function TNativeMirrorProcessScanReport.HasModuleContaining(Address: UInt64; Size: NativeUInt): Boolean;
begin
  Result := FModulesInfo.FindModuleContaining(Address, Size) <> nil;
end;

function TNativeMirrorProcessScanReport.GetScannedSize(Address: UInt64): NativeUInt;
begin
  Result := FModulesInfo.GetScannedSize(Address);
end;

function TNativeMirrorProcessScanReport.GetModuleContaining(Address: UInt64; Size: NativeUInt): TNativeMirrorScannedModule;
begin
  Result := FModulesInfo.FindModuleContaining(Address, Size);
end;

function TNativeMirrorProcessScanReport.CountReports(ReportType: TNativeMirrorScanReportType): NativeUInt;
var
  Report: TNativeMirrorModuleScanReport;
begin
  Result := 0;
  for Report in FReports do
    if Report.ReportType = ReportType then
      Inc(Result);
end;

function TNativeMirrorProcessScanReport.CountResults(ReportType: TNativeMirrorScanReportType; Status: TNativeMirrorScanStatus): NativeUInt;
var
  Report: TNativeMirrorModuleScanReport;
begin
  Result := 0;
  for Report in FReports do
    if (Report.ReportType = ReportType) and (Report.Status = Status) then
      Inc(Result);
end;

function TNativeMirrorProcessScanReport.CountHeaderReplaced: NativeUInt;
var
  Report: TNativeMirrorModuleScanReport;
  Headers: TNativeMirrorHeadersScanReport;
begin
  Result := 0;
  for Report in FReports do
    if (Report is TNativeMirrorHeadersScanReport) and (Report.Status = NM_SCAN_SUSPICIOUS) then
    begin
      Headers := TNativeMirrorHeadersScanReport(Report);
      if Headers.IsHeaderReplaced then
        Inc(Result);
    end;
end;

function TNativeMirrorProcessScanReport.IsModuleReplaced(Address: UInt64): Boolean;
var
  Report: TNativeMirrorModuleScanReport;
begin
  Result := False;
  if not HasModule(Address) then
    Exit;
  for Report in FReports do
    if (Report is TNativeMirrorHeadersScanReport) and (Report.ModuleBase = Address) and TNativeMirrorHeadersScanReport(Report).IsHeaderReplaced then
      Exit(True);
end;

function ToDword(Value: NativeUInt): DWORD;
begin
  if Value > High(DWORD) then
    Result := High(DWORD)
  else
    Result := DWORD(Value);
end;

function TNativeMirrorProcessScanReport.GenerateSummary: TNativeMirrorProcessSummary;
var
  Report: TNativeMirrorModuleScanReport;
  Known: UInt64;
begin
  FillChar(Result, SizeOf(Result), 0);
  Result.Pid := FPid;
  Result.IsManaged := FIsManaged;
  Result.Is64Bit := FIs64Bit;
  Result.IsReflection := FIsReflection;
  Result.Errors := ToDword(FErrorsCount);
  Result.Skipped := ToDword(CountReports(nmReportSkippedScan));
  Result.Scanned := ToDword(CountReports(nmReportHeadersScan));
  for Report in FReports do
    if Report.Status = NM_SCAN_SUSPICIOUS then
      Inc(Result.Suspicious);
  Result.Replaced := ToDword(CountHeaderReplaced);
  Result.Patched := ToDword(CountResults(nmReportCodeScan, NM_SCAN_SUSPICIOUS));
  Result.IatHooked := ToDword(CountResults(nmReportIatScan, NM_SCAN_SUSPICIOUS));
  Result.ImplantedShellcode := ToDword(CountResults(nmReportMemPageScan, NM_SCAN_SUSPICIOUS) + CountResults(nmReportThreadsScan, NM_SCAN_SUSPICIOUS));
  Result.ImplantedPe := ToDword(CountResults(nmReportArtefactScan, NM_SCAN_SUSPICIOUS));
  Result.Implanted := Result.ImplantedShellcode + Result.ImplantedPe;
  Result.HeaderModified := ToDword(CountResults(nmReportHeadersScan, NM_SCAN_SUSPICIOUS));
  if Result.HeaderModified >= Result.Replaced then
    Dec(Result.HeaderModified, Result.Replaced)
  else
    Result.HeaderModified := 0;
  Result.UnreachableFile := ToDword(CountResults(nmReportUnreachableScan, NM_SCAN_SUSPICIOUS) + CountResults(nmReportUnreachableScan, NM_SCAN_ERROR));
  Known := UInt64(Result.Patched) + Result.Replaced + Result.Implanted + Result.HeaderModified + Result.IatHooked;
  if UInt64(Result.Suspicious) >= Known then
    Result.Other := DWORD(UInt64(Result.Suspicious) - Known)
  else
    Result.Other := 0;
end;

function TNativeMirrorProcessScanReport.ToJson(Filter: TNativeMirrorResultsFilter; Level: TNativeMirrorJsonLevel): TJSONObject;
var
  Summary: TNativeMirrorProcessSummary;
  Scanned, Modified: TJSONObject;
  Scans: TJSONArray;
  Report: TNativeMirrorModuleScanReport;
begin
  Summary := GenerateSummary;
  Result := TJSONObject.Create;
  Result.AddPair('pid', TJSONNumber.Create(Summary.Pid));
  Result.AddPair('is_64_bit', TJSONNumber.Create(Ord(Summary.Is64Bit)));
  Result.AddPair('is_managed', TJSONNumber.Create(Ord(Summary.IsManaged)));
  Result.AddPair('main_image_path', FMainImagePath);
  Result.AddPair('used_reflection', TJSONNumber.Create(Ord(Summary.IsReflection)));
  Result.AddPair('scanner_version', '0.4.1.5');
  Scanned := TJSONObject.Create;
  Scanned.AddPair('total', TJSONNumber.Create(Summary.Scanned));
  Scanned.AddPair('skipped', TJSONNumber.Create(Summary.Skipped));
  Modified := TJSONObject.Create;
  Modified.AddPair('total', TJSONNumber.Create(Summary.Suspicious));
  Modified.AddPair('patched', TJSONNumber.Create(Summary.Patched));
  Modified.AddPair('iat_hooked', TJSONNumber.Create(Summary.IatHooked));
  Modified.AddPair('replaced', TJSONNumber.Create(Summary.Replaced));
  Modified.AddPair('hdr_modified', TJSONNumber.Create(Summary.HeaderModified));
  Modified.AddPair('implanted_pe', TJSONNumber.Create(Summary.ImplantedPe));
  Modified.AddPair('implanted_shc', TJSONNumber.Create(Summary.ImplantedShellcode));
  Modified.AddPair('unreachable_file', TJSONNumber.Create(Summary.UnreachableFile));
  Modified.AddPair('other', TJSONNumber.Create(Summary.Other));
  Scanned.AddPair('modified', Modified);
  Scanned.AddPair('errors', TJSONNumber.Create(Summary.Errors));
  Result.AddPair('scanned', Scanned);
  Scans := TJSONArray.Create;
  for Report in FReports do
    if NativePeIsShownStatus(Report.Status, Filter) then
      Scans.AddElement(Report.ToJson(Level));
  Result.AddPair('scans', Scans);
end;

end.
