{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Scanner.Reports;

interface

uses
  System.JSON,
  NativeMirror.Core.Types;

type
  TNativeMirrorElementScanReport = class
  private
    FStatus: TNativeMirrorScanStatus;
  protected
    procedure AddBaseJson(Json: TJSONObject); virtual;
  public
    constructor Create(Status: TNativeMirrorScanStatus = NM_SCAN_NOT_SUSPICIOUS);
    class function ScanStatus(Report: TNativeMirrorElementScanReport): TNativeMirrorScanStatus; static;
    function ToJson(Level: TNativeMirrorJsonLevel = nmJsonBasic): TJSONObject; virtual;
    property Status: TNativeMirrorScanStatus read FStatus write FStatus;
  end;

  TNativeMirrorModuleScanReport = class(TNativeMirrorElementScanReport)
  private
    FModuleBase: UInt64;
    FModuleSize: NativeUInt;
    FIsDotNetModule: Boolean;
    FModuleFile: string;
    FOriginalBase: UInt64;
    FRelocBase: UInt64;
  protected
    procedure AddBaseJson(Json: TJSONObject); override;
    function JsonName: string; virtual;
  public
    constructor Create(ModuleBase: UInt64; ModuleSize: NativeUInt; Status: TNativeMirrorScanStatus = NM_SCAN_NOT_SUSPICIOUS);
    function ToJson(Level: TNativeMirrorJsonLevel = nmJsonBasic): TJSONObject; override;
    function ReportType: TNativeMirrorScanReportType; virtual;
    function GetRelocBase: UInt64; virtual;
    function GenerateTags(const ReportPath: string): NativeUInt; virtual;
    property ModuleBase: UInt64 read FModuleBase write FModuleBase;
    property ModuleSize: NativeUInt read FModuleSize write FModuleSize;
    property IsDotNetModule: Boolean read FIsDotNetModule write FIsDotNetModule;
    property ModuleFile: string read FModuleFile write FModuleFile;
    property OriginalBase: UInt64 read FOriginalBase write FOriginalBase;
    property RelocBase: UInt64 read FRelocBase write FRelocBase;
  end;

  TNativeMirrorUnreachableModuleReport = class(TNativeMirrorModuleScanReport)
  public
    constructor Create(ModuleBase: UInt64; ModuleSize: NativeUInt; const ModuleFile: string);
    function ReportType: TNativeMirrorScanReportType; override;
  end;

  TNativeMirrorSkippedModuleReport = class(TNativeMirrorModuleScanReport)
  public
    constructor Create(ModuleBase: UInt64; ModuleSize: NativeUInt; const ModuleFile: string);
    function ReportType: TNativeMirrorScanReportType; override;
  end;

  TNativeMirrorMalformedHeaderReport = class(TNativeMirrorModuleScanReport)
  public
    constructor Create(ModuleBase: UInt64; ModuleSize: NativeUInt; const ModuleFile: string);
  end;

implementation

uses
  System.SysUtils;

function HexValue(Value: UInt64): string;
begin
  Result := IntToHex(Value, 1).ToLower;
end;

constructor TNativeMirrorElementScanReport.Create(Status: TNativeMirrorScanStatus);
begin
  inherited Create;
  FStatus := Status;
end;

class function TNativeMirrorElementScanReport.ScanStatus(Report: TNativeMirrorElementScanReport): TNativeMirrorScanStatus;
begin
  if Report = nil then
    Exit(NM_SCAN_ERROR);
  Result := Report.Status;
end;

procedure TNativeMirrorElementScanReport.AddBaseJson(Json: TJSONObject);
begin
  Json.AddPair('status', TJSONNumber.Create(FStatus));
end;

function TNativeMirrorElementScanReport.ToJson(Level: TNativeMirrorJsonLevel): TJSONObject;
begin
  Result := TJSONObject.Create;
  AddBaseJson(Result);
end;

constructor TNativeMirrorModuleScanReport.Create(ModuleBase: UInt64; ModuleSize: NativeUInt; Status: TNativeMirrorScanStatus);
begin
  inherited Create(Status);
  FModuleBase := ModuleBase;
  FModuleSize := ModuleSize;
  FIsDotNetModule := False;
  FOriginalBase := 0;
  FRelocBase := ModuleBase;
end;

procedure TNativeMirrorModuleScanReport.AddBaseJson(Json: TJSONObject);
begin
  inherited;
  if FModuleBase <> 0 then
  begin
    Json.AddPair('module', HexValue(FModuleBase));
    if FModuleSize <> 0 then
      Json.AddPair('module_size', HexValue(FModuleSize));
  end;
  if (FRelocBase <> 0) and (FRelocBase <> FModuleBase) then
    Json.AddPair('reloc_base', HexValue(FRelocBase));
  if FModuleFile <> '' then
    Json.AddPair('module_file', FModuleFile);
  if FIsDotNetModule then
    Json.AddPair('is_dot_net', '1');
end;

function TNativeMirrorModuleScanReport.JsonName: string;
begin
  if Self is TNativeMirrorMalformedHeaderReport then
    Exit('malformed_header');
  case ReportType of
    nmReportMappingScan: Result := 'mapping_scan';
    nmReportHeadersScan: Result := 'headers_scan';
    nmReportCodeScan: Result := 'code_scan';
    nmReportMemPageScan, nmReportArtefactScan: Result := 'workingset_scan';
    nmReportUnreachableScan: Result := 'unreachable_scan';
    nmReportSkippedScan: Result := 'skipped_scan';
    nmReportIatScan: Result := 'iat_scan';
    nmReportThreadsScan: Result := 'thread_scan';
  else
    Result := '';
  end;
end;

function TNativeMirrorModuleScanReport.ToJson(Level: TNativeMirrorJsonLevel): TJSONObject;
var
  Details: TJSONObject;
  Name: string;
begin
  Details := inherited ToJson(Level);
  Name := JsonName;
  if Name = '' then
    Exit(Details);
  Result := TJSONObject.Create;
  Result.AddPair(Name, Details);
end;

function TNativeMirrorModuleScanReport.ReportType: TNativeMirrorScanReportType;
begin
  Result := nmReportUnknown;
end;

function TNativeMirrorModuleScanReport.GetRelocBase: UInt64;
begin
  Result := FModuleBase;
end;

constructor TNativeMirrorUnreachableModuleReport.Create(ModuleBase: UInt64; ModuleSize: NativeUInt; const ModuleFile: string);
begin
  inherited Create(ModuleBase, ModuleSize, NM_SCAN_ERROR);
  Self.ModuleFile := ModuleFile;
end;

function TNativeMirrorUnreachableModuleReport.ReportType: TNativeMirrorScanReportType;
begin
  Result := nmReportUnreachableScan;
end;

constructor TNativeMirrorSkippedModuleReport.Create(ModuleBase: UInt64; ModuleSize: NativeUInt; const ModuleFile: string);
begin
  inherited Create(ModuleBase, ModuleSize, NM_SCAN_NOT_SUSPICIOUS);
  Self.ModuleFile := ModuleFile;
end;

function TNativeMirrorSkippedModuleReport.ReportType: TNativeMirrorScanReportType;
begin
  Result := nmReportSkippedScan;
end;

constructor TNativeMirrorMalformedHeaderReport.Create(ModuleBase: UInt64; ModuleSize: NativeUInt; const ModuleFile: string);
begin
  inherited Create(ModuleBase, ModuleSize, NM_SCAN_SUSPICIOUS);
  Self.ModuleFile := ModuleFile;
end;

function TNativeMirrorModuleScanReport.GenerateTags(const ReportPath: string): NativeUInt;
begin
  Result := 0;
end;

end.
