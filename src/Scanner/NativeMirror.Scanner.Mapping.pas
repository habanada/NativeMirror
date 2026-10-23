{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Scanner.Mapping;

interface

uses
  System.JSON,
  NativeMirror.Core.Types,
  NativeMirror.Scanner.Reports,
  NativeMirror.Scanner.ModuleData;

type
  TNativeMirrorMappingScanReport = class(TNativeMirrorModuleScanReport)
  private
    FMappedFile: string;
  protected
    procedure AddBaseJson(Json: TJSONObject); override;
  public
    function ReportType: TNativeMirrorScanReportType; override;
    property MappedFile: string read FMappedFile write FMappedFile;
  end;

  TNativeMirrorMappingScanner = class
  private
    FModuleData: TNativeMirrorModuleData;
    FRemoteData: TNativeMirrorRemoteModuleData;
  public
    constructor Create(ModuleData: TNativeMirrorModuleData); overload;
    constructor Create(ModuleData: TNativeMirrorModuleData; RemoteData: TNativeMirrorRemoteModuleData); overload;
    function ScanRemote: TNativeMirrorMappingScanReport;
  end;

implementation

uses
  System.SysUtils,
  NativePe.PeHdrsHelper,
  NativeMirror.Platform.Paths;

procedure TNativeMirrorMappingScanReport.AddBaseJson(Json: TJSONObject);
begin
  inherited;
  Json.AddPair('mapped_file', FMappedFile);
end;

function TNativeMirrorMappingScanReport.ReportType: TNativeMirrorScanReportType;
begin
  Result := nmReportMappingScan;
end;

constructor TNativeMirrorMappingScanner.Create(ModuleData: TNativeMirrorModuleData);
begin
  inherited Create;
  FModuleData := ModuleData;
  FRemoteData := nil;
end;

constructor TNativeMirrorMappingScanner.Create(ModuleData: TNativeMirrorModuleData; RemoteData: TNativeMirrorRemoteModuleData);
begin
  inherited Create;
  FModuleData := ModuleData;
  FRemoteData := RemoteData;
end;

function TNativeMirrorMappingScanner.ScanRemote: TNativeMirrorMappingScanReport;
var
  MappedName: string;
  ModuleName: string;
  Wow64Name: string;
  IsSame: Boolean;
  IsFilled: Boolean;
begin
  Result := TNativeMirrorMappingScanReport.Create(FModuleData.ModuleBase, FModuleData.OriginalSize);
  if FRemoteData <> nil then
    MappedName := FRemoteData.GetMappedName
  else
    MappedName := TNativeMirrorRemoteModuleData.QueryMappedName(FModuleData.ProcessHandle, FModuleData.ModuleBase);
  ModuleName := FModuleData.ModuleName;
  IsSame := SameText(MappedName, ModuleName);
  Result.MappedFile := MappedName;
  Result.ModuleFile := ModuleName;
  if not IsSame and (ModuleName <> '') then
  begin
    Wow64Name := ConvertToWow64Path(ModuleName);
    IsSame := SameText(MappedName, Wow64Name);
    if IsSame then
      FModuleData.SwitchToWow64Path;
  end;
  if IsSame then
  begin
    Result.Status := NM_SCAN_NOT_SUSPICIOUS;
    Exit;
  end;
  IsFilled := FModuleData.LoadOriginal;
  if not IsFilled then
  begin
    FModuleData.SwitchToMappedPath;
    IsFilled := FModuleData.LoadOriginal;
  end;
  if IsFilled then
  begin
    Result.IsDotNetModule := FModuleData.IsDotNet;
    Result.OriginalBase := GetImageBase(FModuleData.OriginalModule);
  end;
  Result.Status := NM_SCAN_SUSPICIOUS;
end;

end.
