{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Scanner.HookTargets;

interface

uses
  NativeMirror.Scanner.ProcessReport,
  NativeMirror.Scanner.Patches;

type
  TNativeMirrorHookTargetResolver = class
  private
    FProcessReport: TNativeMirrorProcessScanReport;
  public
    constructor Create(ProcessReport: TNativeMirrorProcessScanReport);
    function ResolveTarget(Patch: TNativeMirrorPatch): Boolean;
    function ResolveAll: NativeUInt;
  end;

implementation

uses
  System.SysUtils,
  NativePe.ExportedFunc,
  NativeMirror.Scanner.Code,
  NativeMirror.Scanner.Reports,
  NativeMirror.Scanner.Modules;

constructor TNativeMirrorHookTargetResolver.Create(ProcessReport: TNativeMirrorProcessScanReport);
begin
  inherited Create;
  FProcessReport := ProcessReport;
end;

function TNativeMirrorHookTargetResolver.ResolveTarget(Patch: TNativeMirrorPatch): Boolean;
var
  Module: TNativeMirrorScannedModule;
  Func: TExportedFunc;
  Name: string;
begin
  Result := False;
  if (Patch = nil) or (Patch.HookTargetVa = 0) or (FProcessReport = nil) then
    Exit;
  Module := FProcessReport.GetModuleContaining(Patch.HookTargetVa);
  if Module = nil then
    Exit;
  Name := Module.ModuleName;
  Func := nil;
  if FProcessReport.ExportsMap <> nil then
    Func := FProcessReport.ExportsMap.FindExportByVa(Patch.HookTargetVa);
  if Func <> nil then
    Name := Name + '.' + Func.NameToString;
  Result := Patch.SetHookTargetInfo(Module.Start, Module.Suspicious, Name);
end;

function TNativeMirrorHookTargetResolver.ResolveAll: NativeUInt;
var
  Report: TNativeMirrorModuleScanReport;
  CodeReport: TNativeMirrorCodeScanReport;
  Patch: TNativeMirrorPatch;
begin
  Result := 0;
  if FProcessReport = nil then
    Exit;
  for Report in FProcessReport.Reports do
    if Report is TNativeMirrorCodeScanReport then
    begin
      CodeReport := TNativeMirrorCodeScanReport(Report);
      for Patch in CodeReport.Patches.Patches do
        if ResolveTarget(Patch) then
          Inc(Result);
    end;
end;

end.
