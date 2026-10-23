{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Core.Options;

interface

uses
  Winapi.Windows,
  NativeMirror.Core.Types;

type
  TNativeMirrorOptions = record
    Pid: DWORD;
    DotNetPolicy: TNativeMirrorDotNetPolicy;
    ImportRecoveryMode: TNativeMirrorImportRecoveryMode;
    Quiet: Boolean;
    OutputFilter: TNativeMirrorOutputFilter;
    NoHooks: Boolean;
    ShellcodeMode: TNativeMirrorShellcodeMode;
    ObfuscationMode: TNativeMirrorObfuscationMode;
    ScanThreads: Boolean;
    IatScanMode: TNativeMirrorIatScanMode;
    DataScanMode: TNativeMirrorDataScanMode;
    MakeMiniDump: Boolean;
    Rebase: Boolean;
    DumpMode: TNativeMirrorDumpMode;
    JsonOutput: Boolean;
    MakeReflection: Boolean;
    UseCache: Boolean;
    DownloadSymbols: Boolean;
    JsonLevel: TNativeMirrorJsonLevel;
    ResultsFilter: TNativeMirrorResultsFilter;
    OutputDirectory: string;
    IgnoredModules: string;
    PatternFile: string;
    class function Default: TNativeMirrorOptions; static;
  end;

implementation

class function TNativeMirrorOptions.Default: TNativeMirrorOptions;
begin
  Result.Pid := 0;
  Result.DotNetPolicy := nmDotNetNone;
  Result.ImportRecoveryMode := nmImportNone;
  Result.Quiet := False;
  Result.OutputFilter := nmOutFull;
  Result.NoHooks := False;
  Result.ShellcodeMode := nmShellcodeNone;
  Result.ObfuscationMode := nmObfuscationNone;
  Result.ScanThreads := False;
  Result.IatScanMode := nmIatNone;
  Result.DataScanMode := nmDataNoScan;
  Result.MakeMiniDump := False;
  Result.Rebase := False;
  Result.DumpMode := nmDumpAuto;
  Result.JsonOutput := False;
  Result.MakeReflection := False;
  Result.UseCache := False;
  Result.DownloadSymbols := False;
  Result.JsonLevel := nmJsonBasic;
  Result.ResultsFilter := NM_SHOW_SUSPICIOUS;
  Result.OutputDirectory := '';
  Result.IgnoredModules := '';
  Result.PatternFile := '';
end;

end.
