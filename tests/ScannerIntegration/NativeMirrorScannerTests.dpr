{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-License-Identifier: BSD-2-Clause

  This file contains tests for NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

program NativeMirrorScannerTests;

{$APPTYPE CONSOLE}
{$STRONGLINKTYPES ON}

uses
  System.SysUtils,
  DUnitX.Loggers.Console,
  DUnitX.TestFramework,
  NativeMirror.Tests.Support in 'Source\NativeMirror.Tests.Support.pas',
  NativeMirror.Tests.Integration in 'Source\NativeMirror.Tests.Integration.pas',
  NativeMirror.Tests.Parity in 'Source\NativeMirror.Tests.Parity.pas';

var
  Runner: ITestRunner;
  Results: IRunResults;
  Logger: ITestLogger;
begin
  try
    if (ParamCount > 0) and (ParamStr(1) = '--thread-probe') then
    begin
      if ParamCount <> 2 then Halt(2);
      Halt(RunNativeMirrorThreadProbe(StrToInt(ParamStr(2))));
    end;
    if (ParamCount > 0) and (ParamStr(1) = '--pattern-probe') then
    begin
      if ParamCount <> 4 then Halt(2);
      Halt(RunNativeMirrorPatternProbe(ParamStr(2), ParamStr(3), ParamStr(4)));
    end;
    Writeln('NativeMirror ScannerIntegration build: 2026-10-02.6-diag');
    TScannerHarness.ResetDiagnostics;
    Writeln('Diagnostics: ' + TScannerHarness.DiagnosticsPath);
    TDUnitX.CheckCommandLine;
    Runner := TDUnitX.CreateRunner;
    Runner.UseRTTI := True;
    Runner.FailsOnNoAsserts := True;
    Logger := TDUnitXConsoleLogger.Create(True);
    Runner.AddLogger(Logger);
    Results := Runner.Execute;
    if not Results.AllPassed then
      System.ExitCode := 1;
  except
    on E: Exception do
    begin
      Writeln(E.ClassName + ': ' + E.Message);
      System.ExitCode := 2;
    end;
  end;
end.
