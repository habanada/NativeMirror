{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-License-Identifier: BSD-2-Clause

  This file contains tests for NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

program NativeMirrorHollowsHunterTests;

{$APPTYPE CONSOLE}
{$STRONGLINKTYPES ON}

uses
  Winapi.Windows,
  System.SysUtils,
  DUnitX.Loggers.Console,
  DUnitX.TestFramework,
  NativeMirror.Tests.Support in '..\ScannerIntegration\Source\NativeMirror.Tests.Support.pas',
  NativeMirror.Tests.HollowsHunter in 'Source\NativeMirror.Tests.HollowsHunter.pas';

var
  Runner: ITestRunner;
  Results: IRunResults;
  Logger: ITestLogger;
begin
  SetErrorMode(SEM_FAILCRITICALERRORS or SEM_NOGPFAULTERRORBOX);
  try
    Writeln('NativeMirror HollowsHunterIntegration: Delphi runner 2026-10-17.1');
    TDUnitX.CheckCommandLine;
    Runner := TDUnitX.CreateRunner;
    Runner.UseRTTI := True;
    Runner.FailsOnNoAsserts := True;
    Logger := TDUnitXConsoleLogger.Create(True);
    Runner.AddLogger(Logger);
    Results := Runner.Execute;
    if not Results.AllPassed then System.ExitCode := 1;
  except
    on E: Exception do
    begin
      Writeln(E.ClassName + ': ' + E.Message);
      System.ExitCode := 2;
    end;
  end;
end.
