{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-License-Identifier: BSD-2-Clause

  This file contains tests for NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

program NativeMirrorTestTarget32;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  NativeMirror.Tests.Target in 'Source\NativeMirror.Tests.Target.pas';

begin
  try
    RunNativeMirrorTestTarget;
  except
    on E: Exception do
    begin
      Writeln(E.ClassName + ': ' + E.Message);
      System.Halt(2);
    end;
  end;
end.
