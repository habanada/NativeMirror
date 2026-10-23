{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

program NativeMirrorScan;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  System.StrUtils,
  System.JSON,
  Winapi.Windows,
  NativeMirror.Adapters.Streams in '..\..\src\Adapters\NativeMirror.Adapters.Streams.pas',
  NativeMirror.Core.Buffer in '..\..\src\Core\NativeMirror.Core.Buffer.pas',
  NativeMirror.Core.Engine in '..\..\src\Core\NativeMirror.Core.Engine.pas',
  NativeMirror.Core.Memory in '..\..\src\Core\NativeMirror.Core.Memory.pas',
  NativeMirror.Core.Options in '..\..\src\Core\NativeMirror.Core.Options.pas',
  NativeMirror.Core.Paths in '..\..\src\Core\NativeMirror.Core.Paths.pas',
  NativeMirror.Core.PeValidation in '..\..\src\Core\NativeMirror.Core.PeValidation.pas',
  NativeMirror.Core.Text in '..\..\src\Core\NativeMirror.Core.Text.pas',
  NativeMirror.Core.Types in '..\..\src\Core\NativeMirror.Core.Types.pas',
  NativeMirror.Dumper.Imports.Blocks in '..\..\src\Dumper\Imports\NativeMirror.Dumper.Imports.Blocks.pas',
  NativeMirror.Dumper.Imports.Finder in '..\..\src\Dumper\Imports\NativeMirror.Dumper.Imports.Finder.pas',
  NativeMirror.Dumper.Imports.Reconstructor in '..\..\src\Dumper\Imports\NativeMirror.Dumper.Imports.Reconstructor.pas',
  NativeMirror.Dumper.Buffer in '..\..\src\Dumper\NativeMirror.Dumper.Buffer.pas',
  NativeMirror.Dumper.Engine in '..\..\src\Dumper\NativeMirror.Dumper.Engine.pas',
  NativeMirror.Dumper.Reconstructor in '..\..\src\Dumper\NativeMirror.Dumper.Reconstructor.pas',
  NativeMirror.Dumper.Reports in '..\..\src\Dumper\NativeMirror.Dumper.Reports.pas',
  NativeMirror.Layer.Lde in '..\..\src\Layer\NativeMirror.Layer.Lde.pas',
  NativeMirror.Layer.NativeAsm in '..\..\src\Layer\NativeMirror.Layer.NativeAsm.pas',
  NativeMirror.Layer in '..\..\src\Layer\NativeMirror.Layer.pas',
  NativeMirror.Platform.Enumeration in '..\..\src\Platform\NativeMirror.Platform.Enumeration.pas',
  NativeMirror.Platform.MiniDump in '..\..\src\Platform\NativeMirror.Platform.MiniDump.pas',
  NativeMirror.Platform.Paths in '..\..\src\Platform\NativeMirror.Platform.Paths.pas',
  NativeMirror.Platform.Process in '..\..\src\Platform\NativeMirror.Platform.Process.pas',
  NativeMirror.Platform.Reflection in '..\..\src\Platform\NativeMirror.Platform.Reflection.pas',
  NativeMirror.Platform.Symbols in '..\..\src\Platform\NativeMirror.Platform.Symbols.pas',
  NativeMirror.Platform.Syscalls in '..\..\src\Platform\NativeMirror.Platform.Syscalls.pas',
  NativeMirror.Platform.Threads in '..\..\src\Platform\NativeMirror.Platform.Threads.pas',
  NativeMirror.Scanner.Artefacts in '..\..\src\Scanner\NativeMirror.Scanner.Artefacts.pas',
  NativeMirror.Scanner.Code in '..\..\src\Scanner\NativeMirror.Scanner.Code.pas',
  NativeMirror.Scanner.Headers in '..\..\src\Scanner\NativeMirror.Scanner.Headers.pas',
  NativeMirror.Scanner.HookTargets in '..\..\src\Scanner\NativeMirror.Scanner.HookTargets.pas',
  NativeMirror.Scanner.IAT in '..\..\src\Scanner\NativeMirror.Scanner.IAT.pas',
  NativeMirror.Scanner.Mapping in '..\..\src\Scanner\NativeMirror.Scanner.Mapping.pas',
  NativeMirror.Scanner.MemPage in '..\..\src\Scanner\NativeMirror.Scanner.MemPage.pas',
  NativeMirror.Scanner.ModuleCache in '..\..\src\Scanner\NativeMirror.Scanner.ModuleCache.pas',
  NativeMirror.Scanner.ModuleData in '..\..\src\Scanner\NativeMirror.Scanner.ModuleData.pas',
  NativeMirror.Scanner.Modules in '..\..\src\Scanner\NativeMirror.Scanner.Modules.pas',
  NativeMirror.Scanner.PatchAnalyzer in '..\..\src\Scanner\NativeMirror.Scanner.PatchAnalyzer.pas',
  NativeMirror.Scanner.Patches in '..\..\src\Scanner\NativeMirror.Scanner.Patches.pas',
  NativeMirror.Scanner.Patterns in '..\..\src\Scanner\NativeMirror.Scanner.Patterns.pas',
  NativeMirror.Scanner.PeSection in '..\..\src\Scanner\NativeMirror.Scanner.PeSection.pas',
  NativeMirror.Scanner.ProcessDetails in '..\..\src\Scanner\NativeMirror.Scanner.ProcessDetails.pas',
  NativeMirror.Scanner.ProcessReport in '..\..\src\Scanner\NativeMirror.Scanner.ProcessReport.pas',
  NativeMirror.Scanner.ProcessScanner in '..\..\src\Scanner\NativeMirror.Scanner.ProcessScanner.pas',
  NativeMirror.Scanner.Reports in '..\..\src\Scanner\NativeMirror.Scanner.Reports.pas',
  NativeMirror.Scanner.Signatures in '..\..\src\Scanner\NativeMirror.Scanner.Signatures.pas',
  NativeMirror.Scanner.Threads in '..\..\src\Scanner\NativeMirror.Scanner.Threads.pas',
  NativeMirror.Scanner.WorkingSet in '..\..\src\Scanner\NativeMirror.Scanner.WorkingSet.pas',
  NativeMirror.Stats.Analyzer in '..\..\src\Stats\NativeMirror.Stats.Analyzer.pas',
  NativeMirror.Cli in '..\..\src\NativeMirror.Cli.pas',
  NativeMirrorScan.Tool in '..\..\src\NativeMirrorScan.Tool.pas',
  NativeMirror.Stats.Core in '..\..\src\Stats\NativeMirror.Stats.Core.pas';

function NativeMirrorPause(Command: PWideChar): Integer; cdecl;
  external 'msvcrt.dll' name '_wsystem';

var
  Tool: TNativeMirrorScanTool;
  ExitCode_: Integer;
begin
  Tool := TNativeMirrorScanTool.Create;
  try
    Tool.OnMessage :=
      procedure(Sender: TObject; Kind: TNativeMirrorScanMessageKind; const Text: string)
      begin
        if Kind = nmScanTiming then Exit;
        if Kind = nmScanError then
        begin
          Write(ErrOutput, Text);
          if not Text.EndsWith(sLineBreak) then Writeln(ErrOutput);
        end
        else
        begin
          Write(Text);
          if not Text.EndsWith(sLineBreak) then Writeln;
        end;
      end;
    ExitCode_ := Tool.RunCommandLine;
  finally
    Tool.Free;
  end;
  if ParamCount = 0 then
  begin
    Flush(Output);
    NativeMirrorPause('pause');
  end;
  System.Halt(ExitCode_);
end.
