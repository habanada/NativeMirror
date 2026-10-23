program NativeMirrorScan;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  System.Diagnostics,
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
  NativeMirror.Stats.Core in '..\..\src\Stats\NativeMirror.Stats.Core.pas';

procedure PrintHelp;
begin
  Writeln('NativeMirrorScan  ', NativeMirrorInfo);
  Writeln('Usage:  NativeMirrorScan /pid:<PID> [options]');
  Writeln;
  Writeln('Scan options:');
  Writeln('  /pid:<N>       Target PID (required)');
  Writeln('  /threads       Scan thread callstacks (sleeping beacon detection)');
  Writeln('  /refl          Make process reflection before scan');
  Writeln('  /sym           Auto-download symbols for scanned modules');
  Writeln('  /iat:<N>       IAT scan mode  0=off 1=clean-sys 2=all-sys 3=unfiltered');
  Writeln('  /shellc:<N>    Shellcode mode 0=off 1=patterns 2=stats 3=patterns-or-stats 4=patterns-and-stats');
  Writeln('  /obfusc:<N>    Obfuscation    0=off 1=strong 2=weak 3=any');
  Writeln('  /data:<N>      Data scan mode 0=off 1=dotnet 2=no-dep 3=always 4=inaccessible 5=inaccessible-only');
  Writeln('  /dnet:<N>      .NET policy    0=none 1=skip-map 2=skip-shc 3=skip-hooks 4=skip-all');
  Writeln('  /mignore:<m>   Semicolon-separated list of modules to ignore');
  Writeln('  /pattern:<f>   SIG pattern file for additional shellcode patterns');
  Writeln;
  Writeln('Dump options:');
  Writeln('  /dir:<path>    Output directory (default: current dir)');
  Writeln('  /dmode:<N>     Dump mode      0=auto 1=virtual 2=unmap 3=realign');
  Writeln('  /imp:<N>       Import rec.    0=none 1=auto 2=unerase 3=r0 4=r1 5=r2');
  Writeln('  /rebase        Rebase to original image base if known');
  Writeln('  /minidmp       Create full minidump when suspicious modules found');
  Writeln('  /ofilter:<N>   Output filter  0=full 1=no-dumps 2=no-dir');
  Writeln;
  Writeln('Output options:');
  Writeln('  /quiet         Print only the summary');
  Writeln('  /json          Print JSON summary');
  Writeln('  /jlvl:<N>      JSON detail level  0=basic 1=details 2=details2');
  Writeln('  /report:<N>    Results filter bitmask 1=errors 2=not-suspicious 4=suspicious 5=suspicious+errors 7=all');
end;

function ParamValue(const Args: TArray<string>; const Name: string;
  out Value: string): Boolean;
var
  Arg: string;
  Prefix: string;
begin
  Prefix := '/' + Name.ToLower + ':';
  for Arg in Args do
    if Arg.ToLower.StartsWith(Prefix) then
    begin
      Value := Copy(Arg, Length(Prefix) + 1, MaxInt);
      Exit(True);
    end;
  Result := False;
end;

function HasFlag(const Args: TArray<string>; const Name: string): Boolean;
var
  Arg: string;
begin
  for Arg in Args do
    if SameText(Arg, '/' + Name) or SameText(Arg, '--' + Name) then
      Exit(True);
  Result := False;
end;

function IntParamOr(const Args: TArray<string>; const Name: string; Default, MinValue, MaxValue: Integer): Integer;
var
  Val: string;
  Parsed: Int64;
begin
  if not ParamValue(Args, Name, Val) then Exit(Default);
  if not TryStrToInt64(Val, Parsed) or (Parsed < MinValue) or (Parsed > MaxValue) then
  begin
    Writeln(Format('[ERROR] Invalid /%s value: %s', [Name, Val]));
    System.Halt(255);
  end;
  Result := Integer(Parsed);
end;

procedure PrintSummary(Report: TNativeMirrorReportEx; const Options: TNativeMirrorOptions);
var
  Summary: TNativeMirrorProcessSummary;
  Json: TJSONObject;
begin
  if Options.JsonOutput then
  begin
    Json := Report.ToJson(Options.ResultsFilter, Options.JsonLevel);
    try
      Writeln(Json.ToJSON);
    finally
      Json.Free;
    end;
    Exit;
  end;
  if not Assigned(Report.ScanReport) then
  begin
    if Assigned(Report.ErrorReport) then
      Writeln('[ERROR] ', Report.ErrorReport.Message);
    Exit;
  end;
  Summary := Report.ScanReport.GenerateSummary;
  Writeln('---');
    Writeln(Format('PID:       %d', [Summary.Pid]));
    Writeln(Format('Scanned:   %d', [Summary.Scanned]));
    Writeln(Format('Suspicious:%d', [Summary.Suspicious]));
    Writeln(Format('Errors:    %d', [Summary.Errors]));
    if Assigned(Report.DumpReport) then
    begin
      Writeln(Format('Dumped:    %d', [Report.DumpReport.CountDumped]));
      if Report.DumpReport.OutputDirectory <> '' then
        Writeln('Output:    ', Report.DumpReport.OutputDirectory);
      if Report.DumpReport.MiniDumpPath <> '' then
        Writeln('Minidump:  ', Report.DumpReport.MiniDumpPath);
    end;
end;

var
  Args: TArray<string>;
  Options: TNativeMirrorOptions;
  I: Integer;
  Val: string;
  Report: TNativeMirrorReportEx;
  ExitCode_: Integer;
  PidValue: Int64;
  Timer: TStopwatch;
begin
  ExitCode_ := -1;
  SetLength(Args, ParamCount);
  for I := 1 to ParamCount do
    Args[I - 1] := ParamStr(I);

  if (ParamCount = 0) or HasFlag(Args, 'help') or HasFlag(Args, '?') then
  begin
    PrintHelp;
    System.Halt(0);
  end;

  Options := TNativeMirrorOptions.Default;

  if not ParamValue(Args, 'pid', Val) then
  begin
    Writeln('[ERROR] /pid:<N> is required.');
    PrintHelp;
    System.Halt(255);
  end;
  if not TryStrToInt64(Val, PidValue) or (PidValue <= 0) or (PidValue > High(DWORD)) then
  begin
    Writeln('[ERROR] Invalid PID.');
    System.Halt(255);
  end;
  Options.Pid := DWORD(PidValue);

  Options.ScanThreads := HasFlag(Args, 'threads');
  Options.MakeReflection := HasFlag(Args, 'refl');
  Options.DownloadSymbols := HasFlag(Args, 'sym');
  Options.Rebase := HasFlag(Args, 'rebase');
  Options.MakeMiniDump := HasFlag(Args, 'minidmp');
  Options.Quiet := HasFlag(Args, 'quiet');
  Options.JsonOutput := HasFlag(Args, 'json');

  Options.IatScanMode := TNativeMirrorIatScanMode(IntParamOr(Args, 'iat', Ord(Options.IatScanMode), Ord(Low(TNativeMirrorIatScanMode)), Ord(High(TNativeMirrorIatScanMode))));
  Options.ShellcodeMode := TNativeMirrorShellcodeMode(IntParamOr(Args, 'shellc', Ord(Options.ShellcodeMode), Ord(Low(TNativeMirrorShellcodeMode)), Ord(High(TNativeMirrorShellcodeMode))));
  Options.ObfuscationMode := TNativeMirrorObfuscationMode(IntParamOr(Args, 'obfusc', Ord(Options.ObfuscationMode), Ord(Low(TNativeMirrorObfuscationMode)), Ord(High(TNativeMirrorObfuscationMode))));
  Options.DataScanMode := TNativeMirrorDataScanMode(IntParamOr(Args, 'data', Ord(Options.DataScanMode), Ord(Low(TNativeMirrorDataScanMode)), Ord(High(TNativeMirrorDataScanMode))));
  Options.DotNetPolicy := TNativeMirrorDotNetPolicy(IntParamOr(Args, 'dnet', Ord(Options.DotNetPolicy), Ord(Low(TNativeMirrorDotNetPolicy)), Ord(High(TNativeMirrorDotNetPolicy))));
  Options.DumpMode := TNativeMirrorDumpMode(IntParamOr(Args, 'dmode', Ord(Options.DumpMode), Ord(Low(TNativeMirrorDumpMode)), Ord(High(TNativeMirrorDumpMode))));
  Options.ImportRecoveryMode := TNativeMirrorImportRecoveryMode(IntParamOr(Args, 'imp', Ord(Options.ImportRecoveryMode), Ord(Low(TNativeMirrorImportRecoveryMode)), Ord(High(TNativeMirrorImportRecoveryMode))));
  Options.OutputFilter := TNativeMirrorOutputFilter(IntParamOr(Args, 'ofilter', Ord(Options.OutputFilter), Ord(Low(TNativeMirrorOutputFilter)), Ord(High(TNativeMirrorOutputFilter))));
  Options.JsonLevel := TNativeMirrorJsonLevel(IntParamOr(Args, 'jlvl', Ord(Options.JsonLevel), Ord(Low(TNativeMirrorJsonLevel)), Ord(High(TNativeMirrorJsonLevel))));
  Options.ResultsFilter := TNativeMirrorResultsFilter(IntParamOr(Args, 'report', Integer(Options.ResultsFilter), Integer(NM_SHOW_NONE), Integer(NM_SHOW_ALL)));

  if ParamValue(Args, 'dir', Val) then Options.OutputDirectory := Val;
  if ParamValue(Args, 'mignore', Val) then Options.IgnoredModules := Val;
  if ParamValue(Args, 'pattern', Val) then Options.PatternFile := Val;

  if Options.DataScanMode in [nmDataInaccessible, nmDataInaccessibleOnly] then
    if not Options.MakeReflection then
    begin
      Options.MakeReflection := True;
      if not Options.Quiet then
        Writeln('[WARNING] Inaccessible page scan: reflection mode auto-enabled.');
    end;

  if not Options.Quiet then
  begin
    Writeln(NativeMirrorInfo);
    Writeln(Format('PID: %d', [Options.Pid]));
    if Options.MakeReflection then Writeln('Mode: reflection');
    if Options.ScanThreads then Writeln('Thread scan: on');
  end;

  Timer := TStopwatch.StartNew;
  Writeln('[TIME] Scan started');
  Report := ScanAndDump(Options);
  Timer.Stop;
  Writeln(Format('[TIME] Total scan: %d ms', [Timer.ElapsedMilliseconds]));
  try
    PrintSummary(Report, Options);
    if Assigned(Report.ScanReport) then
    begin
      var Summary := Report.ScanReport.GenerateSummary;
      if Summary.Scanned > 0 then
      begin
        if Summary.Suspicious > 0 then ExitCode_ := 2 else ExitCode_ := 1;
      end
      else
        ExitCode_ := -1;
    end
    else
      ExitCode_ := -1;
  finally
    Report.Free;
  end;
  System.Halt(ExitCode_);
end.
