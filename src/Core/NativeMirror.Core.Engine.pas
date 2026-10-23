{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Core.Engine;

interface

uses
  Winapi.Windows,
  System.JSON,
  NativeMirror.Core.Types,
  NativeMirror.Core.Options,
  NativeMirror.Scanner.ProcessReport,
  NativeMirror.Dumper.Reports;

type
  TNativeMirrorEngineMessageKind = (nmEngineInfo, nmEngineWarning, nmEngineError);
  TNativeMirrorEngineMessageEvent = reference to procedure(Kind: TNativeMirrorEngineMessageKind; const Text: string);

  TNativeMirrorErrorReport = class
  public
    Pid: DWORD;
    Message: string;
    constructor Create(APid: DWORD; const AMessage: string);
    function ToJson: TJSONObject;
  end;

  TNativeMirrorReportEx = class
  public
    ScanReport: TNativeMirrorProcessScanReport;
    DumpReport: TNativeMirrorProcessDumpReport;
    ErrorReport: TNativeMirrorErrorReport;
    constructor Create;
    destructor Destroy; override;
    function ToJson(Filter: TNativeMirrorResultsFilter; Level: TNativeMirrorJsonLevel; OutputKind: TNativeMirrorReportOutput = nmReportAll): TJSONObject;
  end;

function ScanAndDump(const Options: TNativeMirrorOptions): TNativeMirrorReportEx; overload;
function ScanAndDump(const Options: TNativeMirrorOptions; const OnMessage: TNativeMirrorEngineMessageEvent): TNativeMirrorReportEx; overload;
function NativeMirrorInfo: string;

implementation

uses
  System.SysUtils,
  NativeMirror.Core.Paths,
  NativeMirror.Core.Memory,
  NativeMirror.Platform.Process,
  NativeMirror.Platform.Paths,
  NativeMirror.Platform.Reflection,
  NativeMirror.Platform.MiniDump,
  NativeMirror.Scanner.ProcessScanner,
  NativeMirror.Scanner.Signatures,
  NativeMirror.Dumper.Engine,
  NativeMirror.Layer,
  NativeMirror.Layer.Lde
{$IFDEF USE_NATIVEASM}
{$IFDEF WIN64}
  , NativeMirror.Layer.NativeAsm
{$ENDIF}
{$ENDIF}
  ;

const
  BasicAccess      = SYNCHRONIZE or PROCESS_VM_READ or PROCESS_QUERY_INFORMATION;
  ReflAccess1      = PROCESS_CREATE_THREAD or PROCESS_VM_OPERATION or PROCESS_DUP_HANDLE;
  ReflAccess2      = ReflAccess1 or PROCESS_CREATE_PROCESS;
  ProcessQueryLimitedInformation = DWORD($1000);
  NativeMirrorVersion = '0.1.0';

{ TNativeMirrorErrorReport }

constructor TNativeMirrorErrorReport.Create(APid: DWORD; const AMessage: string);
begin
  inherited Create;
  Pid := APid;
  Message := AMessage;
end;

function TNativeMirrorErrorReport.ToJson: TJSONObject;
begin
  Result := TJSONObject.Create;
  Result.AddPair('pid', TJSONNumber.Create(Pid));
  Result.AddPair('err_message', Message);
end;

{ TNativeMirrorReportEx }

constructor TNativeMirrorReportEx.Create;
begin
  inherited Create;
  ScanReport := nil;
  DumpReport := nil;
  ErrorReport := nil;
end;

destructor TNativeMirrorReportEx.Destroy;
begin
  ScanReport.Free;
  DumpReport.Free;
  ErrorReport.Free;
  inherited;
end;

function TNativeMirrorReportEx.ToJson(Filter: TNativeMirrorResultsFilter; Level: TNativeMirrorJsonLevel; OutputKind: TNativeMirrorReportOutput): TJSONObject;
begin
  Result := TJSONObject.Create;
  if Assigned(ErrorReport) and ((Filter and NM_SHOW_ERRORS) <> 0) then
  begin
    Result.AddPair('error_report', ErrorReport.ToJson);
    Exit;
  end;
  if Assigned(ScanReport) and (OutputKind in [nmReportScanned, nmReportAll]) then
    Result.AddPair('scan_report', ScanReport.ToJson(Filter, Level));
  if Assigned(DumpReport) and (OutputKind in [nmReportDumped, nmReportAll]) and ((DumpReport.CountDumped > 0) or (OutputKind = nmReportDumped)) then
    Result.AddPair('dump_report', DumpReport.ToJson);
end;

function IsScannerCompatible(hProcess: THandle): Boolean;
var
  ScannerWow64, ProcessWow64: Boolean;
begin
  ScannerWow64 := IsCurrentWow64;
  IsProcessWow64(hProcess, ProcessWow64);
  Result := not (ScannerWow64 and not ProcessWow64);
end;

function TryOpenProcess(Pid: DWORD; MakeReflection: Boolean): THandle;
var
  Access: DWORD;
begin
  Access := BasicAccess;
  if MakeReflection then
    Access := Access or ReflAccess2 or PROCESS_VM_OPERATION;
  Result := OpenProcess(Access, False, Pid);
  if (Result = 0) and MakeReflection then
  begin
    Result := OpenProcess(ReflAccess1, False, Pid);
    if Result = 0 then
      Result := OpenProcess(BasicAccess, False, Pid);
  end;
end;

function ExpandOutputDir(const Dir: string): string;
var
  Buf: array[0..MAX_PATH] of Char;
begin
  if Dir = '' then
  begin
    GetCurrentDirectory(MAX_PATH, Buf);
    Result := string(Buf);
  end
  else
  begin
    ExpandEnvironmentStrings(PChar(Dir), Buf, MAX_PATH);
    Result := string(Buf);
  end;
  Result := NormalizeModulePath(Result);
end;

function MakeDump(const Reader: INativeMirrorMemoryReader; IsRefl: Boolean;
  const Options: TNativeMirrorOptions;
  ProcessReport: TNativeMirrorProcessScanReport;
  const OnMessage: TNativeMirrorEngineMessageEvent): TNativeMirrorProcessDumpReport;
var
  Dumper: TNativeMirrorResultsDumper;
  Summary: TNativeMirrorProcessSummary;
  MiniPath: string;
  OutDir: string;
  Message: TNativeMirrorEngineMessageEvent;
begin
  Message := OnMessage;
  Result := nil;
  if (Reader = nil) or (Reader.ProcessHandle = 0) or (Options.OutputFilter = nmOutNoDir) then Exit;
  OutDir := ExpandOutputDir(Options.OutputDirectory);
  Dumper := TNativeMirrorResultsDumper.Create(OutDir, Options.Quiet);
  try
    Dumper.OnMessage :=
      procedure(const Text: string; IsError: Boolean)
      begin
        if IsError then Message(nmEngineError, Text)
        else Message(nmEngineInfo, Text);
      end;
    if Dumper.DumpJsonScanReport(ProcessReport, Options.ResultsFilter, Options.JsonLevel) and not Options.Quiet then
      OnMessage(nmEngineInfo, '[+] Report dumped to: ' + Dumper.OutputDir);
    if Options.OutputFilter <> nmOutNoDumps then
    begin
      Result := Dumper.DumpDetectedModules(
        Reader, IsRefl, ProcessReport,
        Options.DumpMode, Options.ImportRecoveryMode, Options.Rebase);
      if (Result <> nil) and (Result.CountDumped > 0) and not Options.Quiet then
        OnMessage(nmEngineInfo, '[+] Dumped modified to: ' + Dumper.OutputDir);
    end;
    if Options.MakeMiniDump then
    begin
      Summary := ProcessReport.GenerateSummary;
      if Summary.Suspicious > 0 then
      begin
        if not Options.Quiet then
          OnMessage(nmEngineInfo, '[*] Creating minidump...');
        MiniPath := Dumper.MakeOutPath(
          ExtractFileName(ProcessReport.MainImagePath) + '.dmp');
        if MakeMiniDump(ProcessReport.Pid, MiniPath) then
        begin
          if Result = nil then
            Result := TNativeMirrorProcessDumpReport.Create(ProcessReport.Pid);
          Result.MiniDumpPath := MiniPath;
          if not Options.Quiet then
            OnMessage(nmEngineInfo, '[+] Minidump saved to: ' + Result.MiniDumpPath);
        end
        else if not Options.Quiet then
          OnMessage(nmEngineInfo, '[-] Creating minidump failed! ');
      end;
    end;
    if Result <> nil then
    begin
      Result.OutputDirectory := Dumper.OutputDir;
      if Dumper.DumpJsonDumpReport(Result) and not Options.Quiet then
        OnMessage(nmEngineInfo, '[+] Report dumped to: ' + Dumper.OutputDir);
    end;
  finally
    Dumper.Free;
  end;
end;

function ScanAndDump(const Options: TNativeMirrorOptions): TNativeMirrorReportEx;
begin
  Result := ScanAndDump(Options, nil);
end;

function ScanAndDump(const Options: TNativeMirrorOptions; const OnMessage: TNativeMirrorEngineMessageEvent): TNativeMirrorReportEx;
var
  Report: TNativeMirrorReportEx;
  OrigHandle, TargetHandle, ProbeHandle: THandle;
  OpenError: DWORD;
  LoadedPatterns: NativeUInt;
  Refl: TNativeMirrorProcessReflection;
  IsRefl: Boolean;
  Scanner: TNativeMirrorProcessScanner;
  Reader: INativeMirrorMemoryReader;
  Disasm: IDisassembler;
  CodeGen: ICodeGen;
  ErrorDumper: TNativeMirrorResultsDumper;
  Message: TNativeMirrorEngineMessageEvent;
begin
  Message := OnMessage;
  if not Assigned(Message) then
    Message :=
      procedure(Kind: TNativeMirrorEngineMessageKind; const Text: string)
      begin
        if Kind = nmEngineError then Writeln(ErrOutput, Text)
        else Writeln(Text);
      end;
  Report := TNativeMirrorReportEx.Create;
  OrigHandle := 0;
  TargetHandle := 0;
  Refl := nil;
  IsRefl := False;
  if not SetDebugPrivilege and not Options.Quiet then
    Message(nmEngineError, '[-] Could not set debug privilege');
  LoadedPatterns := NativeMirrorInitializePatterns(Options.PatternFile,
    Options.ShellcodeMode in [nmShellcodePatterns, nmShellcodePatternsOrStats, nmShellcodePatternsAndStats],
    procedure(const Text: string; IsError: Boolean)
    begin
      if IsError then Message(nmEngineError, Text)
      else Message(nmEngineInfo, Text);
    end);
  if (Options.PatternFile <> '') and not Options.Quiet then
  begin
    if LoadedPatterns <> 0 then
      Message(nmEngineInfo, '[+] Pattern file loaded: ' + Options.PatternFile + ', Signs: ' + UIntToStr(LoadedPatterns))
    else
      Message(nmEngineError, '[-] Failed to load pattern file: ' + Options.PatternFile);
  end;
  try
    OrigHandle := TryOpenProcess(Options.Pid, Options.MakeReflection);
    if OrigHandle = 0 then
    begin
      OpenError := GetLastError;
      if OpenError = ERROR_ACCESS_DENIED then
      begin
        if not Options.Quiet then
        begin
          Message(nmEngineError, Format('[-][%d] Could not open the process Error: %d', [Options.Pid, OpenError]));
          ProbeHandle := OpenProcess(ProcessQueryLimitedInformation, False, Options.Pid);
          if ProbeHandle = 0 then
            Message(nmEngineError, '-> Access denied. Try to run the scanner as Administrator.')
          else
          begin
            try
              case GetProcessIntegrityLevel(ProbeHandle) of
                nmIntegrityUnknown: Message(nmEngineError, '-> Access denied. Could not query the process token.');
                nmIntegritySystem: Message(nmEngineError, '-> Access denied. Could not access the system process.');
              end;
            finally
              CloseHandle(ProbeHandle);
            end;
          end;
        end;
        SetLastError(OpenError);
        raise Exception.Create('Could not open the process: Access Denied');
      end;
      if OpenError = ERROR_INVALID_PARAMETER then
      begin
        if not Options.Quiet then Message(nmEngineError, '-> Is this process still running?');
        SetLastError(OpenError);
        raise Exception.Create('Could not open the process: Invalid Parameter');
      end;
      raise Exception.CreateFmt('Could not open process %d: Error %d', [Options.Pid, OpenError]);
    end;
    TargetHandle := OrigHandle;
    if Options.MakeReflection then
    begin
      Refl := MakeProcessReflection(OrigHandle);
      if Assigned(Refl) and (Refl.ReflHandle <> 0) then
        TargetHandle := Refl.ReflHandle
      else if not Options.Quiet then
        Message(nmEngineError, '[-] Failed to create the process reflection');
    end;
    IsRefl := Assigned(Refl) and (Refl.ReflHandle <> 0);
    if not Options.Quiet then
    begin
      if IsRefl then
        Message(nmEngineInfo, '[*] Using process reflection!')
      else
      begin
        Message(nmEngineInfo, '[*] Using raw process!');
        if Options.DataScanMode in [nmDataInaccessible, nmDataInaccessibleOnly] then
          Message(nmEngineWarning, '[WARNING] Scanning of inaccessible pages is possible only in reflection mode!');
      end;
    end;
    if not Options.Quiet and not IsScannerCompatible(TargetHandle) then
      Message(nmEngineError, '[!] Scanner mismatch! Try to use the 64bit version of the scanner!');
    Reader := TNativeMirrorProcessMemoryReader.Create(TargetHandle, False);
    Scanner := TNativeMirrorProcessScanner.Create(Reader, IsRefl, Options);
    try
      Scanner.OnMessage :=
        procedure(const Text: string; IsError: Boolean)
        begin
          if IsError then Message(nmEngineError, Text)
          else Message(nmEngineInfo, Text);
        end;
{$IFDEF USE_NATIVEASM}
{$IFDEF WIN64}
      Disasm := TNativeAsmAdapter.Create;
      CodeGen := Disasm as ICodeGen;
      Scanner.SetLayer(Disasm, CodeGen);
{$ELSE}
      Disasm := TLdeAdapter.Create;
      Scanner.SetLayer(Disasm);
{$ENDIF}
{$ELSE}
      Disasm := TLdeAdapter.Create;
      Scanner.SetLayer(Disasm);
{$ENDIF}
      Report.ScanReport := Scanner.ScanRemote;
      if Assigned(Report.ScanReport) then
        Report.DumpReport := MakeDump(Reader, IsRefl, Options, Report.ScanReport, Message);
    finally
      Scanner.Free;
    end;
  except
    on E: Exception do
    begin
      Report.ErrorReport := TNativeMirrorErrorReport.Create(Options.Pid, E.Message);
      if not Options.Quiet then
        Message(nmEngineError, '[ERROR] ' + E.Message);
      try
        ErrorDumper := TNativeMirrorResultsDumper.Create(ExpandOutputDir(Options.OutputDirectory), Options.Quiet);
        try
          ErrorDumper.DumpJsonErrorReport(Options.Pid, E.Message, Options.ResultsFilter);
        finally
          ErrorDumper.Free;
        end;
      except
        on DumpError: Exception do
          if not Options.Quiet then Message(nmEngineError, '[-] Could not write error report: ' + DumpError.Message);
      end;
    end;
  end;
  if Assigned(Refl) then Refl.Free;
  if OrigHandle <> 0 then CloseHandle(OrigHandle);
  Result := Report;
end;

function NativeMirrorInfo: string;
begin
  Result := 'NativeMirror v' + NativeMirrorVersion;
{$IFDEF WIN64}
  Result := Result + ' (x64)';
{$ELSE}
  Result := Result + ' (x86)';
{$ENDIF}
  Result := Result + #13#10 +
    'Process memory scanner and dumper - Delphi port of PE-sieve 0.4.1.5.' + #13#10 +
    'Copyright (c) 2026 Selahattin Erkoc. License: BSD-2-Clause.' + #13#10 +
    'Based on PE-sieve by hasherezade (c) 2017-2026.' + #13#10;
end;

end.
