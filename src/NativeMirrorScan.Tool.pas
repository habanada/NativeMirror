{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirrorScan.Tool;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  NativeMirror.Core.Options,
  NativeMirror.Core.Engine;

type
  TNativeMirrorScanMessageKind = (nmScanInfo, nmScanWarning, nmScanError, nmScanTiming, nmScanResult);
  TNativeMirrorScanMessageEvent = reference to procedure(Sender: TObject; Kind: TNativeMirrorScanMessageKind; const Text: string);
  TNativeMirrorScanStartedEvent = reference to procedure(Sender: TObject; const Options: TNativeMirrorOptions);
  TNativeMirrorScanFinishedEvent = reference to procedure(Sender: TObject; Report: TNativeMirrorReportEx; ElapsedMilliseconds: Int64; ExitCode: Integer);

  ENativeMirrorScanArgumentError = class(Exception);

  TNativeMirrorScanTool = class
  private
    FOptions: TNativeMirrorOptions;
    FElapsedMilliseconds: Int64;
    FLastExitCode: Integer;
    FOnMessage: TNativeMirrorScanMessageEvent;
    FOnStarted: TNativeMirrorScanStartedEvent;
    FOnFinished: TNativeMirrorScanFinishedEvent;
    procedure Emit(Kind: TNativeMirrorScanMessageKind; const Text: string);
    procedure EngineMessage(Kind: TNativeMirrorEngineMessageKind; const Text: string);
    procedure PrepareOptions;
    procedure EmitStartInfo;
    procedure EmitSummary(Report: TNativeMirrorReportEx);
    function CalculateExitCode(Report: TNativeMirrorReportEx): Integer;
  public
    constructor Create; overload;
    constructor Create(const AOptions: TNativeMirrorOptions); overload;
    procedure Reset;
    procedure ParseArguments(const Args: TArray<string>);
    function Start: TNativeMirrorReportEx; overload;
    function Start(Pid: DWORD): TNativeMirrorReportEx; overload;
    function Start(const AOptions: TNativeMirrorOptions): TNativeMirrorReportEx; overload;
    function Run(const Args: TArray<string>): Integer;
    function RunCommandLine: Integer;
    class function HelpText: string; static;
    property Options: TNativeMirrorOptions read FOptions write FOptions;
    property ElapsedMilliseconds: Int64 read FElapsedMilliseconds;
    property LastExitCode: Integer read FLastExitCode;
    property OnMessage: TNativeMirrorScanMessageEvent read FOnMessage write FOnMessage;
    property OnStarted: TNativeMirrorScanStartedEvent read FOnStarted write FOnStarted;
    property OnFinished: TNativeMirrorScanFinishedEvent read FOnFinished write FOnFinished;
  end;

implementation

uses
  Winapi.ShellAPI,
  System.Diagnostics,
  System.JSON,
  NativeMirror.Core.Types,
  NativeMirror.Core.Text,
  NativeMirror.Cli;

constructor TNativeMirrorScanTool.Create;
begin
  inherited Create;
  Reset;
end;

constructor TNativeMirrorScanTool.Create(const AOptions: TNativeMirrorOptions);
begin
  inherited Create;
  FOptions := AOptions;
  FElapsedMilliseconds := 0;
  FLastExitCode := -1;
end;

procedure TNativeMirrorScanTool.Reset;
begin
  FOptions := TNativeMirrorOptions.Default;
  FElapsedMilliseconds := 0;
  FLastExitCode := -1;
end;

procedure TNativeMirrorScanTool.Emit(Kind: TNativeMirrorScanMessageKind; const Text: string);
begin
  if Assigned(FOnMessage) then FOnMessage(Self, Kind, Text);
end;

procedure TNativeMirrorScanTool.EngineMessage(Kind: TNativeMirrorEngineMessageKind; const Text: string);
begin
  case Kind of
    nmEngineInfo: Emit(nmScanInfo, Text);
    nmEngineWarning: Emit(nmScanWarning, Text);
    nmEngineError: Emit(nmScanError, Text);
  end;
end;

procedure TNativeMirrorScanTool.ParseArguments(const Args: TArray<string>);
var
  Parser: TNativeMirrorCommandLine;
begin
  Reset;
  Parser := TNativeMirrorCommandLine.Create;
  try
    if not Parser.Parse(Args) then
      raise ENativeMirrorScanArgumentError.Create(Parser.Output);
    FOptions := Parser.Options;
  finally
    Parser.Free;
  end;
end;

procedure TNativeMirrorScanTool.PrepareOptions;
begin
  if (FOptions.DataScanMode in [nmDataInaccessible, nmDataInaccessibleOnly]) and not FOptions.MakeReflection then
  begin
    FOptions.MakeReflection := True;
    if not FOptions.Quiet then Emit(nmScanWarning, '[WARNING] Scanning of inaccessible pages requested: auto-enabled reflection mode!');
  end;
end;

procedure TNativeMirrorScanTool.EmitStartInfo;
begin
  if FOptions.Quiet then Exit;
  Emit(nmScanInfo, Format('PID: %d', [FOptions.Pid]));
  Emit(nmScanInfo, 'Output filter: ' + NativeMirrorOutputFilterText(FOptions));
  Emit(nmScanInfo, 'Dump mode: ' + NativeMirrorDumpModeText(FOptions));
end;

procedure TNativeMirrorScanTool.EmitSummary(Report: TNativeMirrorReportEx);
var
  Json: TJSONObject;
begin
  if not Assigned(Report) or not Assigned(Report.ScanReport) then Exit;
  if FOptions.JsonOutput then
  begin
    Json := Report.ToJson(FOptions.ResultsFilter, FOptions.JsonLevel);
    try
      Emit(nmScanResult, Json.ToJSON);
    finally
      Json.Free;
    end;
    Exit;
  end;
  Emit(nmScanResult, FormatScanSummary(Report.ScanReport.GenerateSummary) + '---' + sLineBreak);
end;

function TNativeMirrorScanTool.CalculateExitCode(Report: TNativeMirrorReportEx): Integer;
var
  Summary: TNativeMirrorProcessSummary;
begin
  Result := -1;
  if not Assigned(Report) or not Assigned(Report.ScanReport) then Exit;
  Summary := Report.ScanReport.GenerateSummary;
  if Summary.Scanned <= 0 then Exit;
  if Summary.Suspicious > 0 then Result := 2 else Result := 1;
end;

function TNativeMirrorScanTool.Start: TNativeMirrorReportEx;
var
  Timer: TStopwatch;
  Report: TNativeMirrorReportEx;
begin
  FElapsedMilliseconds := 0;
  FLastExitCode := -1;
  PrepareOptions;
  EmitStartInfo;
  Timer := TStopwatch.StartNew;
  Emit(nmScanTiming, '[TIME] Scan started');
  if Assigned(FOnStarted) then FOnStarted(Self, FOptions);
  Report := ScanAndDump(FOptions, EngineMessage);
  try
    Timer.Stop;
    FElapsedMilliseconds := Timer.ElapsedMilliseconds;
    FLastExitCode := CalculateExitCode(Report);
    Emit(nmScanTiming, Format('[TIME] Total scan: %d ms', [FElapsedMilliseconds]));
    EmitSummary(Report);
    if Assigned(FOnFinished) then FOnFinished(Self, Report, FElapsedMilliseconds, FLastExitCode);
    Result := Report;
  except
    Report.Free;
    raise;
  end;
end;

function TNativeMirrorScanTool.Start(Pid: DWORD): TNativeMirrorReportEx;
begin
  FOptions.Pid := Pid;
  Result := Start;
end;

function TNativeMirrorScanTool.Start(const AOptions: TNativeMirrorOptions): TNativeMirrorReportEx;
begin
  FOptions := AOptions;
  Result := Start;
end;

function TNativeMirrorScanTool.Run(const Args: TArray<string>): Integer;
var
  Report: TNativeMirrorReportEx;
  Parser: TNativeMirrorCommandLine;
begin
  Reset;
  Parser := TNativeMirrorCommandLine.Create;
  try
    if not Parser.Parse(Args) then
    begin
      Emit(nmScanResult, Parser.Output);
      FLastExitCode := 0;
      Exit(FLastExitCode);
    end;
    FOptions := Parser.Options;
    if Parser.Output <> '' then Emit(nmScanResult, Parser.Output);
  finally
    Parser.Free;
  end;
  Report := Start;
  try
    Result := FLastExitCode;
  finally
    Report.Free;
  end;
end;

function TNativeMirrorScanTool.RunCommandLine: Integer;
var
  Args: TArray<string>;
  I, Count: Integer;
  Arguments: PPWideChar;
begin
  Arguments := CommandLineToArgvW(GetCommandLineW, Count);
  if Arguments = nil then RaiseLastOSError;
  try
    SetLength(Args, Count - 1);
    for I := 1 to Count - 1 do
      Args[I - 1] := PWideChar(PPointer(NativeUInt(Arguments) + NativeUInt(I) * SizeOf(Pointer))^);
  finally
    LocalFree(HLOCAL(Arguments));
  end;
  Result := Run(Args);
end;

class function TNativeMirrorScanTool.HelpText: string;
begin
  Result := TNativeMirrorCommandLine.HelpText;
end;

end.
