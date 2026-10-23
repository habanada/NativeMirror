{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-License-Identifier: BSD-2-Clause

  This file contains tests for NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Tests.Support;

interface

uses
  Winapi.Windows,
  System.JSON,
  System.SysUtils;

type
  TScanSummary = record
    Pid: DWORD;
    Scanned: Integer;
    Suspicious: Integer;
    Patched: Integer;
    IatHooked: Integer;
    Replaced: Integer;
    HeaderModified: Integer;
    ImplantedPe: Integer;
    ImplantedShellcode: Integer;
    UnreachableFile: Integer;
    Other: Integer;
    Errors: Integer;
  end;

  TScanResult = class
  private
    FRoot: TJSONObject;
    FScanRoot: TJSONObject;
    FRawOutput: string;
    FExitCode: DWORD;
    FSummary: TScanSummary;
  public
    constructor Create(Root: TJSONObject; const RawOutput: string; ExitCode: DWORD);
    destructor Destroy; override;
    function HasModuleFinding(const ScanName, ModulePath: string): Boolean;
    function ModuleFindingInt(const ScanName, ModulePath, FieldName: string): Integer;
    function HasAddressFinding(const ScanName: string; Address: UInt64): Boolean;
    function HasThreadFinding(ThreadId: DWORD): Boolean;
    property Root: TJSONObject read FRoot;
    property RawOutput: string read FRawOutput;
    property ExitCode: DWORD read FExitCode;
    property Summary: TScanSummary read FSummary;
  end;

  TTargetProcess = class
  private
    FProcessHandle: THandle;
    FPid: DWORD;
    FStatusPath: string;
    FScenario: string;
    FModulePath: string;
    FPrimaryAddress: UInt64;
    FSecondaryAddress: UInt64;
    FThirdAddress: UInt64;
    FThreadId: DWORD;
    FPatternPath: string;
    procedure LoadStatus;
  public
    constructor Create(ProcessHandle: THandle; Pid: DWORD; const Scenario, StatusPath: string);
    destructor Destroy; override;
    procedure WaitReady(TimeoutMs: DWORD = 10000);
    property ProcessHandle: THandle read FProcessHandle;
    property Pid: DWORD read FPid;
    property Scenario: string read FScenario;
    property ModulePath: string read FModulePath;
    property PrimaryAddress: UInt64 read FPrimaryAddress;
    property SecondaryAddress: UInt64 read FSecondaryAddress;
    property ThirdAddress: UInt64 read FThirdAddress;
    property ThreadId: DWORD read FThreadId;
    property PatternPath: string read FPatternPath;
  end;

  TScannerHarness = class sealed
  private
    class function Quote(const Value: string): string; static;
    class function RunCaptured(const ExePath, Arguments: string; TimeoutMs: DWORD; out ExitCode: DWORD): string; static;
    class function ExtractJsonObject(const Output: string): TJSONObject; static;
    class function FindNativeMirrorScanner: string; static;
    class function FindPeSieve: string; static;
    class function FindWin32Target: string; static;
    class function BuildNativeMirrorArgs(Target: TTargetProcess): string; static;
    class function BuildPeSieveArgs(Target: TTargetProcess): string; static;
    class function StartTargetProcess(const ExePath, Scenario, StatusPath: string): TTargetProcess; static;
    class procedure AppendDiagnostic(const Text: string); static;
    class procedure AppendDiagnosticFile(const LabelText, FilePath: string); static;
  public
    class function StartTargetWithExe(const ExePath, Scenario: string): TTargetProcess; static;
    class function StartTarget(const Scenario: string): TTargetProcess; static;
    class function StartTarget32(const Scenario: string): TTargetProcess; static;
    class function ScanNativeMirror(Target: TTargetProcess): TScanResult; static;
    class function ScanPeSieve(Target: TTargetProcess): TScanResult; static;
    class procedure AssertParity(const NativeResult, PeResult: TScanResult); static;
    class function DiagnosticsPath: string; static;
    class procedure ResetDiagnostics; static;
  end;

implementation

uses
  System.Classes,
  System.IOUtils,
  DUnitX.TestFramework;

function JsonInt(Json: TJSONObject; const Name: string): Integer;
var
  Value: TJSONValue;
begin
  Value := Json.GetValue(Name);
  if Value = nil then
    raise Exception.CreateFmt('Missing JSON integer: %s', [Name]);
  Result := StrToInt(Value.Value);
end;

procedure ValidateBinaryFlag(Json: TJSONObject; const Name: string);
var
  Value: TJSONValue;
begin
  Value := Json.GetValue(Name);
  if not (Value is TJSONNumber) then
    raise Exception.CreateFmt('Expected numeric JSON flag: %s', [Name]);
  if (Value.Value <> '0') and (Value.Value <> '1') then
    raise Exception.CreateFmt('JSON flag must be 0 or 1: %s', [Name]);
end;

function JsonDword(Json: TJSONObject; const Name: string): DWORD;
var
  Value: TJSONValue;
  Parsed: UInt64;
begin
  Value := Json.GetValue(Name);
  if Value = nil then
    raise Exception.CreateFmt('Missing JSON DWORD: %s', [Name]);
  Parsed := StrToUInt64(Value.Value);
  if Parsed > High(DWORD) then
    raise Exception.CreateFmt('JSON DWORD out of range: %s', [Name]);
  Result := DWORD(Parsed);
end;

function JsonString(Json: TJSONObject; const Name: string): string;
var
  Value: TJSONValue;
begin
  Value := Json.GetValue(Name);
  if Value = nil then
    Exit('');
  Result := Value.Value;
end;

function HexToUInt64(const Value: string): UInt64;
begin
  if Value = '' then
    Exit(0);
  Result := StrToUInt64('$' + Value);
end;

function ScenarioUsesPattern(const Scenario: string): Boolean;
begin
  Result := SameText(Scenario, 'PrivateExecutable') or SameText(Scenario, 'PrivateExecutablePageBoundary') or SameText(Scenario, 'PrivateExecutableRegionTail') or SameText(Scenario, 'MultiplePrivateExecutable') or SameText(Scenario, 'MixedExtended');
end;

function ScenarioUsesIatScan(const Scenario: string): Boolean;
begin
  Result := SameText(Scenario, 'IatRedirect') or SameText(Scenario, 'Mixed') or SameText(Scenario, 'MixedExtended');
end;

function ScenarioUsesThreadScan(const Scenario: string): Boolean;
begin
  Result := SameText(Scenario, 'PrivateThread') or SameText(Scenario, 'Mixed') or SameText(Scenario, 'MixedExtended');
end;

constructor TScanResult.Create(Root: TJSONObject; const RawOutput: string; ExitCode: DWORD);
var
  Value: TJSONValue;
  Scanned, Modified: TJSONObject;
begin
  inherited Create;
  FRoot := Root;
  FRawOutput := RawOutput;
  FExitCode := ExitCode;
  if FRoot = nil then
    raise Exception.Create('Scanner JSON is nil');
  FScanRoot := FRoot;
  Value := FRoot.GetValue('scan_report');
  if Value is TJSONObject then
    FScanRoot := TJSONObject(Value);
  ValidateBinaryFlag(FScanRoot, 'is_64_bit');
  ValidateBinaryFlag(FScanRoot, 'is_managed');
  ValidateBinaryFlag(FScanRoot, 'used_reflection');
  Value := FScanRoot.GetValue('scanner_version');
  if not (Value is TJSONString) then
    raise Exception.Create('Missing scanner_version JSON string');
  if Value.Value = '' then
    raise Exception.Create('Empty scanner_version JSON string');
  Value := FScanRoot.GetValue('scanned');
  if not (Value is TJSONObject) then
    raise Exception.Create('Missing scanned JSON object: ' + RawOutput);
  Scanned := TJSONObject(Value);
  Value := Scanned.GetValue('modified');
  if not (Value is TJSONObject) then
    raise Exception.Create('Missing modified JSON object: ' + RawOutput);
  Modified := TJSONObject(Value);
  FSummary.Pid := JsonDword(FScanRoot, 'pid');
  FSummary.Scanned := JsonInt(Scanned, 'total');
  FSummary.Errors := JsonInt(Scanned, 'errors');
  FSummary.Suspicious := JsonInt(Modified, 'total');
  FSummary.Patched := JsonInt(Modified, 'patched');
  FSummary.IatHooked := JsonInt(Modified, 'iat_hooked');
  FSummary.Replaced := JsonInt(Modified, 'replaced');
  FSummary.HeaderModified := JsonInt(Modified, 'hdr_modified');
  FSummary.ImplantedPe := JsonInt(Modified, 'implanted_pe');
  FSummary.ImplantedShellcode := JsonInt(Modified, 'implanted_shc');
  FSummary.UnreachableFile := JsonInt(Modified, 'unreachable_file');
  FSummary.Other := JsonInt(Modified, 'other');
end;

destructor TScanResult.Destroy;
begin
  FRoot.Free;
  inherited;
end;

function TScanResult.HasModuleFinding(const ScanName, ModulePath: string): Boolean;
var
  Scans: TJSONArray;
  I: Integer;
  Wrapper, Details: TJSONObject;
  Value: TJSONValue;
  FoundPath: string;
begin
  Result := False;
  Scans := FScanRoot.GetValue<TJSONArray>('scans');
  if Scans = nil then
    Exit;
  for I := 0 to Scans.Count - 1 do
  begin
    if not (Scans.Items[I] is TJSONObject) then
      Continue;
    Wrapper := TJSONObject(Scans.Items[I]);
    Value := Wrapper.GetValue(ScanName);
    if not (Value is TJSONObject) then
      Continue;
    Details := TJSONObject(Value);
    if JsonInt(Details, 'status') <> 1 then
      Continue;
    FoundPath := JsonString(Details, 'module_file');
    if (FoundPath <> '') and SameText(ExpandFileName(FoundPath), ExpandFileName(ModulePath)) then
      Exit(True);
  end;
end;

function TScanResult.ModuleFindingInt(const ScanName, ModulePath, FieldName: string): Integer;
var
  Scans: TJSONArray;
  I: Integer;
  Wrapper, Details: TJSONObject;
  Value, FieldValue: TJSONValue;
  FoundPath: string;
begin
  Result := -1;
  Scans := FScanRoot.GetValue<TJSONArray>('scans');
  if Scans = nil then
    Exit;
  for I := 0 to Scans.Count - 1 do
  begin
    if not (Scans.Items[I] is TJSONObject) then
      Continue;
    Wrapper := TJSONObject(Scans.Items[I]);
    Value := Wrapper.GetValue(ScanName);
    if not (Value is TJSONObject) then
      Continue;
    Details := TJSONObject(Value);
    if JsonInt(Details, 'status') <> 1 then
      Continue;
    FoundPath := JsonString(Details, 'module_file');
    if (FoundPath = '') or not SameText(ExpandFileName(FoundPath), ExpandFileName(ModulePath)) then
      Continue;
    FieldValue := Details.GetValue(FieldName);
    if FieldValue <> nil then
      Exit(StrToInt(FieldValue.Value));
  end;
end;

function TScanResult.HasAddressFinding(const ScanName: string; Address: UInt64): Boolean;
var
  Scans: TJSONArray;
  I: Integer;
  Wrapper, Details: TJSONObject;
  Value: TJSONValue;
  ModuleValue: string;
begin
  Result := False;
  Scans := FScanRoot.GetValue<TJSONArray>('scans');
  if Scans = nil then
    Exit;
  for I := 0 to Scans.Count - 1 do
  begin
    if not (Scans.Items[I] is TJSONObject) then
      Continue;
    Wrapper := TJSONObject(Scans.Items[I]);
    Value := Wrapper.GetValue(ScanName);
    if not (Value is TJSONObject) then
      Continue;
    Details := TJSONObject(Value);
    if JsonInt(Details, 'status') <> 1 then
      Continue;
    ModuleValue := JsonString(Details, 'module');
    if (ModuleValue <> '') and (HexToUInt64(ModuleValue) = Address) then
      Exit(True);
  end;
end;

function TScanResult.HasThreadFinding(ThreadId: DWORD): Boolean;
var
  Scans: TJSONArray;
  I: Integer;
  Wrapper, Details: TJSONObject;
  Value: TJSONValue;
begin
  Result := False;
  Scans := FScanRoot.GetValue<TJSONArray>('scans');
  if Scans = nil then
    Exit;
  for I := 0 to Scans.Count - 1 do
  begin
    if not (Scans.Items[I] is TJSONObject) then
      Continue;
    Wrapper := TJSONObject(Scans.Items[I]);
    Value := Wrapper.GetValue('thread_scan');
    if not (Value is TJSONObject) then
      Continue;
    Details := TJSONObject(Value);
    if (JsonInt(Details, 'status') = 1) and (JsonDword(Details, 'thread_id') = ThreadId) then
      Exit(True);
  end;
end;

constructor TTargetProcess.Create(ProcessHandle: THandle; Pid: DWORD; const Scenario, StatusPath: string);
begin
  inherited Create;
  FProcessHandle := ProcessHandle;
  FPid := Pid;
  FScenario := Scenario;
  FStatusPath := StatusPath;
  FPatternPath := FStatusPath + '.sig';
end;

destructor TTargetProcess.Destroy;
var
  StopPath: string;
begin
  StopPath := FStatusPath + '.stop';
  if FProcessHandle <> 0 then
  begin
    if WaitForSingleObject(FProcessHandle, 0) = WAIT_TIMEOUT then
    begin
      TFile.WriteAllText(StopPath, '', TEncoding.ASCII);
      if WaitForSingleObject(FProcessHandle, 3000) = WAIT_TIMEOUT then
      begin
        TerminateProcess(FProcessHandle, 0);
        WaitForSingleObject(FProcessHandle, 5000);
      end;
    end;
    CloseHandle(FProcessHandle);
  end;
  if TFile.Exists(FStatusPath) then
    TFile.Delete(FStatusPath);
  if TFile.Exists(StopPath) then
    TFile.Delete(StopPath);
  if TFile.Exists(FPatternPath) then
    TFile.Delete(FPatternPath);
  inherited;
end;

procedure TTargetProcess.LoadStatus;
var
  Json: TJSONObject;
  Text: string;
begin
  Text := TFile.ReadAllText(FStatusPath, TEncoding.UTF8);
  Json := TJSONObject.ParseJSONValue(Text) as TJSONObject;
  if Json = nil then
    raise Exception.Create('Invalid target status JSON');
  try
    if JsonDword(Json, 'pid') <> FPid then
      raise Exception.Create('Target status PID mismatch');
    FModulePath := JsonString(Json, 'module_path');
    FPrimaryAddress := HexToUInt64(JsonString(Json, 'primary_address'));
    FSecondaryAddress := HexToUInt64(JsonString(Json, 'secondary_address'));
    FThirdAddress := HexToUInt64(JsonString(Json, 'third_address'));
    FThreadId := JsonDword(Json, 'thread_id');
  finally
    Json.Free;
  end;
end;

procedure TTargetProcess.WaitReady(TimeoutMs: DWORD);
var
  Started: UInt64;
begin
  Started := GetTickCount64;
  while GetTickCount64 - Started < TimeoutMs do
  begin
    if TFile.Exists(FStatusPath) then
    begin
      LoadStatus;
      Exit;
    end;
    if WaitForSingleObject(FProcessHandle, 0) <> WAIT_TIMEOUT then
      raise Exception.CreateFmt('Target exited before ready: %s', [FScenario]);
    Sleep(25);
  end;
  raise Exception.CreateFmt('Target readiness timeout: %s', [FScenario]);
end;

class function TScannerHarness.DiagnosticsPath: string;
begin
  Result := TPath.Combine(ExtractFilePath(ParamStr(0)), 'NativeMirrorScannerDiagnostics.log');
end;

class procedure TScannerHarness.ResetDiagnostics;
var
  Header: string;
begin
  Header := 'NativeMirror ScannerIntegration diagnostics' + sLineBreak +
    'Started=' + FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', Now) + sLineBreak +
    'TestExe=' + ExpandFileName(ParamStr(0)) + sLineBreak +
    'CurrentDir=' + GetCurrentDir + sLineBreak +
    'NATIVEMIRROR_SCAN_EXE=' + GetEnvironmentVariable('NATIVEMIRROR_SCAN_EXE') + sLineBreak +
    'PESIEVE_EXE=' + GetEnvironmentVariable('PESIEVE_EXE') + sLineBreak +
    'NATIVEMIRROR_TARGET32_EXE=' + GetEnvironmentVariable('NATIVEMIRROR_TARGET32_EXE') + sLineBreak +
    StringOfChar('=', 96) + sLineBreak;
  TFile.WriteAllText(DiagnosticsPath, Header, TEncoding.UTF8);
end;

class procedure TScannerHarness.AppendDiagnostic(const Text: string);
begin
  TFile.AppendAllText(DiagnosticsPath, Text + sLineBreak, TEncoding.UTF8);
end;

class procedure TScannerHarness.AppendDiagnosticFile(const LabelText, FilePath: string);
var
  Content: string;
begin
  AppendDiagnostic(LabelText + '.Path=' + FilePath);
  if not TFile.Exists(FilePath) then
  begin
    AppendDiagnostic(LabelText + '.Exists=False');
    Exit;
  end;
  AppendDiagnostic(LabelText + '.Exists=True');
  AppendDiagnostic(LabelText + '.Modified=' + FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', TFile.GetLastWriteTime(FilePath)));
  try
    Content := TFile.ReadAllText(FilePath, TEncoding.UTF8);
    AppendDiagnostic(LabelText + '.Content.Begin');
    AppendDiagnostic(Content);
    AppendDiagnostic(LabelText + '.Content.End');
  except
    on E: Exception do
      AppendDiagnostic(LabelText + '.ReadError=' + E.ClassName + ': ' + E.Message);
  end;
end;

class function TScannerHarness.Quote(const Value: string): string;
begin
  Result := '"' + Value + '"';
end;

class function TScannerHarness.RunCaptured(const ExePath, Arguments: string; TimeoutMs: DWORD; out ExitCode: DWORD): string;
var
  Security: TSecurityAttributes;
  Startup: TStartupInfo;
  ProcessInfo: TProcessInformation;
  ReadPipe, WritePipe: THandle;
  CommandLine, WorkDir: string;
  Buffer: array[0..4095] of Byte;
  ReadCount, Available: DWORD;
  Stream: TBytesStream;
  WaitResult: DWORD;
  Started: UInt64;

  procedure DrainPipe;
  begin
    while PeekNamedPipe(ReadPipe, nil, 0, nil, @Available, nil) and (Available <> 0) do
    begin
      if Available > SizeOf(Buffer) then
        Available := SizeOf(Buffer);
      if not ReadFile(ReadPipe, Buffer[0], Available, ReadCount, nil) then
      begin
        if GetLastError = ERROR_BROKEN_PIPE then
          Exit;
        RaiseLastOSError;
      end;
      if ReadCount = 0 then
        Exit;
      Stream.WriteBuffer(Buffer[0], ReadCount);
    end;
  end;

begin
  Result := '';
  ExitCode := DWORD(-1);
  FillChar(Security, SizeOf(Security), 0);
  Security.nLength := SizeOf(Security);
  Security.bInheritHandle := True;
  if not CreatePipe(ReadPipe, WritePipe, @Security, 0) then
    RaiseLastOSError;
  try
    if not SetHandleInformation(ReadPipe, HANDLE_FLAG_INHERIT, 0) then
      RaiseLastOSError;
    FillChar(Startup, SizeOf(Startup), 0);
    Startup.cb := SizeOf(Startup);
    Startup.dwFlags := STARTF_USESTDHANDLES;
    Startup.hStdOutput := WritePipe;
    Startup.hStdError := WritePipe;
    Startup.hStdInput := GetStdHandle(STD_INPUT_HANDLE);
    FillChar(ProcessInfo, SizeOf(ProcessInfo), 0);
    CommandLine := Quote(ExePath) + ' ' + Arguments;
    UniqueString(CommandLine);
    WorkDir := ExtractFilePath(ExePath);
    if not CreateProcess(nil, PChar(CommandLine), nil, nil, True, CREATE_NO_WINDOW, nil, PChar(WorkDir), Startup, ProcessInfo) then
      RaiseLastOSError;
    CloseHandle(ProcessInfo.hThread);
    CloseHandle(WritePipe);
    WritePipe := 0;
    Stream := TBytesStream.Create;
    try
      Started := GetTickCount64;
      repeat
        DrainPipe;
        WaitResult := WaitForSingleObject(ProcessInfo.hProcess, 20);
        if (WaitResult = WAIT_TIMEOUT) and (GetTickCount64 - Started >= TimeoutMs) then
        begin
          TerminateProcess(ProcessInfo.hProcess, 255);
          WaitForSingleObject(ProcessInfo.hProcess, 5000);
          raise Exception.CreateFmt('Process timeout: %s', [ExePath]);
        end;
        if (WaitResult <> WAIT_TIMEOUT) and (WaitResult <> WAIT_OBJECT_0) then
          raise Exception.CreateFmt('Process wait failed: %s', [ExePath]);
      until WaitResult = WAIT_OBJECT_0;
      DrainPipe;
      if not GetExitCodeProcess(ProcessInfo.hProcess, ExitCode) then
        RaiseLastOSError;
      if Stream.Size <> 0 then
        Result := TEncoding.UTF8.GetString(Stream.Bytes, 0, Integer(Stream.Size));
    finally
      Stream.Free;
      CloseHandle(ProcessInfo.hProcess);
    end;
  finally
    if WritePipe <> 0 then
      CloseHandle(WritePipe);
    CloseHandle(ReadPipe);
  end;
end;

class function TScannerHarness.ExtractJsonObject(const Output: string): TJSONObject;
var
  FirstPos, LastPos, I: Integer;
  JsonText: string;
begin
  FirstPos := 0;
  LastPos := 0;
  for I := 1 to Length(Output) do
    if Output[I] = '{' then
    begin
      FirstPos := I;
      Break;
    end;
  for I := Length(Output) downto 1 do
    if Output[I] = '}' then
    begin
      LastPos := I;
      Break;
    end;
  if (FirstPos = 0) or (LastPos < FirstPos) then
    raise Exception.Create('Scanner output contains no JSON object: ' + Output);
  JsonText := Copy(Output, FirstPos, LastPos - FirstPos + 1);
  Result := TJSONObject.ParseJSONValue(JsonText) as TJSONObject;
  if Result = nil then
    raise Exception.Create('Scanner JSON could not be parsed: ' + Output);
end;

class function TScannerHarness.FindNativeMirrorScanner: string;
var
  Env, Base, Candidate: string;
begin
  Env := GetEnvironmentVariable('NATIVEMIRROR_SCAN_EXE');
  if Env <> '' then
  begin
    if not TFile.Exists(Env) then
      raise Exception.CreateFmt('NATIVEMIRROR_SCAN_EXE not found: %s', [Env]);
    Exit(ExpandFileName(Env));
  end;
  Base := ExtractFilePath(ParamStr(0));
  Candidate := TPath.Combine(Base, 'NativeMirrorScan.exe');
  if TFile.Exists(Candidate) then
    Exit(Candidate);
  raise Exception.Create('NativeMirror scanner not found. Set NATIVEMIRROR_SCAN_EXE.');
end;

class function TScannerHarness.FindPeSieve: string;
var
  Env, Base, Candidate: string;
begin
  Env := GetEnvironmentVariable('PESIEVE_EXE');
  if Env <> '' then
  begin
    if not TFile.Exists(Env) then
      raise Exception.CreateFmt('PESIEVE_EXE not found: %s', [Env]);
    Exit(ExpandFileName(Env));
  end;
  Base := ExtractFilePath(ParamStr(0));
  Candidate := TPath.Combine(Base, 'pe-sieve64.exe');
  if TFile.Exists(Candidate) then
    Exit(Candidate);
  Result := '';
end;

class function TScannerHarness.FindWin32Target: string;
var
  Env, Base, Config, Candidate: string;
begin
  Env := GetEnvironmentVariable('NATIVEMIRROR_TARGET32_EXE');
  if Env <> '' then
  begin
    if not TFile.Exists(Env) then
      raise Exception.CreateFmt('NATIVEMIRROR_TARGET32_EXE not found: %s', [Env]);
    Exit(ExpandFileName(Env));
  end;
  Base := ExtractFilePath(ParamStr(0));
  Config := ExtractFileName(ExcludeTrailingPathDelimiter(Base));
  Candidate := ExpandFileName(TPath.Combine(Base, '..\..\..\bin\Win32\' + Config + '\NativeMirrorTestTarget32.exe'));
  if TFile.Exists(Candidate) then
    Exit(Candidate);
  raise Exception.CreateFmt('Win32 test target not found: %s', [Candidate]);
end;

class function TScannerHarness.BuildNativeMirrorArgs(Target: TTargetProcess): string;
begin
  Result := BuildPeSieveArgs(Target);
end;

class function TScannerHarness.BuildPeSieveArgs(Target: TTargetProcess): string;
begin
  Result := Format('/pid %d /quiet /json /jlvl 2 /report 5 /ofilter 2', [Target.Pid]);
  if ScenarioUsesIatScan(Target.Scenario) then
    Result := Result + ' /iat 3';
  if ScenarioUsesPattern(Target.Scenario) then
    Result := Result + ' /pattern ' + Quote(Target.PatternPath);
  if ScenarioUsesThreadScan(Target.Scenario) then
    Result := Result + ' /threads';
end;

class function TScannerHarness.StartTargetProcess(const ExePath, Scenario, StatusPath: string): TTargetProcess;
var
  Startup: TStartupInfo;
  ProcessInfo: TProcessInformation;
  CommandLine, WorkDir: string;
begin
  FillChar(Startup, SizeOf(Startup), 0);
  Startup.cb := SizeOf(Startup);
  FillChar(ProcessInfo, SizeOf(ProcessInfo), 0);
  CommandLine := Quote(ExePath) + ' /scenario:' + Scenario + ' /status:' + Quote(StatusPath);
  UniqueString(CommandLine);
  WorkDir := ExtractFilePath(ExePath);
  if not CreateProcess(nil, PChar(CommandLine), nil, nil, False, CREATE_NO_WINDOW, nil, PChar(WorkDir), Startup, ProcessInfo) then
    RaiseLastOSError;
  CloseHandle(ProcessInfo.hThread);
  Result := TTargetProcess.Create(ProcessInfo.hProcess, ProcessInfo.dwProcessId, Scenario, StatusPath);
end;

class function TScannerHarness.StartTargetWithExe(const ExePath, Scenario: string): TTargetProcess;
var
  StatusPath, GuidText: string;
  Id: TGUID;
begin
  if not TFile.Exists(ExePath) then
    raise Exception.CreateFmt('Test target not found: %s', [ExePath]);
  CreateGUID(Id);
  GuidText := GUIDToString(Id);
  GuidText := StringReplace(GuidText, '{', '', [rfReplaceAll]);
  GuidText := StringReplace(GuidText, '}', '', [rfReplaceAll]);
  StatusPath := TPath.Combine(TPath.GetTempPath, 'NativeMirror_' + GuidText + '.json');
  Result := StartTargetProcess(ExePath, Scenario, StatusPath);
  try
    Result.WaitReady;
    if ScenarioUsesPattern(Scenario) then
      TFile.WriteAllText(Result.PatternPath, 'NativeMirror_PrivateExecutable_Test' + sLineBreak + '16' + sLineBreak + 'DE AD BE EF 13 37 C0 DE 42 24 66 99 A5 5A 7E E7' + sLineBreak, TEncoding.ASCII);
    AppendDiagnostic(StringOfChar('-', 96));
    AppendDiagnostic('[TARGET]');
    AppendDiagnostic('Timestamp=' + FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', Now));
    AppendDiagnostic('Scenario=' + Scenario);
    AppendDiagnostic('TargetExe=' + ExpandFileName(ExePath));
    AppendDiagnostic('PID=' + UIntToStr(Result.Pid));
    AppendDiagnostic('ModulePath=' + Result.ModulePath);
    AppendDiagnostic('StatusPath=' + StatusPath);
    AppendDiagnostic('PrimaryAddress=' + IntToHex(Result.PrimaryAddress, 16));
    AppendDiagnostic('SecondaryAddress=' + IntToHex(Result.SecondaryAddress, 16));
    AppendDiagnostic('ThirdAddress=' + IntToHex(Result.ThirdAddress, 16));
    AppendDiagnostic('ThreadId=' + UIntToStr(Result.ThreadId));
    AppendDiagnosticFile('TargetStatus', StatusPath);
    if ScenarioUsesPattern(Scenario) then
      AppendDiagnosticFile('Pattern', Result.PatternPath);
  except
    Result.Free;
    raise;
  end;
end;

class function TScannerHarness.StartTarget(const Scenario: string): TTargetProcess;
var
  TargetExe: string;
begin
  TargetExe := TPath.Combine(ExtractFilePath(ParamStr(0)), 'NativeMirrorTestTarget.exe');
  Result := StartTargetWithExe(TargetExe, Scenario);
end;

class function TScannerHarness.StartTarget32(const Scenario: string): TTargetProcess;
begin
  Result := StartTargetWithExe(FindWin32Target, Scenario);
end;

class function TScannerHarness.ScanNativeMirror(Target: TTargetProcess): TScanResult;
var
  ExePath, Output, Arguments, WorkDir: string;
  ExitCode: DWORD;
  Root: TJSONObject;
begin
  ExePath := FindNativeMirrorScanner;
  Arguments := BuildNativeMirrorArgs(Target);
  WorkDir := ExtractFilePath(ExePath);
  AppendDiagnostic('[NATIVEMIRROR]');
  AppendDiagnostic('Exe=' + ExePath);
  AppendDiagnostic('Arguments=' + Arguments);
  AppendDiagnostic('CommandLine=' + Quote(ExePath) + ' ' + Arguments);
  AppendDiagnostic('WorkDir=' + WorkDir);
  try
    Output := RunCaptured(ExePath, Arguments, 60000, ExitCode);
  except
    on E: Exception do
    begin
      AppendDiagnostic('RunError=' + E.ClassName + ': ' + E.Message);
      raise;
    end;
  end;
  AppendDiagnostic('ExitCode=' + UIntToStr(ExitCode));
  AppendDiagnostic('Output.Begin');
  AppendDiagnostic(Output);
  AppendDiagnostic('Output.End');
  AppendDiagnosticFile('NativeMirror.scan_report', TPath.Combine(WorkDir, 'scan_report.json'));
  AppendDiagnosticFile('NativeMirror.dump_report', TPath.Combine(WorkDir, 'dump_report.json'));
  try
    Root := ExtractJsonObject(Output);
  except
    on E: Exception do
    begin
      AppendDiagnostic('ParseError=' + E.ClassName + ': ' + E.Message);
      raise;
    end;
  end;
  Result := TScanResult.Create(Root, Output, ExitCode);
end;

class function TScannerHarness.ScanPeSieve(Target: TTargetProcess): TScanResult;
var
  ExePath, Output, Arguments, WorkDir: string;
  ExitCode: DWORD;
  Root: TJSONObject;
begin
  ExePath := FindPeSieve;
  if ExePath = '' then
  begin
    AppendDiagnostic('[PE-SIEVE]');
    AppendDiagnostic('Skipped=True');
    AppendDiagnostic('Reason=pe-sieve64.exe not found');
    Exit(nil);
  end;
  Arguments := BuildPeSieveArgs(Target);
  WorkDir := ExtractFilePath(ExePath);
  AppendDiagnostic('[PE-SIEVE]');
  AppendDiagnostic('Exe=' + ExePath);
  AppendDiagnostic('Arguments=' + Arguments);
  AppendDiagnostic('CommandLine=' + Quote(ExePath) + ' ' + Arguments);
  AppendDiagnostic('WorkDir=' + WorkDir);
  try
    Output := RunCaptured(ExePath, Arguments, 60000, ExitCode);
  except
    on E: Exception do
    begin
      AppendDiagnostic('RunError=' + E.ClassName + ': ' + E.Message);
      raise;
    end;
  end;
  AppendDiagnostic('ExitCode=' + UIntToStr(ExitCode));
  AppendDiagnostic('Output.Begin');
  AppendDiagnostic(Output);
  AppendDiagnostic('Output.End');
  AppendDiagnosticFile('PeSieve.scan_report', TPath.Combine(WorkDir, 'scan_report.json'));
  AppendDiagnosticFile('PeSieve.dump_report', TPath.Combine(WorkDir, 'dump_report.json'));
  try
    Root := ExtractJsonObject(Output);
  except
    on E: Exception do
    begin
      AppendDiagnostic('ParseError=' + E.ClassName + ': ' + E.Message);
      raise;
    end;
  end;
  Result := TScanResult.Create(Root, Output, ExitCode);
end;

class procedure TScannerHarness.AssertParity(const NativeResult, PeResult: TScanResult);
var
  Msg: string;
begin
  if PeResult = nil then
    Exit;
  Msg := 'NativeMirror/PE-Sieve category mismatch';
  Assert.AreEqual(PeResult.Summary.Patched, NativeResult.Summary.Patched, Msg + ': patched');
  Assert.AreEqual(PeResult.Summary.IatHooked, NativeResult.Summary.IatHooked, Msg + ': iat_hooked');
  Assert.AreEqual(PeResult.Summary.Replaced, NativeResult.Summary.Replaced, Msg + ': replaced');
  Assert.AreEqual(PeResult.Summary.HeaderModified, NativeResult.Summary.HeaderModified, Msg + ': hdr_modified');
  Assert.AreEqual(PeResult.Summary.ImplantedPe, NativeResult.Summary.ImplantedPe, Msg + ': implanted_pe');
  Assert.AreEqual(PeResult.Summary.ImplantedShellcode, NativeResult.Summary.ImplantedShellcode, Msg + ': implanted_shc');
  Assert.AreEqual(PeResult.Summary.UnreachableFile, NativeResult.Summary.UnreachableFile, Msg + ': unreachable_file');
end;

end.
