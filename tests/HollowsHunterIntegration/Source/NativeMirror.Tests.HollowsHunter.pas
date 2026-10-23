{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-License-Identifier: BSD-2-Clause

  This file contains tests for NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Tests.HollowsHunter;

interface

uses
  System.SysUtils,
  DUnitX.TestFramework;

type
  [TestFixture]
  THollowsHunterIntegrationTests = class
  private
    FRoot: string;
    FRunDir: string;
    FReferenceDir: string;
    FNativeDir: string;
    FTarget64: string;
    FTarget32: string;
    FHostVersion: string;
    FReferenceVersion: string;
    procedure RunScenario(const Scenario: string; Is32Bit: Boolean);
  public
    [SetupFixture] procedure Prepare;
    [Test] procedure Clean64;
    [Test] procedure HeaderPatch64;
    [Test] procedure CodePatch64;
    [Test] procedure PrivatePe64;
    [Test] procedure Clean32;
    [Test] procedure PrivatePe32;
  end;

  [TestFixture]
  THollowsHunterComparisonTests = class
  public
    [Test] procedure ObjectOrderIsIrrelevant;
    [Test] procedure UnexpectedFieldFails;
    [Test] procedure MissingAndNullDiffer;
    [Test] procedure ArrayOrderIsPreserved;
    [Test] procedure QuotedIntegerFails;
    [Test] procedure UnknownDifferenceFails;
    [Test] procedure MissingBinaryFails;
    [Test] procedure WrongVersionFails;
    [Test] procedure InconsistentTimestampFails;
    [Test] procedure ExcessiveDurationFails;
  end;

implementation

uses
  Winapi.Windows,
  System.Classes,
  System.JSON,
  System.IOUtils,
  System.Hash,
  System.DateUtils,
  NativePe.PeLoader,
  NativePe.PeHdrsHelper,
  NativePe.BufferUtil,
  NativePe.ExportsLookup,
  NativeMirror.Tests.Support;

type
  EHHContract = class(Exception);

  TToolResult = record
    StdOut: string;
    StdErr: string;
    ExitCode: DWORD;
    Started: TDateTime;
    Finished: TDateTime;
    ElapsedMs: UInt64;
  end;

const
  ScanTimeout = DWORD(60000);
  NativeVersion = Cardinal($00040105);
  ReferenceVersion = Cardinal($00040101);

procedure Require(Condition: Boolean; const Detail: string);
begin
  if not Condition then raise EHHContract.Create(Detail);
end;

procedure RequireFile(const FilePath: string);
begin
  Require(TFile.Exists(FilePath), 'Required file missing: ' + FilePath);
end;

function FileHash(const FilePath: string): string;
begin
  RequireFile(FilePath);
  Result := THashSHA2.GetHashStringFromFile(FilePath).ToLower;
end;

function ReadJson(const FilePath: string): TJSONObject;
var
  Value: TJSONValue;
begin
  RequireFile(FilePath);
  Value := TJSONObject.ParseJSONValue(TFile.ReadAllText(FilePath, TEncoding.UTF8));
  if not (Value is TJSONObject) then
  begin
    Value.Free;
    raise EHHContract.Create('Expected JSON object: ' + FilePath);
  end;
  Result := TJSONObject(Value);
end;

function RequiredText(Json: TJSONObject; const Name: string): string;
var
  Value: TJSONValue;
begin
  Value := Json.GetValue(Name);
  Require(Value is TJSONString, Name + ': expected JSON string');
  Result := Value.Value;
  Require(Result <> '', Name + ': empty string');
end;

function RequiredInteger(Json: TJSONObject; const Name: string): Int64;
var
  Value: TJSONValue;
begin
  Value := Json.GetValue(Name);
  Require(Value is TJSONNumber, Name + ': expected JSON number');
  Require(TryStrToInt64(Value.Value, Result), Name + ': expected integer');
end;

procedure CompareJson(Expected, Actual: TJSONValue; const JsonPath: string);
var
  LeftObject, RightObject: TJSONObject;
  LeftArray, RightArray: TJSONArray;
  I, J: Integer;
  Key: string;
begin
  Require(Assigned(Expected) and Assigned(Actual), JsonPath + ': missing value');
  Require(Expected.ClassType = Actual.ClassType, JsonPath + ': JSON type differs');
  if Expected is TJSONObject then
  begin
    LeftObject := TJSONObject(Expected);
    RightObject := TJSONObject(Actual);
    Require(LeftObject.Count = RightObject.Count, JsonPath + ': field count differs');
    for I := 0 to RightObject.Count - 1 do
      for J := 0 to I - 1 do
        Require(RightObject.Pairs[I].JsonString.Value <> RightObject.Pairs[J].JsonString.Value,
          JsonPath + ': duplicate field');
    for I := 0 to LeftObject.Count - 1 do
    begin
      Key := LeftObject.Pairs[I].JsonString.Value;
      for J := 0 to I - 1 do
        Require(Key <> LeftObject.Pairs[J].JsonString.Value, JsonPath + ': duplicate field');
      CompareJson(LeftObject.Pairs[I].JsonValue, RightObject.GetValue(Key), JsonPath + '/' + Key);
    end;
  end
  else if Expected is TJSONArray then
  begin
    LeftArray := TJSONArray(Expected);
    RightArray := TJSONArray(Actual);
    Require(LeftArray.Count = RightArray.Count, JsonPath + ': array length differs');
    for I := 0 to LeftArray.Count - 1 do
      CompareJson(LeftArray.Items[I], RightArray.Items[I], JsonPath + '/' + IntToStr(I));
  end
  else
    Require(Expected.Value = Actual.Value,
      JsonPath + ': expected ' + Expected.ToJSON + ', got ' + Actual.ToJSON);
end;

procedure CheckImage(const FilePath: string; Expected64Bit, ExpectedDll: Boolean;
  ExpectedVersion: Cardinal = 0);
var
  Image: PByte;
  Size: NativeUInt;
  ExportAddress: FARPROC;
  ExportName: AnsiString;
begin
  RequireFile(FilePath);
  Image := LoadPeModule(FilePath, Size, False, False);
  Require(Image <> nil, 'Invalid PE image: ' + FilePath);
  try
    Require(Is64Bit(Image) = Expected64Bit, 'Wrong architecture: ' + FilePath);
    Require(IsModuleDll(Image) = ExpectedDll, 'Wrong EXE/DLL type: ' + FilePath);
    if ExpectedVersion <> 0 then
    begin
      ExportName := 'PESieve_version';
      ExportAddress := GetExportedFunc(Image, PAnsiChar(ExportName));
      Require(Assigned(ExportAddress), 'Missing PESieve_version: ' + FilePath);
      Require(ValidatePtr(Image, Size, Pointer(ExportAddress), SizeOf(Cardinal)),
        'Version export outside image: ' + FilePath);
      Require(PCardinal(Pointer(ExportAddress))^ = ExpectedVersion,
        'Wrong version data export: ' + FilePath);
    end;
  finally
    FreePeBuffer(Image, Size);
  end;
end;

function RunTool(const ExePath, Arguments, WorkDir: string): TToolResult;
var
  Security: TSecurityAttributes;
  Startup: TStartupInfo;
  ProcessInfo: TProcessInformation;
  OutHandle, ErrHandle, InHandle: THandle;
  CommandLine, OutPath, ErrPath: string;
  StartedTick: UInt64;
  WaitResult: DWORD;
  Meta: TJSONObject;
begin
  Result := Default(TToolResult);
  OutHandle := INVALID_HANDLE_VALUE;
  ErrHandle := INVALID_HANDLE_VALUE;
  InHandle := INVALID_HANDLE_VALUE;
  OutPath := TPath.Combine(WorkDir, 'stdout.txt');
  ErrPath := TPath.Combine(WorkDir, 'stderr.txt');
  CommandLine := '"' + ExePath + '" ' + Arguments;
  TFile.WriteAllText(TPath.Combine(WorkDir, 'command.txt'), CommandLine, TEncoding.UTF8);
  FillChar(Security, SizeOf(Security), 0);
  Security.nLength := SizeOf(Security);
  Security.bInheritHandle := True;
  try
    OutHandle := CreateFile(PChar(OutPath), GENERIC_WRITE, FILE_SHARE_READ,
      @Security, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
    if OutHandle = INVALID_HANDLE_VALUE then RaiseLastOSError;
    ErrHandle := CreateFile(PChar(ErrPath), GENERIC_WRITE, FILE_SHARE_READ,
      @Security, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
    if ErrHandle = INVALID_HANDLE_VALUE then RaiseLastOSError;
    InHandle := CreateFile('NUL', GENERIC_READ, FILE_SHARE_READ or FILE_SHARE_WRITE,
      @Security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if InHandle = INVALID_HANDLE_VALUE then RaiseLastOSError;
    FillChar(Startup, SizeOf(Startup), 0);
    Startup.cb := SizeOf(Startup);
    Startup.dwFlags := STARTF_USESTDHANDLES;
    Startup.hStdOutput := OutHandle;
    Startup.hStdError := ErrHandle;
    Startup.hStdInput := InHandle;
    FillChar(ProcessInfo, SizeOf(ProcessInfo), 0);
    UniqueString(CommandLine);
    Result.Started := Now;
    StartedTick := GetTickCount64;
    if not CreateProcess(PChar(ExePath), PChar(CommandLine), nil, nil, True,
      CREATE_NO_WINDOW, nil, PChar(WorkDir), Startup, ProcessInfo) then RaiseLastOSError;
    CloseHandle(ProcessInfo.hThread);
    try
      WaitResult := WaitForSingleObject(ProcessInfo.hProcess, ScanTimeout);
      if WaitResult <> WAIT_OBJECT_0 then
      begin
        TerminateProcess(ProcessInfo.hProcess, 255);
        WaitForSingleObject(ProcessInfo.hProcess, 5000);
        Require(False, 'Child process timeout/wait error: ' + CommandLine);
      end;
      if not GetExitCodeProcess(ProcessInfo.hProcess, Result.ExitCode) then RaiseLastOSError;
    finally
      Result.Finished := Now;
      Result.ElapsedMs := GetTickCount64 - StartedTick;
      CloseHandle(ProcessInfo.hProcess);
    end;
  finally
    if InHandle <> INVALID_HANDLE_VALUE then CloseHandle(InHandle);
    if ErrHandle <> INVALID_HANDLE_VALUE then CloseHandle(ErrHandle);
    if OutHandle <> INVALID_HANDLE_VALUE then CloseHandle(OutHandle);
  end;
  Result.StdOut := TFile.ReadAllText(OutPath, TEncoding.UTF8);
  Result.StdErr := TFile.ReadAllText(ErrPath, TEncoding.UTF8);
  Meta := TJSONObject.Create;
  try
    Meta.AddPair('exe', ExePath);
    Meta.AddPair('arguments', Arguments);
    Meta.AddPair('working_directory', WorkDir);
    Meta.AddPair('exit_code', TJSONNumber.Create(Result.ExitCode));
    Meta.AddPair('elapsed_ms', TJSONNumber.Create(Result.ElapsedMs));
    Meta.AddPair('started_local', FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', Result.Started));
    Meta.AddPair('finished_local', FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', Result.Finished));
    TFile.WriteAllText(TPath.Combine(WorkDir, 'process.json'), Meta.ToJSON, TEncoding.UTF8);
  finally
    Meta.Free;
  end;
end;

function ParseReport(const Run: TToolResult; const HostVersion, PeVersion: string;
  out Prefix: string): TJSONObject;
var
  First: Integer;
  Value: TJSONValue;
  VersionLine: string;
begin
  Require(Run.StdErr = '', 'Unexpected stderr: ' + Run.StdErr);
  First := Pos('{', Run.StdOut);
  Require(First > 0, 'HollowsHunter produced no JSON');
  Prefix := Copy(Run.StdOut, 1, First - 1);
  Require(Pos('HollowsHunter v.' + HostVersion + ' (x64)', Prefix) > 0,
    'Unexpected HollowsHunter version banner');
  VersionLine := 'using: PE-sieve v.' + PeVersion;
  Require(Pos(VersionLine + #13, Prefix) > 0, 'Unexpected PE-sieve version banner');
  Require(Pos(VersionLine, Copy(Prefix, Pos(VersionLine, Prefix) + Length(VersionLine), MaxInt)) = 0,
    'Duplicate PE-sieve version banner');
  Prefix := StringReplace(Prefix, VersionLine, 'using: PE-sieve v.<validated>', []);
  Value := TJSONObject.ParseJSONValue(Copy(Run.StdOut, First, MaxInt));
  if not (Value is TJSONObject) then
  begin
    Value.Free;
    raise EHHContract.Create('Invalid HollowsHunter JSON');
  end;
  Result := TJSONObject(Value);
end;

procedure NormalizeTimes(Json: TJSONObject; const Run: TToolResult);
var
  Text: string;
  Stamp, Duration, Lower, Upper: Int64;
  Parsed: TDateTime;
  Settings: TFormatSettings;
begin
  Text := RequiredText(Json, 'scan_date_time');
  Stamp := RequiredInteger(Json, 'scan_timestamp');
  Duration := RequiredInteger(Json, 'scan_time_ms');
  Settings := TFormatSettings.Create('en-US');
  Settings.DateSeparator := '/';
  Settings.TimeSeparator := ':';
  Settings.ShortDateFormat := 'mm/dd/yy';
  Settings.ShortTimeFormat := 'hh:nn:ss';
  Settings.LongTimeFormat := 'hh:nn:ss';
  Require(TryStrToDateTime(Text, Parsed, Settings), 'Invalid scan_date_time');
  Require(FormatDateTime('mm/dd/yy hh:nn:ss', Parsed, Settings) = Text,
    'Unexpected scan_date_time format');
  Require(DateTimeToUnix(Parsed, False) = Stamp, 'Date string and timestamp differ');
  Lower := DateTimeToUnix(Run.Started, False) - 2;
  Upper := DateTimeToUnix(Run.Finished, False) + 2;
  Require((Stamp >= Lower) and (Stamp <= Upper), 'Timestamp outside process execution');
  Require((Duration >= 0) and (Duration < ScanTimeout) and
    (UInt64(Duration) <= Run.ElapsedMs + 1000), 'Invalid scan_time_ms');
  Json.RemovePair('scan_date_time').Free;
  Json.RemovePair('scan_timestamp').Free;
  Json.RemovePair('scan_time_ms').Free;
end;

procedure ValidateScenario(Json: TJSONObject; const Run: TToolResult;
  Target: TTargetProcess; const Scenario: string);
const
  Categories: array[0..6] of string = ('replaced', 'hdr_modified', 'patched',
    'implanted_pe', 'implanted_shc', 'unreachable_file', 'other');
var
  Items: TJSONArray;
  Item: TJSONObject;
  Value: TJSONValue;
  Name, ExpectedField: string;
  Expected: Int64;
begin
  Require(RequiredInteger(Json, 'scanned_count') = 1, 'Expected exactly one scanned target');
  Require(RequiredInteger(Json, 'failed_count') = 0, 'HollowsHunter scan failed');
  if Scenario = 'Clean' then
  begin
    Require(Run.ExitCode = 1, 'Unexpected clean exit code');
    Require(RequiredInteger(Json, 'suspicious_count') = 0, 'Clean target has false positives');
    Require(Json.GetValue('suspicious') = nil, 'Unexpected suspicious list for clean target');
    Exit;
  end;
  Require(Run.ExitCode = 2, 'Unexpected detection exit code');
  Require(RequiredInteger(Json, 'suspicious_count') = 1, 'Expected one suspicious target');
  Value := Json.GetValue('suspicious');
  Require(Value is TJSONArray, 'Missing suspicious array');
  Items := TJSONArray(Value);
  Require(Items.Count = 1, 'Unexpected suspicious array length');
  Require(Items.Items[0] is TJSONObject, 'Invalid suspicious process');
  Item := TJSONObject(Items.Items[0]);
  Require(RequiredInteger(Item, 'pid') = Target.Pid, 'Suspicious PID differs from fixture PID');
  Require(RequiredInteger(Item, 'is_managed') = 0, 'Fixture must not be managed');
  Require(RequiredText(Item, 'name') = ExtractFileName(Target.ModulePath), 'Wrong fixture name');
  ExpectedField := '';
  if Scenario = 'HeaderPatch' then ExpectedField := 'hdr_modified'
  else if Scenario = 'CodePatch' then ExpectedField := 'patched'
  else if Scenario = 'PrivatePe' then ExpectedField := 'implanted_pe';
  Require(ExpectedField <> '', 'Unknown expected scenario');
  for Name in Categories do
  begin
    if Name = ExpectedField then Expected := 1 else Expected := 0;
    Require(RequiredInteger(Item, Name) = Expected, 'Unexpected category: ' + Name);
  end;
end;

procedure THollowsHunterIntegrationTests.Prepare;
var
  Base, Fixtures, Host, ReferenceDll, NativeDll, NativeEvidence, Candidate: string;
  HostHash, ReferenceHash, NativeHash: string;
  Manifest, Evidence, Snapshot: TJSONObject;
  Id: TGUID;
begin
  FRoot := GetEnvironmentVariable('NATIVEMIRROR_TEST_ROOT');
  Base := ExtractFilePath(ParamStr(0));
  if FRoot = '' then FRoot := ExpandFileName(TPath.Combine(Base, '..\..\..'));
  FRoot := ExpandFileName(FRoot);
  RequireFile(TPath.Combine(FRoot, 'AGENTS.md'));
  CreateGUID(Id);
  FRunDir := TPath.Combine(FRoot, 'parity-work\hollows-hunter-delphi-' +
    FormatDateTime('yyyymmdd-hhnnss-zzz', Now) + '-' + GUIDToString(Id));
  TDirectory.CreateDirectory(FRunDir);
  Writeln('HollowsHunter artifacts: ' + FRunDir);
  Fixtures := TPath.Combine(FRoot, 'tests\HollowsHunterIntegration\fixtures\Win64\pe-sieve-C');
  Manifest := ReadJson(TPath.Combine(Fixtures, 'manifest.json'));
  try
    FHostVersion := RequiredText(Manifest, 'hollows_hunter_version');
    FReferenceVersion := RequiredText(Manifest, 'pe_sieve_version');
    Require(FHostVersion = '0.4.1.1', 'Unverified HollowsHunter fixture version');
    Require(FReferenceVersion = '0.4.1.1', 'Unverified original PE-sieve fixture version');
    Host := TPath.Combine(Fixtures, 'hollows_hunter.exe');
    ReferenceDll := TPath.Combine(Fixtures, 'pe-sieve.dll');
    HostHash := RequiredText(Manifest, 'hollows_hunter_sha256');
    ReferenceHash := RequiredText(Manifest, 'pe_sieve_sha256');
    Require(FileHash(Host) = HostHash, 'Original EXE hash differs');
    Require(FileHash(ReferenceDll) = ReferenceHash, 'Original DLL hash differs');
    NativeDll := TPath.Combine(Base, 'pe-sieve.dll');
    NativeEvidence := NativeDll + '.exports.json';
    Evidence := ReadJson(NativeEvidence);
    try
      NativeHash := RequiredText(Evidence, 'sha256');
      Require(FileHash(NativeDll) = NativeHash, 'Native DLL finalization hash differs');
      Require(RequiredInteger(Evidence, 'version') = NativeVersion, 'Native finalization version differs');
    finally
      Evidence.Free;
    end;
    Require(FileHash(ReferenceDll) <> FileHash(NativeDll), 'Reference and NativeMirror DLL are identical');
    CheckImage(Host, True, False);
    CheckImage(ReferenceDll, True, True, ReferenceVersion);
    CheckImage(NativeDll, True, True, NativeVersion);
    FTarget64 := TPath.Combine(Base, 'NativeMirrorTestTarget.exe');
    FTarget32 := GetEnvironmentVariable('NATIVEMIRROR_TARGET32_EXE');
    if FTarget32 = '' then
    begin
      Candidate := TPath.Combine(FRoot, 'bin\Win32\' + ExtractFileName(ExcludeTrailingPathDelimiter(Base)) +
        '\NativeMirrorTestTarget32.exe');
      if TFile.Exists(Candidate) then FTarget32 := Candidate
      else FTarget32 := TPath.Combine(Base, 'NativeMirrorTestTarget32.exe');
    end;
    CheckImage(FTarget64, True, False);
    CheckImage(FTarget32, False, False);
    FReferenceDir := TPath.Combine(FRunDir, 'pe-sieve-C');
    FNativeDir := TPath.Combine(FRunDir, 'pe-sieve-Pas');
    TDirectory.CreateDirectory(FReferenceDir);
    TDirectory.CreateDirectory(FNativeDir);
    TFile.Copy(Host, TPath.Combine(FReferenceDir, 'hollows_hunter.exe'), False);
    TFile.Copy(Host, TPath.Combine(FNativeDir, 'hollows_hunter.exe'), False);
    TFile.Copy(ReferenceDll, TPath.Combine(FReferenceDir, 'pe-sieve.dll'), False);
    TFile.Copy(NativeDll, TPath.Combine(FNativeDir, 'pe-sieve.dll'), False);
    Require(FileHash(TPath.Combine(FNativeDir, 'hollows_hunter.exe')) = HostHash, 'Native host copy differs');
    Require(FileHash(TPath.Combine(FReferenceDir, 'hollows_hunter.exe')) = HostHash, 'Reference host copy differs');
    Require(FileHash(TPath.Combine(FReferenceDir, 'pe-sieve.dll')) = ReferenceHash, 'Reference DLL copy differs');
    Require(FileHash(TPath.Combine(FNativeDir, 'pe-sieve.dll')) = NativeHash, 'Native DLL copy differs');
    TFile.Copy(TPath.Combine(Fixtures, 'manifest.json'), TPath.Combine(FRunDir, 'reference-manifest.json'), False);
    TFile.Copy(NativeEvidence, TPath.Combine(FRunDir, 'native-exports.json'), False);
    Evidence := ReadJson(TPath.Combine(FRunDir, 'native-exports.json'));
    try
      Require(RequiredText(Evidence, 'sha256') = NativeHash, 'Native export evidence changed during preparation');
    finally
      Evidence.Free;
    end;
    Snapshot := TJSONObject.Create;
    try
      Snapshot.AddPair('reference_dll', ReferenceDll);
      Snapshot.AddPair('native_dll', NativeDll);
      Snapshot.AddPair('native_sha256', NativeHash);
      Snapshot.AddPair('target64', FTarget64);
      Snapshot.AddPair('target64_sha256', FileHash(FTarget64));
      Snapshot.AddPair('target32', FTarget32);
      Snapshot.AddPair('target32_sha256', FileHash(FTarget32));
      Snapshot.AddPair('reference_version', FReferenceVersion);
      Snapshot.AddPair('native_version', '0.4.1.5');
      TFile.WriteAllText(TPath.Combine(FRunDir, 'inputs.json'), Snapshot.ToJSON, TEncoding.UTF8);
    finally
      Snapshot.Free;
    end;
  finally
    Manifest.Free;
  end;
end;

procedure THollowsHunterIntegrationTests.RunScenario(const Scenario: string; Is32Bit: Boolean);
var
  Target: TTargetProcess;
  ReferenceRun, NativeRun: TToolResult;
  ReferenceJson, NativeJson, Status: TJSONObject;
  CaseDir, ReferenceWork, NativeWork, Arguments, ReferencePrefix, NativePrefix: string;
  Passed: Boolean;
begin
  if Is32Bit then CaseDir := 'WOW64-' else CaseDir := 'Win64-';
  CaseDir := TPath.Combine(FRunDir, CaseDir + Scenario);
  ReferenceWork := TPath.Combine(CaseDir, 'pe-sieve-C');
  NativeWork := TPath.Combine(CaseDir, 'pe-sieve-Pas');
  TDirectory.CreateDirectory(ReferenceWork);
  TDirectory.CreateDirectory(NativeWork);
  Passed := False;
  ReferenceJson := nil;
  NativeJson := nil;
  Target := nil;
  Status := TJSONObject.Create;
  try
    try
      if Is32Bit then Target := TScannerHarness.StartTargetWithExe(FTarget32, Scenario)
      else Target := TScannerHarness.StartTargetWithExe(FTarget64, Scenario);
      Status.AddPair('pid', TJSONNumber.Create(Target.Pid));
      Status.AddPair('scenario', Scenario);
      Status.AddPair('target_module', Target.ModulePath);
      Arguments := '/pid ' + UIntToStr(Target.Pid) + ' /quiet /hooks /ofilter 2 /json /report 7';
      ReferenceRun := RunTool(TPath.Combine(FReferenceDir, 'hollows_hunter.exe'), Arguments, ReferenceWork);
      NativeRun := RunTool(TPath.Combine(FNativeDir, 'hollows_hunter.exe'), Arguments, NativeWork);
      ReferenceJson := ParseReport(ReferenceRun, FHostVersion, FReferenceVersion, ReferencePrefix);
      NativeJson := ParseReport(NativeRun, FHostVersion, '0.4.1.5', NativePrefix);
      Require(ReferencePrefix = NativePrefix, 'stdout differs outside the validated PE-sieve version banner');
      ValidateScenario(ReferenceJson, ReferenceRun, Target, Scenario);
      ValidateScenario(NativeJson, NativeRun, Target, Scenario);
      Assert.AreEqual(Integer(ReferenceRun.ExitCode), Integer(NativeRun.ExitCode), 'HollowsHunter exit codes differ');
      NormalizeTimes(ReferenceJson, ReferenceRun);
      NormalizeTimes(NativeJson, NativeRun);
      TFile.WriteAllText(TPath.Combine(ReferenceWork, 'normalized.json'), ReferenceJson.ToJSON, TEncoding.UTF8);
      TFile.WriteAllText(TPath.Combine(NativeWork, 'normalized.json'), NativeJson.ToJSON, TEncoding.UTF8);
      CompareJson(ReferenceJson, NativeJson, '');
      Passed := True;
      Assert.IsTrue(Passed, 'HollowsHunter comparison completed');
    except
      on E: Exception do
      begin
        Status.AddPair('error', E.ClassName + ': ' + E.Message);
        raise;
      end;
    end;
  finally
    if Passed then Status.AddPair('status', 'passed') else Status.AddPair('status', 'failed');
    Status.AddPair('normalized_fields', 'scan_date_time,scan_timestamp,scan_time_ms');
    try
      TFile.WriteAllText(TPath.Combine(CaseDir, 'comparison.json'), Status.ToJSON, TEncoding.UTF8);
    finally
      Status.Free;
      ReferenceJson.Free;
      NativeJson.Free;
      Target.Free;
    end;
  end;
end;

procedure THollowsHunterIntegrationTests.Clean64;
begin
  RunScenario('Clean', False);
end;

procedure THollowsHunterIntegrationTests.HeaderPatch64;
begin
  RunScenario('HeaderPatch', False);
end;

procedure THollowsHunterIntegrationTests.CodePatch64;
begin
  RunScenario('CodePatch', False);
end;

procedure THollowsHunterIntegrationTests.PrivatePe64;
begin
  RunScenario('PrivatePe', False);
end;

procedure THollowsHunterIntegrationTests.Clean32;
begin
  RunScenario('Clean', True);
end;

procedure THollowsHunterIntegrationTests.PrivatePe32;
begin
  RunScenario('PrivatePe', True);
end;

procedure CompareTexts(const Expected, Actual: string);
var
  Left, Right: TJSONValue;
begin
  Left := TJSONObject.ParseJSONValue(Expected);
  Right := TJSONObject.ParseJSONValue(Actual);
  try
    CompareJson(Left, Right, '');
  finally
    Left.Free;
    Right.Free;
  end;
end;

procedure ExpectFailure(const Action: TProc);
var
  Raised: Boolean;
begin
  Raised := False;
  try
    Action;
  except
    on E: EHHContract do Raised := True;
  end;
  Assert.IsTrue(Raised, 'Contract violation must fail');
end;

procedure THollowsHunterComparisonTests.ObjectOrderIsIrrelevant;
begin
  CompareTexts('{"a":1,"b":2}', '{"b":2,"a":1}');
  Assert.IsTrue(True);
end;

procedure THollowsHunterComparisonTests.UnexpectedFieldFails;
begin
  ExpectFailure(procedure begin CompareTexts('{"a":1}', '{"a":1,"extra":0}'); end);
end;

procedure THollowsHunterComparisonTests.MissingAndNullDiffer;
begin
  ExpectFailure(procedure begin CompareTexts('{"a":null}', '{"b":null}'); end);
end;

procedure THollowsHunterComparisonTests.ArrayOrderIsPreserved;
begin
  ExpectFailure(procedure begin CompareTexts('[1,2]', '[2,1]'); end);
end;

procedure THollowsHunterComparisonTests.QuotedIntegerFails;
var
  Json: TJSONObject;
begin
  Json := TJSONObject.ParseJSONValue('{"scan_time_ms":"1"}') as TJSONObject;
  try
    ExpectFailure(procedure begin RequiredInteger(Json, 'scan_time_ms'); end);
  finally
    Json.Free;
  end;
end;

procedure THollowsHunterComparisonTests.UnknownDifferenceFails;
begin
  ExpectFailure(procedure begin CompareTexts('{"new":{"x":1}}', '{"new":{"x":2}}'); end);
end;

procedure THollowsHunterComparisonTests.MissingBinaryFails;
var
  Id: TGUID;
  FilePath: string;
begin
  CreateGUID(Id);
  FilePath := TPath.Combine(ExtractFilePath(ParamStr(0)), GUIDToString(Id) + '.missing');
  ExpectFailure(procedure begin RequireFile(FilePath); end);
end;

procedure THollowsHunterComparisonTests.WrongVersionFails;
var
  Run: TToolResult;
  Prefix: string;
  Json: TJSONObject;
begin
  Run := Default(TToolResult);
  Run.StdOut := 'HollowsHunter v.0.4.1.1 (x64)' + #13#10 +
    'using: PE-sieve v.0.4.1.1' + #13#10 + '{}';
  ExpectFailure(
    procedure
    begin
      Json := ParseReport(Run, '0.4.1.1', '0.4.1.5', Prefix);
      Json.Free;
    end);
end;

procedure CheckBadTiming(WrongTimestamp: Boolean);
var
  Run: TToolResult;
  Json: TJSONObject;
  Stamp: Int64;
begin
  Run := Default(TToolResult);
  Run.Started := EncodeDate(2026, 10, 17) + EncodeTime(10, 54, 16, 0);
  Run.Finished := IncSecond(Run.Started, 1);
  Run.ElapsedMs := 1000;
  Stamp := DateTimeToUnix(Run.Started, False);
  if WrongTimestamp then Inc(Stamp);
  Json := TJSONObject.Create;
  try
    Json.AddPair('scan_date_time', '10/17/26 10:54:16');
    Json.AddPair('scan_timestamp', TJSONNumber.Create(Stamp));
    if WrongTimestamp then Json.AddPair('scan_time_ms', TJSONNumber.Create(1))
    else Json.AddPair('scan_time_ms', TJSONNumber.Create(60000));
    ExpectFailure(procedure begin NormalizeTimes(Json, Run); end);
  finally
    Json.Free;
  end;
end;

procedure THollowsHunterComparisonTests.InconsistentTimestampFails;
begin
  CheckBadTiming(True);
end;

procedure THollowsHunterComparisonTests.ExcessiveDurationFails;
begin
  CheckBadTiming(False);
end;

initialization
  TDUnitX.RegisterTestFixture(THollowsHunterIntegrationTests);
  TDUnitX.RegisterTestFixture(THollowsHunterComparisonTests);

end.
