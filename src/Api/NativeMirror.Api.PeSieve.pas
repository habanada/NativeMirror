{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Api.PeSieve;

interface

uses
  Winapi.Windows;

type
  TPeSieveParamString = packed record
    Length: Cardinal;
{$IFDEF WIN64}
    Reserved: Cardinal;
{$ENDIF}
    Buffer: PAnsiChar;
  end;

  TPeSieveParams = packed record
    Pid: Cardinal;
    DotNetPolicy: Integer;
    ImportRecoveryMode: Integer;
    Quiet: Byte;
    Reserved1: array[0..2] of Byte;
    OutputFilter: Integer;
    NoHooks: Byte;
    Reserved2: array[0..2] of Byte;
    ShellcodeMode: Integer;
    ObfuscationMode: Integer;
    ScanThreads: Byte;
    Reserved3: array[0..2] of Byte;
    IatScanMode: Integer;
    DataScanMode: Integer;
    MakeMiniDump: Byte;
    Rebase: Byte;
    Reserved4: array[0..1] of Byte;
    DumpMode: Integer;
    JsonOutput: Byte;
    MakeReflection: Byte;
    UseCache: Byte;
    DownloadSymbols: Byte;
    JsonLevel: Integer;
    ResultsFilter: Cardinal;
    OutputDirectory: array[0..MAX_PATH] of AnsiChar;
    Reserved5: array[0..2] of Byte;
    IgnoredModules: TPeSieveParamString;
    PatternFile: TPeSieveParamString;
  end;
  PPeSieveParams = ^TPeSieveParams;

  TPeSieveReport = packed record
    Pid: Cardinal;
    IsManaged: Byte;
    Is64Bit: Byte;
    IsReflection: Byte;
    Reserved: Byte;
    Scanned: Cardinal;
    Suspicious: Cardinal;
    Replaced: Cardinal;
    HeaderModified: Cardinal;
    UnreachableFile: Cardinal;
    Patched: Cardinal;
    IatHooked: Cardinal;
    Implanted: Cardinal;
    ImplantedPe: Cardinal;
    ImplantedShellcode: Cardinal;
    Other: Cardinal;
    Skipped: Cardinal;
    Errors: Cardinal;
  end;
  PPeSieveReport = ^TPeSieveReport;

function PESieve_scan(ReturnBuffer: PPeSieveReport; Args: PPeSieveParams): PPeSieveReport; cdecl;
function PESieve_scan_ex(ReturnBuffer: PPeSieveReport; Args: PPeSieveParams;
  ReportType: Integer; JsonBuffer: PAnsiChar; JsonBufferSize: NativeUInt;
  NeededSize: PNativeUInt): PPeSieveReport; cdecl;
procedure PESieve_help; cdecl;

implementation

uses
  System.SysUtils,
  System.JSON,
  NativeMirror.Core.Types,
  NativeMirror.Core.Options,
  NativeMirror.Core.Engine;

procedure WriteApiMessage(Kind: TNativeMirrorEngineMessageKind; const Text: string);
var
  Handle: THandle;
  Bytes: TBytes;
  Written: DWORD;
begin
  if Kind = nmEngineError then Handle := GetStdHandle(STD_ERROR_HANDLE)
  else Handle := GetStdHandle(STD_OUTPUT_HANDLE);
  if (Handle = 0) or (Handle = INVALID_HANDLE_VALUE) then Exit;
  Bytes := TEncoding.Default.GetBytes(Text + #13#10);
  if Length(Bytes) <> 0 then
    WriteFile(Handle, Bytes[0], Length(Bytes), Written, nil);
end;

function ReadApiString(const Value: TPeSieveParamString; Validate: Boolean): string;
begin
  Result := '';
  if (Value.Length = 0) or (Value.Buffer = nil) then Exit;
  if Validate and IsBadReadPtr(Value.Buffer, Value.Length) then Exit;
  Result := string(AnsiString(Value.Buffer));
end;

function ConvertOptions(const Args: TPeSieveParams): TNativeMirrorOptions;
var
  Count: Integer;
  Directory: AnsiString;
begin
  Result := TNativeMirrorOptions.Default;
  Result.Pid := Args.Pid;
  Result.DotNetPolicy := TNativeMirrorDotNetPolicy(Args.DotNetPolicy);
  Result.ImportRecoveryMode := TNativeMirrorImportRecoveryMode(Args.ImportRecoveryMode);
  Result.Quiet := Args.Quiet <> 0;
  Result.OutputFilter := TNativeMirrorOutputFilter(Args.OutputFilter);
  Result.NoHooks := Args.NoHooks <> 0;
  Result.ShellcodeMode := TNativeMirrorShellcodeMode(Args.ShellcodeMode);
  Result.ObfuscationMode := TNativeMirrorObfuscationMode(Args.ObfuscationMode);
  Result.ScanThreads := Args.ScanThreads <> 0;
  Result.IatScanMode := TNativeMirrorIatScanMode(Args.IatScanMode);
  Result.DataScanMode := TNativeMirrorDataScanMode(Args.DataScanMode);
  Result.MakeMiniDump := Args.MakeMiniDump <> 0;
  Result.Rebase := Args.Rebase <> 0;
  Result.DumpMode := TNativeMirrorDumpMode(Args.DumpMode);
  Result.JsonOutput := Args.JsonOutput <> 0;
  Result.MakeReflection := Args.MakeReflection <> 0;
  Result.UseCache := Args.UseCache <> 0;
  Result.DownloadSymbols := Args.DownloadSymbols <> 0;
  Result.JsonLevel := TNativeMirrorJsonLevel(Args.JsonLevel);
  Result.ResultsFilter := Args.ResultsFilter;
  Count := 0;
  while (Count < Length(Args.OutputDirectory)) and (Args.OutputDirectory[Count] <> #0) do
    Inc(Count);
  SetString(Directory, PAnsiChar(@Args.OutputDirectory[0]), Count);
  Result.OutputDirectory := string(Directory);
  Result.IgnoredModules := ReadApiString(Args.IgnoredModules, True);
  Result.PatternFile := ReadApiString(Args.PatternFile, False);
end;

procedure CopySummary(const Summary: TNativeMirrorProcessSummary; var Report: TPeSieveReport);
begin
  Report.Pid := Summary.Pid;
  Report.IsManaged := Ord(Summary.IsManaged);
  Report.Is64Bit := Ord(Summary.Is64Bit);
  Report.IsReflection := Ord(Summary.IsReflection);
  Report.Scanned := Summary.Scanned;
  Report.Suspicious := Summary.Suspicious;
  Report.Replaced := Summary.Replaced;
  Report.HeaderModified := Summary.HeaderModified;
  Report.UnreachableFile := Summary.UnreachableFile;
  Report.Patched := Summary.Patched;
  Report.IatHooked := Summary.IatHooked;
  Report.Implanted := Summary.Implanted;
  Report.ImplantedPe := Summary.ImplantedPe;
  Report.ImplantedShellcode := Summary.ImplantedShellcode;
  Report.Other := Summary.Other;
  Report.Skipped := Summary.Skipped;
  Report.Errors := Summary.Errors;
end;

function PESieve_scan_ex(ReturnBuffer: PPeSieveReport; Args: PPeSieveParams;
  ReportType: Integer; JsonBuffer: PAnsiChar; JsonBufferSize: NativeUInt;
  NeededSize: PNativeUInt): PPeSieveReport;
var
  Params: TPeSieveParams;
  Options: TNativeMirrorOptions;
  Report: TNativeMirrorReportEx;
  Json: TJSONObject;
  Bytes: TBytes;
  Required, CopySize: NativeUInt;
begin
  Result := ReturnBuffer;
  FillChar(ReturnBuffer^, SizeOf(ReturnBuffer^), 0);
  if (Args = nil) or IsBadReadPtr(Args, SizeOf(Args^)) then
  begin
    ReturnBuffer.Errors := 1;
    Exit;
  end;
  Params := Args^;
  ReturnBuffer.Pid := Params.Pid;
  ReturnBuffer.Errors := $FFFFFFFF;
  Report := nil;
  try
    try
      Options := ConvertOptions(Params);
      Report := ScanAndDump(Options,
        procedure(Kind: TNativeMirrorEngineMessageKind; const Text: string)
        begin
          WriteApiMessage(Kind, Text);
        end);
      if Report = nil then Exit;
      if Report.ScanReport <> nil then
        CopySummary(Report.ScanReport.GenerateSummary, ReturnBuffer^);
      if (JsonBuffer <> nil) and
        ((JsonBufferSize = 0) or IsBadWritePtr(JsonBuffer, JsonBufferSize)) then
      begin
        JsonBuffer := nil;
        JsonBufferSize := 0;
      end;
      if (NeededSize <> nil) and IsBadWritePtr(NeededSize, SizeOf(NativeUInt)) then
        NeededSize := nil;
      if (JsonBuffer = nil) and (NeededSize = nil) then Exit;
      Required := 0;
      if ReportType <> 0 then
      begin
        Json := Report.ToJson(Options.ResultsFilter, Options.JsonLevel,
          TNativeMirrorReportOutput(ReportType));
        try
          Bytes := TEncoding.UTF8.GetBytes(Json.ToJSON);
        finally
          Json.Free;
        end;
        if Length(Bytes) <> 0 then
        begin
          Required := NativeUInt(Length(Bytes)) + 1;
          if (JsonBuffer <> nil) and (JsonBufferSize <> 0) then
          begin
            FillChar(JsonBuffer^, JsonBufferSize, 0);
            CopySize := Length(Bytes);
            if CopySize >= JsonBufferSize then CopySize := JsonBufferSize - 1;
            if CopySize <> 0 then Move(Bytes[0], JsonBuffer^, CopySize);
          end;
        end;
      end;
      if NeededSize <> nil then NeededSize^ := Required;
    finally
      Report.Free;
    end;
  except
    ReturnBuffer.Errors := $FFFFFFFF;
  end;
end;

function PESieve_scan(ReturnBuffer: PPeSieveReport; Args: PPeSieveParams): PPeSieveReport;
begin
  Result := PESieve_scan_ex(ReturnBuffer, Args, 0, nil, 0, nil);
end;

procedure PESieve_help;
const
{$IFDEF WIN64}
  Architecture = 'x64';
{$ELSE}
  Architecture = 'x86';
{$ENDIF}
  Info = 'Version:  0.4.1.5 (' + Architecture + ')' + #10 +
    'Built on: ' + {$I NativeMirror.Api.BuildDate.inc} + #10#10 +
    '~ from hasherezade with love ~' + #10 +
    'Scans a given process, recognizes and dumps a variety of in-memory implants:' + #10 +
    'replaced/injected PEs, shellcodes, inline hooks, patches etc.' + #10 +
    'URL: https://github.com/hasherezade/pe-sieve' + #10;
var
  Handle: THandle;
  Written: DWORD;
  Text: AnsiString;
begin
  try
    Text := AnsiString(Info);
    Handle := GetStdHandle(STD_OUTPUT_HANDLE);
    if (Handle <> 0) and (Handle <> INVALID_HANDLE_VALUE) then
      WriteFile(Handle, Text[1], Length(Text), Written, nil);
    MessageBoxA(0, PAnsiChar(Text), 'PE-sieve', MB_ICONINFORMATION);
  except
  end;
end;

end.
