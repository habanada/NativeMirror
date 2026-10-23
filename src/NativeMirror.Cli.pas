{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Cli;

interface

uses
  System.SysUtils,
  NativeMirror.Core.Options;

type
  TNativeMirrorCommandLine = class
  private
    FOptions: TNativeMirrorOptions;
    FOutput: string;
    function Information(const Filter: string; Extended, Missing: Boolean): string;
  public
    function Parse(const Args: TArray<string>): Boolean;
    class function HelpText: string; static;
    property Options: TNativeMirrorOptions read FOptions;
    property Output: string read FOutput;
  end;

function NativeMirrorOutputFilterText(const Options: TNativeMirrorOptions): string;
function NativeMirrorDumpModeText(const Options: TNativeMirrorOptions): string;

implementation

uses
  System.Math,
  NativeMirror.Core.Engine,
  NativeMirror.Core.Types;

const
  ParamNames: array[0..20] of string = ('data', 'dir', 'dmode', 'dnet',
    'iat', 'imp', 'jlvl', 'json', 'mignore', 'minidmp', 'obfusc', 'ofilter',
    'pattern', 'pid', 'quiet', 'rebase', 'refl', 'report', 'shellc', 'sym', 'threads');
  ParamGroups: array[0..20] of Integer = (3, 5, 4, 2, 3, 4, 5, 5, 2, 4,
    3, 5, 3, 0, 1, 4, 1, 5, 3, 1, 3);
  GroupNames: array[1..5] of string = ('1. scanner settings',
    '2. scan exclusions', '3. scan options', '4. dump options', '5. output options');

{$I NativeMirror.Cli.Descriptions.inc}

function BannerText: string;
begin
  Result := NativeMirrorInfo;
end;

function IsSwitch(const Value: string): Boolean;
begin
  Result := (Length(Value) > 1) and CharInSet(Value[1], ['/', '-']);
end;

function SwitchName(const Value: string): string;
begin
  if Value.StartsWith('--') and (Length(Value) > 2) then
    Result := Copy(Value, 3, MaxInt)
  else
    Result := Copy(Value, 2, MaxInt);
end;

function ParamIndex(const Name: string): Integer;
var
  I: Integer;
begin
  for I := Low(ParamNames) to High(ParamNames) do
    if ParamNames[I] = Name then Exit(I);
  Result := -1;
end;

function IsBooleanParam(Index: Integer): Boolean;
begin
  Result := Index in [7, 9, 14, 15, 16, 19, 20];
end;

function IsStringParam(Index: Integer): Boolean;
begin
  Result := Index in [1, 8, 12];
end;

function LoadNumber(const Value: string; out Number: UInt64; out IsHex: Boolean): Boolean;
var
  I, Start, Base, Digit: Integer;
begin
  Number := 0;
  IsHex := (Length(Value) > 2) and SameText(Copy(Value, 1, 2), '0x');
  Base := 10;
  Start := 1;
  if IsHex then
  begin
    Base := 16;
    Start := 3;
  end;
  Result := False;
  if Length(Value) < Start then Exit;
  for I := Start to Length(Value) do
  begin
    Digit := Pos(UpCase(Value[I]), '0123456789ABCDEF') - 1;
    if (Digit < 0) or (Digit >= Base) then Exit;
    if Number > (High(UInt64) - UInt64(Digit)) div UInt64(Base) then
      Number := High(UInt64)
    else
      Number := Number * UInt64(Base) + UInt64(Digit);
  end;
  Result := True;
end;

function LoadBoolean(const Value: string; out Flag: Boolean): Boolean;
var
  Number: UInt64;
  IsHex: Boolean;
begin
  Result := True;
  if SameText(Value, 'true') or SameText(Value, 'on') or SameText(Value, 'yes') then
    Flag := True
  else if SameText(Value, 'false') or SameText(Value, 'off') or SameText(Value, 'no') then
    Flag := False
  else
  begin
    Result := LoadNumber(Value, Number, IsHex) and not IsHex and (Number <= 1);
    Flag := Number = 1;
  end;
end;

function LoadEnum(Index: Integer; const Value: string; out Number: Integer): Boolean;
var
  Aliases: TArray<string>;
  I, Limit: Integer;
  Parsed: UInt64;
  IsHex: Boolean;
begin
  Aliases := nil;
  case Index of
    2: Aliases := ['A', 'V', 'U', 'R'];
    5: Aliases := ['N', 'A', 'U', 'R0', 'R1', 'R2'];
    10: Aliases := ['N', 'S', 'W', 'A'];
    18: Aliases := ['N', 'P', 'S', 'A', 'B'];
    17:
      begin
        if Value = 'S' then begin Number := 4; Exit(True); end;
        if Value = 'SE' then begin Number := 5; Exit(True); end;
        if Value = 'L' then begin Number := 7; Exit(True); end;
      end;
  end;
  for I := 0 to High(Aliases) do
    if Value = Aliases[I] then begin Number := I; Exit(True); end;
  Result := LoadNumber(Value, Parsed, IsHex);
  if not Result then Exit;
  if IsHex then Parsed := 0;
  if Parsed > High(Integer) then Exit(False);
  Number := Integer(Parsed);
  case Index of
    0, 5: Limit := 5;
    3, 18: Limit := 4;
    2, 4, 10: Limit := 3;
    6, 11: Limit := 2;
    17: Exit(Number in [4, 5, 7]);
  else
    Exit(False);
  end;
  Result := Number <= Limit;
end;

function HasKeyword(const Text, Filter: string): Boolean;
var
  A, B: string;
begin
  A := LowerCase(Text);
  B := LowerCase(Filter);
  Result := (A <> '') and (B <> '') and (A.Contains(B) or B.Contains(A));
end;

function SimilarName(const Name, Filter: string): Boolean;
var
  A, B: string;
  Previous, Current: TArray<Integer>;
  HistA, HistB: set of AnsiChar;
  I, J, Cost, Distance: Integer;
begin
  if HasKeyword(Name, Filter) then Exit(True);
  A := LowerCase(Name);
  B := LowerCase(Filter);
  if (A = '') or (B = '') then Exit(False);
  if (Length(A) < 100) and (Length(B) < 100) then
  begin
    SetLength(Previous, Length(B) + 1);
    SetLength(Current, Length(B) + 1);
    for J := 0 to Length(B) do Previous[J] := J;
    for I := 1 to Length(A) do
    begin
      Current[0] := I;
      for J := 1 to Length(B) do
      begin
        Cost := Ord(A[I] <> B[J]);
        Current[J] := Min(Min(Current[J - 1] + 1, Previous[J] + 1), Previous[J - 1] + Cost);
      end;
      for J := 0 to Length(B) do Previous[J] := Current[J];
    end;
    Distance := Previous[Length(B)];
    if ((Distance = 1) or (Distance <= Length(A) div 2)) and
      (Distance < Length(A)) and (Distance < Length(B)) then Exit(True);
  end;
  HistA := [];
  HistB := [];
  for I := 1 to Length(A) do Include(HistA, AnsiChar(A[I]));
  for I := 1 to Length(B) do Include(HistB, AnsiChar(B[I]));
  Result := HistA = HistB;
end;

function DescriptionMatches(Index: Integer; const Filter: string): Boolean;
var
  Lines: TArray<string>;
  I, Separator: Integer;
  Entry, TypeName: string;
begin
  Lines := ParamDescription(Index, True).Replace(#13, '').Split([#10]);
  Result := False;
  if Length(Lines) < 2 then Exit;
  if HasKeyword(Copy(Lines[1], 5, MaxInt), Filter) then Exit(True);
  if not IsBooleanParam(Index) and not IsStringParam(Index) and (Index <> 13) then
  begin
    Separator := Pos('<', Lines[0]);
    TypeName := Copy(Lines[0], Separator + 1, Length(Lines[0]) - Separator - 1);
    if HasKeyword(TypeName, Filter) then Exit(True);
    Entry := '';
    for I := 3 to High(Lines) do
    begin
      Separator := Pos(' - ', Lines[I]);
      if Separator > 0 then
      begin
        if HasKeyword(Entry, Filter) then Exit(True);
        Entry := Copy(Lines[I], Separator + 3, MaxInt);
      end
      else if Lines[I] <> '' then
        Entry := Entry + sLineBreak + Lines[I];
    end;
    Result := HasKeyword(Entry, Filter);
  end
  else
  begin
    Entry := '';
    for I := 2 to High(Lines) do
      if Lines[I] <> '' then
      begin
        if Entry <> '' then Entry := Entry + sLineBreak;
        Entry := Entry + Lines[I];
      end;
    Result := HasKeyword(Entry, Filter);
  end;
end;

function InfoSection(Extended: Boolean): string;
begin
  Result := sLineBreak + 'Info:' + sLineBreak +
    '/help' + sLineBreak + #9' : Print complete help.' + sLineBreak +
    '/help <string>' + sLineBreak + #9' : Print help about a given keyword.' + sLineBreak +
    '/<param> ?' + sLineBreak + #9' : Print details of a given parameter.' + sLineBreak;
  if Extended then Result := Result + #9'   Example: /data ?' + sLineBreak;
  Result := Result + '/version' + sLineBreak + #9' : Print version info.' + sLineBreak;
end;

function TNativeMirrorCommandLine.Information(const Filter: string; Extended, Missing: Boolean): string;
var
  Selected: array[0..20] of Boolean;
  I, G, Count: Integer;
begin
  for I := Low(ParamNames) to High(ParamNames) do
    Selected[I] := ((not Missing) or (I = 13)) and ((Filter = '') or
      SimilarName(ParamNames[I], Filter) or DescriptionMatches(I, Filter));
  Result := '---' + sLineBreak + sLineBreak + 'Required:' + sLineBreak;
  if Selected[13] then Result := Result + '/' + ParamDescription(13, Extended)
  else Result := Result + sLineBreak + '[...]' + sLineBreak;
  Result := Result + sLineBreak + 'Optional:' + sLineBreak;
  Count := 0;
  for G := 1 to 5 do
  begin
    for I := Low(ParamNames) to High(ParamNames) do
      if (ParamGroups[I] = G) and Selected[I] then
      begin
        Result := Result + sLineBreak + '---' + GroupNames[G] + '---' + sLineBreak;
        Break;
      end;
    for I := Low(ParamNames) to High(ParamNames) do
      if (ParamGroups[I] = G) and Selected[I] then
      begin
        Result := Result + '/' + ParamDescription(I, Extended);
        Inc(Count);
      end;
  end;
  if Count < High(ParamNames) then Result := Result + sLineBreak + '[...]' + sLineBreak;
  Result := Result + InfoSection(Extended and (Filter = '') and not Missing) + '---' + sLineBreak;
end;

class function TNativeMirrorCommandLine.HelpText: string;
var
  Parser: TNativeMirrorCommandLine;
begin
  Parser := TNativeMirrorCommandLine.Create;
  try
    Result := BannerText + Parser.Information('', True, False);
  finally
    Parser.Free;
  end;
end;

function TNativeMirrorCommandLine.Parse(const Args: TArray<string>): Boolean;
var
  I, Index, Number: Integer;
  Name, Value: string;
  HasArgument, Valid, Flag, IsHex, Failed, PidSet: Boolean;
  Parsed: UInt64;
begin
  FOptions := TNativeMirrorOptions.Default;
  FOutput := '';
  Failed := False;
  PidSet := False;
  I := 0;
  if Length(Args) = 0 then
  begin
    FOutput := BannerText + Information('', False, False);
    Exit(False);
  end;
  while I < Length(Args) do
  begin
    if not IsSwitch(Args[I]) then
    begin
      FOutput := FOutput + 'Redundant argument: ' + Args[I] + sLineBreak;
      Inc(I);
      Continue;
    end;
    Name := SwitchName(Args[I]);
    if (Name = 'version') or (Name = 'ver') then
    begin
      FOutput := FOutput + BannerText;
      Exit(False);
    end;
    if (Name = 'help') or (Name = '?') then
    begin
      Value := '';
      if (Name = 'help') and (I + 1 < Length(Args)) and not IsSwitch(Args[I + 1]) then
        Value := Args[I + 1];
      if (Value = 'version') or (Value = 'ver') then
        FOutput := FOutput + '/version' + sLineBreak + #9' : Print version info.' + sLineBreak
      else if (Value = '?') or (Value = 'help') then
        FOutput := FOutput + BannerText + InfoSection(True)
      else
      begin
        if Value = '' then FOutput := FOutput + BannerText;
        FOutput := FOutput + Information(Value, Name = 'help', False);
      end;
      Exit(False);
    end;
    Index := ParamIndex(Name);
    if Index < 0 then
    begin
      FOutput := FOutput + 'Invalid parameter: ' + Name + sLineBreak +
        'Similar parameters:' + sLineBreak + Information(Name, True, False);
      Exit(False);
    end;
    HasArgument := I + 1 < Length(Args);
    if HasArgument and IsBooleanParam(Index) then HasArgument := not IsSwitch(Args[I + 1]);
    Valid := False;
    Flag := True;
    Number := 0;
    Value := '';
    if HasArgument then
    begin
      Inc(I);
      Value := Args[I];
      if Value = '?' then
      begin
        FOutput := FOutput + ParamDescription(Index, True);
        Failed := True;
        Inc(I);
        Continue;
      end;
      if IsBooleanParam(Index) then Valid := LoadBoolean(Value, Flag)
      else if IsStringParam(Index) then Valid := True
      else if Index = 13 then
      begin
        Valid := LoadNumber(Value, Parsed, IsHex);
        PidSet := Valid;
        if Valid then FOptions.Pid := Cardinal(Parsed and $FFFFFFFF);
      end
      else Valid := LoadEnum(Index, Value, Number);
    end
    else if IsBooleanParam(Index) then Valid := True;
    if not Valid then
    begin
      if HasArgument then FOutput := FOutput + 'Parsing the parameter failed. Correct options:' + sLineBreak;
      FOutput := FOutput + ParamDescription(Index, True);
      Failed := True;
    end
    else
      case Index of
        0: FOptions.DataScanMode := TNativeMirrorDataScanMode(Number);
        1: FOptions.OutputDirectory := Copy(Value, 1, 259);
        2: FOptions.DumpMode := TNativeMirrorDumpMode(Number);
        3: FOptions.DotNetPolicy := TNativeMirrorDotNetPolicy(Number);
        4: FOptions.IatScanMode := TNativeMirrorIatScanMode(Number);
        5: FOptions.ImportRecoveryMode := TNativeMirrorImportRecoveryMode(Number);
        6: FOptions.JsonLevel := TNativeMirrorJsonLevel(Number);
        7: FOptions.JsonOutput := Flag;
        8: FOptions.IgnoredModules := Value;
        9: FOptions.MakeMiniDump := Flag;
        10: FOptions.ObfuscationMode := TNativeMirrorObfuscationMode(Number);
        11: FOptions.OutputFilter := TNativeMirrorOutputFilter(Number);
        12: FOptions.PatternFile := Value;
        14: FOptions.Quiet := Flag;
        15: FOptions.Rebase := Flag;
        16: FOptions.MakeReflection := Flag;
        17: FOptions.ResultsFilter := TNativeMirrorResultsFilter(Number);
        18: FOptions.ShellcodeMode := TNativeMirrorShellcodeMode(Number);
        19: FOptions.DownloadSymbols := Flag;
        20: FOptions.ScanThreads := Flag;
      end;
    Inc(I);
  end;
  if Failed then Exit(False);
  if not PidSet then
  begin
    FOutput := FOutput + 'Missing required parameters:' + sLineBreak + Information('', True, True);
    Exit(False);
  end;
  Result := True;
end;

function NativeMirrorOutputFilterText(const Options: TNativeMirrorOptions): string;
begin
  case Options.OutputFilter of
    nmOutFull: Result := 'no filter: dump everything (default)';
    nmOutNoDumps: Result := 'don''t dump the modified PEs, but save the report';
    nmOutNoDir: Result := 'don''t dump any files';
  else
    Result := '';
  end;
end;

function NativeMirrorDumpModeText(const Options: TNativeMirrorOptions): string;
begin
  case Options.DumpMode of
    nmDumpAuto: Result := 'autodetect (default)';
    nmDumpVirtual: Result := 'virtual (as is in the memory, no unmapping)';
    nmDumpUnmap: Result := 'unmapped (converted to raw using sections'' raw headers)';
    nmDumpRealign: Result := 'realigned raw (converted raw format to be the same as virtual)';
  else
    Result := '';
  end;
end;

end.
