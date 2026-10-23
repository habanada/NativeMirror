{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Core.Text;

interface

uses
  System.Generics.Collections,
  NativeMirror.Core.Types;

function ToLowerInvariant(const Value: string): string;
function IsStringInList(const Value: string; Values: TList<string>; IgnoreCase: Boolean = True): Boolean;
function StringToList(const Value: string; Delimiter: Char; Values: TList<string>; ToLower: Boolean = False): NativeUInt;
function FormatScanSummary(const Summary: TNativeMirrorProcessSummary): string;
function FormatScanTime(const ScannedElement: string; Milliseconds: Cardinal): string;

implementation

uses
  System.SysUtils;

function ScanTimeNumber(Value: Single): string;
var
  ExponentPos, ExponentValue: Integer;
  ExponentSign: Char;
begin
  Result := FloatToStrF(Value, ffGeneral, 6, 0, TFormatSettings.Invariant).ToLower;
  ExponentPos := Pos('e', Result);
  if ExponentPos = 0 then Exit;
  ExponentValue := StrToInt(Copy(Result, ExponentPos + 1, MaxInt));
  if ExponentValue < 0 then ExponentSign := '-' else ExponentSign := '+';
  Result := Copy(Result, 1, ExponentPos - 1) + 'e' + ExponentSign +
    IntToStr(Abs(ExponentValue)).PadLeft(2, '0');
end;

function FormatScanTime(const ScannedElement: string; Milliseconds: Cardinal): string;
var
  Seconds, Minutes: Single;
begin
  Seconds := Single(Milliseconds) / 1000;
  Minutes := Single(Milliseconds) / 60000;
  Result := '[*] ' + ScannedElement + ' scanned in ' + UIntToStr(Milliseconds) + ' ms.';
  if Seconds > 0.5 then
    Result := Result + ' = ' + ScanTimeNumber(Seconds) + ' sec.';
  if Minutes > 0.5 then
    Result := Result + ' = ' + ScanTimeNumber(Minutes) + ' min.';
end;

function FormatScanSummary(const Summary: TNativeMirrorProcessSummary): string;
begin
  Result := '---' + sLineBreak +
    'PID: ' + UIntToStr(Summary.Pid) + sLineBreak +
    '---' + sLineBreak +
    'SUMMARY: ' + sLineBreak + sLineBreak +
    'Total scanned:      ' + UIntToStr(Summary.Scanned) + sLineBreak +
    'Skipped:            ' + UIntToStr(Summary.Skipped) + sLineBreak +
    '-' + sLineBreak +
    'Hooked:             ' + UIntToStr(Summary.Patched) + sLineBreak +
    'Replaced:           ' + UIntToStr(Summary.Replaced) + sLineBreak +
    'Hdrs Modified:      ' + UIntToStr(Summary.HeaderModified) + sLineBreak +
    'IAT Hooks:          ' + UIntToStr(Summary.IatHooked) + sLineBreak +
    'Implanted:          ' + UIntToStr(Summary.Implanted) + sLineBreak;
  if Summary.Implanted <> 0 then
    Result := Result +
      'Implanted PE:       ' + UIntToStr(Summary.ImplantedPe) + sLineBreak +
      'Implanted shc:      ' + UIntToStr(Summary.ImplantedShellcode) + sLineBreak;
  Result := Result +
    'Unreachable files:  ' + UIntToStr(Summary.UnreachableFile) + sLineBreak +
    'Other:              ' + UIntToStr(Summary.Other) + sLineBreak +
    '-' + sLineBreak +
    'Total suspicious:   ' + UIntToStr(Summary.Suspicious) + sLineBreak;
  if Summary.Errors <> 0 then
    Result := Result + '[!] Errors:         ' + UIntToStr(Summary.Errors) + sLineBreak;
end;

function ToLowerInvariant(const Value: string): string;
begin
  Result := LowerCase(Value);
end;

function IsStringInList(const Value: string; Values: TList<string>; IgnoreCase: Boolean): Boolean;
var
  Item: string;
begin
  Result := False;
  if Values = nil then
    Exit;
  for Item in Values do
    if (IgnoreCase and SameText(Value, Item)) or ((not IgnoreCase) and (Value = Item)) then
      Exit(True);
end;

function StringToList(const Value: string; Delimiter: Char; Values: TList<string>; ToLower: Boolean): NativeUInt;
var
  Parts: TArray<string>;
  Part: string;
  Item: string;
begin
  Result := 0;
  if Values = nil then
    Exit;
  Parts := Value.Split([Delimiter]);
  for Part in Parts do
  begin
    Item := Trim(Part);
    if Item = '' then
      Continue;
    if ToLower then
      Item := LowerCase(Item);
    if Values.IndexOf(Item) < 0 then
    begin
      Values.Add(Item);
      Inc(Result);
    end;
  end;
end;

end.
