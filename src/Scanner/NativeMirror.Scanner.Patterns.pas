{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Scanner.Patterns;

interface

uses
  Winapi.Windows;

const
  NM_PATTERN_NOT_FOUND = NativeUInt(-1);

function FindPattern(Buffer: PByte; BufferSize: NativeUInt; Pattern: PByte; PatternSize: NativeUInt; MaxIterations: NativeUInt = 0): PByte;
function Find32BitCode(Buffer: PByte; BufferSize: NativeUInt): NativeUInt;
function Find64BitCode(Buffer: PByte; BufferSize: NativeUInt): NativeUInt;
function IsCode(Buffer: PByte; BufferSize: NativeUInt): Boolean;
function IsExecutableProtection(MappingType, Protection: DWORD): Boolean;
function IsReadableProtection(MappingType, Protection: DWORD): Boolean;
function IsNormalInaccessible(State, MappingType, Protection: DWORD): Boolean;

implementation

uses
  System.SysUtils,
  NativePe.Util;

const
  Pattern32_0: array[0..2] of Byte = ($55, $8B, $EC);
  Pattern32_1: array[0..2] of Byte = ($55, $89, $E5);
  Pattern32_2: array[0..2] of Byte = ($60, $89, $E5);
  Pattern64_0: array[0..4] of Byte = ($40, $53, $48, $83, $EC);
  Pattern64_1: array[0..3] of Byte = ($55, $48, $8B, $EC);
  Pattern64_2: array[0..4] of Byte = ($40, $55, $48, $83, $EC);
  Pattern64_3: array[0..4] of Byte = ($53, $48, $81, $EC, $00);
  Pattern64_4: array[0..3] of Byte = ($48, $83, $E4, $F0);
  Pattern64_5: array[0..3] of Byte = ($57, $48, $89, $E7);
  Pattern64_6: array[0..29] of Byte = ($48,$8B,$C4,$48,$89,$58,$08,$4C,$89,$48,$20,$4C,$89,$40,$18,$48,$89,$50,$10,$55,$56,$57,$41,$54,$41,$55,$41,$56,$41,$57);

function FindPatternBounded(Buffer: PByte; BufferSize: NativeUInt; Pattern: PByte; PatternSize: NativeUInt; MaxIterations: NativeUInt; IncludeLast: Boolean): PByte;
var
  I, SearchSize: NativeUInt;
begin
  Result := nil;
  if (Buffer = nil) or (Pattern = nil) or (PatternSize = 0) or (BufferSize < PatternSize) then
    Exit;
  SearchSize := BufferSize - PatternSize;
  I := 0;
  while (I < SearchSize) or (IncludeLast and (I = SearchSize)) do
  begin
    if (MaxIterations <> 0) and (I > MaxIterations) then
      Break;
    if CompareMem(PByte(NativeUInt(Buffer) + I), Pattern, PatternSize) then
      Exit(PByte(NativeUInt(Buffer) + I));
    Inc(I);
  end;
end;

function FindPattern(Buffer: PByte; BufferSize: NativeUInt; Pattern: PByte; PatternSize: NativeUInt; MaxIterations: NativeUInt): PByte;
begin
  Result := FindPatternBounded(Buffer, BufferSize, Pattern, PatternSize, MaxIterations, False);
end;

function FindFirst(Buffer: PByte; BufferSize: NativeUInt; const Patterns: array of Pointer; const Sizes: array of NativeUInt): NativeUInt;
var
  I: Integer;
  P: PByte;
  Offset: NativeUInt;
begin
  Result := NM_PATTERN_NOT_FOUND;
  for I := 0 to High(Patterns) do
  begin
    P := FindPatternBounded(Buffer, BufferSize, Patterns[I], Sizes[I], 0, True);
    if P = nil then
      Continue;
    Offset := NativeUInt(P) - NativeUInt(Buffer);
    if (Result = NM_PATTERN_NOT_FOUND) or (Offset < Result) then
      Result := Offset;
  end;
end;

function Find32BitCode(Buffer: PByte; BufferSize: NativeUInt): NativeUInt;
var
  Patterns: array[0..2] of Pointer;
  Sizes: array[0..2] of NativeUInt;
begin
  Patterns[0] := @Pattern32_0[0]; Sizes[0] := Length(Pattern32_0);
  Patterns[1] := @Pattern32_1[0]; Sizes[1] := Length(Pattern32_1);
  Patterns[2] := @Pattern32_2[0]; Sizes[2] := Length(Pattern32_2);
  Result := FindFirst(Buffer, BufferSize, Patterns, Sizes);
end;

function Find64BitCode(Buffer: PByte; BufferSize: NativeUInt): NativeUInt;
var
  Patterns: array[0..6] of Pointer;
  Sizes: array[0..6] of NativeUInt;
begin
  Patterns[0] := @Pattern64_0[0]; Sizes[0] := Length(Pattern64_0);
  Patterns[1] := @Pattern64_1[0]; Sizes[1] := Length(Pattern64_1);
  Patterns[2] := @Pattern64_2[0]; Sizes[2] := Length(Pattern64_2);
  Patterns[3] := @Pattern64_3[0]; Sizes[3] := 4;
  Patterns[4] := @Pattern64_4[0]; Sizes[4] := Length(Pattern64_4);
  Patterns[5] := @Pattern64_5[0]; Sizes[5] := Length(Pattern64_5);
  Patterns[6] := @Pattern64_6[0]; Sizes[6] := Length(Pattern64_6);
  Result := FindFirst(Buffer, BufferSize, Patterns, Sizes);
end;

function IsCode(Buffer: PByte; BufferSize: NativeUInt): Boolean;
begin
  if (Buffer = nil) or (BufferSize = 0) or IsPadding(Buffer, BufferSize, 0) then
    Exit(False);
  Result := (Find32BitCode(Buffer, BufferSize) <> NM_PATTERN_NOT_FOUND) or (Find64BitCode(Buffer, BufferSize) <> NM_PATTERN_NOT_FOUND);
end;

function IsExecutableProtection(MappingType, Protection: DWORD): Boolean;
begin
  Result := ((Protection and PAGE_EXECUTE_READWRITE) <> 0) or ((Protection and PAGE_EXECUTE_READ) <> 0) or ((Protection and PAGE_EXECUTE) <> 0) or ((Protection and PAGE_EXECUTE_WRITECOPY) <> 0);
end;

function IsReadableProtection(MappingType, Protection: DWORD): Boolean;
begin
  Result := ((Protection and PAGE_READWRITE) <> 0) or ((Protection and PAGE_READONLY) <> 0);
end;

function IsNormalInaccessible(State, MappingType, Protection: DWORD): Boolean;
begin
  if (State and MEM_COMMIT) = 0 then
    Exit(False);
  if (MappingType <> MEM_IMAGE) and (MappingType <> MEM_MAPPED) and (MappingType <> MEM_PRIVATE) then
    Exit(False);
  Result := (Protection and PAGE_NOACCESS) <> 0;
end;

end.
