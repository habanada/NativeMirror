{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Scanner.Signatures;

interface

uses
  System.Classes,
  System.Generics.Collections;

type
  TNativeMirrorSignatureByte = record
    Value: Byte;
    Mask: Byte;
  end;

  TNativeMirrorSignature = class
  private
    FName: string;
    FBytes: TArray<TNativeMirrorSignatureByte>;
    FBuiltIn: Boolean;
  public
    constructor Create(const AName: string; const ABytes: TArray<TNativeMirrorSignatureByte>; BuiltIn: Boolean);
    function Matches(Buffer: PByte; BufferSize, Offset: NativeUInt): Boolean;
    function Length: NativeUInt;
    property Name: string read FName;
    property BuiltIn: Boolean read FBuiltIn;
  end;

  TNativeMirrorSignatureMatch = record
    Signature: TNativeMirrorSignature;
    Offset: NativeUInt;
  end;

  TNativeMirrorPatternMatcher = class
  private
    FSignatures: TObjectList<TNativeMirrorSignature>;
    function ParseElement(const S: string; out Element: TNativeMirrorSignatureByte): Boolean;
    function AddSignature(const Name: string; Elements: TStrings; BuiltIn: Boolean): Boolean;
    procedure AddBuiltIn(const Name: string; Data: PByte; Size: NativeUInt);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Clear;
    function IsReady: Boolean;
    function InitShellcodePatterns: Boolean;
    function LoadFromStream(Stream: TStream): NativeUInt;
    function LoadFromFile(const FileName: string): NativeUInt;
    function FindAll(Buffer: PByte; BufferSize: NativeUInt; Matches: TList<TNativeMirrorSignatureMatch>): NativeUInt;
    function FilterCustom(const Matches: TList<TNativeMirrorSignatureMatch>; Custom: TList<TNativeMirrorSignatureMatch>): NativeUInt;
  end;

type
  TNativeMirrorPatternMessageEvent = reference to procedure(const Text: string; IsError: Boolean);

function NativeMirrorSharedPatternMatcher: TNativeMirrorPatternMatcher;
function NativeMirrorInitializePatterns(const FileName: string; UseBuiltIns: Boolean; const OnMessage: TNativeMirrorPatternMessageEvent = nil): NativeUInt;

implementation

uses
  System.SysUtils,
  System.StrUtils,
  NativePe.Util;

const
  Pattern32_0: array[0..2] of Byte = ($55, $8B, $EC);
  Pattern32_1: array[0..2] of Byte = ($55, $89, $E5);
  Pattern32_2: array[0..2] of Byte = ($60, $89, $E5);
  Pattern64_0: array[0..4] of Byte = ($40, $53, $48, $83, $EC);
  Pattern64_1: array[0..3] of Byte = ($55, $48, $8B, $EC);
  Pattern64_2: array[0..4] of Byte = ($40, $55, $48, $83, $EC);
  Pattern64_3: array[0..3] of Byte = ($53, $48, $81, $EC);
  Pattern64_4: array[0..3] of Byte = ($48, $83, $E4, $F0);
  Pattern64_5: array[0..3] of Byte = ($57, $48, $89, $E7);
  Pattern64_6: array[0..29] of Byte = ($48,$8B,$C4,$48,$89,$58,$08,$4C,$89,$48,$20,$4C,$89,$40,$18,$48,$89,$50,$10,$55,$56,$57,$41,$54,$41,$55,$41,$56,$41,$57);

var
  GSharedMatcher: TNativeMirrorPatternMatcher;
  GPatternFileAttempted: Boolean;
  GBuiltInsInitialized: Boolean;

function NativeMirrorSharedPatternMatcher: TNativeMirrorPatternMatcher;
begin
  Result := GSharedMatcher;
end;

function NativeMirrorInitializePatterns(const FileName: string; UseBuiltIns: Boolean; const OnMessage: TNativeMirrorPatternMessageEvent): NativeUInt;
var
  Text: string;
begin
  Result := 0;
  TMonitor.Enter(GSharedMatcher);
  try
    if (FileName <> '') and not GPatternFileAttempted then
    begin
      GPatternFileAttempted := True;
      try
        Result := GSharedMatcher.LoadFromFile(FileName);
      except
        on E: EStreamError do Result := 0;
      end;
      Text := 'Added patterns: ' + UIntToStr(Result);
      if Assigned(OnMessage) then OnMessage(Text, False)
      else Writeln(Text);
    end;
    if UseBuiltIns and not GBuiltInsInitialized then
    begin
      GBuiltInsInitialized := True;
      GSharedMatcher.InitShellcodePatterns;
    end;
  finally
    TMonitor.Exit(GSharedMatcher);
  end;
end;

constructor TNativeMirrorSignature.Create(const AName: string; const ABytes: TArray<TNativeMirrorSignatureByte>; BuiltIn: Boolean);
begin
  inherited Create;
  FName := AName;
  FBytes := Copy(ABytes);
  FBuiltIn := BuiltIn;
end;

function TNativeMirrorSignature.Length: NativeUInt;
begin
  Result := System.Length(FBytes);
end;

function TNativeMirrorSignature.Matches(Buffer: PByte; BufferSize, Offset: NativeUInt): Boolean;
var
  I: NativeUInt;
  B: Byte;
begin
  Result := False;
  if (Buffer = nil) or (Length = 0) or (Offset + Length > BufferSize) then
    Exit;
  for I := 0 to Length - 1 do
  begin
    B := PByte(NativeUInt(Buffer) + Offset + I)^;
    if (B and FBytes[I].Mask) <> (FBytes[I].Value and FBytes[I].Mask) then
      Exit;
  end;
  Result := True;
end;

constructor TNativeMirrorPatternMatcher.Create;
begin
  inherited Create;
  FSignatures := TObjectList<TNativeMirrorSignature>.Create(True);
end;

destructor TNativeMirrorPatternMatcher.Destroy;
begin
  FSignatures.Free;
  inherited;
end;

procedure TNativeMirrorPatternMatcher.Clear;
begin
  FSignatures.Clear;
end;

function TNativeMirrorPatternMatcher.IsReady: Boolean;
begin
  TMonitor.Enter(Self);
  try
    Result := FSignatures.Count <> 0;
  finally
    TMonitor.Exit(Self);
  end;
end;

procedure TNativeMirrorPatternMatcher.AddBuiltIn(const Name: string; Data: PByte; Size: NativeUInt);
var
  A: TArray<TNativeMirrorSignatureByte>;
  I: NativeUInt;
begin
  if (Data = nil) or (Size = 0) then
    Exit;
  SetLength(A, Size);
  for I := 0 to Size - 1 do
  begin
    A[I].Value := PByte(NativeUInt(Data) + I)^;
    A[I].Mask := $FF;
  end;
  FSignatures.Add(TNativeMirrorSignature.Create(Name, A, True));
end;

function TNativeMirrorPatternMatcher.InitShellcodePatterns: Boolean;
begin
  AddBuiltIn('prolog32_0', @Pattern32_0[0], Length(Pattern32_0));
  AddBuiltIn('prolog32_1', @Pattern32_1[0], Length(Pattern32_1));
  AddBuiltIn('prolog32_2', @Pattern32_2[0], Length(Pattern32_2));
  AddBuiltIn('prolog64_0', @Pattern64_0[0], Length(Pattern64_0));
  AddBuiltIn('prolog64_1', @Pattern64_1[0], Length(Pattern64_1));
  AddBuiltIn('prolog64_2', @Pattern64_2[0], Length(Pattern64_2));
  AddBuiltIn('prolog64_3', @Pattern64_3[0], Length(Pattern64_3));
  AddBuiltIn('prolog64_4', @Pattern64_4[0], Length(Pattern64_4));
  AddBuiltIn('prolog64_5', @Pattern64_5[0], Length(Pattern64_5));
  AddBuiltIn('prolog64_6', @Pattern64_6[0], Length(Pattern64_6));
  Result := True;
end;

function HexNibble(C: Char; out Value: Byte): Boolean;
begin
  Result := True;
  case C of
    '0'..'9': Value := Ord(C) - Ord('0');
    'a'..'f': Value := Ord(C) - Ord('a') + 10;
    'A'..'F': Value := Ord(C) - Ord('A') + 10;
  else
    Value := 0;
    Result := False;
  end;
end;

function TNativeMirrorPatternMatcher.ParseElement(const S: string; out Element: TNativeMirrorSignatureByte): Boolean;
var
  H, L: Byte;
  HighKnown, LowKnown: Boolean;
  V: string;
begin
  Element.Value := 0;
  Element.Mask := 0;
  V := Trim(S);
  Result := Length(V) = 2;
  if not Result then
    Exit;
  HighKnown := V[1] <> '?';
  LowKnown := V[2] <> '?';
  if HighKnown and not HexNibble(V[1], H) then
    Exit(False);
  if LowKnown and not HexNibble(V[2], L) then
    Exit(False);
  if HighKnown then
  begin
    Element.Value := Element.Value or (H shl 4);
    Element.Mask := Element.Mask or $F0;
  end;
  if LowKnown then
  begin
    Element.Value := Element.Value or L;
    Element.Mask := Element.Mask or $0F;
  end;
end;

function TNativeMirrorPatternMatcher.AddSignature(const Name: string; Elements: TStrings; BuiltIn: Boolean): Boolean;
var
  Tokens: TStringList;
  A: TArray<TNativeMirrorSignatureByte>;
  I, J: Integer;
  Token: string;
  Element: TNativeMirrorSignatureByte;
begin
  Result := False;
  if (Name = '') or (Elements = nil) or (Elements.Count = 0) then
    Exit;
  Tokens := TStringList.Create;
  try
    Tokens.Delimiter := ' ';
    Tokens.StrictDelimiter := True;
    for I := 0 to Elements.Count - 1 do
      for Token in Elements[I].Split([' ', #9]) do
        if Trim(Token) <> '' then
          Tokens.Add(Trim(Token));
    if Tokens.Count = 0 then
      Exit;
    SetLength(A, Tokens.Count);
    J := 0;
    for I := 0 to Tokens.Count - 1 do
    begin
      if not ParseElement(Tokens[I], Element) then
        Exit;
      A[J] := Element;
      Inc(J);
    end;
    FSignatures.Add(TNativeMirrorSignature.Create(Name, A, BuiltIn));
    Result := True;
  finally
    Tokens.Free;
  end;
end;

function TNativeMirrorPatternMatcher.LoadFromStream(Stream: TStream): NativeUInt;
var
  Lines, Elements: TStringList;
  Name, S: string;
  I, Expected, Collected, Before: Integer;
begin
  Result := 0;
  if Stream = nil then
    Exit;
  Lines := TStringList.Create;
  Elements := TStringList.Create;
  try
    Lines.LoadFromStream(Stream, TEncoding.UTF8);
    I := 0;
    while I < Lines.Count do
    begin
      Name := Trim(Lines[I]);
      Inc(I);
      if Name = '' then
        Continue;
      while (I < Lines.Count) and (Trim(Lines[I]) = '') do
        Inc(I);
      if I >= Lines.Count then
        Break;
      S := Trim(Lines[I]);
      Inc(I);
      if not TryStrToInt(S, Expected) or (Expected <= 0) then
        Continue;
      Elements.Clear;
      Collected := 0;
      while (I < Lines.Count) and (Collected < Expected) do
      begin
        S := Trim(Lines[I]);
        Inc(I);
        if S = '' then
          Continue;
        Elements.Add(S);
        Inc(Collected, Length(S.Split([' ', #9], TStringSplitOptions.ExcludeEmpty)));
      end;
      if Collected <> Expected then
        Continue;
      Before := FSignatures.Count;
      if AddSignature(Name, Elements, False) and (FSignatures.Count > Before) then
        Inc(Result);
    end;
  finally
    Elements.Free;
    Lines.Free;
  end;
end;

function TNativeMirrorPatternMatcher.LoadFromFile(const FileName: string): NativeUInt;
var
  Stream: TFileStream;
begin
  Result := 0;
  if not FileExists(FileName) then
    Exit;
  Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
  try
    Result := LoadFromStream(Stream);
  finally
    Stream.Free;
  end;
end;

function TNativeMirrorPatternMatcher.FindAll(Buffer: PByte; BufferSize: NativeUInt; Matches: TList<TNativeMirrorSignatureMatch>): NativeUInt;
var
  Signature: TNativeMirrorSignature;
  Offset: NativeUInt;
  M: TNativeMirrorSignatureMatch;
begin
  Result := 0;
  if (Buffer = nil) or (BufferSize = 0) or (Matches = nil) or IsPadding(Buffer, BufferSize, 0) then
    Exit;
  TMonitor.Enter(Self);
  try
    for Signature in FSignatures do
    begin
      if Signature.Length = 0 then
        Continue;
      Offset := 0;
      while Offset + Signature.Length <= BufferSize do
      begin
        if Signature.Matches(Buffer, BufferSize, Offset) then
        begin
          M.Signature := Signature;
          M.Offset := Offset;
          Matches.Add(M);
          Inc(Result);
        end;
        Inc(Offset);
      end;
    end;
  finally
    TMonitor.Exit(Self);
  end;
end;

function TNativeMirrorPatternMatcher.FilterCustom(const Matches: TList<TNativeMirrorSignatureMatch>; Custom: TList<TNativeMirrorSignatureMatch>): NativeUInt;
var
  M: TNativeMirrorSignatureMatch;
begin
  Result := 0;
  if (Matches = nil) or (Custom = nil) then
    Exit;
  for M in Matches do
    if (M.Signature <> nil) and not M.Signature.BuiltIn then
    begin
      Custom.Add(M);
      Inc(Result);
    end;
end;

initialization
  GSharedMatcher := TNativeMirrorPatternMatcher.Create;

finalization
  GSharedMatcher.Free;

end.
