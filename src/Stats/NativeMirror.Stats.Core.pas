{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Stats.Core;

interface

uses
  System.SysUtils,
  System.Generics.Collections;

type
  TNativeMirrorByteHistogram = array[Byte] of NativeUInt;

  TNativeMirrorMultiStatsSettings = class
  private
    FWatchedStrings: TList<string>;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Add(const Value: string);
    function Match(const Value: string): string;
    property WatchedStrings: TList<string> read FWatchedStrings;
  end;

  TNativeMirrorChunkStats = class
  private
    FHistogram: TNativeMirrorByteHistogram;
    FFoundStrings: TDictionary<string, NativeUInt>;
    FSettings: TNativeMirrorMultiStatsSettings;
    FLastString: RawByteString;
    FSize: NativeUInt;
    FOffset: NativeUInt;
    FEntropy: Double;
    FLongestString: NativeUInt;
    FStringsCount: NativeUInt;
    FCleanStringsCount: NativeUInt;
    procedure FinishLastString(IsClean: Boolean);
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reset;
    procedure AppendValue(Value: Byte);
    procedure Summarize;
    function PopulationSize: NativeUInt;
    function MostFrequentValue: Byte;
    function ValueRatio(Value: Byte): Double;
    function PrintableRatio: Double;
    function ValuesNotBelowMean(Mean: Double): NativeUInt;
    function FetchPeakValues(StandardDeviation: Double; DeviationCount: Integer; out Peaks: TArray<Byte>): NativeUInt;
    function MostFrequentValuesHex(Top, MaxDiff: NativeUInt): string;
    function CountFoundStrings(const Needed: array of string; MinOccurrence: NativeUInt): NativeUInt;
    property Histogram: TNativeMirrorByteHistogram read FHistogram;
    property FoundStrings: TDictionary<string, NativeUInt> read FFoundStrings;
    property Settings: TNativeMirrorMultiStatsSettings read FSettings write FSettings;
    property Size: NativeUInt read FSize;
    property Offset: NativeUInt read FOffset write FOffset;
    property Entropy: Double read FEntropy;
    property LongestString: NativeUInt read FLongestString;
    property StringsCount: NativeUInt read FStringsCount;
    property CleanStringsCount: NativeUInt read FCleanStringsCount;
  end;

  TNativeMirrorAreaMultiStats = class
  private
    FArea: TNativeMirrorChunkStats;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Fill(Buffer: PByte; BufferSize, StartOffset: NativeUInt; Settings: TNativeMirrorMultiStatsSettings = nil);
    function IsFilled: Boolean;
    property Area: TNativeMirrorChunkStats read FArea;
  end;

function NativePeShannonEntropy(const Histogram: TNativeMirrorByteHistogram; TotalSize: NativeUInt): Double;
function NativePeIsPrintable(Value: Byte): Boolean;

implementation

uses
  System.Math;

function NativePeIsPrintable(Value: Byte): Boolean;
begin
  Result := (Value >= 32) and (Value <= 126);
end;

function NativePeShannonEntropy(const Histogram: TNativeMirrorByteHistogram; TotalSize: NativeUInt): Double;
var
  I: Integer;
  P: Double;
begin
  Result := 0;
  if TotalSize = 0 then
    Exit;
  for I := 0 to 255 do
    if Histogram[I] <> 0 then
    begin
      P := Histogram[I] / TotalSize;
      Result := Result - P * (Ln(P) / Ln(2));
    end;
end;

constructor TNativeMirrorMultiStatsSettings.Create;
begin
  inherited Create;
  FWatchedStrings := TList<string>.Create;
end;

destructor TNativeMirrorMultiStatsSettings.Destroy;
begin
  FWatchedStrings.Free;
  inherited;
end;

procedure TNativeMirrorMultiStatsSettings.Add(const Value: string);
begin
  if (Value <> '') and not FWatchedStrings.Contains(Value) then
    FWatchedStrings.Add(Value);
end;

function TNativeMirrorMultiStatsSettings.Match(const Value: string): string;
var
  S: string;
begin
  Result := '';
  for S in FWatchedStrings do
    if (S <> '') and Value.Contains(S) and ((Result = '') or (CompareStr(S, Result) < 0)) then
      Result := S;
end;

constructor TNativeMirrorChunkStats.Create;
begin
  inherited Create;
  FFoundStrings := TDictionary<string, NativeUInt>.Create;
  Reset;
end;

destructor TNativeMirrorChunkStats.Destroy;
begin
  FFoundStrings.Free;
  inherited;
end;

procedure TNativeMirrorChunkStats.Reset;
begin
  FillChar(FHistogram, SizeOf(FHistogram), 0);
  FFoundStrings.Clear;
  FLastString := '';
  FSize := 0;
  FOffset := 0;
  FEntropy := 0;
  FLongestString := 0;
  FStringsCount := 0;
  FCleanStringsCount := 0;
  FSettings := nil;
end;

procedure TNativeMirrorChunkStats.FinishLastString(IsClean: Boolean);
var
  S, Key: string;
  Count: NativeUInt;
begin
  if Length(FLastString) < 2 then
    Exit;
  Inc(FStringsCount);
  if IsClean then
    Inc(FCleanStringsCount);
  if FSettings <> nil then
  begin
    S := string(AnsiString(FLastString));
    Key := FSettings.Match(S);
    if Key <> '' then
    begin
      if FFoundStrings.TryGetValue(Key, Count) then
        FFoundStrings[Key] := Count + 1
      else
        FFoundStrings.Add(Key, 1);
    end;
  end;
  if NativeUInt(Length(FLastString)) > FLongestString then
    FLongestString := Length(FLastString);
  FLastString := '';
end;

procedure TNativeMirrorChunkStats.AppendValue(Value: Byte);
begin
  Inc(FSize);
  Inc(FHistogram[Value]);
  if NativePeIsPrintable(Value) then
    FLastString := FLastString + AnsiChar(Value)
  else
  begin
    FinishLastString(Value = 0);
    FLastString := '';
  end;
end;

procedure TNativeMirrorChunkStats.Summarize;
begin
  FEntropy := NativePeShannonEntropy(FHistogram, FSize);
  FinishLastString(True);
end;

function TNativeMirrorChunkStats.PopulationSize: NativeUInt;
var
  I: Integer;
begin
  Result := 0;
  for I := 0 to 255 do
    if FHistogram[I] <> 0 then
      Inc(Result);
end;

function TNativeMirrorChunkStats.MostFrequentValue: Byte;
var
  I: Integer;
  Best: NativeUInt;
begin
  Result := 0;
  Best := 0;
  for I := 0 to 255 do
    if FHistogram[I] > Best then
    begin
      Best := FHistogram[I];
      Result := Byte(I);
    end;
end;

function TNativeMirrorChunkStats.ValueRatio(Value: Byte): Double;
begin
  if FSize = 0 then
    Exit(0);
  Result := FHistogram[Value] / FSize;
end;

function TNativeMirrorChunkStats.PrintableRatio: Double;
var
  I: Integer;
  Total: NativeUInt;
begin
  if FSize = 0 then
    Exit(0);
  Total := 0;
  for I := 0 to 255 do
    if NativePeIsPrintable(Byte(I)) then
      Inc(Total, FHistogram[I]);
  Result := Total / FSize;
end;

function TNativeMirrorChunkStats.ValuesNotBelowMean(Mean: Double): NativeUInt;
var
  I: Integer;
begin
  Result := 0;
  for I := 0 to 255 do
    if FHistogram[I] >= Mean then
      Inc(Result);
end;

function TNativeMirrorChunkStats.FetchPeakValues(StandardDeviation: Double; DeviationCount: Integer; out Peaks: TArray<Byte>): NativeUInt;
var
  I, J, N: Integer;
  MaxCount, Threshold: Double;
  Values: TList<Byte>;
begin
  Values := TList<Byte>.Create;
  try
    MaxCount := 0;
    for I := 0 to 255 do
      if FHistogram[I] > MaxCount then
        MaxCount := FHistogram[I];
    Threshold := MaxCount - DeviationCount * StandardDeviation;
    for I := 0 to 255 do
      if (FHistogram[I] <> 0) and (FHistogram[I] >= Threshold) then
        Values.Add(Byte(I));
    N := Values.Count;
    SetLength(Peaks, N);
    for J := 0 to N - 1 do
      Peaks[J] := Values[J];
    Result := N;
  finally
    Values.Free;
  end;
end;

function TNativeMirrorChunkStats.MostFrequentValuesHex(Top, MaxDiff: NativeUInt): string;
var
  Counts: TList<NativeUInt>;
  Count, Prev: NativeUInt;
  I, J: Integer;
  Exists: Boolean;
  Selected: array[Byte] of Boolean;
  SB: TStringBuilder;
begin
  Result := '';
  FillChar(Selected, SizeOf(Selected), 0);
  Counts := TList<NativeUInt>.Create;
  SB := TStringBuilder.Create;
  try
    for I := 0 to 255 do
      if FHistogram[I] <> 0 then
      begin
        Exists := False;
        for J := 0 to Counts.Count - 1 do
          if Counts[J] = FHistogram[I] then
          begin
            Exists := True;
            Break;
          end;
        if not Exists then
          Counts.Add(FHistogram[I]);
      end;
    for I := 0 to Counts.Count - 2 do
      for J := I + 1 to Counts.Count - 1 do
        if Counts[J] > Counts[I] then
        begin
          Count := Counts[I];
          Counts[I] := Counts[J];
          Counts[J] := Count;
        end;
    if Counts.Count = 0 then
      Exit;
    Prev := Counts[0];
    for J := 0 to Counts.Count - 1 do
    begin
      if (Top <> 0) and (NativeUInt(J) >= Top) then
        Break;
      Count := Counts[J];
      if (J <> 0) and (Prev - Count > MaxDiff) then
        Break;
      Prev := Count;
      for I := 0 to 255 do
        if FHistogram[I] = Count then
          Selected[I] := True;
    end;
    for I := 0 to 255 do
      if Selected[I] then
        SB.Append('\x' + IntToHex(I, 2).ToLower);
    Result := SB.ToString;
  finally
    SB.Free;
    Counts.Free;
  end;
end;

function TNativeMirrorChunkStats.CountFoundStrings(const Needed: array of string; MinOccurrence: NativeUInt): NativeUInt;
var
  I: Integer;
  Count: NativeUInt;
begin
  Result := 0;
  for I := Low(Needed) to High(Needed) do
    if FFoundStrings.TryGetValue(Needed[I], Count) and (Count >= MinOccurrence) then
      Inc(Result);
end;

constructor TNativeMirrorAreaMultiStats.Create;
begin
  inherited Create;
  FArea := TNativeMirrorChunkStats.Create;
end;

destructor TNativeMirrorAreaMultiStats.Destroy;
begin
  FArea.Free;
  inherited;
end;

procedure TNativeMirrorAreaMultiStats.Fill(Buffer: PByte; BufferSize, StartOffset: NativeUInt; Settings: TNativeMirrorMultiStatsSettings);
var
  I: NativeUInt;
begin
  FArea.Reset;
  FArea.Offset := StartOffset;
  FArea.Settings := Settings;
  if (Buffer = nil) or (BufferSize = 0) then
    Exit;
  for I := 0 to BufferSize - 1 do
    FArea.AppendValue(PByte(NativeUInt(Buffer) + I)^);
  FArea.Summarize;
end;

function TNativeMirrorAreaMultiStats.IsFilled: Boolean;
begin
  Result := FArea.Size <> 0;
end;

end.
