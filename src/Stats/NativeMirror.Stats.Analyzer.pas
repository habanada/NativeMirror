{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Stats.Analyzer;

interface

uses
  System.JSON,
  System.Generics.Collections,
  NativeMirror.Stats.Core;

const
  NM_RULE_NONE = Cardinal(0);
  NM_RULE_CODE = Cardinal(1);
  NM_RULE_TEXT = Cardinal(2);
  NM_RULE_OBFUSCATED = Cardinal(4);
  NM_RULE_ENCRYPTED = Cardinal(8);
  NM_CODE_RULE = 'possible_code';
  NM_TEXT_RULE = 'possible_text';
  NM_OBFUSCATED_RULE = 'possible_obfuscated';
  NM_ENCRYPTED_RULE = 'possible_encrypted';

type
  TNativeMirrorAreaInfo = class
  private
    FMatchedRules: TList<string>;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Clear;
    procedure Add(const Rule: string);
    function HasMatch(const Rule: string): Boolean;
    function HasAnyMatch: Boolean;
    function ToJson: TJSONObject;
    property MatchedRules: TList<string> read FMatchedRules;
  end;

  TNativeMirrorStatsAnalyzer = class sealed
  public
    class procedure FillCodeStrings(Settings: TNativeMirrorMultiStatsSettings); static;
    class function FindMatches(Stats: TNativeMirrorAreaMultiStats; RuleTypes: Cardinal; Info: TNativeMirrorAreaInfo): NativeUInt; static;
    class function IsCode(Stats: TNativeMirrorAreaMultiStats): Boolean; static;
    class function IsText(Stats: TNativeMirrorAreaMultiStats): Boolean; static;
    class function IsObfuscated(Stats: TNativeMirrorAreaMultiStats): Boolean; static;
    class function IsEncrypted(Stats: TNativeMirrorAreaMultiStats): Boolean; static;
  end;

implementation

uses
  System.Math,
  System.SysUtils;

const
  ENTROPY_DATA_THRESHOLD = 3.0;
  ENTROPY_CODE_THRESHOLD = ENTROPY_DATA_THRESHOLD;
  ENTROPY_ENC_THRESHOLD = 6.0;
  ENTROPY_STRONG_ENC_THRESHOLD = 7.0;
  CHARSET_SIZE = $FF;

constructor TNativeMirrorAreaInfo.Create;
begin
  inherited Create;
  FMatchedRules := TList<string>.Create;
end;

destructor TNativeMirrorAreaInfo.Destroy;
begin
  FMatchedRules.Free;
  inherited;
end;

procedure TNativeMirrorAreaInfo.Clear;
begin
  FMatchedRules.Clear;
end;

procedure TNativeMirrorAreaInfo.Add(const Rule: string);
begin
  if not FMatchedRules.Contains(Rule) then
    FMatchedRules.Add(Rule);
end;

function TNativeMirrorAreaInfo.HasMatch(const Rule: string): Boolean;
begin
  Result := FMatchedRules.Contains(Rule);
end;

function TNativeMirrorAreaInfo.HasAnyMatch: Boolean;
begin
  Result := FMatchedRules.Count <> 0;
end;

function TNativeMirrorAreaInfo.ToJson: TJSONObject;
var
  Rule: string;
begin
  Result := TJSONObject.Create;
  for Rule in FMatchedRules do
    Result.AddPair(Rule, TJSONNumber.Create(1));
end;

class procedure TNativeMirrorStatsAnalyzer.FillCodeStrings(Settings: TNativeMirrorMultiStatsSettings);
begin
  if Settings = nil then
    Exit;
  Settings.Add('WVS');
  Settings.Add('SVW');
  Settings.Add('D$');
  Settings.Add('AQ');
  Settings.Add('AX');
  Settings.Add('UWV');
  Settings.Add('[^_]');
  Settings.Add('ZX[]');
end;

function HistogramMean(const Stats: TNativeMirrorChunkStats): Double;
var
  I: Integer;
  Sum: Double;
begin
  if Stats.PopulationSize = 0 then
    Exit(0);
  Sum := 0;
  for I := 0 to 255 do
    Sum := Sum + Stats.Histogram[I];
  Result := Sum / Stats.PopulationSize;
end;

function HistogramSampleDeviation(const Stats: TNativeMirrorChunkStats): Double;
var
  I: Integer;
  Mean, Total: Double;
  Population: NativeUInt;
begin
  Population := Stats.PopulationSize;
  if Population <= 1 then
    Exit(0);
  Mean := HistogramMean(Stats);
  Total := 0;
  for I := 0 to 255 do
    if Stats.Histogram[I] <> 0 then
      Total := Total + Sqr(Stats.Histogram[I] - Mean);
  Result := Sqrt(Total / (Population - 1));
end;

class function TNativeMirrorStatsAnalyzer.IsCode(Stats: TNativeMirrorAreaMultiStats): Boolean;
const
  CodeStrings: array[0..7] of string = ('WVS', 'SVW', 'D$', 'AQ', 'AX', 'UWV', '[^_]', 'ZX[]');
  RatioValues: array[0..6] of Byte = ($00, $0F, $48, $8B, $CC, $E8, $FF);
  RatioMin: array[0..6] of Double = (0.1, 0.01, 0.02, 0.02, 0.01, 0.01, 0.02);
var
  I: Integer;
  RatioPoints, StringPoints: NativeUInt;
begin
  Result := False;
  if (Stats = nil) or not Stats.IsFilled or (Stats.Area.Entropy < ENTROPY_CODE_THRESHOLD) then
    Exit;
  StringPoints := Stats.Area.CountFoundStrings(CodeStrings, 1);
  if StringPoints = 0 then
    Exit;
  RatioPoints := 0;
  for I := 0 to High(RatioValues) do
    if Stats.Area.ValueRatio(RatioValues[I]) >= RatioMin[I] then
      Inc(RatioPoints);
  if RatioPoints < 2 then
    Exit;
  if RatioPoints >= (Length(RatioValues) div 2 + 1) then
    Exit(True);
  Result := StringPoints >= 2;
end;

class function TNativeMirrorStatsAnalyzer.IsObfuscated(Stats: TNativeMirrorAreaMultiStats): Boolean;
var
  MostFrequent: Byte;
  Entropy, Mean, NotBelowRatio, PrintRatio, Deviation, PeaksRatio: Double;
  Population, NotBelow, PeaksCount: NativeUInt;
  Peaks: TArray<Byte>;
  I: Integer;
  HasZeroPeak: Boolean;
begin
  Result := False;
  if (Stats = nil) or not Stats.IsFilled then
    Exit;
  Population := Stats.Area.PopulationSize;
  if Population < (CHARSET_SIZE div 3) then
    Exit;
  MostFrequent := Stats.Area.MostFrequentValue;
  Entropy := Stats.Area.Entropy;
  if (MostFrequent = 0) or (Entropy <= ENTROPY_DATA_THRESHOLD) then
    Exit;
  Mean := HistogramMean(Stats.Area);
  NotBelow := Stats.Area.ValuesNotBelowMean(Mean);
  NotBelowRatio := NotBelow / Population;
  if NotBelowRatio > 0.5 then
    Exit(True);
  PrintRatio := Stats.Area.PrintableRatio;
  if PrintRatio > 0.8 then
    Exit;
  if (Entropy < ENTROPY_ENC_THRESHOLD) and (PrintRatio > 0.6) then
    Exit;
  Deviation := HistogramSampleDeviation(Stats.Area);
  PeaksCount := Stats.Area.FetchPeakValues(Deviation, 2, Peaks);
  PeaksRatio := PeaksCount / Population;
  if PeaksRatio > 0.4 then
    Exit(True);
  HasZeroPeak := False;
  for I := 0 to High(Peaks) do
    if Peaks[I] = 0 then
    begin
      HasZeroPeak := True;
      Break;
    end;
  if not HasZeroPeak then
    Exit(True);
  if NotBelowRatio < 0.17 then
    Exit;
end;

class function TNativeMirrorStatsAnalyzer.IsEncrypted(Stats: TNativeMirrorAreaMultiStats): Boolean;
var
  I: Integer;
  MostFrequent: Byte;
  MinCount, MaxCount: NativeUInt;
  Diff: Double;
begin
  Result := False;
  if (Stats = nil) or not Stats.IsFilled then
    Exit;
  if Stats.Area.Entropy > ENTROPY_STRONG_ENC_THRESHOLD then
    Exit(True);
  MostFrequent := Stats.Area.MostFrequentValue;
  if (MostFrequent = 0) or (Stats.Area.Entropy <= ENTROPY_ENC_THRESHOLD) then
    Exit;
  MinCount := High(NativeUInt);
  MaxCount := 0;
  for I := 0 to 255 do
    if Stats.Area.Histogram[I] <> 0 then
    begin
      if Stats.Area.Histogram[I] < MinCount then
        MinCount := Stats.Area.Histogram[I];
      if Stats.Area.Histogram[I] > MaxCount then
        MaxCount := Stats.Area.Histogram[I];
    end;
  if (MinCount = High(NativeUInt)) or (MaxCount = MinCount) or (Stats.Area.Size = 0) then
    Exit;
  Diff := (MaxCount - MinCount) / Stats.Area.Size;
  Result := Diff < 0.01;
end;

class function TNativeMirrorStatsAnalyzer.IsText(Stats: TNativeMirrorAreaMultiStats): Boolean;
begin
  Result := (Stats <> nil) and Stats.IsFilled and (Stats.Area.PrintableRatio > 0.8);
end;

class function TNativeMirrorStatsAnalyzer.FindMatches(Stats: TNativeMirrorAreaMultiStats; RuleTypes: Cardinal; Info: TNativeMirrorAreaInfo): NativeUInt;
begin
  Result := 0;
  if (Stats = nil) or not Stats.IsFilled or (Info = nil) then
    Exit;
  if ((RuleTypes and NM_RULE_CODE) <> 0) and IsCode(Stats) then
  begin
    Info.Add(NM_CODE_RULE);
    Inc(Result);
  end;
  if ((RuleTypes and NM_RULE_TEXT) <> 0) and IsText(Stats) then
  begin
    Info.Add(NM_TEXT_RULE);
    Inc(Result);
  end;
  if ((RuleTypes and NM_RULE_ENCRYPTED) <> 0) and IsEncrypted(Stats) then
  begin
    Info.Add(NM_ENCRYPTED_RULE);
    Inc(Result);
  end;
  if ((RuleTypes and NM_RULE_OBFUSCATED) <> 0) and IsObfuscated(Stats) then
  begin
    Info.Add(NM_OBFUSCATED_RULE);
    Inc(Result);
  end;
end;

end.
