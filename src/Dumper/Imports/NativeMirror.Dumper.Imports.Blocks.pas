{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Dumper.Imports.Blocks;

interface

uses
  Winapi.Windows,
  System.Generics.Collections,
  NativePe.ExportedFunc,
  NativePe.ExportsMapper,
  NativePe.ImportsUneraser,
  NativePe.Types;

type
  TNativeMirrorIatThunkSeries = class
  private
    FStartOffset: DWORD;
    FEndOffset: DWORD;
    FCoverage: TImportedDllCoverage;
    FCovered: Boolean;
    FDllFullName: string;
    FFunctionAddresses: TList<UInt64>;
    FRvaToFunction: TDictionary<DWORD, UInt64>;
    function LongestFunctionName: NativeUInt;
  public
    constructor Create(StartOffset: DWORD);
    destructor Destroy; override;
    function Insert(Rva: DWORD; FunctionAddress: UInt64): Boolean;
    function MakeCoverage(ExportsMap: TExportsMapper): Boolean;
    function IsCovered: Boolean;
    function FunctionCount: NativeUInt;
    function DllName: string;
    function SizeOfNamesSpace(Is64Bit: Boolean): NativeUInt;
    function FillNamesSpace(Buffer: PByte; BufferSize: NativeUInt; BufferRva: DWORD; Is64Bit: Boolean): Boolean;
    function GetSortedRvas: TArray<DWORD>;
    function GetFunctionAddress(Rva: DWORD): UInt64;
    property StartOffset: DWORD read FStartOffset;
    property EndOffset: DWORD read FEndOffset;
    property Coverage: TImportedDllCoverage read FCoverage;
  end;

  TNativeMirrorIatBlock = class
  private
    FIs64Bit: Boolean;
    FIatOffset: DWORD;
    FIatSize: NativeUInt;
    FIsInMain: Boolean;
    FIsTerminated: Boolean;
    FCoverageComplete: Boolean;
    FImportTableOffset: DWORD;
    FThunkSeries: TObjectList<TNativeMirrorIatThunkSeries>;
    FFunctions: TDictionary<UInt64, TExportedFunc>;
    FAddressToFunctionVa: TDictionary<UInt64, UInt64>;
    function SplitSeries(Series: TNativeMirrorIatThunkSeries; ExportsMap: TExportsMapper): TObjectList<TNativeMirrorIatThunkSeries>;
    procedure SortSeries;
  public
    constructor Create(Is64Bit: Boolean; IatOffset: DWORD);
    destructor Destroy; override;
    function Append(Rva: DWORD; FunctionVa: UInt64; ExportedFunction: TExportedFunc): Boolean;
    function IsCovered: Boolean;
    function IsValid: Boolean;
    function CountThunks: NativeUInt;
    function MakeCoverage(ExportsMap: TExportsMapper): Boolean;
    function MaxDllLength: NativeUInt;
    function SizeOfDllsSpace: NativeUInt;
    function ToText: string;
    property Is64Bit: Boolean read FIs64Bit;
    property IatOffset: DWORD read FIatOffset;
    property IatSize: NativeUInt read FIatSize write FIatSize;
    property IsInMain: Boolean read FIsInMain write FIsInMain;
    property IsTerminated: Boolean read FIsTerminated write FIsTerminated;
    property ImportTableOffset: DWORD read FImportTableOffset write FImportTableOffset;
    property ThunkSeries: TObjectList<TNativeMirrorIatThunkSeries> read FThunkSeries;
  end;

implementation

uses
  System.SysUtils,
  System.Generics.Defaults;

const
  NATIVE_MIRROR_IMPORT_BY_NAME_SIZE = SizeOf(Word) * 2;

constructor TNativeMirrorIatThunkSeries.Create(StartOffset: DWORD);
begin
  inherited Create;
  FStartOffset := StartOffset;
  FEndOffset := StartOffset;
  FFunctionAddresses := TList<UInt64>.Create;
  FRvaToFunction := TDictionary<DWORD, UInt64>.Create;
end;

destructor TNativeMirrorIatThunkSeries.Destroy;
begin
  FCoverage.Free;
  FRvaToFunction.Free;
  FFunctionAddresses.Free;
  inherited;
end;

function TNativeMirrorIatThunkSeries.Insert(Rva: DWORD; FunctionAddress: UInt64): Boolean;
begin
  FRvaToFunction.AddOrSetValue(Rva, FunctionAddress);
  if FFunctionAddresses.IndexOf(FunctionAddress) < 0 then
    FFunctionAddresses.Add(FunctionAddress);
  if Rva > FEndOffset then
    FEndOffset := Rva;
  Result := True;
end;

function TNativeMirrorIatThunkSeries.MakeCoverage(ExportsMap: TExportsMapper): Boolean;
var
  CoveredCount: NativeUInt;
begin
  FreeAndNil(FCoverage);
  FCoverage := TImportedDllCoverage.Create(FFunctionAddresses, ExportsMap);
  if not FCoverage.FindCoveringDll then
    Exit(False);
  CoveredCount := FCoverage.MapAddressesToFunctions(FCoverage.DllName);
  FDllFullName := ExportsMap.GetDllFullName(FCoverage.DllName);
  FCovered := CoveredCount = NativeUInt(FFunctionAddresses.Count);
  Result := FCovered;
end;

function TNativeMirrorIatThunkSeries.IsCovered: Boolean;
begin
  Result := FCovered;
end;

function TNativeMirrorIatThunkSeries.FunctionCount: NativeUInt;
begin
  Result := FRvaToFunction.Count;
end;

function TNativeMirrorIatThunkSeries.DllName: string;
begin
  Result := FDllFullName;
end;

function TNativeMirrorIatThunkSeries.LongestFunctionName: NativeUInt;
var
  Pair: TPair<UInt64, TExportedFuncSet>;
  FuncPair: TPair<string, TExportedFunc>;
  FirstFunction: TExportedFunc;
begin
  Result := 0;
  if FCoverage = nil then
    Exit;
  for Pair in FCoverage.AddrToFunc do
  begin
    FirstFunction := nil;
    for FuncPair in Pair.Value do
      if (FirstFunction = nil) or FuncPair.Value.IsLessThan(FirstFunction) then
        FirstFunction := FuncPair.Value;
    if (FirstFunction <> nil) and not FirstFunction.IsByOrdinal and
      (NativeUInt(Length(FirstFunction.FuncName)) > Result) then
      Result := Length(FirstFunction.FuncName);
  end;
end;

function TNativeMirrorIatThunkSeries.SizeOfNamesSpace(Is64Bit: Boolean): NativeUInt;
var
  FieldSize, LongestName: NativeUInt;
  I, Count: NativeUInt;
begin
  Result := 0;
  if (FCoverage = nil) or not FCoverage.IsMappingComplete then
    Exit;
  LongestName := LongestFunctionName;
  if Is64Bit then
    FieldSize := SizeOf(UInt64)
  else
    FieldSize := SizeOf(DWORD);
  Count := FunctionCount;
  I := 0;
  while I < Count do
  begin
    Inc(Result, FieldSize);
    Inc(Result, NATIVE_MIRROR_IMPORT_BY_NAME_SIZE + LongestName);
    Inc(I);
  end;
  if Result > 0 then
    Inc(Result, SizeOf(NativeUInt));
end;

function TNativeMirrorIatThunkSeries.FillNamesSpace(Buffer: PByte; BufferSize: NativeUInt; BufferRva: DWORD; Is64Bit: Boolean): Boolean;
var
  FieldSize, ThunksCount, ThunksAreaSize, NamesRva, I, LongestName: NativeUInt;
  Cursor, BufferEnd: PByte;
begin
  Result := False;
  if (Buffer = nil) or (FCoverage = nil) or not FCoverage.IsMappingComplete then
    Exit;
  LongestName := LongestFunctionName;
  if Is64Bit then
    FieldSize := SizeOf(UInt64)
  else
    FieldSize := SizeOf(DWORD);
  ThunksCount := FunctionCount;
  ThunksAreaSize := ThunksCount * FieldSize + FieldSize;
  NamesRva := UInt64(BufferRva) + ThunksAreaSize;
  Cursor := Buffer;
  BufferEnd := PByte(NativeUInt(Buffer) + BufferSize);
  I := 0;
  while I < ThunksCount do
  begin
    if NativeUInt(Cursor) >= NativeUInt(BufferEnd) then
      Break;
    if Is64Bit then
      PUInt64(Cursor)^ := NamesRva
    else
      PDWORD(Cursor)^ := DWORD(NamesRva and $FFFFFFFF);
    Inc(Cursor, FieldSize);
    Inc(NamesRva, NATIVE_MIRROR_IMPORT_BY_NAME_SIZE + LongestName);
    Inc(I);
  end;
  Result := I = ThunksCount;
end;

function TNativeMirrorIatThunkSeries.GetSortedRvas: TArray<DWORD>;
var
  Key: DWORD;
  List: TList<DWORD>;
begin
  List := TList<DWORD>.Create;
  try
    for Key in FRvaToFunction.Keys do
      List.Add(Key);
    List.Sort;
    Result := List.ToArray;
  finally
    List.Free;
  end;
end;

function TNativeMirrorIatThunkSeries.GetFunctionAddress(Rva: DWORD): UInt64;
begin
  if not FRvaToFunction.TryGetValue(Rva, Result) then
    Result := 0;
end;

constructor TNativeMirrorIatBlock.Create(Is64Bit: Boolean; IatOffset: DWORD);
begin
  inherited Create;
  FIs64Bit := Is64Bit;
  FIatOffset := IatOffset;
  FThunkSeries := TObjectList<TNativeMirrorIatThunkSeries>.Create(True);
  FFunctions := TDictionary<UInt64, TExportedFunc>.Create;
  FAddressToFunctionVa := TDictionary<UInt64, UInt64>.Create;
end;

destructor TNativeMirrorIatBlock.Destroy;
begin
  FAddressToFunctionVa.Free;
  FFunctions.Free;
  FThunkSeries.Free;
  inherited;
end;

procedure TNativeMirrorIatBlock.SortSeries;
begin
  FThunkSeries.Sort(TComparer<TNativeMirrorIatThunkSeries>.Construct(
    function(const Left, Right: TNativeMirrorIatThunkSeries): Integer
    begin
      if Left.StartOffset < Right.StartOffset then Exit(-1);
      if Left.StartOffset > Right.StartOffset then Exit(1);
      Result := 0;
    end));
end;

function TNativeMirrorIatBlock.Append(Rva: DWORD; FunctionVa: UInt64; ExportedFunction: TExportedFunc): Boolean;
var
  Series: TNativeMirrorIatThunkSeries;
begin
  Result := False;
  if ExportedFunction = nil then
    Exit;
  FFunctions.AddOrSetValue(Rva, ExportedFunction);
  FAddressToFunctionVa.AddOrSetValue(Rva, FunctionVa);
  Series := nil;
  for var I := 0 to FThunkSeries.Count - 1 do
    if FThunkSeries[I].EndOffset + SizeOf(Rva) = Rva then
    begin
      Series := FThunkSeries[I];
      Break;
    end;
  if Series = nil then
  begin
    Series := TNativeMirrorIatThunkSeries.Create(Rva);
    FThunkSeries.Add(Series);
    SortSeries;
  end;
  Series.Insert(Rva, FunctionVa);
  Result := True;
end;

function TNativeMirrorIatBlock.IsCovered: Boolean;
begin
  Result := FCoverageComplete;
end;

function TNativeMirrorIatBlock.IsValid: Boolean;
begin
  Result := IsCovered;
end;

function TNativeMirrorIatBlock.CountThunks: NativeUInt;
begin
  Result := FFunctions.Count;
end;

function TNativeMirrorIatBlock.SplitSeries(Series: TNativeMirrorIatThunkSeries; ExportsMap: TExportsMapper): TObjectList<TNativeMirrorIatThunkSeries>;
var
  Rvas: TArray<DWORD>;
  Rva: DWORD;
  FunctionAddress: UInt64;
  ExportedFunction: TExportedFunc;
  Current: TNativeMirrorIatThunkSeries;
  LastDll: string;
begin
  Result := TObjectList<TNativeMirrorIatThunkSeries>.Create(True);
  if Series = nil then
    Exit;
  Current := nil;
  LastDll := '';
  Rvas := Series.GetSortedRvas;
  for Rva in Rvas do
  begin
    FunctionAddress := Series.GetFunctionAddress(Rva);
    ExportedFunction := ExportsMap.FindExportByVa(FunctionAddress);
    if (Current <> nil) and ((ExportedFunction = nil) or (ExportedFunction.LibName <> LastDll)) then
    begin
      Result.Add(Current);
      Current := nil;
      LastDll := '';
    end;
    if ExportedFunction = nil then
      Continue;
    if Current = nil then
    begin
      Current := TNativeMirrorIatThunkSeries.Create(Rva);
      LastDll := ExportedFunction.LibName;
    end;
    Current.Insert(Rva, FunctionAddress);
  end;
  if Current <> nil then
    Result.Add(Current);
end;

function TNativeMirrorIatBlock.MakeCoverage(ExportsMap: TExportsMapper): Boolean;
var
  ToSplit: TList<TNativeMirrorIatThunkSeries>;
  Series: TNativeMirrorIatThunkSeries;
  Split: TObjectList<TNativeMirrorIatThunkSeries>;
  I, CoveredCount: Integer;
begin
  Result := False;
  if ExportsMap = nil then
    Exit;
  ToSplit := TList<TNativeMirrorIatThunkSeries>.Create;
  try
    for Series in FThunkSeries do
      if not Series.MakeCoverage(ExportsMap) then
        ToSplit.Add(Series);
    for Series in ToSplit do
    begin
      Split := SplitSeries(Series, ExportsMap);
      try
        if Split.Count = 0 then
          Continue;
        FThunkSeries.Extract(Series);
        Series.Free;
        for I := Split.Count - 1 downto 0 do
          FThunkSeries.Add(Split.Extract(Split[I]));
      finally
        Split.Free;
      end;
    end;
    SortSeries;
    CoveredCount := 0;
    for Series in FThunkSeries do
      if Series.IsCovered or Series.MakeCoverage(ExportsMap) then
        Inc(CoveredCount);
    FCoverageComplete := CoveredCount = FThunkSeries.Count;
    Result := FCoverageComplete;
  finally
    ToSplit.Free;
  end;
end;

function TNativeMirrorIatBlock.MaxDllLength: NativeUInt;
var
  Series: TNativeMirrorIatThunkSeries;
  Current: NativeUInt;
begin
  Result := 0;
  for Series in FThunkSeries do
  begin
    Current := Length(Series.DllName) + 1;
    if Current > Result then
      Result := Current;
  end;
end;

function TNativeMirrorIatBlock.SizeOfDllsSpace: NativeUInt;
begin
  Result := MaxDllLength * NativeUInt(FThunkSeries.Count + 1);
end;

function TNativeMirrorIatBlock.ToText: string;
var
  Builder: TStringBuilder;
  Keys: TList<UInt64>;
  Key: UInt64;
  ExportedFunction: TExportedFunc;
  FunctionVa: UInt64;
begin
  Builder := TStringBuilder.Create;
  Keys := TList<UInt64>.Create;
  try
    Builder.AppendLine('---');
    Builder.AppendFormat('IAT at: %s, size: %s, thunks: %s, is_terminated: %d, in_main: %d', [IntToHex(FIatOffset, 1).ToLower, IntToHex(FIatSize, 1).ToLower, IntToHex(CountThunks, 1).ToLower, Ord(FIsTerminated), Ord(FIsInMain)]).AppendLine;
    if FImportTableOffset <> 0 then
      Builder.AppendFormat('ImportTable: %s', [IntToHex(FImportTableOffset, 1).ToLower]).AppendLine;
    Builder.AppendLine('---');
    for Key in FFunctions.Keys do
      Keys.Add(Key);
    Keys.Sort;
    for Key in Keys do
    begin
      FFunctions.TryGetValue(Key, ExportedFunction);
      FAddressToFunctionVa.TryGetValue(Key, FunctionVa);
      Builder.AppendFormat('%s,%s,%s', [IntToHex(Key, 1).ToLower, IntToHex(FunctionVa, 1).ToLower, ExportedFunction.ToStringFull]).AppendLine;
    end;
    Result := Builder.ToString;
  finally
    Keys.Free;
    Builder.Free;
  end;
end;

end.
