{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Dumper.Imports.Reconstructor;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Generics.Collections,
  NativePe.ExportsMapper,
  NativePe.Types,
  NativeMirror.Core.Types,
  NativeMirror.Dumper.Buffer,
  NativeMirror.Dumper.Imports.Blocks;

type
  TNativeMirrorImportTableBuffer = class
  private
    FDescriptorsRva: DWORD;
    FDescriptors: TArray<NativePe.Types.TImageImportDescriptor>;
    FNamesRva: DWORD;
    FNames: TBytes;
    FDllsRva: DWORD;
    FDlls: TBytes;
    function GetBufferSpace(Buffer: PByte; BufferSize: NativeUInt; BufferRva, RequiredRva: DWORD; RequiredSize: NativeUInt): PByte;
  public
    constructor Create(DescriptorsRva: DWORD);
    function AllocateDescriptors(Count: NativeUInt): Boolean;
    function AllocateNamesSpace(NamesRva: DWORD; NamesSize: NativeUInt): Boolean;
    function AllocateDllsSpace(DllsRva: DWORD; DllsSize: NativeUInt): Boolean;
    function DescriptorCount: NativeUInt;
    function DescriptorsSize: NativeUInt;
    function NamesSize: NativeUInt;
    function DllNamesSize: NativeUInt;
    function Rva: DWORD;
    function NamesSpaceAt(ValueRva: DWORD; RequiredSize: NativeUInt): PByte;
    function DllSpaceAt(ValueRva: DWORD; RequiredSize: NativeUInt): PByte;
    function SetTableInPe(Buffer: PByte; BufferSize: NativeUInt): Boolean;
    property Descriptors: TArray<NativePe.Types.TImageImportDescriptor> read FDescriptors write FDescriptors;
  end;

  TNativeMirrorImportReconstructor = class
  private
    FBuffer: TNativeMirrorDumpBuffer;
    FIs64Bit: Boolean;
    FFoundIats: TObjectDictionary<DWORD, TNativeMirrorIatBlock>;
    FMainIatThunks: TDictionary<DWORD, Byte>;
    function RecreateImportTableFiltered(ExportsMap: TExportsMapper; Mode: TNativeMirrorImportRecoveryMode): TNativeMirrorImportRecoveryResult;
    function FindIatBlock(ExportsMap: TExportsMapper; StartOffset: NativeUInt): TNativeMirrorIatBlock;
    function FindIat(ExportsMap: TExportsMapper; StartOffset: NativeUInt): TNativeMirrorIatBlock;
    procedure CollectMainIatData;
    function HasDynamicIat: Boolean;
    function MainIatSize: NativeUInt;
    function MaxDynamicIatSize(IsIatTerminated: Boolean): NativeUInt;
    function FindImportTableForIats(ExportsMap: TExportsMapper): Boolean;
    function CollectIats(ExportsMap: TExportsMapper): NativeUInt;
    function IsDefaultImportValid(ExportsMap: TExportsMapper): Boolean;
    function FindIatsCoverage(ExportsMap: TExportsMapper; Filter: TNativeMirrorImportRecoveryFilter): Boolean;
    function ConstructImportTable: TNativeMirrorImportTableBuffer;
    function AppendImportTable(ImportTable: TNativeMirrorImportTableBuffer): Boolean;
    function AppendFoundIat(IatOffset: DWORD; FoundBlock: TNativeMirrorIatBlock): Boolean;
    function SortedIatKeys: TArray<DWORD>;
  public
    constructor Create(Buffer: TNativeMirrorDumpBuffer);
    destructor Destroy; override;
    function RebuildImportTable(ExportsMap: TExportsMapper; Mode: TNativeMirrorImportRecoveryMode): TNativeMirrorImportRecoveryResult;
    function PrintFoundIats(const ReportPath: string): Boolean;
    property Is64Bit: Boolean read FIs64Bit;
    property FoundIats: TObjectDictionary<DWORD, TNativeMirrorIatBlock> read FFoundIats;
  end;

implementation

uses
  System.Classes,
  NativePe.BufferUtil,
  NativePe.ExportedFunc,
  NativePe.ImportsLoader,
  NativePe.PeHdrsHelper,
  NativePe.PeModeDetector,
  NativeMirror.Dumper.Imports.Finder,
  NativeMirror.Scanner.Patterns;

type
  TNativeMirrorSelfThunkFilter = class(TNativeMirrorThunkFoundCallback)
  private
    FStartAddress: UInt64;
    FEndAddress: UInt64;
  public
    constructor Create(StartAddress: UInt64; ModuleSize: NativeUInt);
    function ShouldProcessVa(Va: UInt64): Boolean; override;
    function ShouldAcceptExport(Va: UInt64; ExportedFunction: TExportedFunc): Boolean; override;
  end;

constructor TNativeMirrorSelfThunkFilter.Create(StartAddress: UInt64; ModuleSize: NativeUInt);
begin
  inherited Create;
  FStartAddress := StartAddress;
  FEndAddress := StartAddress + ModuleSize;
end;

function TNativeMirrorSelfThunkFilter.ShouldProcessVa(Va: UInt64): Boolean;
begin
  Result := not ((Va >= FStartAddress) and (Va < FEndAddress));
end;

function TNativeMirrorSelfThunkFilter.ShouldAcceptExport(Va: UInt64; ExportedFunction: TExportedFunc): Boolean;
begin
  Result := True;
end;

constructor TNativeMirrorImportTableBuffer.Create(DescriptorsRva: DWORD);
begin
  inherited Create;
  FDescriptorsRva := DescriptorsRva;
end;

function TNativeMirrorImportTableBuffer.AllocateDescriptors(Count: NativeUInt): Boolean;
begin
  Result := False;
  if Count > High(Integer) then
    Exit;
  SetLength(FDescriptors, Integer(Count));
  if Count > 0 then
    FillChar(FDescriptors[0], Count * SizeOf(NativePe.Types.TImageImportDescriptor), 0);
  Result := Length(FDescriptors) = Integer(Count);
end;

function TNativeMirrorImportTableBuffer.AllocateNamesSpace(NamesRva: DWORD; NamesSize: NativeUInt): Boolean;
begin
  Result := False;
  if NamesSize > High(Integer) then
    Exit;
  FNamesRva := NamesRva;
  SetLength(FNames, Integer(NamesSize));
  if NamesSize > 0 then
    FillChar(FNames[0], NamesSize, 0);
  Result := Length(FNames) = Integer(NamesSize);
end;

function TNativeMirrorImportTableBuffer.AllocateDllsSpace(DllsRva: DWORD; DllsSize: NativeUInt): Boolean;
begin
  Result := False;
  if DllsSize > High(Integer) then
    Exit;
  FDllsRva := DllsRva;
  SetLength(FDlls, Integer(DllsSize));
  if DllsSize > 0 then
    FillChar(FDlls[0], DllsSize, 0);
  Result := Length(FDlls) = Integer(DllsSize);
end;

function TNativeMirrorImportTableBuffer.DescriptorCount: NativeUInt;
begin
  Result := Length(FDescriptors);
end;

function TNativeMirrorImportTableBuffer.DescriptorsSize: NativeUInt;
begin
  Result := NativeUInt(Length(FDescriptors)) * SizeOf(NativePe.Types.TImageImportDescriptor);
end;

function TNativeMirrorImportTableBuffer.NamesSize: NativeUInt;
begin
  Result := Length(FNames);
end;

function TNativeMirrorImportTableBuffer.DllNamesSize: NativeUInt;
begin
  Result := Length(FDlls);
end;

function TNativeMirrorImportTableBuffer.Rva: DWORD;
begin
  Result := FDescriptorsRva;
end;

function TNativeMirrorImportTableBuffer.GetBufferSpace(Buffer: PByte; BufferSize: NativeUInt; BufferRva, RequiredRva: DWORD; RequiredSize: NativeUInt): PByte;
var
  Offset: NativeUInt;
begin
  Result := nil;
  if (Buffer = nil) or (BufferRva > RequiredRva) then
    Exit;
  Offset := RequiredRva - BufferRva;
  if ValidatePtr(Buffer, BufferSize, PByte(NativeUInt(Buffer) + Offset), RequiredSize) then
    Result := PByte(NativeUInt(Buffer) + Offset);
end;

function TNativeMirrorImportTableBuffer.NamesSpaceAt(ValueRva: DWORD; RequiredSize: NativeUInt): PByte;
begin
  if Length(FNames) = 0 then
    Exit(nil);
  Result := GetBufferSpace(@FNames[0], Length(FNames), FNamesRva, ValueRva, RequiredSize);
end;

function TNativeMirrorImportTableBuffer.DllSpaceAt(ValueRva: DWORD; RequiredSize: NativeUInt): PByte;
begin
  if Length(FDlls) = 0 then
    Exit(nil);
  Result := GetBufferSpace(@FDlls[0], Length(FDlls), FDllsRva, ValueRva, RequiredSize);
end;

function TNativeMirrorImportTableBuffer.SetTableInPe(Buffer: PByte; BufferSize: NativeUInt): Boolean;
var
  ImportDirectory: NativePe.Types.PImageDataDirectory;
  ImportTableSize: NativeUInt;
begin
  Result := False;
  if (Length(FDescriptors) = 0) or (Length(FNames) = 0) or (Length(FDlls) = 0) then
    Exit;
  if (UInt64(FDescriptorsRva) + DescriptorsSize > BufferSize) or (UInt64(FNamesRva) + NamesSize > BufferSize) or (UInt64(FDllsRva) + DllNamesSize > BufferSize) then
    Exit;
  ImportDirectory := NativePe.PeHdrsHelper.GetDirectoryEntry(Buffer, IMAGE_DIRECTORY_ENTRY_IMPORT, True);
  if ImportDirectory = nil then
    Exit;
  Move(FDescriptors[0], PByte(NativeUInt(Buffer) + FDescriptorsRva)^, DescriptorsSize);
  Move(FNames[0], PByte(NativeUInt(Buffer) + FNamesRva)^, NamesSize);
  Move(FDlls[0], PByte(NativeUInt(Buffer) + FDllsRva)^, DllNamesSize);
  ImportTableSize := DescriptorsSize + NamesSize;
  ImportDirectory.VirtualAddress := FDescriptorsRva;
  ImportDirectory.Size := MaskToDword(ImportTableSize);
  Result := True;
end;

constructor TNativeMirrorImportReconstructor.Create(Buffer: TNativeMirrorDumpBuffer);
begin
  inherited Create;
  FBuffer := Buffer;
  FFoundIats := TObjectDictionary<DWORD, TNativeMirrorIatBlock>.Create([doOwnsValues]);
  FMainIatThunks := TDictionary<DWORD, Byte>.Create;
  if (FBuffer <> nil) and (FBuffer.Data <> nil) then
  begin
    if FBuffer.IsValidPe then
      FIs64Bit := NativePe.PeHdrsHelper.Is64Bit(FBuffer.Data)
    else
      FIs64Bit := Find64BitCode(FBuffer.Data, FBuffer.Size) <> NM_PATTERN_NOT_FOUND;
  end;
  CollectMainIatData;
end;

destructor TNativeMirrorImportReconstructor.Destroy;
begin
  FMainIatThunks.Free;
  FFoundIats.Free;
  inherited;
end;

function TNativeMirrorImportReconstructor.SortedIatKeys: TArray<DWORD>;
var
  Key: DWORD;
  List: TList<DWORD>;
begin
  List := TList<DWORD>.Create;
  try
    for Key in FFoundIats.Keys do
      List.Add(Key);
    List.Sort;
    Result := List.ToArray;
  finally
    List.Free;
  end;
end;

function TNativeMirrorImportReconstructor.AppendFoundIat(IatOffset: DWORD; FoundBlock: TNativeMirrorIatBlock): Boolean;
begin
  Result := not FFoundIats.ContainsKey(IatOffset);
  if Result then
    FFoundIats.Add(IatOffset, FoundBlock);
end;

procedure TNativeMirrorImportReconstructor.CollectMainIatData;
var
  Thunks: TList<DWORD>;
  Thunk: DWORD;
begin
  if (FBuffer = nil) or (FBuffer.Data = nil) or not NativePe.ImportsLoader.HasValidImportTable(FBuffer.Data, FBuffer.Size) then
    Exit;
  Thunks := TList<DWORD>.Create;
  try
    if NativePe.ImportsLoader.CollectThunks(FBuffer.Data, FBuffer.Size, Thunks) then
      for Thunk in Thunks do
        FMainIatThunks.AddOrSetValue(Thunk, 1);
  finally
    Thunks.Free;
  end;
end;

function TNativeMirrorImportReconstructor.FindIatBlock(ExportsMap: TExportsMapper; StartOffset: NativeUInt): TNativeMirrorIatBlock;
var
  Filter: TNativeMirrorSelfThunkFilter;
begin
  Result := nil;
  if (ExportsMap = nil) or (FBuffer = nil) then
    Exit;
  Filter := TNativeMirrorSelfThunkFilter.Create(FBuffer.ModuleBase, FBuffer.Size);
  try
    Result := NativeMirror.Dumper.Imports.Finder.FindIat(FBuffer.Data, FBuffer.Size, ExportsMap, StartOffset, Filter, FIs64Bit);
  finally
    Filter.Free;
  end;
end;

function TNativeMirrorImportReconstructor.FindIat(ExportsMap: TExportsMapper; StartOffset: NativeUInt): TNativeMirrorIatBlock;
var
  Directory: NativePe.Types.PImageDataDirectory;
  MainRva, MainSize: DWORD;
begin
  Result := FindIatBlock(ExportsMap, StartOffset);
  if Result = nil then
    Exit;
  MainRva := 0;
  MainSize := 0;
  Directory := NativePe.PeHdrsHelper.GetDirectoryEntry(FBuffer.Data, IMAGE_DIRECTORY_ENTRY_IAT, True);
  if Directory <> nil then
  begin
    MainRva := Directory.VirtualAddress;
    MainSize := Directory.Size;
  end;
  if ((MainRva <> 0) and (Result.IatOffset >= MainRva) and (UInt64(Result.IatOffset) < UInt64(MainRva) + MainSize)) or FMainIatThunks.ContainsKey(Result.IatOffset) then
    Result.IsInMain := True;
end;

function TNativeMirrorImportReconstructor.CollectIats(ExportsMap: TExportsMapper): NativeUInt;
var
  SearchOffset, EndOffset: NativeUInt;
  Current: TNativeMirrorIatBlock;
  IatOffset: DWORD;
begin
  Result := 0;
  if (FBuffer = nil) or (FBuffer.Data = nil) then
    Exit;
  SearchOffset := NativePe.PeHdrsHelper.GetHdrsSize(FBuffer.Data);
  while SearchOffset < FBuffer.Size do
  begin
    Current := FindIat(ExportsMap, SearchOffset);
    if Current = nil then
      Break;
    Inc(Result);
    IatOffset := Current.IatOffset;
    EndOffset := UInt64(IatOffset) + Current.IatSize;
    if not AppendFoundIat(IatOffset, Current) then
      Current.Free;
    if EndOffset <= SearchOffset then
      Break;
    SearchOffset := EndOffset;
  end;
end;

function TNativeMirrorImportReconstructor.HasDynamicIat: Boolean;
begin
  Result := MaxDynamicIatSize(True) >= NATIVE_MIRROR_MIN_IAT_THUNKS;
end;

function TNativeMirrorImportReconstructor.MainIatSize: NativeUInt;
var
  Key: DWORD;
  Block: TNativeMirrorIatBlock;
begin
  Result := 0;
  for Key in SortedIatKeys do
  begin
    Block := FFoundIats[Key];
    if Block.IsInMain then
      Inc(Result, Block.CountThunks);
  end;
end;

function TNativeMirrorImportReconstructor.MaxDynamicIatSize(IsIatTerminated: Boolean): NativeUInt;
var
  Key: DWORD;
  Block: TNativeMirrorIatBlock;
  Count: NativeUInt;
begin
  Result := 0;
  for Key in SortedIatKeys do
  begin
    Block := FFoundIats[Key];
    Count := Block.CountThunks;
    if (not Block.IsInMain) and (Block.IsTerminated = IsIatTerminated) and (Count > Result) then
      Result := Count;
  end;
end;

function TNativeMirrorImportReconstructor.IsDefaultImportValid(ExportsMap: TExportsMapper): Boolean;
var
  IatDirectory, ImportDirectory: NativePe.Types.PImageDataDirectory;
  IatOffset: DWORD;
  Block: TNativeMirrorIatBlock;
  StartOffset, TableSize, ImportOffset: NativeUInt;
  ImportTable: NativePe.Types.PImageImportDescriptor;
begin
  Result := False;
  if (FBuffer = nil) or (FBuffer.Data = nil) then
    Exit;
  IatDirectory := NativePe.PeHdrsHelper.GetDirectoryEntry(FBuffer.Data, IMAGE_DIRECTORY_ENTRY_IAT, True);
  ImportDirectory := NativePe.PeHdrsHelper.GetDirectoryEntry(FBuffer.Data, IMAGE_DIRECTORY_ENTRY_IMPORT, True);
  if (IatDirectory = nil) or (ImportDirectory = nil) then
    Exit;
  if (ImportDirectory.VirtualAddress = 0) and (ImportDirectory.Size = 0) and (IatDirectory.VirtualAddress = 0) and (IatDirectory.Size = 0) then
    Exit;
  if (IatDirectory.VirtualAddress <> 0) and (ImportDirectory.VirtualAddress = 0) then
    Exit;
  IatOffset := IatDirectory.VirtualAddress;
  Block := FindIatBlock(ExportsMap, IatOffset);
  try
    if Block = nil then
      Exit;
    StartOffset := NativePe.PeHdrsHelper.GetHdrsSize(FBuffer.Data);
    ImportTable := NativeMirror.Dumper.Imports.Finder.FindImportTable(FIs64Bit, FBuffer.Data, FBuffer.Size, ExportsMap, IatOffset, TableSize, StartOffset);
    if ImportTable = nil then
      Exit;
    ImportOffset := NativeUInt(ImportTable) - NativeUInt(FBuffer.Data);
    Result := ImportDirectory.VirtualAddress = DWORD(ImportOffset and $FFFFFFFF);
  finally
    Block.Free;
  end;
end;

function TNativeMirrorImportReconstructor.FindImportTableForIats(ExportsMap: TExportsMapper): Boolean;
var
  ImportDirectory, IatDirectory: NativePe.Types.PImageDataDirectory;
  Key: DWORD;
  Current: TNativeMirrorIatBlock;
  ImportTable: NativePe.Types.PImageImportDescriptor;
  TableSize, StartOffset, ImportOffset: NativeUInt;
begin
  Result := False;
  if (FBuffer = nil) or (FBuffer.Data = nil) then
    Exit;
  ImportDirectory := NativePe.PeHdrsHelper.GetDirectoryEntry(FBuffer.Data, IMAGE_DIRECTORY_ENTRY_IMPORT, True);
  IatDirectory := NativePe.PeHdrsHelper.GetDirectoryEntry(FBuffer.Data, IMAGE_DIRECTORY_ENTRY_IAT, True);
  if (ImportDirectory = nil) or (IatDirectory = nil) then
    Exit;
  StartOffset := NativePe.PeHdrsHelper.GetHdrsSize(FBuffer.Data);
  ImportTable := nil;
  TableSize := 0;
  for Key in SortedIatKeys do
  begin
    Current := FFoundIats[Key];
    ImportTable := NativeMirror.Dumper.Imports.Finder.FindImportTable(FIs64Bit, FBuffer.Data, FBuffer.Size, ExportsMap, Current.IatOffset, TableSize, StartOffset);
    if ImportTable <> nil then
    begin
      Current.ImportTableOffset := DWORD((NativeUInt(ImportTable) - NativeUInt(FBuffer.Data)) and $FFFFFFFF);
      IatDirectory.VirtualAddress := Current.IatOffset;
      IatDirectory.Size := MaskToDword(Current.IatSize);
      Break;
    end;
  end;
  if ImportTable = nil then
    Exit;
  ImportOffset := NativeUInt(ImportTable) - NativeUInt(FBuffer.Data);
  if (ImportDirectory.VirtualAddress = DWORD(ImportOffset and $FFFFFFFF)) and (ImportDirectory.Size = TableSize) then
    Exit(True);
  ImportDirectory.VirtualAddress := DWORD(ImportOffset and $FFFFFFFF);
  ImportDirectory.Size := MaskToDword(TableSize);
  Result := True;
end;

function TNativeMirrorImportReconstructor.FindIatsCoverage(ExportsMap: TExportsMapper; Filter: TNativeMirrorImportRecoveryFilter): Boolean;
var
  Key: DWORD;
  Block: TNativeMirrorIatBlock;
  Needed, Covered: NativeUInt;
begin
  Needed := 0;
  Covered := 0;
  for Key in SortedIatKeys do
  begin
    Block := FFoundIats[Key];
    if (Filter = nmImportFilter0) and (not Block.IsInMain) and (not Block.IsTerminated) then
      Continue;
    if (Filter in [nmImportFilter0, nmImportFilter1]) and (not Block.IsInMain) and (not Block.IsTerminated) and (Block.CountThunks < NATIVE_MIRROR_MIN_IAT_THUNKS) then
      Continue;
    Inc(Needed);
    if Block.MakeCoverage(ExportsMap) then
      Inc(Covered);
  end;
  Result := (Needed <> 0) and (Covered = Needed);
end;

function TNativeMirrorImportReconstructor.ConstructImportTable: TNativeMirrorImportTableBuffer;
var
  Key: DWORD;
  Block: TNativeMirrorIatBlock;
  Series: TNativeMirrorIatThunkSeries;
  ReadyBlocks, NamesSpace, DllsAreaSize, I, NamesSpaceSize, MaxDllName: NativeUInt;
  EndRva, NamesStartRva, OriginalThunkRva, DllsRva, DllNameRva, NameRva: DWORD;
  BufferPtr: PByte;
  NameAnsi: AnsiString;
  Descriptors: TArray<NativePe.Types.TImageImportDescriptor>;
begin
  Result := nil;
  if (FBuffer = nil) or (FBuffer.Data = nil) or (FBuffer.Size = 0) then
    Exit;
  ReadyBlocks := 0;
  for Key in SortedIatKeys do
  begin
    Block := FFoundIats[Key];
    if Block.IsValid then
      Inc(ReadyBlocks, Block.ThunkSeries.Count);
  end;
  if ReadyBlocks = 0 then
    Exit;
  EndRva := MaskToDword(FBuffer.Size);
  Result := TNativeMirrorImportTableBuffer.Create(EndRva);
  if not Result.AllocateDescriptors(ReadyBlocks + 1) then
  begin
    FreeAndNil(Result);
    Exit;
  end;
  Descriptors := Result.Descriptors;
  NamesStartRva := MaskToDword(UInt64(Result.Rva) + Result.DescriptorsSize);
  OriginalThunkRva := NamesStartRva;
  NamesSpace := 0;
  I := 0;
  for Key in SortedIatKeys do
  begin
    Block := FFoundIats[Key];
    if not Block.IsValid then
      Continue;
    for Series in Block.ThunkSeries do
    begin
      Descriptors[I].FirstThunk := Series.StartOffset;
      Descriptors[I].OriginalFirstThunk := OriginalThunkRva;
      NamesSpaceSize := Series.SizeOfNamesSpace(FIs64Bit);
      Inc(NamesSpace, NamesSpaceSize);
      Inc(OriginalThunkRva, DWORD(NamesSpaceSize));
      Inc(I);
    end;
  end;
  Result.Descriptors := Descriptors;
  if not Result.AllocateNamesSpace(NamesStartRva, NamesSpace) then
  begin
    FreeAndNil(Result);
    Exit;
  end;
  Descriptors := Result.Descriptors;
  DllsRva := MaskToDword(UInt64(NamesStartRva) + NamesSpace);
  DllsAreaSize := 0;
  I := 0;
  for Key in SortedIatKeys do
  begin
    Block := FFoundIats[Key];
    if not Block.IsValid then
      Continue;
    for Series in Block.ThunkSeries do
    begin
      NameRva := Descriptors[I].OriginalFirstThunk;
      NamesSpaceSize := Series.SizeOfNamesSpace(FIs64Bit);
      BufferPtr := Result.NamesSpaceAt(NameRva, NamesSpaceSize);
      if BufferPtr <> nil then
        Series.FillNamesSpace(BufferPtr, NamesSpaceSize, NameRva, FIs64Bit);
      Inc(I);
    end;
    Inc(DllsAreaSize, Block.SizeOfDllsSpace);
  end;
  if not Result.AllocateDllsSpace(DllsRva, DllsAreaSize) then
  begin
    FreeAndNil(Result);
    Exit;
  end;
  DllNameRva := DllsRva;
  I := 0;
  for Key in SortedIatKeys do
  begin
    Block := FFoundIats[Key];
    if not Block.IsValid then
      Continue;
    MaxDllName := Block.MaxDllLength;
    for Series in Block.ThunkSeries do
    begin
      Descriptors[I].Name := DllNameRva;
      BufferPtr := Result.DllSpaceAt(DllNameRva, MaxDllName);
      if BufferPtr <> nil then
      begin
        NameAnsi := AnsiString(Series.DllName);
        if Length(NameAnsi) > 0 then
          Move(PAnsiChar(NameAnsi)^, BufferPtr^, Length(NameAnsi));
        BufferPtr[Length(NameAnsi)] := 0;
      end;
      Inc(DllNameRva, DWORD(MaxDllName));
      Inc(I);
    end;
  end;
  Result.Descriptors := Descriptors;
end;

function TNativeMirrorImportReconstructor.AppendImportTable(ImportTable: TNativeMirrorImportTableBuffer): Boolean;
var
  ImportTableSize, NewSize: NativeUInt;
  StartRva: DWORD;
begin
  Result := False;
  if (ImportTable = nil) or (FBuffer = nil) then
    Exit;
  ImportTableSize := ImportTable.DescriptorsSize + ImportTable.NamesSize + ImportTable.DllNamesSize;
  if ImportTableSize > High(NativeUInt) - FBuffer.Size then
    Exit;
  NewSize := FBuffer.Size + ImportTableSize;
  if not FBuffer.ResizeBuffer(NewSize) then
    Exit;
  StartRva := ImportTable.Rva;
  if not FBuffer.ResizeLastSection(UInt64(StartRva) + ImportTableSize) then
    Exit;
  Result := ImportTable.SetTableInPe(FBuffer.Data, FBuffer.Size);
end;

function TNativeMirrorImportReconstructor.RecreateImportTableFiltered(ExportsMap: TExportsMapper; Mode: TNativeMirrorImportRecoveryMode): TNativeMirrorImportRecoveryResult;
var
  Filter: TNativeMirrorImportRecoveryFilter;
  UnterminatedSize, MainSize, TerminatedSize: NativeUInt;
  ImportTable: TNativeMirrorImportTableBuffer;
  Ok: Boolean;
begin
  Filter := nmImportFilter0;
  case Mode of
    nmImportRebuild0: Filter := nmImportFilter0;
    nmImportRebuild1: Filter := nmImportFilter1;
    nmImportRebuild2: Filter := nmImportFilter2;
  end;
  if Mode = nmImportAuto then
  begin
    UnterminatedSize := MaxDynamicIatSize(False);
    if UnterminatedSize > NATIVE_MIRROR_MIN_IAT_THUNKS then
    begin
      MainSize := MainIatSize;
      TerminatedSize := MaxDynamicIatSize(True);
      if (UnterminatedSize > MainSize) and (UnterminatedSize > TerminatedSize) then
        Filter := nmImportFilter1;
    end;
  end;
  while not FindIatsCoverage(ExportsMap, Filter) do
  begin
    if Mode <> nmImportAuto then
      Exit(nmImportRecoveryError);
    if Filter = nmImportFilter2 then
      Exit(nmImportRecoveryError);
    Filter := TNativeMirrorImportRecoveryFilter(Ord(Filter) + 1);
  end;
  ImportTable := ConstructImportTable;
  try
    Ok := (ImportTable <> nil) and AppendImportTable(ImportTable);
  finally
    ImportTable.Free;
  end;
  if not Ok then
    Exit(nmImportRecoveryError);
  case Filter of
    nmImportFilter0: Result := nmImportRecreatedFilter0;
    nmImportFilter1: Result := nmImportRecreatedFilter1;
    nmImportFilter2: Result := nmImportRecreatedFilter2;
  else
    Result := nmImportRecreatedFilter0;
  end;
end;

function TNativeMirrorImportReconstructor.RebuildImportTable(ExportsMap: TExportsMapper; Mode: TNativeMirrorImportRecoveryMode): TNativeMirrorImportRecoveryResult;
begin
  if (ExportsMap = nil) or (Mode = nmImportNone) then
    Exit(nmImportRecoverySkipped);
  if CollectIats(ExportsMap) = 0 then
    Exit(nmImportNotFound);
  if not FBuffer.IsValidPe then
    Exit(nmImportRecoveryNotApplicable);
  if (not NativePe.PeModeDetector.IsPeRawEqVirtual(FBuffer.Data, FBuffer.Size)) and NativePe.PeModeDetector.IsPeRaw(FBuffer.Data, FBuffer.Size) then
    Exit(nmImportRecoveryNotApplicable);
  if (Mode = nmImportUnerase) or ((Mode = nmImportAuto) and not HasDynamicIat) then
  begin
    if IsDefaultImportValid(ExportsMap) then
      Exit(nmImportAlreadyOk);
    if FindImportTableForIats(ExportsMap) then
      Exit(nmImportDirectoryFixed);
  end;
  if NativePe.PeHdrsHelper.IsDotNet(FBuffer.Data, FBuffer.Size) and (Mode = nmImportAuto) then
    Exit(nmImportAlreadyOk);
  if Mode in [nmImportRebuild0, nmImportRebuild1, nmImportRebuild2, nmImportAuto] then
    Exit(RecreateImportTableFiltered(ExportsMap, Mode));
  Result := nmImportRecoveryError;
end;

function TNativeMirrorImportReconstructor.PrintFoundIats(const ReportPath: string): Boolean;
var
  Writer: TFileStream;
  Bytes: TBytes;
  Key: DWORD;
begin
  Result := False;
  if FFoundIats.Count = 0 then
    Exit;
  try
    Writer := TFileStream.Create(ReportPath, fmCreate);
    try
      for Key in SortedIatKeys do
      begin
        Bytes := TEncoding.UTF8.GetBytes(FFoundIats[Key].ToText);
        if Length(Bytes) <> 0 then
          Writer.WriteBuffer(Bytes[0], Length(Bytes));
      end;
    finally
      Writer.Free;
    end;
    Result := True;
  except
    Result := False;
  end;
end;

end.
