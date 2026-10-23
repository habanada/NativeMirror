{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Dumper.Buffer;

interface

uses
  Winapi.Windows,
  System.Classes,
  NativePe.ExportsMapper,
  NativePe.ImportsUneraser,
  NativeMirror.Core.Buffer,
  NativeMirror.Core.Memory,
  NativeMirror.Core.Types;

type
  TNativeMirrorDumpBuffer = class
  private
    FReader: INativeMirrorMemoryReader;
    FBuffer: TNativeMirrorBuffer;
    FModuleBase: UInt64;
    FRelocBase: UInt64;
    FIsReflection: Boolean;
    function ReadRemoteInternal(ModuleBase: UInt64; VirtualSize: NativeUInt): Boolean;
    function CalculateRemoteImageSize(ModuleBase: UInt64): NativeUInt;
    function ConvertDumpMode(Mode: TNativeMirrorDumpMode): Integer;
    function ConvertNativeDumpMode(Mode: Integer): TNativeMirrorDumpMode;
    function GetData: PByte;
    function GetSize: NativeUInt;
  public
    constructor Create(const Reader: INativeMirrorMemoryReader = nil; IsReflection: Boolean = False);
    destructor Destroy; override;
    function IsFilled: Boolean;
    function IsValidPe: Boolean;
    function IsCode: Boolean;
    function ReadRemote(ModuleBase: UInt64; VirtualSize: NativeUInt = 0): Boolean;
    function FillFromBuffer(ModuleBase: UInt64; Data: Pointer; DataSize: NativeUInt): Boolean;
    function FillFromStream(ModuleBase: UInt64; Stream: TStream): Boolean;
    function ResizeBuffer(NewSize: NativeUInt): Boolean;
    function ResizeLastSection(NewImageSize: NativeUInt): Boolean;
    function BuildPe(var DumpMode: TNativeMirrorDumpMode; ExportsMap: TExportsMapper; NotCovered: TImpsNotCovered; out Output: TNativeMirrorBuffer): Boolean;
    function DumpPeToFile(const FileName: string; var DumpMode: TNativeMirrorDumpMode; ExportsMap: TExportsMapper = nil; NotCovered: TImpsNotCovered = nil): Boolean;
    function DumpPeToStream(Stream: TStream; var DumpMode: TNativeMirrorDumpMode; ExportsMap: TExportsMapper = nil; NotCovered: TImpsNotCovered = nil): Boolean;
    function DumpToFile(const FileName: string): Boolean;
    function DumpToStream(Stream: TStream): Boolean;
    property Data: PByte read GetData;
    property Size: NativeUInt read GetSize;
    property ModuleBase: UInt64 read FModuleBase;
    property RelocBase: UInt64 read FRelocBase write FRelocBase;
    property Reader: INativeMirrorMemoryReader read FReader;
  end;

implementation

uses
  System.SysUtils,
  NativePe.BufferUtil,
  NativePe.DotNetEpFixer,
  NativePe.FileUtil,
  NativePe.FindBase,
  NativePe.FixImports,
  NativePe.PeDumper,
  NativePe.PeHdrsHelper,
  NativePe.PeModeDetector,
  NativePe.PeVirtualToRaw,
  NativePe.RemotePeReader,
  NativePe.Types,
  NativeMirror.Scanner.Patterns,
  NativeMirror.Core.PeValidation;

constructor TNativeMirrorDumpBuffer.Create(const Reader: INativeMirrorMemoryReader; IsReflection: Boolean);
begin
  inherited Create;
  FReader := Reader;
  FIsReflection := IsReflection;
  FBuffer := TNativeMirrorBuffer.Create;
end;

destructor TNativeMirrorDumpBuffer.Destroy;
begin
  FBuffer.Free;
  inherited;
end;


function TNativeMirrorDumpBuffer.GetData: PByte;
begin
  Result := FBuffer.Data;
end;

function TNativeMirrorDumpBuffer.GetSize: NativeUInt;
begin
  Result := FBuffer.Size;
end;

function TNativeMirrorDumpBuffer.IsFilled: Boolean;
begin
  Result := (FBuffer.Data <> nil) and (FBuffer.Size > 0);
end;

function TNativeMirrorDumpBuffer.IsValidPe: Boolean;
begin
  Result := (FBuffer.Data <> nil) and (GetNtHdrs(FBuffer.Data, FBuffer.Size) <> nil);
end;

function TNativeMirrorDumpBuffer.IsCode: Boolean;
begin
  Result := NativeMirror.Scanner.Patterns.IsCode(FBuffer.Data, FBuffer.Size);
end;

function TNativeMirrorDumpBuffer.CalculateRemoteImageSize(ModuleBase: UInt64): NativeUInt;
var
  Header: array[0..PE_PAGE_SIZE - 1] of Byte;
  ReadSize: NativeUInt;
  FirstSection, Current: NativePe.Types.PImageSectionHeader;
  MainRegion, SectionRegion: TNativeMirrorMemoryRegion;
  MaxRva, LastSize: UInt64;
begin
  Result := 0;
  if FReader = nil then
    Exit;
  ReadSize := FReader.ReadMemory(ModuleBase, @Header[0], SizeOf(Header), FIsReflection);
  if ReadSize = 0 then
    Exit;
  FirstSection := GetSectionHdr(@Header[0], ReadSize, 0);
  if FirstSection = nil then
  begin
    Result := NativeMirrorRegionSize(FReader, ModuleBase);
    Exit;
  end;
  if not FReader.QueryRegion(ModuleBase, MainRegion) then
    Exit;
  MaxRva := 0;
  Current := FirstSection;
  while NativeMirror.Core.PeValidation.IsValidSectionHeader(@Header[0], ReadSize, Current, 0) do
  begin
    if (Current.Misc.VirtualSize <> 0) and (Current.VirtualAddress <> 0) then
    begin
      if not FReader.QueryRegion(ModuleBase + Current.VirtualAddress, SectionRegion) then
        Break;
      if SectionRegion.AllocationBase <> MainRegion.AllocationBase then
        Break;
      if (SectionRegion.MappingType = 0) or (SectionRegion.Protect = 0) then
        Break;
      if ((SectionRegion.State and MEM_COMMIT) <> 0) and (Current.VirtualAddress > MaxRva) then
        MaxRva := Current.VirtualAddress;
    end;
    Inc(Current);
  end;
  LastSize := NativeMirrorRegionSize(FReader, ModuleBase + MaxRva);
  Result := MaxRva + LastSize;
end;

function TNativeMirrorDumpBuffer.ReadRemoteInternal(ModuleBase: UInt64; VirtualSize: NativeUInt): Boolean;
var
  ReadSize: NativeUInt;
begin
  Result := False;
  if (FReader = nil) or (VirtualSize = 0) then
    Exit;
  if not FBuffer.Allocate(VirtualSize) then
    Exit;
  FModuleBase := ModuleBase;
  FRelocBase := ModuleBase;
  ReadSize := FReader.ReadMemory(ModuleBase, FBuffer.Data, VirtualSize, FIsReflection);
  if ReadSize <> VirtualSize then
  begin
    FBuffer.Clear;
    Exit;
  end;
  Result := True;
end;

function TNativeMirrorDumpBuffer.ReadRemote(ModuleBase: UInt64; VirtualSize: NativeUInt): Boolean;
begin
  if VirtualSize = 0 then
  begin
    if (FReader <> nil) and (FReader.ProcessHandle <> 0) then
      VirtualSize := GetRemoteImageSize(FReader.ProcessHandle, Pointer(NativeUInt(ModuleBase)));
  end;
  if ReadRemoteInternal(ModuleBase, VirtualSize) then
    Exit(True);
  VirtualSize := CalculateRemoteImageSize(ModuleBase);
  Result := ReadRemoteInternal(ModuleBase, VirtualSize);
end;

function TNativeMirrorDumpBuffer.FillFromBuffer(ModuleBase: UInt64; Data: Pointer; DataSize: NativeUInt): Boolean;
begin
  Result := FBuffer.Assign(Data, DataSize);
  if Result then
  begin
    FModuleBase := ModuleBase;
    FRelocBase := ModuleBase;
  end;
end;

function TNativeMirrorDumpBuffer.FillFromStream(ModuleBase: UInt64; Stream: TStream): Boolean;
var
  SizeToRead: Int64;
begin
  Result := False;
  if Stream = nil then
    Exit;
  SizeToRead := Stream.Size - Stream.Position;
  if (SizeToRead <= 0) or (UInt64(SizeToRead) > High(Integer)) then
    Exit;
  if not FBuffer.Allocate(NativeUInt(SizeToRead)) then
    Exit;
  if Stream.Read(FBuffer.Data^, Integer(SizeToRead)) <> SizeToRead then
  begin
    FBuffer.Clear;
    Exit;
  end;
  FModuleBase := ModuleBase;
  FRelocBase := ModuleBase;
  Result := True;
end;

function TNativeMirrorDumpBuffer.ResizeBuffer(NewSize: NativeUInt): Boolean;
begin
  Result := FBuffer.Resize(NewSize);
end;

function TNativeMirrorDumpBuffer.ResizeLastSection(NewImageSize: NativeUInt): Boolean;
var
  LastSection: NativePe.Types.PImageSectionHeader;
  NewSectionSize: NativeUInt;
begin
  Result := False;
  if FBuffer.Data = nil then
    Exit;
  LastSection := GetLastSection(FBuffer.Data, FBuffer.Size, False);
  if LastSection = nil then
    Exit;
  if NewImageSize < LastSection.VirtualAddress then
    Exit;
  NewSectionSize := NewImageSize - LastSection.VirtualAddress;
  if UInt64(LastSection.VirtualAddress) + NewSectionSize > FBuffer.Size then
    Exit;
  if not UpdateImageSize(FBuffer.Data, MaskToDword(NewImageSize)) then
    Exit;
  LastSection.Misc.VirtualSize := MaskToDword(NewSectionSize);
  LastSection.SizeOfRawData := MaskToDword(NewSectionSize);
  Result := True;
end;

function TNativeMirrorDumpBuffer.ConvertDumpMode(Mode: TNativeMirrorDumpMode): Integer;
begin
  case Mode of
    nmDumpVirtual: Result := PE_DUMP_VIRTUAL;
    nmDumpUnmap: Result := PE_DUMP_UNMAP;
    nmDumpRealign: Result := PE_DUMP_REALIGN;
  else
    Result := PE_DUMP_AUTO;
  end;
end;

function TNativeMirrorDumpBuffer.ConvertNativeDumpMode(Mode: Integer): TNativeMirrorDumpMode;
begin
  case Mode of
    PE_DUMP_VIRTUAL: Result := nmDumpVirtual;
    PE_DUMP_UNMAP: Result := nmDumpUnmap;
    PE_DUMP_REALIGN: Result := nmDumpRealign;
  else
    Result := nmDumpAuto;
  end;
end;

function TNativeMirrorDumpBuffer.BuildPe(var DumpMode: TNativeMirrorDumpMode; ExportsMap: TExportsMapper; NotCovered: TImpsNotCovered; out Output: TNativeMirrorBuffer): Boolean;
var
  NativeMode: Integer;
  OutputSize: NativeUInt;
  Converted: PByte;
  HdrBase, TargetBase: UInt64;
  TryMode: TNativeMirrorDumpMode;
begin
  Result := False;
  Output := nil;
  if not IsValidPe then
    Exit;
  if ExportsMap <> nil then
    FixImports(FBuffer.Data, FBuffer.Size, ExportsMap, NotCovered);
  TryMode := DumpMode;
  if TryMode = nmDumpAuto then
  begin
    if (not IsValidSectionsAlignment(FBuffer.Data, FBuffer.Size, True)) and IsValidSectionsAlignment(FBuffer.Data, FBuffer.Size, False) then
    begin
      TryMode := nmDumpRealign;
      if BuildPe(TryMode, nil, nil, Output) then
      begin
        DumpMode := TryMode;
        Exit(True);
      end;
      TryMode := nmDumpAuto;
    end;
  end;
  NativeMode := ConvertDumpMode(TryMode);
  if NativeMode = PE_DUMP_AUTO then
    NativeMode := DetectDumpMode(FBuffer.Data, FBuffer.Size);
  DumpMode := ConvertNativeDumpMode(NativeMode);
  if NativeMode = PE_DUMP_VIRTUAL then
  begin
    Output := TNativeMirrorBuffer.Create;
    Result := Output.Assign(FBuffer.Data, FBuffer.Size);
    if not Result then
      FreeAndNil(Output);
    Exit;
  end;
  if GetImageBase(FBuffer.Data) = 0 then
    UpdateImageBase(FBuffer.Data, FRelocBase);
  if IsDotNet(FBuffer.Data, FBuffer.Size) then
    FixDotNetEp(FBuffer.Data, FBuffer.Size);
  HdrBase := GetImageBase(FBuffer.Data);
  TargetBase := FRelocBase;
  if HasRelocations(FBuffer.Data) then
  begin
    TargetBase := HdrBase;
    UpdateImageBase(FBuffer.Data, FRelocBase);
  end;
  Converted := nil;
  OutputSize := 0;
  if NativeMode = PE_DUMP_UNMAP then
    Converted := PeVirtualToRaw(FBuffer.Data, FBuffer.Size, TargetBase, OutputSize, False)
  else if NativeMode = PE_DUMP_REALIGN then
    Converted := PeRealignRawToVirtual(FBuffer.Data, FBuffer.Size, TargetBase, OutputSize);
  if (Converted = nil) or (OutputSize = 0) then
    Exit;
  Output := TNativeMirrorBuffer.Create;
  Result := Output.Assign(Converted, OutputSize);
  FreePeBuffer(Converted, OutputSize);
  if not Result then
    FreeAndNil(Output);
end;

function TNativeMirrorDumpBuffer.DumpPeToFile(const FileName: string; var DumpMode: TNativeMirrorDumpMode; ExportsMap: TExportsMapper; NotCovered: TImpsNotCovered): Boolean;
var
  Output: TNativeMirrorBuffer;
begin
  Output := nil;
  try
    Result := BuildPe(DumpMode, ExportsMap, NotCovered, Output) and NativePe.FileUtil.DumpToFile(FileName, Output.Data, Output.Size);
  finally
    Output.Free;
  end;
end;

function TNativeMirrorDumpBuffer.DumpPeToStream(Stream: TStream; var DumpMode: TNativeMirrorDumpMode; ExportsMap: TExportsMapper; NotCovered: TImpsNotCovered): Boolean;
var
  Output: TNativeMirrorBuffer;
begin
  Result := False;
  Output := nil;
  if Stream = nil then
    Exit;
  try
    if not BuildPe(DumpMode, ExportsMap, NotCovered, Output) or (Output.Size > High(Integer)) then
      Exit;
    Result := Stream.Write(Output.Data^, Integer(Output.Size)) = Integer(Output.Size);
  finally
    Output.Free;
  end;
end;

function TNativeMirrorDumpBuffer.DumpToFile(const FileName: string): Boolean;
begin
  Result := IsFilled and NativePe.FileUtil.DumpToFile(FileName, FBuffer.Data, FBuffer.Size);
end;

function TNativeMirrorDumpBuffer.DumpToStream(Stream: TStream): Boolean;
begin
  Result := False;
  if (Stream = nil) or not IsFilled or (FBuffer.Size > High(Integer)) then
    Exit;
  Result := Stream.Write(FBuffer.Data^, Integer(FBuffer.Size)) = Integer(FBuffer.Size);
end;

end.
