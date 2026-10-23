{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Scanner.MemPage;

interface

uses
  Winapi.Windows,
  NativeMirror.Core.Memory,
  NativeMirror.Core.Buffer;

type
  TNativeMirrorMemPageData = class
  private
    FReader: INativeMirrorMemoryReader;
    FIsReflection: Boolean;
    FInfoFilled: Boolean;
    FLoadedData: TNativeMirrorBuffer;
    FTrimStart: NativeUInt;
    FTrimSize: NativeUInt;
    function LoadRemote: Boolean;
    procedure Trim;
  public
    StartVa: UInt64;
    StopVa: UInt64;
    Protection: DWORD;
    InitialProtect: DWORD;
    MappingType: DWORD;
    IsListedModule: Boolean;
    AllocationBase: UInt64;
    RegionStart: UInt64;
    RegionEnd: UInt64;
    MappedName: string;
    ModuleName: string;
    constructor Create(const Reader: INativeMirrorMemoryReader; IsReflection: Boolean; AStartVa, AStopVa: UInt64);
    destructor Destroy; override;
    function FillInfo: Boolean;
    function Load: Boolean;
    function LoadMappedName: Boolean;
    function LoadModuleName: Boolean;
    function IsRealMapping: Boolean;
    function ValidatePtr(Field: Pointer; FieldSize: NativeUInt): Boolean;
    function GetLoadedData(Trimmed: Boolean = False): PByte;
    function GetLoadedSize(Trimmed: Boolean = False): NativeUInt;
    function GetStartOffset(Trimmed: Boolean = False): NativeUInt;
    property IsInfoFilled: Boolean read FInfoFilled;
    property Reader: INativeMirrorMemoryReader read FReader;
    property LoadedData: TNativeMirrorBuffer read FLoadedData;
  end;

implementation

uses
  Winapi.PsAPI,
  System.SysUtils,
  System.Classes,
  NativePe.BufferUtil,
  NativeMirror.Core.Types,
  NativeMirror.Platform.Paths;

constructor TNativeMirrorMemPageData.Create(const Reader: INativeMirrorMemoryReader; IsReflection: Boolean; AStartVa, AStopVa: UInt64);
begin
  inherited Create;
  FReader := Reader;
  FIsReflection := IsReflection;
  FLoadedData := TNativeMirrorBuffer.Create;
  StartVa := AStartVa;
  StopVa := AStopVa;
  FillInfo;
end;

destructor TNativeMirrorMemPageData.Destroy;
begin
  FLoadedData.Free;
  inherited;
end;

function TNativeMirrorMemPageData.FillInfo: Boolean;
var
  Region: TNativeMirrorMemoryRegion;
begin
  Result := False;
  FInfoFilled := False;
  if (FReader = nil) or not FReader.QueryRegion(StartVa, Region) then
    Exit;
  InitialProtect := Region.AllocationProtect;
  MappingType := Region.MappingType;
  Protection := Region.Protect;
  AllocationBase := Region.AllocationBase;
  RegionStart := Region.BaseAddress;
  RegionEnd := Region.BaseAddress + Region.RegionSize;
  FInfoFilled := True;
  Result := True;
end;

procedure TNativeMirrorMemPageData.Trim;
var
  I, Last: NativeUInt;
begin
  FTrimStart := 0;
  FTrimSize := FLoadedData.Size;
  if (FLoadedData.Data = nil) or (FLoadedData.Size = 0) then
    Exit;
  I := 0;
  while (I < FLoadedData.Size) and (PByte(NativeUInt(FLoadedData.Data) + I)^ = 0) do
    Inc(I);
  if I = FLoadedData.Size then
    Exit;
  FTrimStart := I;
  Last := FLoadedData.Size;
  while (Last > I) and (PByte(NativeUInt(FLoadedData.Data) + Last - 1)^ = 0) do
    Dec(Last);
  FTrimSize := Last - I;
end;

function TNativeMirrorMemPageData.LoadRemote: Boolean;
var
  RegionSize, ReadSize: UInt64;
  Got: NativeUInt;
begin
  Result := False;
  FLoadedData.Clear;
  if not FInfoFilled and not FillInfo then
    Exit;
  if RegionEnd <= StartVa then
    Exit;
  RegionSize := RegionEnd - StartVa;
  if (StopVa <> 0) and (StopVa >= StartVa) and (StopVa < RegionEnd) then
    RegionSize := StopVa - StartVa;
  if (RegionSize = 0) or (RegionSize > High(NativeUInt)) then
    Exit;
  ReadSize := RegionSize;
  if not FLoadedData.Allocate(NativeUInt(ReadSize)) then
    Exit;
  Got := FReader.ReadMemory(StartVa, FLoadedData.Data, FLoadedData.Size, FIsReflection);
  if Got = 0 then
  begin
    FLoadedData.Clear;
    Exit;
  end;
  Trim;
  Result := True;
end;

function TNativeMirrorMemPageData.Load: Boolean;
begin
  if (FLoadedData.Data <> nil) and (FLoadedData.Size <> 0) then
    Exit(True);
  Result := LoadRemote and (FLoadedData.Data <> nil) and (FLoadedData.Size <> 0);
end;

function TNativeMirrorMemPageData.LoadModuleName: Boolean;
var
  Buffer: array[0..32767] of Char;
  Len: DWORD;
begin
  Result := False;
  if (FReader = nil) or (FReader.ProcessHandle = 0) then
    Exit;
  FillChar(Buffer, SizeOf(Buffer), 0);
  Len := GetModuleFileNameEx(FReader.ProcessHandle, HMODULE(NativeUInt(AllocationBase)), Buffer, Length(Buffer));
  if Len = 0 then
    Exit;
  ModuleName := NormalizeModulePath(Buffer);
  Result := ModuleName <> '';
end;

function TNativeMirrorMemPageData.LoadMappedName: Boolean;
var
  Buffer: array[0..32767] of Char;
  Len: DWORD;
begin
  Result := False;
  if not FInfoFilled and not FillInfo then
    Exit;
  if (FReader = nil) or (FReader.ProcessHandle = 0) then
    Exit;
  FillChar(Buffer, SizeOf(Buffer), 0);
  Len := GetMappedFileName(FReader.ProcessHandle, Pointer(NativeUInt(AllocationBase)), Buffer, Length(Buffer));
  if Len = 0 then
    Exit;
  MappedName := NormalizeModulePath(Buffer);
  Result := MappedName <> '';
end;

function TNativeMirrorMemPageData.IsRealMapping: Boolean;
var
  Stream: TFileStream;
  Raw: TBytes;
  CompareSize: NativeUInt;
begin
  Result := False;
  if not LoadMappedName or not Load or not FileExists(MappedName) then
    Exit;
  try
    Stream := TFileStream.Create(MappedName, fmOpenRead or fmShareDenyNone);
    try
      if Stream.Size <= 0 then
        Exit;
      SetLength(Raw, Stream.Size);
      if Stream.Read(Raw[0], Length(Raw)) <> Length(Raw) then
        Exit;
      CompareSize := FLoadedData.Size;
      if CompareSize > NativeUInt(Length(Raw)) then
        CompareSize := Length(Raw);
      Result := (CompareSize <> 0) and CompareMem(FLoadedData.Data, @Raw[0], CompareSize);
    finally
      Stream.Free;
    end;
  except
    Result := False;
  end;
end;

function TNativeMirrorMemPageData.ValidatePtr(Field: Pointer; FieldSize: NativeUInt): Boolean;
begin
  Result := (FLoadedData.Data <> nil) and NativePe.BufferUtil.ValidatePtr(FLoadedData.Data, FLoadedData.Size, Field, FieldSize);
end;

function TNativeMirrorMemPageData.GetLoadedData(Trimmed: Boolean): PByte;
begin
  Result := FLoadedData.Data;
  if Trimmed and (FTrimSize <> 0) and (FTrimSize < FLoadedData.Size) then
    Result := PByte(NativeUInt(FLoadedData.Data) + FTrimStart);
end;

function TNativeMirrorMemPageData.GetLoadedSize(Trimmed: Boolean): NativeUInt;
begin
  Result := FLoadedData.Size;
  if Trimmed and (FTrimSize <> 0) and (FTrimSize < FLoadedData.Size) then
    Result := FTrimSize;
end;

function TNativeMirrorMemPageData.GetStartOffset(Trimmed: Boolean): NativeUInt;
begin
  if Trimmed and (FTrimSize <> 0) and (FTrimSize < FLoadedData.Size) then
    Result := FTrimStart
  else
    Result := 0;
end;

end.
