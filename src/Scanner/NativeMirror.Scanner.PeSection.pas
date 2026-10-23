{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Scanner.PeSection;

interface

uses
  Winapi.Windows,
  NativeMirror.Core.Buffer,
  NativeMirror.Scanner.ModuleData;

type
  TNativeMirrorSection = class
  private
    FBuffer: TNativeMirrorBuffer;
    FRawSize: NativeUInt;
    FRva: DWORD;
    function GetData: PByte;
    function GetLoadedSize: NativeUInt;
    function LoadRemote(RemoteData: TNativeMirrorRemoteModuleData; SectionNumber: NativeUInt): Boolean;
    function LoadOriginal(ModuleData: TNativeMirrorModuleData; SectionNumber: NativeUInt): Boolean;
    function LoadRemoteImage(RemoteData: TNativeMirrorRemoteModuleData; Size: NativeUInt): Boolean;
    function LoadRemoteImageAsSection(RemoteData: TNativeMirrorRemoteModuleData): Boolean;
    function LoadOriginalImageAsSection(ModuleData: TNativeMirrorModuleData): Boolean;
  public
    constructor CreateRemote(RemoteData: TNativeMirrorRemoteModuleData; SectionNumber: NativeUInt);
    constructor CreateOriginal(ModuleData: TNativeMirrorModuleData; SectionNumber: NativeUInt);
    destructor Destroy; override;
    function IsInitialized: Boolean;
    function IsContained(FieldStart: UInt64; FieldSize: NativeUInt): Boolean;
    property Data: PByte read GetData;
    property LoadedSize: NativeUInt read GetLoadedSize;
    property RawSize: NativeUInt read FRawSize;
    property Rva: DWORD read FRva;
  end;

implementation

uses
  NativePe.Types,
  NativePe.PeHdrsHelper;

constructor TNativeMirrorSection.CreateRemote(RemoteData: TNativeMirrorRemoteModuleData; SectionNumber: NativeUInt);
begin
  inherited Create;
  FBuffer := TNativeMirrorBuffer.Create;
  LoadRemote(RemoteData, SectionNumber);
end;

constructor TNativeMirrorSection.CreateOriginal(ModuleData: TNativeMirrorModuleData; SectionNumber: NativeUInt);
begin
  inherited Create;
  FBuffer := TNativeMirrorBuffer.Create;
  LoadOriginal(ModuleData, SectionNumber);
end;

destructor TNativeMirrorSection.Destroy;
begin
  FBuffer.Free;
  inherited;
end;

function TNativeMirrorSection.GetData: PByte;
begin
  Result := FBuffer.Data;
end;

function TNativeMirrorSection.GetLoadedSize: NativeUInt;
begin
  Result := FBuffer.Size;
end;

function TNativeMirrorSection.IsInitialized: Boolean;
begin
  Result := (FBuffer.Data <> nil) and (FBuffer.Size > 0);
end;

function TNativeMirrorSection.IsContained(FieldStart: UInt64; FieldSize: NativeUInt): Boolean;
var
  SectionEnd: UInt64;
begin
  SectionEnd := UInt64(FRva) + FBuffer.Size;
  Result := (FBuffer.Size > 0) and (FieldStart >= FRva) and (FieldStart < SectionEnd) and (UInt64(FieldSize) <= SectionEnd - FieldStart);
end;

function TNativeMirrorSection.LoadRemote(RemoteData: TNativeMirrorRemoteModuleData; SectionNumber: NativeUInt): Boolean;
var
  Count: NativeUInt;
  Sec: NativePe.Types.PImageSectionHeader;
  Size, Alignment: NativeUInt;
  Read: NativeUInt;
begin
  Result := False;
  if (RemoteData = nil) or (RemoteData.Reader = nil) then
    Exit;
  Count := GetSectionsCount(RemoteData.HeaderData, RemoteData.GetHeaderSize);
  if (Count = 0) and (SectionNumber = 0) then
    Exit(LoadRemoteImageAsSection(RemoteData));
  Sec := GetSectionHdr(RemoteData.HeaderData, RemoteData.GetHeaderSize, SectionNumber);
  if (Sec = nil) or (Sec.Misc.VirtualSize = 0) then
    Exit;
  FRawSize := Sec.SizeOfRawData;
  FRva := Sec.VirtualAddress;
  Alignment := GetSecAlignment(RemoteData.HeaderData, False);
  if Alignment = 0 then
    Alignment := PE_PAGE_SIZE;
  Size := RoundUpToUnitU(Sec.Misc.VirtualSize, Alignment);
  if not FBuffer.Allocate(Size) then
    Exit;
  Read := RemoteData.Reader.ReadMemory(RemoteData.ModuleBase + FRva, FBuffer.Data, Size, RemoteData.IsReflection);
  Result := Read <> 0;
  if not Result then
    FBuffer.Clear;
end;

function TNativeMirrorSection.LoadOriginal(ModuleData: TNativeMirrorModuleData; SectionNumber: NativeUInt): Boolean;
var
  Count: NativeUInt;
  Sec: NativePe.Types.PImageSectionHeader;
  Size: NativeUInt;
  CopySize: NativeUInt;
begin
  Result := False;
  if (ModuleData = nil) or (ModuleData.OriginalModule = nil) then
    Exit;
  Count := GetSectionsCount(ModuleData.OriginalModule, ModuleData.OriginalSize);
  if (Count = 0) and (SectionNumber = 0) then
    Exit(LoadOriginalImageAsSection(ModuleData));
  Sec := GetSectionHdr(ModuleData.OriginalModule, ModuleData.OriginalSize, SectionNumber);
  if Sec = nil then
    Exit;
  FRawSize := Sec.SizeOfRawData;
  FRva := Sec.VirtualAddress;
  Size := Sec.Misc.VirtualSize;
  if Size < Sec.SizeOfRawData then
    Size := Sec.SizeOfRawData;
  CopySize := Sec.SizeOfRawData;
  if (CopySize > 0) and (FRva >= ModuleData.OriginalSize) then
    Exit;
  if UInt64(FRva) + CopySize > ModuleData.OriginalSize then
    CopySize := ModuleData.OriginalSize - FRva;
  if not FBuffer.Allocate(Size) then
    Exit;
  if CopySize > 0 then
    Move(PByte(NativeUInt(ModuleData.OriginalModule) + FRva)^, FBuffer.Data^, CopySize);
  Result := True;
end;

function TNativeMirrorSection.LoadOriginalImageAsSection(ModuleData: TNativeMirrorModuleData): Boolean;
begin
  FRawSize := ModuleData.OriginalSize;
  FRva := 0;
  Result := FBuffer.Assign(ModuleData.OriginalModule, ModuleData.OriginalSize);
end;

function TNativeMirrorSection.LoadRemoteImage(RemoteData: TNativeMirrorRemoteModuleData; Size: NativeUInt): Boolean;
var
  Read: NativeUInt;
begin
  Result := False;
  if (RemoteData = nil) or (RemoteData.Reader = nil) or (Size = 0) then
    Exit;
  if not FBuffer.Allocate(Size) then
    Exit;
  Read := RemoteData.Reader.ReadMemory(RemoteData.ModuleBase, FBuffer.Data, Size, False);
  if Read <> Size then
  begin
    FBuffer.Clear;
    Exit;
  end;
  FRawSize := 0;
  FRva := 0;
  Result := True;
end;

function TNativeMirrorSection.LoadRemoteImageAsSection(RemoteData: TNativeMirrorRemoteModuleData): Boolean;
var
  ModuleSize: NativeUInt;
  CalculatedSize: NativeUInt;
begin
  Result := False;
  if RemoteData = nil then
    Exit;
  ModuleSize := RemoteData.GetModuleSize;
  if LoadRemoteImage(RemoteData, ModuleSize) then
    Exit(True);
  CalculatedSize := RemoteData.CalcImageSize;
  if (CalculatedSize = 0) or (CalculatedSize = ModuleSize) then
    Exit;
  Result := LoadRemoteImage(RemoteData, CalculatedSize);
end;

end.
