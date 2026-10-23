{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Core.PeValidation;

interface

uses
  Winapi.Windows,
  NativePe.Types;

function IsValidSectionHeader(Buffer: PByte; BufferSize: NativeUInt; Header: PImageSectionHeader; RequiredCharacteristics: DWORD = 0): Boolean;
function IsValidFileHeader(Buffer: PByte; BufferSize: NativeUInt; Header: PImageFileHeader; RequiredCharacteristics: DWORD = 0): Boolean;
function CountSectionHeaders(Buffer: PByte; BufferSize: NativeUInt; Header: PImageSectionHeader; RequiredCharacteristics: DWORD = IMAGE_SCN_MEM_READ): NativeUInt;

implementation

uses
  NativePe.BufferUtil;

function IsValidSectionHeader(Buffer: PByte; BufferSize: NativeUInt; Header: PImageSectionHeader; RequiredCharacteristics: DWORD): Boolean;
begin
  Result := False;
  if not ValidatePtr(Buffer, BufferSize, Header, SizeOf(TImageSectionHeader)) then
    Exit;
  if (Header.PointerToRelocations <> 0) or (Header.NumberOfRelocations <> 0) or (Header.PointerToLinenumbers <> 0) then
    Exit;
  if (RequiredCharacteristics <> 0) and ((Header.Characteristics and RequiredCharacteristics) = 0) then
    Exit;
  Result := True;
end;

function IsValidFileHeader(Buffer: PByte; BufferSize: NativeUInt; Header: PImageFileHeader; RequiredCharacteristics: DWORD): Boolean;
var
  OptionalSize: NativeUInt;
begin
  Result := False;
  if not ValidatePtr(Buffer, BufferSize, Header, SizeOf(TImageFileHeader)) then
    Exit;
  if Header.NumberOfSections > 100 then
    Exit;
  if (Header.NumberOfSymbols <> 0) or (Header.PointerToSymbolTable <> 0) then
    Exit;
  case Header.Machine of
    IMAGE_FILE_MACHINE_I386: OptionalSize := SizeOf(TImageOptionalHeader32);
    IMAGE_FILE_MACHINE_AMD64: OptionalSize := SizeOf(TImageOptionalHeader64);
  else
    Exit;
  end;
  if Header.SizeOfOptionalHeader > PE_PAGE_SIZE then
    Exit;
  if not ValidatePtr(Buffer, BufferSize, Header, SizeOf(TImageFileHeader) + OptionalSize) then
    Exit;
  if Header.SizeOfOptionalHeader = OptionalSize then
    Exit(True);
  if (RequiredCharacteristics <> 0) and ((Header.Characteristics and RequiredCharacteristics) = 0) then
    Exit;
  Result := True;
end;

function CountSectionHeaders(Buffer: PByte; BufferSize: NativeUInt; Header: PImageSectionHeader; RequiredCharacteristics: DWORD): NativeUInt;
var
  Current: PImageSectionHeader;
begin
  Result := 0;
  if (Buffer = nil) or (Header = nil) then
    Exit;
  Current := Header;
  while IsValidSectionHeader(Buffer, BufferSize, Current, RequiredCharacteristics) do
  begin
    Inc(Result);
    Inc(Current);
  end;
end;

end.
