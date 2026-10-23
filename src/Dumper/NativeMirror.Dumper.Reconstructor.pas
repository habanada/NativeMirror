{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Dumper.Reconstructor;

interface

uses
  NativeMirror.Core.Types,
  NativeMirror.Dumper.Buffer;

type
  TNativeMirrorReconstructor = class
  private
    FOriginalArtefacts: TPeArtefacts;
    FArtefacts: TPeArtefacts;
    FBuffer: TNativeMirrorDumpBuffer;
    function ShiftPeHeader: NativeUInt;
    function ReconstructFileHeader: Boolean;
    function ReconstructPeHeader: Boolean;
    function FixSectionsVirtualSize: Boolean;
    function FixSectionsCharacteristics: Boolean;
    function OverwriteOptionalHeader32(Header: Pointer): Boolean;
    function OverwriteOptionalHeader64(Header: Pointer): Boolean;
    function RegionReadableSize(Address: UInt64): NativeUInt;
  public
    constructor Create(const Artefacts: TPeArtefacts; Buffer: TNativeMirrorDumpBuffer);
    function Reconstruct: Boolean;
    property Artefacts: TPeArtefacts read FArtefacts;
  end;

implementation

uses
  Winapi.Windows,
  NativePe.BufferUtil,
  NativePe.FindBase,
  NativePe.PeHdrsHelper,
  NativePe.PeModeDetector,
  NativePe.Types,
  NativePe.Util,
  NativeMirror.Core.PeValidation,
  NativeMirror.Core.Memory;

const
  NM_IMAGE_SCN_TYPE_NO_PAD = DWORD($00000008);
  NM_IMAGE_SCN_CNT_CODE = DWORD($00000020);
  NM_IMAGE_SCN_CNT_INITIALIZED_DATA = DWORD($00000040);
  NM_IMAGE_SCN_CNT_UNINITIALIZED_DATA = DWORD($00000080);
  NM_IMAGE_SCN_NO_DEFER_SPEC_EXC = DWORD($00004000);
  NM_IMAGE_SCN_GPREL = DWORD($00008000);
  NM_IMAGE_SCN_LNK_NRELOC_OVFL = DWORD($01000000);
  NM_IMAGE_SCN_MEM_DISCARDABLE = DWORD($02000000);
  NM_IMAGE_SCN_MEM_NOT_CACHED = DWORD($04000000);
  NM_IMAGE_SCN_MEM_NOT_PAGED = DWORD($08000000);
  NM_IMAGE_SCN_MEM_SHARED = DWORD($10000000);

constructor TNativeMirrorReconstructor.Create(const Artefacts: TPeArtefacts; Buffer: TNativeMirrorDumpBuffer);
begin
  inherited Create;
  FOriginalArtefacts := Artefacts;
  FArtefacts := Artefacts;
  FBuffer := Buffer;
end;

function TNativeMirrorReconstructor.RegionReadableSize(Address: UInt64): NativeUInt;
begin
  if FBuffer = nil then
    Exit(0);
  Result := NativeMirrorRegionSize(FBuffer.Reader, Address);
end;

function TNativeMirrorReconstructor.ShiftPeHeader: NativeUInt;
var
  DosPeSize, NtOffset, ShiftSize, HeadersEnd, HeadersSize, PeOffset: NativeUInt;
  NewNtPtr, MzPtr: PByte;
  PePtr: PDWORD;
  DosTemplate: TImageDosHeader;
begin
  Result := 0;
  if (FBuffer = nil) or (FBuffer.Data = nil) or not FArtefacts.HasNtHeaders or not FArtefacts.HasSectionHeaders then
    Exit;
  DosPeSize := SizeOf(TImageDosHeader) + SizeOf(DWORD);
  NtOffset := FArtefacts.DropPeBase(FArtefacts.NtFileHeadersOffset);
  if (NtOffset = NATIVE_MIRROR_INVALID_OFFSET) or (NtOffset >= DosPeSize) then
    Exit;
  ShiftSize := DosPeSize - NtOffset;
  HeadersEnd := FArtefacts.SectionHeadersOffset + (FArtefacts.SectionCount + 1) * SizeOf(TImageSectionHeader);
  if HeadersEnd > FBuffer.Size then
    Exit;
  if not IsPadding(PByte(NativeUInt(FBuffer.Data) + HeadersEnd), ShiftSize, 0) then
    Exit;
  HeadersSize := FArtefacts.DropPeBase(HeadersEnd);
  if HeadersSize = NATIVE_MIRROR_INVALID_OFFSET then
    Exit;
  NewNtPtr := PByte(NativeUInt(FBuffer.Data) + FArtefacts.PeBaseOffset + ShiftSize);
  if not ValidatePtr(FBuffer.Data, FBuffer.Size, NewNtPtr, HeadersSize) then
    Exit;
  if NtOffset < SizeOf(DWORD) then
    Exit;
  PeOffset := NtOffset - SizeOf(DWORD);
  FillChar(DosTemplate, SizeOf(DosTemplate), 0);
  DosTemplate.e_magic := IMAGE_DOS_SIGNATURE;
  DosTemplate.e_lfanew := LongInt(PeOffset + ShiftSize);
  MzPtr := PByte(NativeUInt(FBuffer.Data) + FArtefacts.PeBaseOffset);
  if not ValidatePtr(FBuffer.Data, FBuffer.Size, MzPtr, SizeOf(TImageDosHeader)) then
    Exit;
  PePtr := PDWORD(NativeUInt(FBuffer.Data) + FArtefacts.PeBaseOffset + NativeUInt(DosTemplate.e_lfanew));
  if not ValidatePtr(FBuffer.Data, FBuffer.Size, PePtr, SizeOf(DWORD)) then
    Exit;
  Move(PByte(NativeUInt(FBuffer.Data) + FArtefacts.PeBaseOffset)^, NewNtPtr^, HeadersSize);
  Move(DosTemplate, MzPtr^, SizeOf(DosTemplate));
  PePtr^ := IMAGE_NT_SIGNATURE;
  Inc(FArtefacts.NtFileHeadersOffset, ShiftSize);
  Inc(FArtefacts.SectionHeadersOffset, ShiftSize);
  Result := ShiftSize;
end;

function TNativeMirrorReconstructor.ReconstructFileHeader: Boolean;
var
  NtOffset, SectionOffset, CalculatedOffset, OptionalSize: UInt64;
  Header: PImageFileHeader;
begin
  Result := False;
  if (FBuffer = nil) or (FBuffer.Data = nil) or not FArtefacts.HasNtHeaders then
    Exit;
  NtOffset := FArtefacts.DropPeBase(FArtefacts.NtFileHeadersOffset);
  if NtOffset = NATIVE_MIRROR_INVALID_OFFSET then
    Exit;
  Header := PImageFileHeader(NativeUInt(FBuffer.Data) + NativeUInt(NtOffset));
  if IsValidFileHeader(FBuffer.Data, FBuffer.Size, Header, 0) then
    Exit(True);
  if not ValidatePtr(FBuffer.Data, FBuffer.Size, Header, SizeOf(TImageFileHeader)) then
    Exit;
  if FArtefacts.Is64Bit then
  begin
    Header.Machine := IMAGE_FILE_MACHINE_AMD64;
    OptionalSize := SizeOf(TImageOptionalHeader64);
  end
  else
  begin
    Header.Machine := IMAGE_FILE_MACHINE_I386;
    OptionalSize := SizeOf(TImageOptionalHeader32);
  end;
  if FArtefacts.SectionHeadersOffset <> NATIVE_MIRROR_INVALID_OFFSET then
  begin
    SectionOffset := FArtefacts.DropPeBase(FArtefacts.SectionHeadersOffset);
    if SectionOffset = NATIVE_MIRROR_INVALID_OFFSET then
      Exit;
    if SectionOffset < NtOffset + SizeOf(TImageFileHeader) then
      Exit;
    CalculatedOffset := SectionOffset - (NtOffset + SizeOf(TImageFileHeader));
    if CalculatedOffset > High(Word) then
      Exit;
    Header.NumberOfSections := Word(FArtefacts.SectionCount);
    Header.SizeOfOptionalHeader := Word(CalculatedOffset);
  end
  else
    Header.SizeOfOptionalHeader := Word(OptionalSize);
  Header.NumberOfSymbols := 0;
  Header.PointerToSymbolTable := 0;
  Result := True;
end;

function TNativeMirrorReconstructor.OverwriteOptionalHeader32(Header: Pointer): Boolean;
var
  H: PImageOptionalHeader32;
begin
  Result := False;
  H := PImageOptionalHeader32(Header);
  if not ValidatePtr(FBuffer.Data, FBuffer.Size, H, SizeOf(TImageOptionalHeader32)) then
    Exit;
  if FArtefacts.Is64Bit then
    H.Magic := IMAGE_NT_OPTIONAL_HDR64_MAGIC
  else
    H.Magic := IMAGE_NT_OPTIONAL_HDR32_MAGIC;
  if H.SectionAlignment = 0 then
    H.SectionAlignment := PE_PAGE_SIZE;
  if H.FileAlignment = 0 then
    H.FileAlignment := $200;
  if H.SizeOfHeaders = 0 then
    H.SizeOfHeaders := $400;
  if H.SizeOfImage < FArtefacts.CalculatedImageSize then
    H.SizeOfImage := MaskToDword(FArtefacts.CalculatedImageSize);
  Result := True;
end;

function TNativeMirrorReconstructor.OverwriteOptionalHeader64(Header: Pointer): Boolean;
var
  H: PImageOptionalHeader64;
begin
  Result := False;
  H := PImageOptionalHeader64(Header);
  if not ValidatePtr(FBuffer.Data, FBuffer.Size, H, SizeOf(TImageOptionalHeader64)) then
    Exit;
  if FArtefacts.Is64Bit then
    H.Magic := IMAGE_NT_OPTIONAL_HDR64_MAGIC
  else
    H.Magic := IMAGE_NT_OPTIONAL_HDR32_MAGIC;
  if H.SectionAlignment = 0 then
    H.SectionAlignment := PE_PAGE_SIZE;
  if H.FileAlignment = 0 then
    H.FileAlignment := $200;
  if H.SizeOfHeaders = 0 then
    H.SizeOfHeaders := $400;
  if H.SizeOfImage < FArtefacts.CalculatedImageSize then
    H.SizeOfImage := MaskToDword(FArtefacts.CalculatedImageSize);
  Result := True;
end;

function TNativeMirrorReconstructor.ReconstructPeHeader: Boolean;
var
  NtOffset: UInt64;
  NtPtr, PePtr: PByte;
  Nt32: PImageNtHeaders32;
  FileHeader: PImageFileHeader;
  DosHeader: PImageDosHeader;
  Is64: Boolean;
  PeOffset: NativeInt;
begin
  Result := False;
  if (FBuffer = nil) or (FBuffer.Data = nil) or not FArtefacts.HasNtHeaders then
    Exit;
  NtOffset := FArtefacts.DropPeBase(FArtefacts.NtFileHeadersOffset);
  if (NtOffset = NATIVE_MIRROR_INVALID_OFFSET) or (NtOffset < SizeOf(DWORD)) then
    Exit;
  NtPtr := PByte(NativeUInt(FBuffer.Data) + NativeUInt(NtOffset));
  PePtr := PByte(NativeUInt(NtPtr) - SizeOf(DWORD));
  if not ValidatePtr(FBuffer.Data, FBuffer.Size, PePtr, SizeOf(TImageNtHeaders32)) then
    Exit;
  Nt32 := PImageNtHeaders32(PePtr);
  Nt32.Signature := IMAGE_NT_SIGNATURE;
  FileHeader := @Nt32.FileHeader;
  Is64 := FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
  if FileHeader.SizeOfOptionalHeader = 0 then
  begin
    if Is64 then
      FileHeader.SizeOfOptionalHeader := SizeOf(TImageOptionalHeader64)
    else
      FileHeader.SizeOfOptionalHeader := SizeOf(TImageOptionalHeader32);
  end;
  PeOffset := NativeInt(NativeUInt(PePtr) - NativeUInt(FBuffer.Data));
  if PeOffset < 0 then
    Exit;
  DosHeader := PImageDosHeader(FBuffer.Data);
  if not ValidatePtr(FBuffer.Data, FBuffer.Size, DosHeader, SizeOf(TImageDosHeader)) then
    Exit;
  DosHeader.e_magic := IMAGE_DOS_SIGNATURE;
  DosHeader.e_lfanew := LongInt(PeOffset);
  if Is64 then
    Result := OverwriteOptionalHeader64(PByte(@Nt32.OptionalHeader))
  else
    Result := OverwriteOptionalHeader32(PByte(@Nt32.OptionalHeader));
  if Result then
    Result := GetNtHdrs(FBuffer.Data, FBuffer.Size) <> nil;
end;

function TNativeMirrorReconstructor.FixSectionsVirtualSize: Boolean;
var
  SectionOffset, ImageBase, SectionVa, PreviousEnd: UInt64;
  Header, Current, Previous: PImageSectionHeader;
  HeaderCount, SectionCount, I: NativeUInt;
  RealSize, MaxSectionSize: NativeUInt;
  FileHeader: PImageFileHeader;
begin
  Result := False;
  if (FBuffer = nil) or (FBuffer.Data = nil) or not FArtefacts.HasSectionHeaders then
    Exit;
  SectionOffset := FArtefacts.DropPeBase(FArtefacts.SectionHeadersOffset);
  if SectionOffset = NATIVE_MIRROR_INVALID_OFFSET then
    Exit;
  Header := PImageSectionHeader(NativeUInt(FBuffer.Data) + NativeUInt(SectionOffset));
  Current := Header;
  Previous := nil;
  MaxSectionSize := 0;
  ImageBase := FArtefacts.PeImageBase;
  HeaderCount := GetSectionsCount(FBuffer.Data, FBuffer.Size);
  SectionCount := FArtefacts.SectionCount;
  if HeaderCount > SectionCount then
    SectionCount := HeaderCount;
  I := 0;
  while I < SectionCount do
  begin
    if not ValidatePtr(FBuffer.Data, FBuffer.Size, Current, SizeOf(TImageSectionHeader)) then
      Break;
    SectionVa := ImageBase + Current.VirtualAddress;
    RealSize := RegionReadableSize(SectionVa);
    if (not ValidatePtr(FBuffer.Data, FBuffer.Size, PByte(NativeUInt(FBuffer.Data) + Current.VirtualAddress), 1)) and (RealSize = 0) then
      Break;
    if Current.Misc.VirtualSize > RealSize then
      Current.Misc.VirtualSize := DWORD(RealSize);
    if RealSize > MaxSectionSize then
      MaxSectionSize := RealSize;
    if (Previous <> nil) and (Current.Misc.VirtualSize > 0) then
    begin
      PreviousEnd := UInt64(Previous.VirtualAddress) + Previous.Misc.VirtualSize;
      if (PreviousEnd > Current.VirtualAddress) and (Current.VirtualAddress > Previous.VirtualAddress) then
        Previous.Misc.VirtualSize := Current.VirtualAddress - Previous.VirtualAddress;
    end;
    if Current.Misc.VirtualSize > 0 then
      Previous := Current;
    Inc(Current);
    Inc(I);
  end;
  FileHeader := GetFileHdr(FBuffer.Data, FBuffer.Size);
  if (FileHeader <> nil) and (I > 0) and (I <= High(Word)) then
    FileHeader.NumberOfSections := Word(I);
  Result := MaxSectionSize <> 0;
end;

function TNativeMirrorReconstructor.FixSectionsCharacteristics: Boolean;
const
  AllFlags = NM_IMAGE_SCN_TYPE_NO_PAD or NM_IMAGE_SCN_CNT_CODE or NM_IMAGE_SCN_CNT_INITIALIZED_DATA or NM_IMAGE_SCN_CNT_UNINITIALIZED_DATA or NM_IMAGE_SCN_LNK_NRELOC_OVFL or NM_IMAGE_SCN_MEM_DISCARDABLE or NM_IMAGE_SCN_MEM_NOT_CACHED or NM_IMAGE_SCN_MEM_NOT_PAGED or NM_IMAGE_SCN_MEM_SHARED or IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE or NM_IMAGE_SCN_NO_DEFER_SPEC_EXC or NM_IMAGE_SCN_GPREL;
var
  SectionOffset: UInt64;
  Current: PImageSectionHeader;
  I: NativeUInt;
begin
  Result := False;
  if (FBuffer = nil) or (FBuffer.Data = nil) or not FArtefacts.HasSectionHeaders then
    Exit;
  SectionOffset := FArtefacts.DropPeBase(FArtefacts.SectionHeadersOffset);
  if SectionOffset = NATIVE_MIRROR_INVALID_OFFSET then
    Exit;
  Current := PImageSectionHeader(NativeUInt(FBuffer.Data) + NativeUInt(SectionOffset));
  I := 0;
  while I < FArtefacts.SectionCount do
  begin
    if not IsValidSectionHeader(FBuffer.Data, FBuffer.Size, Current, 0) then
      Break;
    Current.Characteristics := Current.Characteristics and AllFlags;
    Inc(Current);
    Inc(I);
  end;
  Result := True;
end;

function TNativeMirrorReconstructor.Reconstruct: Boolean;
var
  BaseCandidate: UInt64;
begin
  Result := False;
  FArtefacts := FOriginalArtefacts;
  if (FBuffer = nil) or not FBuffer.ReadRemote(FArtefacts.RegionStart + FArtefacts.PeBaseOffset, FArtefacts.CalculatedImageSize) then
    Exit;
  ShiftPeHeader;
  if not FArtefacts.HasNtHeaders or not ReconstructFileHeader or not ReconstructPeHeader then
    Exit;
  if not IsPeRaw(FBuffer.Data, FBuffer.Size) then
  begin
    if not FixSectionsVirtualSize or not FixSectionsCharacteristics then
      Exit;
    BaseCandidate := FindBaseCandidate(FBuffer.Data, FBuffer.Size);
    if BaseCandidate <> 0 then
      UpdateImageBase(FBuffer.Data, BaseCandidate);
  end;
  Result := FBuffer.IsValidPe;
end;

end.
