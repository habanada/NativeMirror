{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Dumper.Imports.Finder;

interface

uses
  Winapi.Windows,
  NativePe.ExportedFunc,
  NativePe.ExportsMapper,
  NativePe.Types,
  NativeMirror.Dumper.Imports.Blocks;

type
  TNativeMirrorThunkFoundCallback = class abstract
  public
    function ShouldProcessVa(Va: UInt64): Boolean; virtual; abstract;
    function ShouldAcceptExport(Va: UInt64; ExportedFunction: TExportedFunc): Boolean; virtual; abstract;
  end;

function FillIat(Buffer: PByte; BufferSize: NativeUInt; ExportsMap: TExportsMapper; Iat: TNativeMirrorIatBlock; Callback: TNativeMirrorThunkFoundCallback; Is64Bit: Boolean): NativeUInt;
function FindIat(Buffer: PByte; BufferSize: NativeUInt; ExportsMap: TExportsMapper; SearchOffset: NativeUInt; Callback: TNativeMirrorThunkFoundCallback; Is64Bit: Boolean): TNativeMirrorIatBlock;
function FindImportTable(Is64Bit: Boolean; Buffer: PByte; BufferSize: NativeUInt; ExportsMap: TExportsMapper; IatOffset: DWORD; out TableSize: NativeUInt; SearchOffset: NativeUInt = 0): PImageImportDescriptor;

implementation

uses
  NativePe.BufferUtil,
  NativePe.ImportsLoader;

function ReadField(Buffer: PByte; Offset: NativeUInt; Is64Bit: Boolean): UInt64;
begin
  if Is64Bit then
    Result := PUInt64(NativeUInt(Buffer) + Offset)^
  else
    Result := PDWORD(NativeUInt(Buffer) + Offset)^;
end;

function FillIat(Buffer: PByte; BufferSize: NativeUInt; ExportsMap: TExportsMapper; Iat: TNativeMirrorIatBlock; Callback: TNativeMirrorThunkFoundCallback; Is64Bit: Boolean): NativeUInt;
var
  FieldSize, MaxCheck, Offset: NativeUInt;
  Value: UInt64;
  ExportedFunction: TExportedFunc;
  IsTerminated: Boolean;
begin
  Result := 0;
  if (Buffer = nil) or (ExportsMap = nil) or (Iat = nil) or (Iat.IatOffset = 0) then
    Exit;
  if Is64Bit then FieldSize := SizeOf(UInt64) else FieldSize := SizeOf(DWORD);
  if BufferSize < FieldSize then
    Exit;
  MaxCheck := BufferSize - FieldSize;
  if MaxCheck < FieldSize then
    Exit;
  Iat.IsTerminated := True;
  IsTerminated := True;
  Offset := Iat.IatOffset;
  while Offset < MaxCheck do
  begin
    Value := ReadField(Buffer, Offset, Is64Bit);
    if Value = 0 then
    begin
      IsTerminated := True;
      Inc(Offset, FieldSize);
      Continue;
    end;
    if (Callback <> nil) and not Callback.ShouldProcessVa(Value) then
      Break;
    ExportedFunction := ExportsMap.FindExportByVa(Value);
    if ExportedFunction = nil then
      Break;
    if (Callback <> nil) and not Callback.ShouldAcceptExport(Value, ExportedFunction) then
      Break;
    IsTerminated := False;
    Iat.Append(DWORD(Offset and $FFFFFFFF), Value, ExportedFunction);
    Inc(Offset, FieldSize);
  end;
  Iat.IsTerminated := IsTerminated;
  if (Iat.IatOffset <> 0) and (Iat.CountThunks > 0) then
  begin
    Result := Offset - Iat.IatOffset;
    Iat.IatSize := Result;
  end;
end;

function FindIat(Buffer: PByte; BufferSize: NativeUInt; ExportsMap: TExportsMapper; SearchOffset: NativeUInt; Callback: TNativeMirrorThunkFoundCallback; Is64Bit: Boolean): TNativeMirrorIatBlock;
var
  FieldSize, MaxCheck, Offset, IatSize: NativeUInt;
  Value: UInt64;
  ExportedFunction: TExportedFunc;
  Block: TNativeMirrorIatBlock;
begin
  Result := nil;
  if (Buffer = nil) or (BufferSize = 0) or (ExportsMap = nil) then
    Exit;
  if Is64Bit then FieldSize := SizeOf(UInt64) else FieldSize := SizeOf(DWORD);
  if BufferSize < FieldSize then
    Exit;
  MaxCheck := BufferSize - FieldSize;
  if (SearchOffset > BufferSize) or (MaxCheck < FieldSize) then
    Exit;
  Offset := SearchOffset;
  while Offset < MaxCheck do
  begin
    if not ValidatePtr(Buffer, BufferSize, PByte(NativeUInt(Buffer) + Offset), FieldSize) then
      Break;
    Value := ReadField(Buffer, Offset, Is64Bit);
    if Value <> 0 then
    begin
      if ((Callback = nil) or Callback.ShouldProcessVa(Value)) then
      begin
        ExportedFunction := ExportsMap.FindExportByVa(Value);
        if (ExportedFunction <> nil) and ((Callback = nil) or Callback.ShouldAcceptExport(Value, ExportedFunction)) then
        begin
          Block := TNativeMirrorIatBlock.Create(Is64Bit, DWORD(Offset and $FFFFFFFF));
          IatSize := FillIat(Buffer, BufferSize, ExportsMap, Block, Callback, Is64Bit);
          if IatSize > 0 then
          begin
            Block.IatSize := IatSize;
            Exit(Block);
          end;
          Block.Free;
        end;
      end;
    end;
    Inc(Offset);
  end;
end;

function IsValidImportDescriptor(Buffer: PByte; BufferSize: NativeUInt; ExportsMap: TExportsMapper; Descriptor: PImageImportDescriptor; Is64Bit: Boolean): Boolean;
var
  NamePtr: PAnsiChar;
  ThunkValue: UInt64;
  FieldSize: NativeUInt;
begin
  Result := False;
  if not ValidatePtr(Buffer, BufferSize, Descriptor, SizeOf(TImageImportDescriptor)) then
    Exit;
  if (Descriptor.TimeDateStamp <> 0) and (Descriptor.TimeDateStamp <> DWORD($FFFFFFFF)) then
    Exit;
  NamePtr := PAnsiChar(NativeUInt(Buffer) + Descriptor.Name);
  if not ValidatePtr(Buffer, BufferSize, NamePtr, SizeOf(AnsiChar)) then
    Exit;
  if (Descriptor.Name <> 0) and not IsValidImportName(Buffer, BufferSize, NamePtr) then
    Exit;
  if (Descriptor.FirstThunk = 0) and (Descriptor.OriginalFirstThunk = 0) then
    Exit(True);
  if Is64Bit then FieldSize := SizeOf(UInt64) else FieldSize := SizeOf(DWORD);
  if not ValidatePtr(Buffer, BufferSize, PByte(NativeUInt(Buffer) + Descriptor.OriginalFirstThunk), FieldSize) then
    Exit;
  if not ValidatePtr(Buffer, BufferSize, PByte(NativeUInt(Buffer) + Descriptor.FirstThunk), FieldSize) then
    Exit;
  ThunkValue := ReadField(Buffer, Descriptor.FirstThunk, Is64Bit);
  Result := ExportsMap.FindExportByVa(ThunkValue) <> nil;
end;

function CalculateImportTableSize(Buffer: PByte; BufferSize: NativeUInt; ExportsMap: TExportsMapper; FirstDescriptor: PImageImportDescriptor; Is64Bit: Boolean): NativeUInt;
var
  Descriptor: PImageImportDescriptor;
begin
  Result := 0;
  if (Buffer = nil) or (ExportsMap = nil) or (FirstDescriptor = nil) then
    Exit;
  Descriptor := FirstDescriptor;
  while True do
  begin
    if not ValidatePtr(Buffer, BufferSize, Descriptor, SizeOf(TImageImportDescriptor)) then
      Exit(0);
    if not IsValidImportDescriptor(Buffer, BufferSize, ExportsMap, Descriptor, Is64Bit) then
      Exit(0);
    if (Descriptor.FirstThunk = 0) and (Descriptor.OriginalFirstThunk = 0) then
      Break;
    Inc(Descriptor);
  end;
  Result := NativeUInt(NativeUInt(Descriptor) - NativeUInt(FirstDescriptor)) + SizeOf(TImageImportDescriptor);
end;

function FindFirstImportDescriptor(Buffer: PByte; BufferSize: NativeUInt; ExportsMap: TExportsMapper; FoundDescriptor: PImageImportDescriptor; Is64Bit: Boolean): PImageImportDescriptor;
var
  Offset, CandidateOffset, TableSize, PreviousSize: NativeUInt;
  Candidate: PImageImportDescriptor;
begin
  Result := nil;
  if (Buffer = nil) or (ExportsMap = nil) or (FoundDescriptor = nil) then
    Exit;
  Offset := NativeUInt(FoundDescriptor) - NativeUInt(Buffer);
  PreviousSize := 0;
  while True do
  begin
    CandidateOffset := Offset;
    Candidate := PImageImportDescriptor(NativeUInt(Buffer) + CandidateOffset);
    TableSize := CalculateImportTableSize(Buffer, BufferSize, ExportsMap, Candidate, Is64Bit);
    if (TableSize = 0) or (TableSize < PreviousSize) then
      Break;
    PreviousSize := TableSize;
    Result := Candidate;
    if CandidateOffset < SizeOf(TImageImportDescriptor) then
      Break;
    Dec(Offset, SizeOf(TImageImportDescriptor));
  end;
end;

function FindImportTable(Is64Bit: Boolean; Buffer: PByte; BufferSize: NativeUInt; ExportsMap: TExportsMapper; IatOffset: DWORD; out TableSize: NativeUInt; SearchOffset: NativeUInt): PImageImportDescriptor;
var
  MaxCheck, Offset, DescriptorOffset, SizeFound: NativeUInt;
  Candidate, FirstDescriptor: PImageImportDescriptor;
begin
  Result := nil;
  TableSize := 0;
  if (Buffer = nil) or (IatOffset = 0) or (SearchOffset > BufferSize) or ((BufferSize - SearchOffset) < SizeOf(DWORD)) then
    Exit;
  MaxCheck := BufferSize - SizeOf(DWORD);
  Offset := SearchOffset;
  while Offset < MaxCheck do
  begin
    if PDWORD(NativeUInt(Buffer) + Offset)^ = IatOffset then
    begin
      if Offset >= SizeOf(TImageImportDescriptor) - SizeOf(DWORD) then
      begin
        DescriptorOffset := Offset - (SizeOf(TImageImportDescriptor) - SizeOf(DWORD));
        Candidate := PImageImportDescriptor(NativeUInt(Buffer) + DescriptorOffset);
        if ValidatePtr(Buffer, BufferSize, Candidate, SizeOf(TImageImportDescriptor)) then
        begin
          FirstDescriptor := FindFirstImportDescriptor(Buffer, BufferSize, ExportsMap, Candidate, Is64Bit);
          SizeFound := CalculateImportTableSize(Buffer, BufferSize, ExportsMap, FirstDescriptor, Is64Bit);
          if SizeFound > 0 then
          begin
            TableSize := SizeFound;
            Exit(FirstDescriptor);
          end;
        end;
      end;
    end;
    Inc(Offset);
  end;
end;

end.
