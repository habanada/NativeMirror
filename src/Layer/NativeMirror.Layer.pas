{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Layer;

interface

type
  TNativeMirrorSectionCompareFunc = function(A, B: Pointer; Size: NativeUInt): NativeInt;

  IDisassembler = interface
    ['{A1B2C3D4-E5F6-A7B8-C9D0-E1F2A3B4C5D6}']
    function InstructionLength(P: Pointer; Bitness: Byte): Integer;
    function SkipBytes(P: Pointer; Bitness: Byte; MinBytes: Integer): Integer;
  end;

  ICodeGen = interface
    ['{E5F6A7B8-C9D0-E1F2-A3B4-C5D6E7F8A9B0}']
    function EmitSyscallStub(SSN: Cardinal; Indirect: Boolean): Pointer;
    function EmitTrampoline(OrigBytes: Pointer; OrigSize: Integer): Pointer;
    function EmitSectionCompare: TNativeMirrorSectionCompareFunc;
    procedure FreeCode(P: Pointer);
  end;

function NativeMirrorScalarSectionCompare(A, B: Pointer; Size: NativeUInt): NativeInt;

implementation

function NativeMirrorScalarSectionCompare(A, B: Pointer; Size: NativeUInt): NativeInt;
var
  PA, PB: PByte;
  I: NativeUInt;
begin
  PA := PByte(A);
  PB := PByte(B);
  I := 0;
  while I < Size do
  begin
    if PA[I] <> PB[I] then
      Exit(NativeInt(I));
    Inc(I);
  end;
  Result := 0;
end;

end.
