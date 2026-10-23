{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Layer.Lde;

interface

uses
  NativeMirror.Layer,
  NativePe.Lde;

type
  TLdeAdapter = class(TInterfacedObject, IDisassembler)
  public
    function InstructionLength(P: Pointer; Bitness: Byte): Integer;
    function SkipBytes(P: Pointer; Bitness: Byte; MinBytes: Integer): Integer;
  end;

implementation

function TLdeAdapter.InstructionLength(P: Pointer; Bitness: Byte): Integer;
var
  Instr: TLdeInstruction;
begin
  Result := LdeDisasm(P, Bitness <> 0, Instr);
  if Result = 0 then
    Result := -1;
end;

function TLdeAdapter.SkipBytes(P: Pointer; Bitness: Byte; MinBytes: Integer): Integer;
var
  Offset, Len: Integer;
  Instr: TLdeInstruction;
begin
  Offset := 0;
  while Offset < MinBytes do
  begin
    Len := LdeDisasm(PByte(P) + Offset, Bitness <> 0, Instr);
    if Len = 0 then
      Exit(-1);
    Inc(Offset, Len);
  end;
  Result := Offset;
end;

end.
