{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Adapters.Streams;

interface

uses
  System.Classes,
  NativeMirror.Core.Memory;

type
  TNativeMirrorStreamReader = class(TInterfacedObject, INativeMirrorReader)
  private
    FStream: TStream;
    FOwnsStream: Boolean;
  public
    constructor Create(Stream: TStream; OwnsStream: Boolean = False);
    destructor Destroy; override;
    function ReadAt(Offset: UInt64; Buffer: Pointer; Size: NativeUInt): NativeUInt;
    function GetSize: UInt64;
  end;

implementation

constructor TNativeMirrorStreamReader.Create(Stream: TStream; OwnsStream: Boolean);
begin
  inherited Create;
  FStream := Stream;
  FOwnsStream := OwnsStream;
end;

destructor TNativeMirrorStreamReader.Destroy;
begin
  if FOwnsStream then
    FStream.Free;
  inherited;
end;

function TNativeMirrorStreamReader.ReadAt(Offset: UInt64; Buffer: Pointer; Size: NativeUInt): NativeUInt;
var
  OldPosition: Int64;
  ReadCount: Integer;
begin
  Result := 0;
  if (FStream = nil) or (Buffer = nil) or (Size = 0) or (Size > High(Integer)) then
    Exit;
  OldPosition := FStream.Position;
  try
    FStream.Position := Int64(Offset);
    ReadCount := FStream.Read(Buffer^, Integer(Size));
    if ReadCount > 0 then
      Result := NativeUInt(ReadCount);
  finally
    FStream.Position := OldPosition;
  end;
end;

function TNativeMirrorStreamReader.GetSize: UInt64;
begin
  if FStream = nil then
    Exit(0);
  Result := UInt64(FStream.Size);
end;

end.
