{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Core.Buffer;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  NativePe.BufferUtil;

type
  TNativeMirrorBuffer = class
  private
    FData: PByte;
    FSize: NativeUInt;
    FOwnsData: Boolean;
    procedure Release;
  public
    constructor Create; overload;
    constructor Create(Size: NativeUInt); overload;
    constructor Create(Data: PByte; Size: NativeUInt; CopyData: Boolean); overload;
    destructor Destroy; override;
    function Allocate(NewSize: NativeUInt): Boolean;
    function Resize(NewSize: NativeUInt): Boolean;
    function Assign(Data: Pointer; DataSize: NativeUInt): Boolean;
    function Detach(out DataSize: NativeUInt): PByte;
    procedure Clear;
    property Data: PByte read FData;
    property Size: NativeUInt read FSize;
    property OwnsData: Boolean read FOwnsData;
  end;

implementation

constructor TNativeMirrorBuffer.Create;
begin
  inherited Create;
end;

constructor TNativeMirrorBuffer.Create(Size: NativeUInt);
begin
  inherited Create;
  Allocate(Size);
end;

constructor TNativeMirrorBuffer.Create(Data: PByte; Size: NativeUInt; CopyData: Boolean);
begin
  inherited Create;
  if CopyData then
    Assign(Data, Size)
  else
  begin
    FData := Data;
    FSize := Size;
    FOwnsData := False;
  end;
end;

destructor TNativeMirrorBuffer.Destroy;
begin
  Release;
  inherited;
end;

procedure TNativeMirrorBuffer.Release;
begin
  if FOwnsData and (FData <> nil) then
    FreeAligned(FData, FSize);
  FData := nil;
  FSize := 0;
  FOwnsData := False;
end;

function TNativeMirrorBuffer.Allocate(NewSize: NativeUInt): Boolean;
begin
  Release;
  if NewSize = 0 then
    Exit(False);
  FData := AllocAligned(NewSize, PAGE_READWRITE);
  Result := FData <> nil;
  if Result then
  begin
    FSize := NewSize;
    FOwnsData := True;
    FillChar(FData^, FSize, 0);
  end;
end;

function TNativeMirrorBuffer.Resize(NewSize: NativeUInt): Boolean;
var
  NewData: PByte;
  CopySize: NativeUInt;
begin
  Result := False;
  if NewSize = 0 then
  begin
    Clear;
    Exit(True);
  end;
  NewData := AllocAligned(NewSize, PAGE_READWRITE);
  if NewData = nil then
    Exit;
  FillChar(NewData^, NewSize, 0);
  CopySize := FSize;
  if CopySize > NewSize then
    CopySize := NewSize;
  if (FData <> nil) and (CopySize > 0) then
    Move(FData^, NewData^, CopySize);
  Release;
  FData := NewData;
  FSize := NewSize;
  FOwnsData := True;
  Result := True;
end;

function TNativeMirrorBuffer.Assign(Data: Pointer; DataSize: NativeUInt): Boolean;
begin
  Result := False;
  if (Data = nil) or (DataSize = 0) then
    Exit;
  if not Allocate(DataSize) then
    Exit;
  Move(Data^, FData^, DataSize);
  Result := True;
end;

function TNativeMirrorBuffer.Detach(out DataSize: NativeUInt): PByte;
begin
  Result := FData;
  DataSize := FSize;
  FData := nil;
  FSize := 0;
  FOwnsData := False;
end;

procedure TNativeMirrorBuffer.Clear;
begin
  Release;
end;

end.
