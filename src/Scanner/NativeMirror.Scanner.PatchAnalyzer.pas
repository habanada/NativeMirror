{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Scanner.PatchAnalyzer;

interface

uses
  Winapi.Windows,
  System.Generics.Collections,
  NativeMirror.Scanner.ModuleData,
  NativeMirror.Scanner.Patches;

type
  TNativeMirrorPatchAnalyzer = class
  private
    FModuleData: TNativeMirrorModuleData;
    FSectionRva: DWORD;
    FPatchedCode: PByte;
    FCodeSize: NativeUInt;
    FIsModule64Bit: Boolean;
    FRelocs: TList<DWORD>;
    function GetJumpDestination(CurrentVa: UInt64; InstructionLength: Integer; Delta: Integer): UInt64;
    function ParseShortJump(Patch: TNativeMirrorPatch; PatchPtr: PByte; PatchVa: UInt64): NativeUInt;
    function ParseJump(Patch: TNativeMirrorPatch; PatchPtr: PByte; PatchVa: UInt64): NativeUInt;
    function ParseJumpViaAddress(Patch: TNativeMirrorPatch; PatchPtr: PByte; PatchVa: UInt64): NativeUInt;
    function ParseMovJump(Patch: TNativeMirrorPatch; PatchPtr: PByte; IsLong: Boolean): NativeUInt;
    function ParsePushRet(Patch: TNativeMirrorPatch; PatchPtr: PByte): NativeUInt;
    function Is64Modifier(Op: Byte): Boolean;
    function IsLongModifier(Op: Byte): Boolean;
    function AnalyzeHookAt(Patch: TNativeMirrorPatch; PatchPtr: PByte; PatchVa: UInt64): NativeUInt;
    function AnalyzeRelocated(Patch: TNativeMirrorPatch; PatchPtr: PByte): NativeUInt;
  public
    constructor Create(ModuleData: TNativeMirrorModuleData; SectionRva: DWORD; PatchedCode: PByte; CodeSize: NativeUInt);
    destructor Destroy; override;
    function AnalyzeHook(Patch: TNativeMirrorPatch): NativeUInt;
    function AnalyzeOther(Patch: TNativeMirrorPatch): NativeUInt;
  end;

implementation

uses
  NativePe.BufferUtil;

constructor TNativeMirrorPatchAnalyzer.Create(ModuleData: TNativeMirrorModuleData; SectionRva: DWORD; PatchedCode: PByte; CodeSize: NativeUInt);
begin
  inherited Create;
  FModuleData := ModuleData;
  FSectionRva := SectionRva;
  FPatchedCode := PatchedCode;
  FCodeSize := CodeSize;
  FIsModule64Bit := ModuleData.Is64Bit;
  FRelocs := TList<DWORD>.Create;
  ModuleData.LoadRelocatedFields(FRelocs);
end;

destructor TNativeMirrorPatchAnalyzer.Destroy;
begin
  FRelocs.Free;
  inherited;
end;

function TNativeMirrorPatchAnalyzer.GetJumpDestination(CurrentVa: UInt64; InstructionLength, Delta: Integer): UInt64;
begin
  Result := UInt64(Int64(CurrentVa) + InstructionLength + Delta);
end;

function TNativeMirrorPatchAnalyzer.ParseShortJump(Patch: TNativeMirrorPatch; PatchPtr: PByte; PatchVa: UInt64): NativeUInt;
begin
  Result := 0;
  if not ValidatePtr(FPatchedCode, FCodeSize, PatchPtr, 2) then
    Exit;
  Patch.SetHookTarget(GetJumpDestination(PatchVa, 2, PByte(NativeUInt(PatchPtr) + 1)^));
  Result := 2;
end;

function TNativeMirrorPatchAnalyzer.ParseJump(Patch: TNativeMirrorPatch; PatchPtr: PByte; PatchVa: UInt64): NativeUInt;
var
  Delta: DWORD;
begin
  Result := 0;
  if not ValidatePtr(FPatchedCode, FCodeSize, PatchPtr, 5) then
    Exit;
  Delta := PDWORD(NativeUInt(PatchPtr) + 1)^;
  Patch.SetHookTarget(GetJumpDestination(PatchVa, 5, Integer(Delta)));
  Result := 5;
end;

function TNativeMirrorPatchAnalyzer.ParseJumpViaAddress(Patch: TNativeMirrorPatch; PatchPtr: PByte; PatchVa: UInt64): NativeUInt;
var
  Delta: DWORD;
begin
  Result := 0;
  if not ValidatePtr(FPatchedCode, FCodeSize, PatchPtr, 6) then
    Exit;
  Delta := PDWORD(NativeUInt(PatchPtr) + 2)^;
  if FIsModule64Bit then
    Patch.SetHookTarget(GetJumpDestination(PatchVa, 6, Integer(Delta)), False)
  else
    Patch.SetHookTarget(Delta, False);
  Result := 6;
end;

function TNativeMirrorPatchAnalyzer.Is64Modifier(Op: Byte): Boolean;
begin
  Result := FIsModule64Bit and (Op >= $40) and (Op <= $4F);
end;

function TNativeMirrorPatchAnalyzer.IsLongModifier(Op: Byte): Boolean;
begin
  Result := FIsModule64Bit and (Op >= $48) and (Op <= $4F);
end;

function TNativeMirrorPatchAnalyzer.ParseMovJump(Patch: TNativeMirrorPatch; PatchPtr: PByte; IsLong: Boolean): NativeUInt;
var
  MovLength: NativeUInt;
  JumpPtr: PByte;
  Register0: DWORD;
  Register1: DWORD;
  Address: UInt64;
begin
  Result := 0;
  if IsLong then
    MovLength := 9
  else
    MovLength := 5;
  if not ValidatePtr(FPatchedCode, FCodeSize, PatchPtr, MovLength + 2) then
    Exit;
  JumpPtr := PByte(NativeUInt(PatchPtr) + MovLength);
  if Is64Modifier(PatchPtr^) then
  begin
    Inc(PatchPtr);
    Inc(JumpPtr);
    Inc(MovLength);
  end;
  Register0 := PatchPtr^ - $B8;
  if Is64Modifier(JumpPtr^) then
  begin
    Inc(JumpPtr);
    Inc(MovLength);
  end;
  if not ValidatePtr(FPatchedCode, FCodeSize, JumpPtr, 2) then
    Exit;
  if (JumpPtr^ = $FF) and (PByte(NativeUInt(JumpPtr) + 1)^ >= $E0) and (PByte(NativeUInt(JumpPtr) + 1)^ <= $EF) then
    Register1 := PByte(NativeUInt(JumpPtr) + 1)^ - $E0
  else if (JumpPtr^ = $FF) and (PByte(NativeUInt(JumpPtr) + 1)^ >= $D0) and (PByte(NativeUInt(JumpPtr) + 1)^ <= $DF) then
    Register1 := PByte(NativeUInt(JumpPtr) + 1)^ - $D0
  else
    Exit;
  if Register1 <> Register0 then
    Exit;
  if IsLong then
    Address := PUInt64(NativeUInt(PatchPtr) + 1)^
  else
    Address := PDWORD(NativeUInt(PatchPtr) + 1)^;
  Patch.SetHookTarget(Address);
  Result := MovLength + 2;
end;

function TNativeMirrorPatchAnalyzer.ParsePushRet(Patch: TNativeMirrorPatch; PatchPtr: PByte): NativeUInt;
begin
  Result := 0;
  if not ValidatePtr(FPatchedCode, FCodeSize, PatchPtr, 6) then
    Exit;
  if PByte(NativeUInt(PatchPtr) + 5)^ <> $C3 then
    Exit;
  Patch.SetHookTarget(PDWORD(NativeUInt(PatchPtr) + 1)^);
  Result := 6;
end;

function TNativeMirrorPatchAnalyzer.AnalyzeHookAt(Patch: TNativeMirrorPatch; PatchPtr: PByte; PatchVa: UInt64): NativeUInt;
var
  Op: Byte;
  IsLong: Boolean;
begin
  Result := 0;
  if not ValidatePtr(FPatchedCode, FCodeSize, PatchPtr, 2) then
    Exit;
  Op := PatchPtr^;
  if (Op = $E9) or (Op = $E8) then
    Exit(ParseJump(Patch, PatchPtr, PatchVa));
  if Op = $EB then
    Exit(ParseShortJump(Patch, PatchPtr, PatchVa));
  if Op = $68 then
    Exit(ParsePushRet(Patch, PatchPtr));
  if (Op = $FF) and (PByte(NativeUInt(PatchPtr) + 1)^ = $25) then
    Exit(ParseJumpViaAddress(Patch, PatchPtr, PatchVa));
  IsLong := False;
  if Is64Modifier(Op) then
  begin
    IsLong := IsLongModifier(Op);
    if not ValidatePtr(FPatchedCode, FCodeSize, PatchPtr, 2) then
      Exit;
    Op := PByte(NativeUInt(PatchPtr) + 1)^;
  end;
  if (Op >= $B8) and (Op <= $BF) then
    Result := ParseMovJump(Patch, PatchPtr, IsLong);
end;

function TNativeMirrorPatchAnalyzer.AnalyzeRelocated(Patch: TNativeMirrorPatch; PatchPtr: PByte): NativeUInt;
var
  FieldSize: NativeUInt;
  FieldValue: UInt64;
begin
  Result := 0;
  if FRelocs.IndexOf(Patch.StartRva) < 0 then
    Exit;
  if FIsModule64Bit then
    FieldSize := SizeOf(UInt64)
  else
    FieldSize := SizeOf(DWORD);
  if not ValidatePtr(FPatchedCode, FCodeSize, PatchPtr, FieldSize) then
    Exit;
  if FIsModule64Bit then
    FieldValue := PUInt64(PatchPtr)^
  else
    FieldValue := PDWORD(PatchPtr)^;
  Patch.SetHookTarget(FieldValue, True, nmHookAddressReplacement);
  Result := FieldSize;
end;

function TNativeMirrorPatchAnalyzer.AnalyzeHook(Patch: TNativeMirrorPatch): NativeUInt;
var
  PatchVa: UInt64;
  PatchOffset: NativeUInt;
  PatchPtr: PByte;
begin
  Result := 0;
  if (Patch = nil) or (Patch.StartRva < FSectionRva) then
    Exit;
  PatchVa := FModuleData.RvaToVa(Patch.StartRva);
  PatchOffset := Patch.StartRva - FSectionRva;
  if PatchOffset >= FCodeSize then
    Exit;
  PatchPtr := PByte(NativeUInt(FPatchedCode) + PatchOffset);
  Result := AnalyzeRelocated(Patch, PatchPtr);
  if Result <> 0 then
    Exit;
  if not ValidatePtr(FPatchedCode, FCodeSize, PatchPtr, 3) then
    Exit(0);
  Result := AnalyzeHookAt(Patch, PatchPtr, PatchVa);
  if (Result = 0) and (PatchOffset > 0) then
  begin
    Result := AnalyzeHookAt(Patch, PByte(NativeUInt(PatchPtr) - 1), PatchVa - 1);
    if Result > 0 then
      Dec(Result);
  end;
end;

function TNativeMirrorPatchAnalyzer.AnalyzeOther(Patch: TNativeMirrorPatch): NativeUInt;
var
  Offset: NativeUInt;
  PatchPtr: PByte;
  Size: NativeUInt;
  I: NativeUInt;
  Padding: Boolean;
begin
  Result := 0;
  if (Patch = nil) or (Patch.StartRva < FSectionRva) then
    Exit;
  Offset := Patch.StartRva - FSectionRva;
  if Offset >= FCodeSize then
    Exit;
  PatchPtr := PByte(NativeUInt(FPatchedCode) + Offset);
  Size := Patch.EndRva - Patch.StartRva;
  if not ValidatePtr(FPatchedCode, FCodeSize, PatchPtr, Size) then
    Exit;
  if Size > 1 then
  begin
    Padding := True;
    for I := 1 to Size - 1 do
      if PatchPtr^ <> PByte(NativeUInt(PatchPtr) + I)^ then
      begin
        Padding := False;
        Break;
      end;
    if Padding then
    begin
      Patch.PatchType := nmPatchPadding;
      Patch.PaddingValue := PatchPtr^;
    end;
  end;
  if (PatchPtr^ = $CC) and ((Size = 1) or (Patch.PatchType = nmPatchPadding)) then
    Patch.PatchType := nmPatchBreakpoint;
  Result := Size;
end;

end.
