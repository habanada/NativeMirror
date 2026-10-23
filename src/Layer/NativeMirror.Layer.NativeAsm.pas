{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Layer.NativeAsm;

interface

{$IFDEF USE_NATIVEASM}
{$IFDEF WIN64}
uses
  Winapi.Windows,
  System.SysUtils,
  System.Generics.Collections,
  NativeAsm.Builder,
  NativeAsm.Extensions,
  NativeAsm.Stubs,
  NativeAsm.Avx.Cpu,
  NativeMirror.Layer,
  NativeMirror.Layer.Lde;

type
  TNativeAsmAdapter = class(TInterfacedObject, IDisassembler, ICodeGen)
  private
    FStubs: TObjectDictionary<NativeUInt, TExecutableCode>;
    FCachedCompareCode: TExecutableCode;
    FCachedSectionCompare: TNativeMirrorSectionCompareFunc;
    FLde: TLdeAdapter;
    class function FindSyscallGadget: Pointer; static;
    class function BuildIndirectStubBytes(SSN: Cardinal; Gadget: Pointer): TBytes; static;
    function BuildSectionCompareKernel: TExecutableCode;
  public
    constructor Create;
    destructor Destroy; override;
    function InstructionLength(P: Pointer; Bitness: Byte): Integer;
    function SkipBytes(P: Pointer; Bitness: Byte; MinBytes: Integer): Integer;
    function EmitSyscallStub(SSN: Cardinal; Indirect: Boolean): Pointer;
    function EmitTrampoline(OrigBytes: Pointer; OrigSize: Integer): Pointer;
    function EmitSectionCompare: TNativeMirrorSectionCompareFunc;
    procedure FreeCode(P: Pointer);
  end;
{$ENDIF WIN64}
{$ENDIF USE_NATIVEASM}

implementation

{$IFDEF USE_NATIVEASM}
{$IFDEF WIN64}

constructor TNativeAsmAdapter.Create;
begin
  inherited;
  FStubs := TObjectDictionary<NativeUInt, TExecutableCode>.Create([doOwnsValues]);
  FLde := TLdeAdapter.Create;
end;

destructor TNativeAsmAdapter.Destroy;
begin
  FCachedCompareCode.Free;
  FStubs.Free;
  FLde.Free;
  inherited;
end;

function TNativeAsmAdapter.InstructionLength(P: Pointer; Bitness: Byte): Integer;
begin
  Result := FLde.InstructionLength(P, Bitness);
end;

function TNativeAsmAdapter.SkipBytes(P: Pointer; Bitness: Byte; MinBytes: Integer): Integer;
begin
  Result := FLde.SkipBytes(P, Bitness, MinBytes);
end;

class function TNativeAsmAdapter.FindSyscallGadget: Pointer;
var
  NtdllBase: PByte;
  P: PByte;
  MI: TMemoryBasicInformation;
  I: NativeUInt;
begin
  Result := nil;
  NtdllBase := GetModuleHandle('ntdll.dll');
  if NtdllBase = nil then Exit;
  P := NtdllBase;
  while VirtualQuery(P, MI, SizeOf(MI)) = SizeOf(MI) do
  begin
    if (MI.AllocationBase = NtdllBase) and (MI.State = MEM_COMMIT) and
       ((MI.Protect and (PAGE_EXECUTE or PAGE_EXECUTE_READ or
         PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_WRITECOPY)) <> 0) and
       (MI.RegionSize >= 3) then
    begin
      I := 0;
      while I <= MI.RegionSize - 3 do
      begin
        if (P[I] = $0F) and (P[I + 1] = $05) and (P[I + 2] = $C3) then
        begin
          Result := P + I;
          Exit;
        end;
        Inc(I);
      end;
    end;
    if PByte(MI.AllocationBase) <> NtdllBase then Break;
    if NativeUInt(MI.BaseAddress) + MI.RegionSize <= NativeUInt(P) then Break;
    P := PByte(NativeUInt(MI.BaseAddress) + MI.RegionSize);
  end;
end;

class function TNativeAsmAdapter.BuildIndirectStubBytes(SSN: Cardinal;
  Gadget: Pointer): TBytes;
begin
  SetLength(Result, 22);
  Result[0] := $49; Result[1] := $89; Result[2] := $CA;  // MOV R10, RCX
  Result[3] := $B8;                                       // MOV EAX, imm32
  Result[4] := Byte(SSN);
  Result[5] := Byte(SSN shr 8);
  Result[6] := Byte(SSN shr 16);
  Result[7] := Byte(SSN shr 24);
  Result[8] := $FF; Result[9] := $25;                    // JMP QWORD PTR [RIP+disp32]
  Result[10] := 0; Result[11] := 0; Result[12] := 0; Result[13] := 0; // disp32=0
  PUInt64(@Result[14])^ := UInt64(NativeUInt(Gadget));   // target at [RIP+0]
end;

function TNativeAsmAdapter.BuildSectionCompareKernel: TExecutableCode;
var
  B: TAsmBuilder;
begin
  // Win64 leaf: RCX=A  RDX=B  R8=Size -> RAX (0=equal, byte offset of first diff)
  // Volatile only: RAX RCX RDX R8 R9 R10 R11 YMM0-YMM5.  No stack frame needed.
  //
  // AVX2 instruction encodings (VEX.256, index-register forms):
  //   VMOVDQU YMM0,[RCX+R9]: C4 A1 7E 6F 04 09  (VEX.X=inv(R9.hi), base=RCX)
  //   VMOVDQU YMM1,[RDX+R9]: C4 A1 7E 6F 0C 0A  (dest=YMM1, base=RDX)
  //   VPCMPEQB YMM2,YMM0,YMM1: C4 E1 7D 74 D1   (VEX.NDS, vvvv=YMM0)
  //   VPMOVMSKB EAX,YMM2: C4 E1 7D D7 C2         (extract MSBs -> r32)
  //   VZEROUPPER: C5 F8 77
  //
  // GPR encodings:
  //   TEST R8,R8   4D 85 C0    XOR R9D,R9D 45 31 C9
  //   CMP R8,32    49 83 F8 20  ADD R9,32  49 83 C1 20
  //   LEA R10,[R9+32] 4D 8D 51 20  CMP R10,R8 4D 3B D0
  //   CMP R9,R8  4D 3B C8     INC R9  49 FF C1
  //   MOVZX EAX,BYTE[RCX+R9] 42 0F B6 04 09
  //   MOVZX R11D,BYTE[RDX+R9] 46 0F B6 1C 0A
  //   CMP R11D,EAX 44 3B D8   NOT EAX F7 D0
  //   BSF EAX,EAX 0F BC C0   ADD RAX,R9 49 03 C1
  //   MOV RAX,R9  49 8B C1   XOR EAX,EAX 33 C0
  B := TAsmBuilder.Create;
  try
    B.EmitBytes([$4D, $85, $C0]);                          // TEST R8, R8
    B.J(cond_JE, 'equal');

    B.EmitBytes([$45, $31, $C9]);                          // XOR R9D, R9D
    B.EmitBytes([$49, $83, $F8, $20]);                     // CMP R8, 32
    B.J(cond_JB, 'tail');

    B.Label_('avx_loop');
    B.EmitBytes([$C4, $A1, $7E, $6F, $04, $09]);           // VMOVDQU YMM0, [RCX+R9]
    B.EmitBytes([$C4, $A1, $7E, $6F, $0C, $0A]);           // VMOVDQU YMM1, [RDX+R9]
    B.EmitBytes([$C4, $E1, $7D, $74, $D1]);                // VPCMPEQB YMM2, YMM0, YMM1
    B.EmitBytes([$C4, $E1, $7D, $D7, $C2]);                // VPMOVMSKB EAX, YMM2
    B.EmitBytes([$F7, $D0]);                               // NOT EAX  (0→equal, 1→diff)
    B.EmitBytes([$85, $C0]);
    B.J(cond_JNE, 'avx_diff');
    B.EmitBytes([$49, $83, $C1, $20]);                     // ADD R9, 32
    B.EmitBytes([$4D, $8D, $51, $20]);                     // LEA R10, [R9+32]
    B.EmitBytes([$4D, $3B, $D0]);                          // CMP R10, R8
    B.J(cond_JBE, 'avx_loop');

    B.Label_('tail');
    B.EmitBytes([$4D, $3B, $C8]);                          // CMP R9, R8
    B.J(cond_JAE, 'equal');

    B.Label_('scalar_loop');
    B.EmitBytes([$42, $0F, $B6, $04, $09]);                // MOVZX EAX, BYTE [RCX+R9]
    B.EmitBytes([$46, $0F, $B6, $1C, $0A]);                // MOVZX R11D, BYTE [RDX+R9]
    B.EmitBytes([$44, $3B, $D8]);                          // CMP R11D, EAX
    B.J(cond_JNE, 'scalar_diff');
    B.EmitBytes([$49, $FF, $C1]);                          // INC R9
    B.EmitBytes([$4D, $3B, $C8]);                          // CMP R9, R8
    B.J(cond_JB, 'scalar_loop');

    B.Label_('equal');
    B.EmitBytes([$C5, $F8, $77]);                          // VZEROUPPER
    B.EmitBytes([$33, $C0]);                               // XOR EAX, EAX
    B.Ret;

    B.Label_('avx_diff');
    // EAX = NOT(VPMOVMSKB): bit k=1 means byte k in block differs
    B.EmitBytes([$0F, $BC, $C0]);                          // BSF EAX, EAX  → first diff in block
    B.EmitBytes([$49, $03, $C1]);                          // ADD RAX, R9   → absolute byte offset
    B.EmitBytes([$C5, $F8, $77]);                          // VZEROUPPER
    B.Ret;

    B.Label_('scalar_diff');
    B.EmitBytes([$49, $8B, $C1]);                          // MOV RAX, R9   → first diff offset
    B.EmitBytes([$C5, $F8, $77]);                          // VZEROUPPER
    B.Ret;

    Result := TExecutableCode.FromBuilder(B);
  finally
    B.Free;
  end;
end;

function TNativeAsmAdapter.EmitSyscallStub(SSN: Cardinal;
  Indirect: Boolean): Pointer;
var
  Bytes: TBytes;
  Exe: TExecutableCode;
  Gadget: Pointer;
begin
  if Indirect then
  begin
    Gadget := FindSyscallGadget;
    if Gadget = nil then Exit(nil);
    Bytes := BuildIndirectStubBytes(SSN, Gadget);
  end
  else
    Bytes := TSyscallStub.Build(SSN);
  Exe := TExecutableCode.Create(Bytes);
  FStubs.Add(NativeUInt(Exe.EntryPoint), Exe);
  Result := Exe.EntryPoint;
end;

function TNativeAsmAdapter.EmitTrampoline(OrigBytes: Pointer;
  OrigSize: Integer): Pointer;
var
  SavedBytes: TBytes;
  Bytes: TBytes;
  Exe: TExecutableCode;
begin
  if (OrigBytes = nil) or (OrigSize <= 0) then Exit(nil);
  SetLength(SavedBytes, OrigSize);
  Move(OrigBytes^, SavedBytes[0], OrigSize);
  Bytes := TTrampoline.Build(OrigBytes, SavedBytes);
  Exe := TExecutableCode.Create(Bytes);
  FStubs.Add(NativeUInt(Exe.EntryPoint), Exe);
  Result := Exe.EntryPoint;
end;

function TNativeAsmAdapter.EmitSectionCompare: TNativeMirrorSectionCompareFunc;
begin
  if not Assigned(FCachedSectionCompare) then
  begin
    if TAvxCpuFeatures.SupportsAvx2 then
    begin
      FCachedCompareCode := BuildSectionCompareKernel;
      FCachedSectionCompare := TNativeMirrorSectionCompareFunc(FCachedCompareCode.EntryPoint);
    end
    else
      FCachedSectionCompare := NativeMirrorScalarSectionCompare;
  end;
  Result := FCachedSectionCompare;
end;

procedure TNativeAsmAdapter.FreeCode(P: Pointer);
begin
  FStubs.Remove(NativeUInt(P));
end;

{$ENDIF WIN64}
{$ENDIF USE_NATIVEASM}

end.
