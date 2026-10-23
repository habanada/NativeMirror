{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-License-Identifier: BSD-2-Clause

  This file contains tests for NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Tests.Target;

interface

procedure RunNativeMirrorTestTarget;

implementation

uses
  Winapi.Windows,
  System.Generics.Collections,
  System.IOUtils,
  System.JSON,
  System.SysUtils;

const
{$IFDEF WIN64}
  IMAGE_ORDINAL_FLAG_NATIVE_LOCAL = NativeUInt($8000000000000000);
  IMAGE_NT_OPTIONAL_HDR_NATIVE_MAGIC = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
{$ELSE}
  IMAGE_ORDINAL_FLAG_NATIVE_LOCAL = NativeUInt($80000000);
  IMAGE_NT_OPTIONAL_HDR_NATIVE_MAGIC = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
{$ENDIF}

  TEST_PATTERN: array[0..15] of Byte = ($DE, $AD, $BE, $EF, $13, $37, $C0, $DE, $42, $24, $66, $99, $A5, $5A, $7E, $E7);

type
  TImageImportDescriptorLocal = packed record
    OriginalFirstThunk: DWORD;
    TimeDateStamp: DWORD;
    ForwarderChain: DWORD;
    Name: DWORD;
    FirstThunk: DWORD;
  end;

  PImageImportDescriptorLocal = ^TImageImportDescriptorLocal;

  TImageThunkDataNativeLocal = packed record
    AddressOfData: NativeUInt;
  end;

  PImageThunkDataNativeLocal = ^TImageThunkDataNativeLocal;
{$IFDEF WIN64}
  TImageNtHeadersNative = TImageNtHeaders64;
  PImageNtHeadersNative = PImageNtHeaders64;
{$ELSE}
  TImageNtHeadersNative = TImageNtHeaders32;
  PImageNtHeadersNative = PImageNtHeaders32;
{$ENDIF}
  TPrivateThreadRoutine = function(Parameter: Pointer): DWORD; stdcall;

  TNativeMirrorTestTarget = class
  private
    FPid: DWORD;
    FScenario: string;
    FStatusPath: string;
    FModulePath: string;
    FPrimaryAddress: UInt64;
    FSecondaryAddress: UInt64;
    FThirdAddress: UInt64;
    FThreadId: DWORD;
    FPrivateThread: THandle;
    FPrivateThreadEvent: THandle;
    FAllocations: TList<Pointer>;
    function FindIatSlot(const FuncName: string): PPointer;
    function CreatePrivatePe: UInt64;
    function CreatePrivateExecutableAt(RegionSize, PatternOffset: NativeUInt): UInt64;
    function CreatePrivateExecutable: UInt64;
    function CreatePrivateExecutablePageBoundary: UInt64;
    function CreatePrivateExecutableRegionTail: UInt64;
    function CreatePrivateExecutableControl: UInt64;
    function CreatePrivateThread: UInt64;
    procedure PatchCodeByte(Target: Pointer; Mask: Byte);
    procedure PatchSectionHeader(UseLastSection: Boolean);
    procedure SetupHeaderPatch;
    procedure SetupNtHeaderPatch;
    procedure SetupSectionReplacement;
    procedure SetupLastSectionReplacement;
    procedure SetupCodePatch;
    procedure SetupMultipleCodePatches;
    procedure SetupIatRedirect;
    procedure SetupScenario;
    procedure WriteStatus;
  public
    constructor Create(const Scenario, StatusPath: string);
    destructor Destroy; override;
    procedure Run;
  end;

var
  GCodeAnchor: NativeUInt;

function ParamValue(const Name: string; out Value: string): Boolean;
var
  I: Integer;
  Arg, Prefix: string;
begin
  Prefix := '/' + LowerCase(Name) + ':';
  for I := 1 to ParamCount do
  begin
    Arg := ParamStr(I);
    if LowerCase(Copy(Arg, 1, Length(Prefix))) = Prefix then
    begin
      Value := Copy(Arg, Length(Prefix) + 1, MaxInt);
      Exit(True);
    end;
  end;
  Result := False;
end;

function CodePatchTarget(Value: NativeUInt): NativeUInt;
begin
  Result := (Value xor NativeUInt($51C39A7D)) + NativeUInt($10001);
end;

function CodePatchTargetSecond(Value: NativeUInt): NativeUInt;
begin
  Result := (Value xor NativeUInt($27D4EB2D)) + NativeUInt($20003);
end;

function IatReplacement: BOOL; stdcall;
begin
  Result := False;
end;

constructor TNativeMirrorTestTarget.Create(const Scenario, StatusPath: string);
begin
  inherited Create;
  FPid := GetCurrentProcessId;
  FScenario := Scenario;
  FStatusPath := StatusPath;
  FModulePath := ExpandFileName(ParamStr(0));
  FAllocations := TList<Pointer>.Create;
end;

destructor TNativeMirrorTestTarget.Destroy;
var
  P: Pointer;
begin
  if FPrivateThreadEvent <> 0 then
    SetEvent(FPrivateThreadEvent);
  if FPrivateThread <> 0 then
  begin
    WaitForSingleObject(FPrivateThread, 2000);
    CloseHandle(FPrivateThread);
  end;
  if FPrivateThreadEvent <> 0 then
    CloseHandle(FPrivateThreadEvent);
  for P in FAllocations do
    VirtualFree(P, 0, MEM_RELEASE);
  FAllocations.Free;
  inherited;
end;

procedure TNativeMirrorTestTarget.SetupHeaderPatch;
var
  Base: PByte;
  Dos: PImageDosHeader;
  OldProtect, IgnoreProtect: DWORD;
begin
  Base := PByte(GetModuleHandle(nil));
  if Base = nil then
    RaiseLastOSError;
  Dos := PImageDosHeader(Base);
  if Dos.e_magic <> IMAGE_DOS_SIGNATURE then
    raise Exception.Create('Invalid DOS header');
  if not VirtualProtect(Base, $1000, PAGE_READWRITE, OldProtect) then
    RaiseLastOSError;
  try
    Dos.e_csum := Dos.e_csum xor $A55A;
  finally
    VirtualProtect(Base, $1000, OldProtect, IgnoreProtect);
  end;
end;

procedure TNativeMirrorTestTarget.SetupNtHeaderPatch;
var
  Base: PByte;
  Dos: PImageDosHeader;
  Nt: PImageNtHeadersNative;
  OldProtect, IgnoreProtect: DWORD;
begin
  Base := PByte(GetModuleHandle(nil));
  if Base = nil then
    RaiseLastOSError;
  Dos := PImageDosHeader(Base);
  if Dos.e_magic <> IMAGE_DOS_SIGNATURE then
    raise Exception.Create('Invalid DOS header');
  Nt := PImageNtHeadersNative(Pointer(NativeUInt(Base) + NativeUInt(Dos._lfanew)));
  if (Nt.Signature <> IMAGE_NT_SIGNATURE) or (Nt.OptionalHeader.Magic <> IMAGE_NT_OPTIONAL_HDR_NATIVE_MAGIC) then
    raise Exception.Create('Invalid NT header');
  if not VirtualProtect(Nt, SizeOf(TImageNtHeadersNative), PAGE_READWRITE, OldProtect) then
    RaiseLastOSError;
  try
    Nt.OptionalHeader.CheckSum := Nt.OptionalHeader.CheckSum xor $A5A55A5A;
  finally
    VirtualProtect(Nt, SizeOf(TImageNtHeadersNative), OldProtect, IgnoreProtect);
  end;
end;

procedure TNativeMirrorTestTarget.PatchSectionHeader(UseLastSection: Boolean);
var
  Base: PByte;
  Dos: PImageDosHeader;
  Nt: PImageNtHeadersNative;
  Sec: PImageSectionHeader;
  SectionIndex: Integer;
  OldProtect, IgnoreProtect: DWORD;
begin
  Base := PByte(GetModuleHandle(nil));
  if Base = nil then
    RaiseLastOSError;
  Dos := PImageDosHeader(Base);
  if Dos.e_magic <> IMAGE_DOS_SIGNATURE then
    raise Exception.Create('Invalid DOS header');
  Nt := PImageNtHeadersNative(Pointer(NativeUInt(Base) + NativeUInt(Dos._lfanew)));
  if (Nt.Signature <> IMAGE_NT_SIGNATURE) or (Nt.OptionalHeader.Magic <> IMAGE_NT_OPTIONAL_HDR_NATIVE_MAGIC) or (Nt.FileHeader.NumberOfSections = 0) then
    raise Exception.Create('Invalid NT header');
  Sec := PImageSectionHeader(Pointer(NativeUInt(@Nt.OptionalHeader) + Nt.FileHeader.SizeOfOptionalHeader));
  if UseLastSection then
  begin
    SectionIndex := Nt.FileHeader.NumberOfSections - 1;
    while SectionIndex > 0 do
    begin
      Sec := PImageSectionHeader(Pointer(NativeUInt(@Nt.OptionalHeader) + Nt.FileHeader.SizeOfOptionalHeader + NativeUInt(SectionIndex) * SizeOf(TImageSectionHeader)));
      if Sec.SizeOfRawData <> 0 then
        Break;
      Dec(SectionIndex);
    end;
    if SectionIndex = 0 then
      Sec := PImageSectionHeader(Pointer(NativeUInt(@Nt.OptionalHeader) + Nt.FileHeader.SizeOfOptionalHeader));
  end;
  if not VirtualProtect(Sec, SizeOf(TImageSectionHeader), PAGE_READWRITE, OldProtect) then
    RaiseLastOSError;
  try
    if Nt.OptionalHeader.FileAlignment = 0 then
      Sec.PointerToRawData := Sec.PointerToRawData xor $200
    else
      Sec.PointerToRawData := Sec.PointerToRawData + Nt.OptionalHeader.FileAlignment;
  finally
    VirtualProtect(Sec, SizeOf(TImageSectionHeader), OldProtect, IgnoreProtect);
  end;
end;

procedure TNativeMirrorTestTarget.SetupSectionReplacement;
begin
  PatchSectionHeader(False);
end;

procedure TNativeMirrorTestTarget.SetupLastSectionReplacement;
begin
  PatchSectionHeader(True);
end;

procedure TNativeMirrorTestTarget.PatchCodeByte(Target: Pointer; Mask: Byte);
var
  Code: PByte;
  OldProtect, IgnoreProtect: DWORD;
begin
  Code := PByte(Target);
  if not VirtualProtect(Code, 1, PAGE_EXECUTE_READWRITE, OldProtect) then
    RaiseLastOSError;
  try
    Code^ := Code^ xor Mask;
    FlushInstructionCache(GetCurrentProcess, Code, 1);
  finally
    VirtualProtect(Code, 1, OldProtect, IgnoreProtect);
  end;
end;

procedure TNativeMirrorTestTarget.SetupCodePatch;
begin
  GCodeAnchor := CodePatchTarget(NativeUInt($7A13));
  PatchCodeByte(@CodePatchTarget, $5A);
end;

procedure TNativeMirrorTestTarget.SetupMultipleCodePatches;
begin
  GCodeAnchor := CodePatchTarget(NativeUInt($7A13)) xor CodePatchTargetSecond(NativeUInt($9B27));
  PatchCodeByte(@CodePatchTarget, $5A);
  PatchCodeByte(@CodePatchTargetSecond, $A5);
end;

function TNativeMirrorTestTarget.FindIatSlot(const FuncName: string): PPointer;
var
  Base: PByte;
  Dos: PImageDosHeader;
  Nt: PImageNtHeadersNative;
  ImportDir: TImageDataDirectory;
  Desc: PImageImportDescriptorLocal;
  OrigThunk, FirstThunk: PImageThunkDataNativeLocal;
  ImportName: PAnsiChar;
  FuncNameA: AnsiString;
  ExpectedAddress: Pointer;
begin
  Result := nil;
  Base := PByte(GetModuleHandle(nil));
  if Base = nil then
    Exit;
  Dos := PImageDosHeader(Base);
  if Dos.e_magic <> IMAGE_DOS_SIGNATURE then
    Exit;
  Nt := PImageNtHeadersNative(Pointer(NativeUInt(Base) + NativeUInt(Dos._lfanew)));
  if (Nt.Signature <> IMAGE_NT_SIGNATURE) or (Nt.OptionalHeader.Magic <> IMAGE_NT_OPTIONAL_HDR_NATIVE_MAGIC) then
    Exit;
  ImportDir := Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if ImportDir.VirtualAddress = 0 then
    Exit;
  FuncNameA := AnsiString(FuncName);
  ExpectedAddress := GetProcAddress(GetModuleHandle('kernel32.dll'), PAnsiChar(FuncNameA));
  Desc := PImageImportDescriptorLocal(Pointer(NativeUInt(Base) + NativeUInt(ImportDir.VirtualAddress)));
  while Desc.Name <> 0 do
  begin
    FirstThunk := PImageThunkDataNativeLocal(Pointer(NativeUInt(Base) + NativeUInt(Desc.FirstThunk)));
    if Desc.OriginalFirstThunk <> 0 then
    begin
      OrigThunk := PImageThunkDataNativeLocal(Pointer(NativeUInt(Base) + NativeUInt(Desc.OriginalFirstThunk)));
      while OrigThunk.AddressOfData <> 0 do
      begin
        if (OrigThunk.AddressOfData and IMAGE_ORDINAL_FLAG_NATIVE_LOCAL) = 0 then
        begin
          ImportName := PAnsiChar(Pointer(NativeUInt(Base) + NativeUInt(OrigThunk.AddressOfData) + SizeOf(Word)));
          if SameText(string(AnsiString(ImportName)), FuncName) then
            Exit(PPointer(FirstThunk));
        end;
        OrigThunk := PImageThunkDataNativeLocal(Pointer(NativeUInt(OrigThunk) + SizeOf(TImageThunkDataNativeLocal)));
        FirstThunk := PImageThunkDataNativeLocal(Pointer(NativeUInt(FirstThunk) + SizeOf(TImageThunkDataNativeLocal)));
      end;
    end
    else if ExpectedAddress <> nil then
      while FirstThunk.AddressOfData <> 0 do
      begin
        if Pointer(FirstThunk.AddressOfData) = ExpectedAddress then
          Exit(PPointer(FirstThunk));
        FirstThunk := PImageThunkDataNativeLocal(Pointer(NativeUInt(FirstThunk) + SizeOf(TImageThunkDataNativeLocal)));
      end;
    Desc := PImageImportDescriptorLocal(Pointer(NativeUInt(Desc) + SizeOf(TImageImportDescriptorLocal)));
  end;
end;

procedure TNativeMirrorTestTarget.SetupIatRedirect;
var
  Slot: PPointer;
  OldProtect, IgnoreProtect: DWORD;
begin
  GCodeAnchor := NativeUInt(Ord(IsDebuggerPresent));
  Slot := FindIatSlot('IsDebuggerPresent');
  if Slot = nil then
    raise Exception.Create('IsDebuggerPresent IAT slot not found');
  if not VirtualProtect(Slot, SizeOf(Pointer), PAGE_READWRITE, OldProtect) then
    RaiseLastOSError;
  try
    Slot^ := @IatReplacement;
  finally
    VirtualProtect(Slot, SizeOf(Pointer), OldProtect, IgnoreProtect);
  end;
end;

function TNativeMirrorTestTarget.CreatePrivatePe: UInt64;
var
  Raw: TBytes;
  RawBase: PByte;
  Dos: PImageDosHeader;
  Nt: PImageNtHeadersNative;
  Sec: PImageSectionHeader;
  Image: PByte;
  ImageSize, HeaderSize, SectionTableOffset, RawOffset, RawSize, CopySize: NativeUInt;
  I: Integer;
  OldProtect: DWORD;
begin
  Raw := TFile.ReadAllBytes(FModulePath);
  if Length(Raw) < SizeOf(TImageDosHeader) then
    raise Exception.Create('Test target image is too small');
  RawBase := @Raw[0];
  Dos := PImageDosHeader(RawBase);
  if Dos.e_magic <> IMAGE_DOS_SIGNATURE then
    raise Exception.Create('Test target DOS header is invalid');
  if NativeUInt(Dos._lfanew) + SizeOf(TImageNtHeadersNative) > NativeUInt(Length(Raw)) then
    raise Exception.Create('Test target NT header is outside the file');
  Nt := PImageNtHeadersNative(Pointer(NativeUInt(RawBase) + NativeUInt(Dos._lfanew)));
  if (Nt.Signature <> IMAGE_NT_SIGNATURE) or (Nt.OptionalHeader.Magic <> IMAGE_NT_OPTIONAL_HDR_NATIVE_MAGIC) then
    raise Exception.Create('Test target architecture does not match the build');
  if Nt.FileHeader.NumberOfSections = 0 then
    raise Exception.Create('Test target has no sections');
  SectionTableOffset := NativeUInt(@Nt.OptionalHeader) - NativeUInt(RawBase) + Nt.FileHeader.SizeOfOptionalHeader;
  if (SectionTableOffset > NativeUInt(Length(Raw))) or (NativeUInt(Nt.FileHeader.NumberOfSections) > (NativeUInt(Length(Raw)) - SectionTableOffset) div SizeOf(TImageSectionHeader)) then
    raise Exception.Create('Test target section table is outside the file');
  ImageSize := Nt.OptionalHeader.SizeOfImage;
  if ImageSize = 0 then
    raise Exception.Create('Test target image size is zero');
  Image := VirtualAlloc(nil, ImageSize, MEM_RESERVE or MEM_COMMIT, PAGE_READWRITE);
  if Image = nil then
    RaiseLastOSError;
  FAllocations.Add(Image);
  FillChar(Image^, ImageSize, 0);
  HeaderSize := Nt.OptionalHeader.SizeOfHeaders;
  if HeaderSize > NativeUInt(Length(Raw)) then
    HeaderSize := NativeUInt(Length(Raw));
  Move(Raw[0], Image^, HeaderSize);
  Sec := PImageSectionHeader(Pointer(NativeUInt(RawBase) + SectionTableOffset));
  for I := 0 to Nt.FileHeader.NumberOfSections - 1 do
  begin
    RawOffset := Sec.PointerToRawData;
    RawSize := Sec.SizeOfRawData;
    if (RawSize <> 0) and (RawOffset < NativeUInt(Length(Raw))) and (Sec.VirtualAddress < ImageSize) then
    begin
      CopySize := RawSize;
      if CopySize > NativeUInt(Length(Raw)) - RawOffset then
        CopySize := NativeUInt(Length(Raw)) - RawOffset;
      if CopySize > ImageSize - Sec.VirtualAddress then
        CopySize := ImageSize - Sec.VirtualAddress;
      if CopySize <> 0 then
        Move(PByte(Pointer(NativeUInt(RawBase) + RawOffset))^, PByte(Pointer(NativeUInt(Image) + Sec.VirtualAddress))^, CopySize);
    end;
    Sec := PImageSectionHeader(Pointer(NativeUInt(Sec) + SizeOf(TImageSectionHeader)));
  end;
  if not VirtualProtect(Image, ImageSize, PAGE_EXECUTE_READ, OldProtect) then
    RaiseLastOSError;
  FlushInstructionCache(GetCurrentProcess, Image, ImageSize);
  Result := UInt64(NativeUInt(Image));
end;

function TNativeMirrorTestTarget.CreatePrivateExecutableAt(RegionSize, PatternOffset: NativeUInt): UInt64;
var
  Buffer: PByte;
  OldProtect: DWORD;
begin
  if (RegionSize = 0) or (PatternOffset > RegionSize) or (SizeOf(TEST_PATTERN) > RegionSize - PatternOffset) then
    raise Exception.Create('Invalid private executable test layout');
  Buffer := VirtualAlloc(nil, RegionSize, MEM_RESERVE or MEM_COMMIT, PAGE_READWRITE);
  if Buffer = nil then
    RaiseLastOSError;
  FAllocations.Add(Buffer);
  FillChar(Buffer^, RegionSize, $90);
  Move(TEST_PATTERN[0], PByte(NativeUInt(Buffer) + PatternOffset)^, SizeOf(TEST_PATTERN));
  if not VirtualProtect(Buffer, RegionSize, PAGE_EXECUTE_READ, OldProtect) then
    RaiseLastOSError;
  FlushInstructionCache(GetCurrentProcess, Buffer, RegionSize);
  Result := UInt64(NativeUInt(Buffer));
end;

function TNativeMirrorTestTarget.CreatePrivateExecutable: UInt64;
begin
  Result := CreatePrivateExecutableAt($1000, $200);
end;

function TNativeMirrorTestTarget.CreatePrivateExecutablePageBoundary: UInt64;
begin
  Result := CreatePrivateExecutableAt($2000, $FF8);
end;

function TNativeMirrorTestTarget.CreatePrivateExecutableRegionTail: UInt64;
begin
  Result := CreatePrivateExecutableAt($1000, $FF0);
end;

function TNativeMirrorTestTarget.CreatePrivateExecutableControl: UInt64;
var
  Buffer: PByte;
  OldProtect: DWORD;
begin
  Buffer := VirtualAlloc(nil, $1000, MEM_RESERVE or MEM_COMMIT, PAGE_READWRITE);
  if Buffer = nil then
    RaiseLastOSError;
  FAllocations.Add(Buffer);
  FillChar(Buffer^, $1000, $90);
  Buffer^ := $C3;
  if not VirtualProtect(Buffer, $1000, PAGE_EXECUTE_READ, OldProtect) then
    RaiseLastOSError;
  FlushInstructionCache(GetCurrentProcess, Buffer, $1000);
  Result := UInt64(NativeUInt(Buffer));
end;

function TNativeMirrorTestTarget.CreatePrivateThread: UInt64;
var
  Code: array[0..63] of Byte;
  CodeSize: NativeUInt;
  Buffer: PByte;
  OldProtect: DWORD;
  WaitProc: Pointer;
  P: PByte;
  ThreadRoutine: TPrivateThreadRoutine;

  procedure PutByte(Value: Byte);
  begin
    P^ := Value;
    Inc(P);
    Inc(CodeSize);
  end;

  procedure PutUInt32(Value: DWORD);
  begin
    Move(Value, P^, SizeOf(Value));
    Inc(P, SizeOf(Value));
    Inc(CodeSize, SizeOf(Value));
  end;

{$IFDEF WIN64}
  procedure PutUInt64(Value: UInt64);
  begin
    Move(Value, P^, SizeOf(Value));
    Inc(P, SizeOf(Value));
    Inc(CodeSize, SizeOf(Value));
  end;
{$ENDIF}

begin
  FillChar(Code, SizeOf(Code), 0);
  FPrivateThreadEvent := CreateEvent(nil, True, False, nil);
  if FPrivateThreadEvent = 0 then
    RaiseLastOSError;
  WaitProc := GetProcAddress(GetModuleHandle('kernel32.dll'), 'WaitForSingleObject');
  if WaitProc = nil then
    RaiseLastOSError;
  CodeSize := 0;
  P := @Code[0];
{$IFDEF WIN64}
  PutByte($48); PutByte($83); PutByte($EC); PutByte($28);
  PutByte($48); PutByte($B9); PutUInt64(UInt64(NativeUInt(FPrivateThreadEvent)));
  PutByte($BA); PutUInt32(INFINITE);
  PutByte($48); PutByte($B8); PutUInt64(UInt64(NativeUInt(WaitProc)));
  PutByte($FF); PutByte($D0);
  PutByte($48); PutByte($83); PutByte($C4); PutByte($28);
  PutByte($31); PutByte($C0); PutByte($C3);
{$ELSE}
  PutByte($68); PutUInt32(INFINITE);
  PutByte($68); PutUInt32(DWORD(NativeUInt(FPrivateThreadEvent)));
  PutByte($B8); PutUInt32(DWORD(NativeUInt(WaitProc)));
  PutByte($FF); PutByte($D0);
  PutByte($31); PutByte($C0);
  PutByte($C2); PutByte($04); PutByte($00);
{$ENDIF}
  Buffer := VirtualAlloc(nil, $1000, MEM_RESERVE or MEM_COMMIT, PAGE_READWRITE);
  if Buffer = nil then
    RaiseLastOSError;
  FAllocations.Add(Buffer);
  Move(Code[0], Buffer^, CodeSize);
  if not VirtualProtect(Buffer, $1000, PAGE_EXECUTE_READ, OldProtect) then
    RaiseLastOSError;
  FlushInstructionCache(GetCurrentProcess, Buffer, CodeSize);
  ThreadRoutine := TPrivateThreadRoutine(Buffer);
  FPrivateThread := CreateThread(nil, 0, @ThreadRoutine, nil, 0, FThreadId);
  if FPrivateThread = 0 then
    RaiseLastOSError;
  Result := UInt64(NativeUInt(Buffer));
end;

procedure TNativeMirrorTestTarget.SetupScenario;
begin
  if SameText(FScenario, 'Clean') then
    Exit;
  if SameText(FScenario, 'HeaderPatch') then
  begin
    SetupHeaderPatch;
    Exit;
  end;
  if SameText(FScenario, 'NtHeaderPatch') then
  begin
    SetupNtHeaderPatch;
    Exit;
  end;
  if SameText(FScenario, 'SectionReplacement') then
  begin
    SetupSectionReplacement;
    Exit;
  end;
  if SameText(FScenario, 'LastSectionReplacement') then
  begin
    SetupLastSectionReplacement;
    Exit;
  end;
  if SameText(FScenario, 'CodePatch') then
  begin
    SetupCodePatch;
    Exit;
  end;
  if SameText(FScenario, 'MultipleCodePatches') then
  begin
    SetupMultipleCodePatches;
    Exit;
  end;
  if SameText(FScenario, 'IatRedirect') then
  begin
    SetupIatRedirect;
    Exit;
  end;
  if SameText(FScenario, 'PrivatePe') then
  begin
    FPrimaryAddress := CreatePrivatePe;
    Exit;
  end;
  if SameText(FScenario, 'MultiplePrivatePe') then
  begin
    FPrimaryAddress := CreatePrivatePe;
    FSecondaryAddress := CreatePrivatePe;
    Exit;
  end;
  if SameText(FScenario, 'PrivateExecutable') then
  begin
    FPrimaryAddress := CreatePrivateExecutable;
    Exit;
  end;
  if SameText(FScenario, 'PrivateExecutablePageBoundary') then
  begin
    FPrimaryAddress := CreatePrivateExecutablePageBoundary;
    Exit;
  end;
  if SameText(FScenario, 'PrivateExecutableRegionTail') then
  begin
    FPrimaryAddress := CreatePrivateExecutableRegionTail;
    Exit;
  end;
  if SameText(FScenario, 'MultiplePrivateExecutable') then
  begin
    FPrimaryAddress := CreatePrivateExecutable;
    FSecondaryAddress := CreatePrivateExecutable;
    Exit;
  end;
  if SameText(FScenario, 'PrivateExecutableControl') then
  begin
    FPrimaryAddress := CreatePrivateExecutableControl;
    Exit;
  end;
  if SameText(FScenario, 'PrivateThread') then
  begin
    FPrimaryAddress := CreatePrivateThread;
    Exit;
  end;
  if SameText(FScenario, 'Mixed') then
  begin
    SetupCodePatch;
    SetupIatRedirect;
    FPrimaryAddress := CreatePrivatePe;
    FSecondaryAddress := CreatePrivateThread;
    Exit;
  end;
  if SameText(FScenario, 'MixedExtended') then
  begin
    SetupMultipleCodePatches;
    SetupIatRedirect;
    FPrimaryAddress := CreatePrivatePe;
    FSecondaryAddress := CreatePrivatePe;
    FThirdAddress := CreatePrivateExecutablePageBoundary;
    CreatePrivateThread;
    Exit;
  end;
  raise Exception.CreateFmt('Unknown scenario: %s', [FScenario]);
end;

procedure TNativeMirrorTestTarget.WriteStatus;
var
  Json: TJSONObject;
  TempPath: string;
begin
  Json := TJSONObject.Create;
  try
    Json.AddPair('pid', TJSONNumber.Create(FPid));
    Json.AddPair('scenario', FScenario);
    Json.AddPair('module_path', FModulePath);
    Json.AddPair('primary_address', IntToHex(FPrimaryAddress, 16).ToLower);
    Json.AddPair('secondary_address', IntToHex(FSecondaryAddress, 16).ToLower);
    Json.AddPair('third_address', IntToHex(FThirdAddress, 16).ToLower);
    Json.AddPair('thread_id', TJSONNumber.Create(FThreadId));
    TempPath := FStatusPath + '.tmp';
    if TFile.Exists(TempPath) then
      TFile.Delete(TempPath);
    if TFile.Exists(FStatusPath) then
      TFile.Delete(FStatusPath);
    TFile.WriteAllText(TempPath, Json.ToJSON, TEncoding.UTF8);
    TFile.Move(TempPath, FStatusPath);
  finally
    Json.Free;
  end;
end;

procedure TNativeMirrorTestTarget.Run;
begin
  SetupScenario;
  WriteStatus;
  while not TFile.Exists(FStatusPath + '.stop') do
    Sleep(50);
end;

procedure RunNativeMirrorTestTarget;
var
  Scenario, StatusPath: string;
  Target: TNativeMirrorTestTarget;
begin
  if not ParamValue('scenario', Scenario) then
    raise Exception.Create('/scenario:<name> is required');
  if not ParamValue('status', StatusPath) then
    raise Exception.Create('/status:<path> is required');
  Target := TNativeMirrorTestTarget.Create(Scenario, StatusPath);
  try
    Target.Run;
  finally
    Target.Free;
  end;
end;

end.
