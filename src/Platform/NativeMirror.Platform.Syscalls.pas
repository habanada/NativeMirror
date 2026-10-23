{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Platform.Syscalls;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Generics.Collections,
  System.Generics.Defaults;

type
  TNativeMirrorSyscallTable = class
  private
    FSyscallToName: TDictionary<DWORD, string>;
    procedure Extract;
    class function ExtractFromModule(ModBase: PByte; ModSize: NativeUInt;
      StartId: DWORD; SyscallToName: TDictionary<DWORD, string>): NativeUInt; static;
    class function IsNtSyscallFunc(const Name: string): Boolean; static;
  public
    constructor Create;
    destructor Destroy; override;
    function IsReady: Boolean;
    function GetSyscallName(Id: DWORD): string;
    class function IsSyscallDll(const LibName: string): Boolean; static;
    class function IsSyscallFunc(const FuncName: string; NtOnly: Boolean = False): Boolean; static;
    class function IsSameSyscallFunc(const Func1, Func2: string): Boolean; static;
    property SyscallToName: TDictionary<DWORD, string> read FSyscallToName;
  end;

function GetGlobalSyscallTable: TNativeMirrorSyscallTable;

implementation


uses
  NativeMirror.Platform.Process;

const
  NM_SEC_IMAGE = $01000000;

var
  GGlobalSyscallTable: TNativeMirrorSyscallTable = nil;

function ReadPeWord(Base: PByte; Offset: NativeUInt): Word; inline;
begin
  Result := PWord(PByte(NativeUInt(Base) + Offset))^;
end;

function ReadPeDword(Base: PByte; Offset: NativeUInt): DWORD; inline;
begin
  Result := PDWORD(PByte(NativeUInt(Base) + Offset))^;
end;

function GetImageHeaderInfo(Base: PByte; out ImageSize: NativeUInt; out ExportRva, ExportSize: DWORD): Boolean;
const
  Pe32Magic = $010B;
  Pe64Magic = $020B;
  FileHeaderSize = 20;
  FileHeaderOptionalSizeOffset = 16;
  OptionalSizeOfImageOffset = 56;
  Pe32DataDirectoryOffset = 96;
  Pe64DataDirectoryOffset = 112;
var
  DosHdr: PImageDosHeader;
  NtOffset, OptionalOffset, DataDirectoryOffset: NativeUInt;
  OptionalSize, Magic: Word;
begin
  Result := False;
  ImageSize := 0;
  ExportRva := 0;
  ExportSize := 0;
  if Base = nil then Exit;
  DosHdr := PImageDosHeader(Base);
  if (DosHdr^.e_magic <> IMAGE_DOS_SIGNATURE) or (DosHdr^._lfanew <= 0) then Exit;
  NtOffset := NativeUInt(DosHdr^._lfanew);
  if NtOffset > $100000 then Exit;
  if ReadPeDword(Base, NtOffset) <> IMAGE_NT_SIGNATURE then Exit;
  OptionalSize := ReadPeWord(Base, NtOffset + SizeOf(DWORD) + FileHeaderOptionalSizeOffset);
  OptionalOffset := NtOffset + SizeOf(DWORD) + FileHeaderSize;
  Magic := ReadPeWord(Base, OptionalOffset);
  case Magic of
    Pe32Magic: DataDirectoryOffset := Pe32DataDirectoryOffset;
    Pe64Magic: DataDirectoryOffset := Pe64DataDirectoryOffset;
  else
    Exit;
  end;
  if OptionalSize < DataDirectoryOffset + 2 * SizeOf(DWORD) then Exit;
  ImageSize := ReadPeDword(Base, OptionalOffset + OptionalSizeOfImageOffset);
  ExportRva := ReadPeDword(Base, OptionalOffset + DataDirectoryOffset);
  ExportSize := ReadPeDword(Base, OptionalOffset + DataDirectoryOffset + SizeOf(DWORD));
  Result := ImageSize <> 0;
end;

function GetLoadedImageSize(Base: PByte): NativeUInt;
var
  ExportRva, ExportSize: DWORD;
begin
  if not GetImageHeaderInfo(Base, Result, ExportRva, ExportSize) then
    Result := 0;
end;

function MapSystemImage(const FileName: string; out FileHandle, MappingHandle: THandle): PByte;
var
  WindowsDir: array[0..MAX_PATH - 1] of Char;
  FullPath: string;
  OldRedirection: Pointer;
  RedirectionDisabled: Boolean;
begin
  Result := nil;
  FileHandle := INVALID_HANDLE_VALUE;
  MappingHandle := 0;
  FillChar(WindowsDir, SizeOf(WindowsDir), 0);
  if GetWindowsDirectory(WindowsDir, Length(WindowsDir)) = 0 then Exit;
  FullPath := IncludeTrailingPathDelimiter(string(WindowsDir)) + 'System32\' + FileName;
  OldRedirection := nil;
  RedirectionDisabled := DisableWow64FsRedirection(OldRedirection);
  try
    FileHandle := CreateFile(PChar(FullPath), GENERIC_READ,
      FILE_SHARE_READ or FILE_SHARE_DELETE, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
  finally
    if RedirectionDisabled then
      RevertWow64FsRedirection(OldRedirection);
  end;
  if FileHandle = INVALID_HANDLE_VALUE then Exit;
  MappingHandle := CreateFileMapping(FileHandle, nil, PAGE_READONLY or NM_SEC_IMAGE, 0, 0, nil);
  if MappingHandle = 0 then Exit;
  Result := PByte(MapViewOfFile(MappingHandle, FILE_MAP_READ, 0, 0, 0));
end;

procedure UnmapSystemImage(Base: PByte; FileHandle, MappingHandle: THandle);
begin
  if Base <> nil then
    UnmapViewOfFile(Base);
  if MappingHandle <> 0 then
    CloseHandle(MappingHandle);
  if FileHandle <> INVALID_HANDLE_VALUE then
    CloseHandle(FileHandle);
end;

function GetGlobalSyscallTable: TNativeMirrorSyscallTable;
begin
  if GGlobalSyscallTable = nil then
    GGlobalSyscallTable := TNativeMirrorSyscallTable.Create;
  Result := GGlobalSyscallTable;
end;

class function TNativeMirrorSyscallTable.IsSyscallDll(const LibName: string): Boolean;
var
  Lower: string;
begin
  Lower := LibName.ToLower;
  Result := (Lower = 'ntdll.dll') or (Lower = 'win32u.dll')
    or (Lower = 'ntdll') or (Lower = 'win32u');
end;

class function TNativeMirrorSyscallTable.IsSyscallFunc(const FuncName: string;
  NtOnly: Boolean): Boolean;
begin
  Result := False;
  if Length(FuncName) < 3 then Exit;
  if not NtOnly then
    if (FuncName[1] = 'Z') and (FuncName[2] = 'w') then
    begin
      if (FuncName[3] >= 'A') and (FuncName[3] <= 'Z') then Exit(True);
    end;
  if (FuncName[1] = 'N') and (FuncName[2] = 't') then
    if (FuncName[3] >= 'A') and (FuncName[3] <= 'Z') then Exit(True);
end;

class function TNativeMirrorSyscallTable.IsNtSyscallFunc(const Name: string): Boolean;
begin
  Result := IsSyscallFunc(Name, True);
end;

class function TNativeMirrorSyscallTable.IsSameSyscallFunc(const Func1, Func2: string): Boolean;
var
  Prefix1, Prefix2, Body1, Body2: string;
  Smaller, Bigger: string;
  SmallLen: Integer;
begin
  if Func1 = Func2 then Exit(True);
  if (Length(Func1) < 2) or (Length(Func2) < 2) then Exit(False);
  Prefix1 := Copy(Func1, 1, 2);
  Prefix2 := Copy(Func2, 1, 2);
  if ((Prefix1 = 'Zw') or (Prefix1 = 'Nt')) and
     ((Prefix2 = 'Zw') or (Prefix2 = 'Nt')) then
  begin
    Body1 := Copy(Func1, 3, MaxInt);
    Body2 := Copy(Func2, 3, MaxInt);
    if Body1 = Body2 then Exit(True);
    if Length(Body1) = Length(Body2) then Exit(False);
    if Length(Body1) < Length(Body2) then
    begin Smaller := Body1; Bigger := Body2; end
    else
    begin Smaller := Body2; Bigger := Body1; end;
    SmallLen := Length(Smaller);
    if Copy(Bigger, 1, SmallLen) = Smaller then
      if Copy(Bigger, SmallLen + 1, MaxInt) = '32' then Exit(True);
  end;
  Result := False;
end;

class function TNativeMirrorSyscallTable.ExtractFromModule(ModBase: PByte;
  ModSize: NativeUInt; StartId: DWORD; SyscallToName: TDictionary<DWORD, string>): NativeUInt;
var
  ExpDir: PImageExportDirectory;
  Names: PCardinal;
  Functions: PCardinal;
  Ordinals: PWord;
  I: Integer;
  Name: PAnsiChar;
  NameA: AnsiString;
  NameEnd: PByte;
  NameAddress, NameEndAddress: NativeUInt;
  NameStr: string;
  FuncRva, NameRva: DWORD;
  // Sorted by RVA to assign sequential IDs
  SortedFuncs: TArray<TPair<DWORD, string>>;
  Pair: TPair<DWORD, string>;
  FuncMap: TDictionary<DWORD, string>;
  Id: DWORD;
begin
  Result := 0;
  if (ModBase = nil) or (ModSize < SizeOf(TImageDosHeader)) then Exit;
  var HeaderImageSize: NativeUInt;
  var ExpDirRva, ExpDirSize: DWORD;
  if not GetImageHeaderInfo(ModBase, HeaderImageSize, ExpDirRva, ExpDirSize) then Exit;
  if (HeaderImageSize > ModSize) or (ExpDirRva = 0) or (UInt64(ExpDirRva) + ExpDirSize > ModSize) then Exit;
  ExpDir := PImageExportDirectory(ModBase + ExpDirRva);
  if ExpDir^.NumberOfNames = 0 then Exit;
  if (ExpDir^.AddressOfNames = 0) or (ExpDir^.AddressOfFunctions = 0)
    or (ExpDir^.AddressOfNameOrdinals = 0) then Exit;
  if UInt64(ExpDir^.AddressOfNames) + UInt64(ExpDir^.NumberOfNames) * SizeOf(DWORD) > ModSize then Exit;
  if UInt64(ExpDir^.AddressOfNameOrdinals) + UInt64(ExpDir^.NumberOfNames) * SizeOf(Word) > ModSize then Exit;
  if UInt64(ExpDir^.AddressOfFunctions) + UInt64(ExpDir^.NumberOfFunctions) * SizeOf(DWORD) > ModSize then Exit;
  Names := PCardinal(ModBase + ExpDir^.AddressOfNames);
  Functions := PCardinal(ModBase + ExpDir^.AddressOfFunctions);
  Ordinals := PWord(ModBase + ExpDir^.AddressOfNameOrdinals);
  FuncMap := TDictionary<DWORD, string>.Create;
  try
    for I := 0 to Integer(ExpDir^.NumberOfNames) - 1 do
    begin
      NameRva := PCardinal(PByte(Names) + NativeUInt(I) * SizeOf(DWORD))^;
      if (NameRva = 0) or (NameRva >= ModSize) then Continue;
      Name := PAnsiChar(ModBase + NameRva);
      NameAddress := NativeUInt(Name);
      NameEndAddress := NameAddress;
      while (NameEndAddress - NativeUInt(ModBase) < ModSize)
        and (PByte(NameEndAddress)^ <> 0) do Inc(NameEndAddress);
      if NameEndAddress - NativeUInt(ModBase) >= ModSize then Continue;
      NameEnd := PByte(NameEndAddress);
      SetString(NameA, Name, NativeInt(NativeUInt(NameEnd) - NameAddress));
      NameStr := string(NameA);
      if not IsNtSyscallFunc(NameStr) then Continue;
      var OrdIdx := PWord(PByte(Ordinals) + NativeUInt(I) * SizeOf(Word))^;
      if OrdIdx >= ExpDir^.NumberOfFunctions then Continue;
      FuncRva := PCardinal(PByte(Functions) + NativeUInt(OrdIdx) * SizeOf(DWORD))^;
      if (FuncRva = 0) or (FuncRva >= ModSize) then Continue;
      if not FuncMap.ContainsKey(FuncRva) then
        FuncMap.Add(FuncRva, NameStr)
      else
        FuncMap[FuncRva] := NameStr;
    end;
    if FuncMap.Count = 0 then Exit;
    SetLength(SortedFuncs, FuncMap.Count);
    var Idx := 0;
    for Pair in FuncMap do
    begin
      SortedFuncs[Idx] := Pair;
      Inc(Idx);
    end;
    TArray.Sort<TPair<DWORD,string>>(SortedFuncs,
      TComparer<TPair<DWORD,string>>.Construct(
        function(const A, B: TPair<DWORD,string>): Integer
        begin
          if A.Key < B.Key then Result := -1
          else if A.Key > B.Key then Result := 1
          else Result := 0;
        end));
    Id := StartId;
    for Pair in SortedFuncs do
    begin
      if not SyscallToName.ContainsKey(Id) then
        SyscallToName.Add(Id, Pair.Value);
      Inc(Id);
      Inc(Result);
    end;
  finally
    FuncMap.Free;
  end;
end;

procedure TNativeMirrorSyscallTable.Extract;
var
  NtdllBase: PByte;
  Win32uBase: PByte;
  NtdllFile, NtdllMapping: THandle;
  Win32uFile, Win32uMapping: THandle;
  NtdllSize, Win32uSize: NativeUInt;
begin
  NtdllBase := MapSystemImage('ntdll.dll', NtdllFile, NtdllMapping);
  try
    if NtdllBase <> nil then
    begin
      NtdllSize := GetLoadedImageSize(NtdllBase);
      if NtdllSize <> 0 then
        ExtractFromModule(NtdllBase, NtdllSize, 0, FSyscallToName);
    end;
  finally
    UnmapSystemImage(NtdllBase, NtdllFile, NtdllMapping);
  end;
  Win32uBase := MapSystemImage('win32u.dll', Win32uFile, Win32uMapping);
  try
    if Win32uBase <> nil then
    begin
      Win32uSize := GetLoadedImageSize(Win32uBase);
      if Win32uSize <> 0 then
        ExtractFromModule(Win32uBase, Win32uSize, $1000, FSyscallToName);
    end;
  finally
    UnmapSystemImage(Win32uBase, Win32uFile, Win32uMapping);
  end;
end;

constructor TNativeMirrorSyscallTable.Create;
begin
  inherited Create;
  FSyscallToName := TDictionary<DWORD, string>.Create;
  Extract;
end;

destructor TNativeMirrorSyscallTable.Destroy;
begin
  FSyscallToName.Free;
  inherited;
end;

function TNativeMirrorSyscallTable.IsReady: Boolean;
begin
  Result := FSyscallToName.Count > 0;
end;

function TNativeMirrorSyscallTable.GetSyscallName(Id: DWORD): string;
begin
  if not FSyscallToName.TryGetValue(Id, Result) then
    Result := '';
end;

initialization

finalization
  GGlobalSyscallTable.Free;
  GGlobalSyscallTable := nil;
end.
