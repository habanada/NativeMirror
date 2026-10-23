{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Scanner.ModuleData;

interface

uses
  Winapi.Windows,
  System.Generics.Collections,
  NativePe.BufferUtil,
  NativePe.ImportsLoader,
  NativeMirror.Core.Memory,
  NativeMirror.Core.Buffer,
  NativeMirror.Scanner.ModuleCache;

const
  NM_MAX_HEADER_SIZE = $1000;

type
  TNativeMirrorHeaderBuffer = array[0..NM_MAX_HEADER_SIZE - 1] of Byte;

  TNativeMirrorModuleData = class
  private
    FProcessHandle: THandle;
    FModuleBase: UInt64;
    FIsPebConnected: Boolean;
    FUseCache: Boolean;
    FModuleName: string;
    FOriginalModule: PByte;
    FOriginalSize: NativeUInt;
    FIsDotNet: Boolean;
    function LoadModuleName: Boolean;
    function AutoSwitchIfWow64Mapping: Boolean;
    function LoadOriginalPath(const Path: string; DisableFsRedirection: Boolean): Boolean;
  public
    constructor Create(ProcessHandle: THandle; ModuleBase: UInt64; IsPebConnected, UseCache: Boolean; const ModuleName: string = '');
    destructor Destroy; override;
    function Is64Bit: Boolean;
    function RvaToVa(Rva: DWORD; ModuleBase: UInt64 = 0): UInt64;
    function VaToRva(Va: UInt64; ModuleBase: UInt64 = 0): DWORD;
    function LoadOriginal: Boolean;
    function SwitchToMappedPath: Boolean;
    function SwitchToWow64Path: Boolean;
    function ReloadWow64: Boolean;
    function RelocateToBase(NewBase: UInt64): Boolean;
    function LoadRelocatedFields(Fields: TList<DWORD>): Boolean;
    function LoadImportThunks(Thunks: TList<DWORD>): Boolean;
    function LoadImportsList(Collection: TImportsCollection): Boolean;
    property ProcessHandle: THandle read FProcessHandle;
    property ModuleBase: UInt64 read FModuleBase;
    property IsPebConnected: Boolean read FIsPebConnected;
    property ModuleName: string read FModuleName;
    property OriginalModule: PByte read FOriginalModule;
    property OriginalSize: NativeUInt read FOriginalSize;
    property IsDotNet: Boolean read FIsDotNet;
  end;

  TNativeMirrorRemoteModuleData = class
  private
    FReader: INativeMirrorMemoryReader;
    FIsReflection: Boolean;
    FModuleBase: UInt64;
    FHeader: TNativeMirrorHeaderBuffer;
    FHeaderReady: Boolean;
    FImage: TNativeMirrorBuffer;
    function LoadHeader: Boolean;
    function LoadFullImageSize(ImageSize: NativeUInt): Boolean;
  public
    constructor Create(const Reader: INativeMirrorMemoryReader; IsReflection: Boolean; ModuleBase: UInt64);
    destructor Destroy; override;
    function CalcImageSize: NativeUInt;
    function Initialize: Boolean;
    function Is64Bit: Boolean;
    function GetHeaderImageSize: NativeUInt;
    function GetHeaderImageBase: UInt64;
    function GetModuleSize: NativeUInt;
    function GetHeaderSize: NativeUInt;
    function LoadFullImage: Boolean;
    function IsFullImageLoaded: Boolean;
    function GetRemoteSectionVa(SectionNumber: NativeUInt): UInt64;
    function IsSectionEntry(SectionNumber: NativeUInt): Boolean;
    function IsSectionExecutable(SectionNumber: NativeUInt; AllowData, AllowInaccessible: Boolean): Boolean;
    function HasExecutableSection(AllowData, AllowInaccessible: Boolean): Boolean;
    function LoadImportsList(Collection: TImportsCollection): Boolean;
    class function QueryMappedName(ProcessHandle: THandle; ModuleBase: UInt64): string; static;
    function GetModuleName: string;
    function GetMappedName: string;
    property Reader: INativeMirrorMemoryReader read FReader;
    property IsReflection: Boolean read FIsReflection;
    property ModuleBase: UInt64 read FModuleBase;
    function GetHeaderData: PByte;
    property Header: TNativeMirrorHeaderBuffer read FHeader;
    property HeaderData: PByte read GetHeaderData;
    property Image: TNativeMirrorBuffer read FImage;
  end;

implementation

uses
  Winapi.PsAPI,
  System.SysUtils,
  NativePe.PeHdrsHelper,
  NativePe.Types,
  NativePe.PeLoader,
  NativePe.Relocate,
  NativePe.PeModeDetector,
  NativeMirror.Platform.Paths,
  NativeMirror.Platform.Process,
  NativeMirror.Core.Types,
  NativeMirror.Scanner.Patterns;

var
  GlobalModuleCache: TNativeMirrorModulesCache;

type
  TRelocCollector = class(TRelocBlockCallback)
  private
    FModule: TNativeMirrorModuleData;
    FFields: TList<DWORD>;
  public
    constructor Create(ModuleData: TNativeMirrorModuleData; Fields: TList<DWORD>);
    function ProcessRelocField(RelocField: NativeUInt): Boolean; override;
  end;

function DisableWow64FsRedirection(out OldValue: Pointer): Boolean;
type
  TDisable = function(var OldValue: Pointer): BOOL; stdcall;
var
  Proc: TDisable;
begin
  OldValue := nil;
  Proc := TDisable(GetProcAddress(GetModuleHandle('kernel32.dll'), 'Wow64DisableWow64FsRedirection'));
  Result := Assigned(Proc) and Proc(OldValue);
end;

procedure RevertWow64FsRedirection(OldValue: Pointer);
type
  TRevert = function(OldValue: Pointer): BOOL; stdcall;
var
  Proc: TRevert;
begin
  Proc := TRevert(GetProcAddress(GetModuleHandle('kernel32.dll'), 'Wow64RevertWow64FsRedirection'));
  if Assigned(Proc) then
    Proc(OldValue);
end;

constructor TRelocCollector.Create(ModuleData: TNativeMirrorModuleData; Fields: TList<DWORD>);
begin
  inherited Create(ModuleData.Is64Bit);
  FModule := ModuleData;
  FFields := Fields;
end;

function TRelocCollector.ProcessRelocField(RelocField: NativeUInt): Boolean;
var
  Rva: DWORD;
begin
  Rva := FModule.VaToRva(RelocField, UInt64(NativeUInt(FModule.OriginalModule)));
  if FFields.IndexOf(Rva) < 0 then
    FFields.Add(Rva);
  Result := True;
end;

constructor TNativeMirrorModuleData.Create(ProcessHandle: THandle; ModuleBase: UInt64; IsPebConnected, UseCache: Boolean; const ModuleName: string);
begin
  inherited Create;
  FProcessHandle := ProcessHandle;
  FModuleBase := ModuleBase;
  FIsPebConnected := IsPebConnected;
  FUseCache := UseCache;
  FModuleName := ModuleName;
  if FModuleName = '' then
    LoadModuleName;
end;

destructor TNativeMirrorModuleData.Destroy;
begin
  if FOriginalModule <> nil then
    FreePeBuffer(FOriginalModule, FOriginalSize);
  inherited;
end;

function TNativeMirrorModuleData.LoadModuleName: Boolean;
var
  Buffer: array[0..MAX_PATH - 1] of Char;
  Len: DWORD;
begin
  FillChar(Buffer, SizeOf(Buffer), 0);
  Len := GetModuleFileNameEx(FProcessHandle, HMODULE(NativeUInt(FModuleBase)), Buffer, Length(Buffer));
  Result := (Len <> 0) and (Len < DWORD(Length(Buffer)));
  if not Result then
    Exit;
  FModuleName := NormalizeModulePath(Buffer);
  Result := FModuleName <> '';
  if Result then
    AutoSwitchIfWow64Mapping;
end;

function TNativeMirrorModuleData.AutoSwitchIfWow64Mapping: Boolean;
var
  MappedName, Wow64Name: string;
begin
  Result := False;
  if FModuleName = '' then
    Exit;
  MappedName := TNativeMirrorRemoteModuleData.QueryMappedName(FProcessHandle, FModuleBase);
  if SameText(MappedName, FModuleName) then
    Exit;
  Wow64Name := ConvertToWow64Path(FModuleName);
  if not SameText(MappedName, Wow64Name) then
    Exit;
  Result := SwitchToWow64Path;
end;

function TNativeMirrorModuleData.LoadOriginalPath(const Path: string; DisableFsRedirection: Boolean): Boolean;
var
  OldValue: Pointer;
  Disabled: Boolean;
begin
  Result := False;
  if FOriginalModule <> nil then
  begin
    FreePeBuffer(FOriginalModule, FOriginalSize);
    FOriginalModule := nil;
    FOriginalSize := 0;
  end;
  Disabled := False;
  OldValue := nil;
  if DisableFsRedirection then
    Disabled := DisableWow64FsRedirection(OldValue);
  try
    if FUseCache then
      FOriginalModule := GlobalModuleCache.LoadCached(Path, FOriginalSize)
    else
      FOriginalModule := LoadPeModule(Path, FOriginalSize, False, False);
  finally
    if Disabled then
      RevertWow64FsRedirection(OldValue);
  end;
  if FOriginalModule = nil then
    Exit;
  FIsDotNet := NativePe.PeHdrsHelper.IsDotNet(FOriginalModule, FOriginalSize);
  Result := True;
end;

function TNativeMirrorModuleData.LoadOriginal: Boolean;
begin
  if FModuleName = '' then
    LoadModuleName;
  Result := (FModuleName <> '') and LoadOriginalPath(FModuleName, True);
  if not Result then
    Result := (FModuleName <> '') and LoadOriginalPath(FModuleName, False);
end;

function TNativeMirrorModuleData.Is64Bit: Boolean;
begin
  Result := (FOriginalModule <> nil) and NativePe.PeHdrsHelper.Is64Bit(FOriginalModule);
end;

function TNativeMirrorModuleData.RvaToVa(Rva: DWORD; ModuleBase: UInt64): UInt64;
begin
  if ModuleBase = 0 then
    ModuleBase := FModuleBase;
  Result := ModuleBase + Rva;
end;

function TNativeMirrorModuleData.VaToRva(Va: UInt64; ModuleBase: UInt64): DWORD;
var
  Diff: UInt64;
begin
  Result := 0;
  if ModuleBase = 0 then
    ModuleBase := FModuleBase;
  if (Va < ModuleBase) or (Va > ModuleBase + FOriginalSize) then
    Exit;
  Diff := Va - ModuleBase;
  if Diff <= High(DWORD) then
    Result := DWORD(Diff);
end;

function TNativeMirrorModuleData.SwitchToMappedPath: Boolean;
var
  Path: string;
begin
  Path := TNativeMirrorRemoteModuleData.QueryMappedName(FProcessHandle, FModuleBase);
  if Length(Path) >= MAX_PATH then
    Exit(False);
  FModuleName := Path;
  Result := True;
end;

function TNativeMirrorModuleData.SwitchToWow64Path: Boolean;
var
  Path: string;
  IsWow64: Boolean;
begin
  IsWow64 := False;
  if not IsProcessWow64(FProcessHandle, IsWow64) or not IsWow64 then
    Exit(False);
  Path := ConvertToWow64Path(FModuleName);
  Result := not SameText(Path, FModuleName);
  if Result then
    FModuleName := Path;
end;

function TNativeMirrorModuleData.ReloadWow64: Boolean;
begin
  if not SwitchToWow64Path then
    Exit(False);
  Result := LoadOriginalPath(FModuleName, False);
end;

function TNativeMirrorModuleData.RelocateToBase(NewBase: UInt64): Boolean;
var
  OldBase: UInt64;
begin
  Result := False;
  if FOriginalModule = nil then
    Exit;
  OldBase := GetImageBase(FOriginalModule);
  if OldBase = NewBase then
    Exit(True);
  if HasRelocations(FOriginalModule) and not RelocateModule(FOriginalModule, FOriginalSize, NewBase, OldBase) then
    Exit;
  Result := UpdateImageBase(FOriginalModule, NewBase);
end;

function TNativeMirrorModuleData.LoadRelocatedFields(Fields: TList<DWORD>): Boolean;
var
  Collector: TRelocCollector;
begin
  Result := False;
  if (FOriginalModule = nil) or (FOriginalSize = 0) or (Fields = nil) then
    Exit;
  if not HasValidRelocationTable(FOriginalModule, FOriginalSize) then
    Exit;
  Collector := TRelocCollector.Create(Self, Fields);
  try
    Result := ProcessRelocationTable(FOriginalModule, FOriginalSize, Collector) and (Fields.Count > 0);
  finally
    Collector.Free;
  end;
end;

function TNativeMirrorModuleData.LoadImportThunks(Thunks: TList<DWORD>): Boolean;
begin
  Result := (FOriginalModule <> nil) and (FOriginalSize <> 0) and (Thunks <> nil) and HasValidImportTable(FOriginalModule, FOriginalSize) and CollectThunks(FOriginalModule, FOriginalSize, Thunks) and (Thunks.Count > 0);
end;

function TNativeMirrorModuleData.LoadImportsList(Collection: TImportsCollection): Boolean;
begin
  Result := (FOriginalModule <> nil) and (FOriginalSize <> 0) and (Collection <> nil) and HasValidImportTable(FOriginalModule, FOriginalSize) and CollectImports(FOriginalModule, FOriginalSize, Collection);
end;

constructor TNativeMirrorRemoteModuleData.Create(const Reader: INativeMirrorMemoryReader; IsReflection: Boolean; ModuleBase: UInt64);
begin
  inherited Create;
  FReader := Reader;
  FIsReflection := IsReflection;
  FModuleBase := ModuleBase;
  FImage := TNativeMirrorBuffer.Create;
  FillChar(FHeader, SizeOf(FHeader), 0);
  Initialize;
end;

destructor TNativeMirrorRemoteModuleData.Destroy;
begin
  FImage.Free;
  inherited;
end;

function TNativeMirrorRemoteModuleData.LoadHeader: Boolean;
begin
  FillChar(FHeader, SizeOf(FHeader), 0);
  Result := (FReader <> nil) and (FReader.ReadMemory(FModuleBase, @FHeader[0], SizeOf(FHeader), FIsReflection) >= $100);
end;

function TNativeMirrorRemoteModuleData.Initialize: Boolean;
begin
  if FHeaderReady then
    Exit(True);
  FHeaderReady := LoadHeader;
  Result := FHeaderReady;
end;

function TNativeMirrorRemoteModuleData.Is64Bit: Boolean;
begin
  Result := FHeaderReady and NativePe.PeHdrsHelper.Is64Bit(@FHeader[0]);
end;

function TNativeMirrorRemoteModuleData.GetHeaderImageSize: NativeUInt;
begin
  if not FHeaderReady then
    Exit(0);
  Result := GetImageSize(@FHeader[0]);
end;

function TNativeMirrorRemoteModuleData.GetHeaderImageBase: UInt64;
begin
  if not FHeaderReady then
    Exit(0);
  Result := GetImageBase(@FHeader[0]);
end;

function TNativeMirrorRemoteModuleData.CalcImageSize: NativeUInt;
var
  MainRegion, Region: TNativeMirrorMemoryRegion;
  Current: NativePe.Types.PImageSectionHeader;
  MaxAddress: DWORD;
  TotalSize: UInt64;

  function IsValidSection(Section: NativePe.Types.PImageSectionHeader): Boolean;
  begin
    Result := (Section <> nil) and ValidatePtr(@FHeader[0], SizeOf(FHeader), Section, SizeOf(NativePe.Types.TImageSectionHeader));
    if not Result then
      Exit;
    Result := (Section.PointerToRelocations = 0) and (Section.NumberOfRelocations = 0) and (Section.PointerToLinenumbers = 0);
  end;

begin
  Result := 0;
  if (FReader = nil) or not FHeaderReady then
    Exit;
  Current := GetSectionHdr(@FHeader[0], SizeOf(FHeader), 0);
  if Current = nil then
  begin
    Result := NativeMirrorRegionSize(FReader, FModuleBase);
    Exit;
  end;
  if not FReader.QueryRegion(FModuleBase, MainRegion) then
    Exit;
  MaxAddress := 0;
  while IsValidSection(Current) do
  begin
    if (Current.Misc.VirtualSize <> 0) and (Current.VirtualAddress <> 0) then
    begin
      if FModuleBase > High(UInt64) - UInt64(Current.VirtualAddress) then
        Break;
      if not FReader.QueryRegion(FModuleBase + UInt64(Current.VirtualAddress), Region) then
        Break;
      if Region.AllocationBase <> MainRegion.AllocationBase then
        Break;
      if (Region.MappingType = 0) or (Region.Protect = 0) then
        Break;
      if ((Region.State and MEM_COMMIT) <> 0) and (Current.VirtualAddress > MaxAddress) then
        MaxAddress := Current.VirtualAddress;
    end;
    Current := NativePe.Types.PImageSectionHeader(NativeUInt(Current) + SizeOf(NativePe.Types.TImageSectionHeader));
  end;
  if FModuleBase > High(UInt64) - UInt64(MaxAddress) then
    Exit;
  TotalSize := UInt64(MaxAddress) + NativeMirrorRegionSize(FReader, FModuleBase + UInt64(MaxAddress));
  if TotalSize <= High(NativeUInt) then
    Result := NativeUInt(TotalSize);
end;

function TNativeMirrorRemoteModuleData.GetModuleSize: NativeUInt;
var
  DefinedSize: NativeUInt;
begin
  if FImage.Size <> 0 then
    Exit(FImage.Size);
  DefinedSize := GetHeaderImageSize;
  if DefinedSize = 0 then
    Exit(0);
  Result := RoundUpToUnitU(DefinedSize, $1000);
end;

function TNativeMirrorRemoteModuleData.GetHeaderSize: NativeUInt;
begin
  Result := SizeOf(FHeader);
end;

function TNativeMirrorRemoteModuleData.LoadFullImageSize(ImageSize: NativeUInt): Boolean;
begin
  Result := False;
  if (ImageSize = 0) or (FReader = nil) then
    Exit;
  if not FImage.Allocate(ImageSize) then
    Exit;
  if FReader.ReadMemory(FModuleBase, FImage.Data, ImageSize, FIsReflection) = ImageSize then
    Exit(True);
  FImage.Clear;
end;

function TNativeMirrorRemoteModuleData.LoadFullImage: Boolean;
var
  ImageSize: NativeUInt;
begin
  if IsFullImageLoaded then
    Exit(True);
  ImageSize := GetHeaderImageSize;
  Result := LoadFullImageSize(ImageSize);
  if Result then
    Exit;
  Result := LoadFullImageSize(CalcImageSize);
end;

function TNativeMirrorRemoteModuleData.IsFullImageLoaded: Boolean;
begin
  Result := (FImage.Data <> nil) and (FImage.Size <> 0);
end;

function TNativeMirrorRemoteModuleData.GetRemoteSectionVa(SectionNumber: NativeUInt): UInt64;
var
  Sec: NativePe.Types.PImageSectionHeader;
begin
  Result := 0;
  if not Initialize then
    Exit;
  Sec := GetSectionHdr(@FHeader[0], SizeOf(FHeader), SectionNumber);
  if (Sec = nil) or (Sec.SizeOfRawData = 0) then
    Exit;
  Result := FModuleBase + Sec.VirtualAddress;
end;

function TNativeMirrorRemoteModuleData.IsSectionEntry(SectionNumber: NativeUInt): Boolean;
var
  Ep: DWORD;
  Sec: NativePe.Types.PImageSectionHeader;
begin
  Result := False;
  if not Initialize then
    Exit;
  Ep := GetEntryPointRva(@FHeader[0]);
  if Ep = 0 then
    Exit;
  Sec := GetSectionHdr(@FHeader[0], SizeOf(FHeader), SectionNumber);
  Result := (Sec <> nil) and (Ep >= Sec.VirtualAddress) and (Ep < UInt64(Sec.VirtualAddress) + Sec.Misc.VirtualSize);
end;

function TNativeMirrorRemoteModuleData.IsSectionExecutable(SectionNumber: NativeUInt; AllowData, AllowInaccessible: Boolean): Boolean;
var
  Va: UInt64;
  Region: TNativeMirrorMemoryRegion;
begin
  Va := GetRemoteSectionVa(SectionNumber);
  if (Va = 0) or (FReader = nil) or not FReader.QueryRegion(Va, Region) then
    Exit(False);
  if NativeMirror.Scanner.Patterns.IsExecutableProtection(Region.MappingType, Region.Protect) then
    Exit(True);
  if AllowData and NativeMirror.Scanner.Patterns.IsReadableProtection(Region.MappingType, Region.Protect) then
    Exit(True);
  Result := AllowInaccessible and NativeMirror.Scanner.Patterns.IsNormalInaccessible(Region.State, Region.MappingType, Region.Protect);
end;

function TNativeMirrorRemoteModuleData.HasExecutableSection(AllowData, AllowInaccessible: Boolean): Boolean;
var
  I: NativeUInt;
  Count: NativeUInt;
begin
  Result := False;
  Count := GetSectionsCount(@FHeader[0], SizeOf(FHeader));
  if Count = 0 then
    Exit;
  for I := 0 to Count - 1 do
    if IsSectionExecutable(I, AllowData, AllowInaccessible) then
      Exit(True);
end;

function TNativeMirrorRemoteModuleData.LoadImportsList(Collection: TImportsCollection): Boolean;
begin
  Result := IsFullImageLoaded and (Collection <> nil) and HasValidImportTable(FImage.Data, FImage.Size) and CollectImports(FImage.Data, FImage.Size, Collection);
end;


function TNativeMirrorRemoteModuleData.GetHeaderData: PByte;
begin
  Result := @FHeader[0];
end;

function TNativeMirrorRemoteModuleData.GetModuleName: string;
var
  Buffer: array[0..32767] of Char;
  Len: DWORD;
begin
  Result := '';
  if (FReader = nil) or (FReader.ProcessHandle = 0) then
    Exit;
  FillChar(Buffer, SizeOf(Buffer), 0);
  Len := GetModuleFileNameEx(FReader.ProcessHandle, HMODULE(NativeUInt(FModuleBase)), Buffer, Length(Buffer));
  if Len <> 0 then
    Result := NormalizeModulePath(Buffer);
end;

class function TNativeMirrorRemoteModuleData.QueryMappedName(ProcessHandle: THandle; ModuleBase: UInt64): string;
var
  Buffer: array[0..32767] of Char;
  Len: DWORD;
begin
  Result := '';
  if ProcessHandle = 0 then
    Exit;
  FillChar(Buffer, SizeOf(Buffer), 0);
  Len := GetMappedFileName(ProcessHandle, Pointer(NativeUInt(ModuleBase)), Buffer, Length(Buffer));
  if Len <> 0 then
    Result := NormalizeModulePath(Buffer);
end;

function TNativeMirrorRemoteModuleData.GetMappedName: string;
begin
  Result := '';
  if FReader = nil then
    Exit;
  Result := QueryMappedName(FReader.ProcessHandle, FModuleBase);
end;

initialization
  GlobalModuleCache := TNativeMirrorModulesCache.Create;

finalization
  GlobalModuleCache.Free;

end.
