{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Scanner.Artefacts;

interface

uses
  Winapi.Windows,
  System.JSON,
  NativePe.Types,
  NativeMirror.Core.Types,
  NativeMirror.Core.Memory,
  NativeMirror.Scanner.MemPage,
  NativeMirror.Scanner.ProcessDetails,
  NativeMirror.Scanner.ProcessReport,
  NativeMirror.Scanner.WorkingSet;

type
  TNativeMirrorArtefactScanReport = class(TNativeMirrorWorkingSetScanReport)
  private
    FArtefacts: TPeArtefacts;
    FInitialRegionSize: NativeUInt;
  protected
    procedure AddBaseJson(Json: TJSONObject); override;
  public
    constructor Create(ModuleBase: UInt64; ModuleSize: NativeUInt; Status: TNativeMirrorScanStatus; const Artefacts: TPeArtefacts);
    function ReportType: TNativeMirrorScanReportType; override;
    property Artefacts: TPeArtefacts read FArtefacts;
    property InitialRegionSize: NativeUInt read FInitialRegionSize;
  end;

  TNativeMirrorArtefactScanner = class
  private type
    TArtefactMapping = record
      PeImageBase: UInt64;
      DosHeader: NativePe.Types.PImageDosHeader;
      NtFileHeader: NativePe.Types.PImageFileHeader;
      SectionHeader: NativePe.Types.PImageSectionHeader;
      SectionCount: NativeUInt;
      IsMzPeFound: Boolean;
      Is64Bit: Boolean;
      procedure Reset(Process64Bit: Boolean);
      function FoundAny: Boolean;
      function Score: NativeUInt;
    end;
  private
    FReader: INativeMirrorMemoryReader;
    FDetails: TNativeMirrorProcessDetails;
    FMemPage: TNativeMirrorMemPageData;
    FProcessReport: TNativeMirrorProcessScanReport;
    FIsProcess64Bit: Boolean;
    FPreviousPage: TNativeMirrorMemPageData;
    FArtefactPage: TNativeMirrorMemPageData;
    function CalcOffset(Page: TNativeMirrorMemPageData; Field: Pointer): UInt64;
    function CalcSectionHeadersOffset(Page: TNativeMirrorMemPageData; FileHeader: NativePe.Types.PImageFileHeader): UInt64;
    function CalcNtHeaderOffset(Page: TNativeMirrorMemPageData; FirstSection: NativePe.Types.PImageSectionHeader; Is64Bit: Boolean): UInt64;
    function ValidateHeadersAlignment(Page: TNativeMirrorMemPageData; FileHeader: NativePe.Types.PImageFileHeader; Section: NativePe.Types.PImageSectionHeader): Boolean;
    function IsValidSection(Page: TNativeMirrorMemPageData; Section: NativePe.Types.PImageSectionHeader; Characteristics: DWORD): Boolean;
    function CountSectionHeaders(Page: TNativeMirrorMemPageData; Header: NativePe.Types.PImageSectionHeader): NativeUInt;
    function GetFirstSection(Page: TNativeMirrorMemPageData; Header: NativePe.Types.PImageSectionHeader): NativePe.Types.PImageSectionHeader;
    function FindMzOffset(Page: TNativeMirrorMemPageData; Header: Pointer): UInt64;
    function CalcPeBase(Page: TNativeMirrorMemPageData; Section: Pointer): UInt64;
    function CalcImageSize(Page: TNativeMirrorMemPageData; Section: NativePe.Types.PImageSectionHeader; PeImageBase: UInt64): NativeUInt;
    function FindDosHeaderByPatterns(Page: TNativeMirrorMemPageData; StartOffset, HeadersOffset: NativeUInt): NativePe.Types.PImageDosHeader;
    function ValidateSectionRegions(Page: TNativeMirrorMemPageData; Section: NativePe.Types.PImageSectionHeader; Count: NativeUInt; PeImageBase: UInt64; VirtualLayout: Boolean): Boolean; overload;
    function ValidateSectionRegions(Page: TNativeMirrorMemPageData; Section: NativePe.Types.PImageSectionHeader; Count: NativeUInt): Boolean; overload;
    function FindSectionByPatterns(Page: TNativeMirrorMemPageData; MaxSearchSize, SearchOffset: NativeUInt): NativePe.Types.PImageSectionHeader;
    function IsValidFileHeader(Page: TNativeMirrorMemPageData; Header: NativePe.Types.PImageFileHeader; Characteristics: DWORD): Boolean;
    function FindNtFileHeader(Page: TNativeMirrorMemPageData; StartOffset: NativeUInt; StopOffset: UInt64 = NATIVE_MIRROR_INVALID_OFFSET): NativePe.Types.PImageFileHeader;
    function FindMzPeHeader(Page: TNativeMirrorMemPageData; SearchOffset: NativeUInt): NativePe.Types.PImageDosHeader;
    function FindMzPe(Page: TNativeMirrorMemPageData; var Mapping: TArtefactMapping; SearchOffset: NativeUInt): Boolean;
    function SetMzPe(Page: TNativeMirrorMemPageData; var Mapping: TArtefactMapping; DosHeader: NativePe.Types.PImageDosHeader): Boolean;
    function SetSectionHeader(Page: TNativeMirrorMemPageData; var Mapping: TArtefactMapping; Section: NativePe.Types.PImageSectionHeader): Boolean;
    function SetNtFileHeader(Page: TNativeMirrorMemPageData; var Mapping: TArtefactMapping; Header: NativePe.Types.PImageFileHeader): Boolean;
    function GenerateArtefacts(Page: TNativeMirrorMemPageData; var Mapping: TArtefactMapping; out Artefacts: TPeArtefacts): Boolean;
    function FindArtefacts(Page: TNativeMirrorMemPageData; StartOffset: NativeUInt; out Artefacts: TPeArtefacts): Boolean;
    function FindInPreviousPages(AddressStart, AddressStop: UInt64; out Artefacts: TPeArtefacts): Boolean;
    function HasShellcode(RegionStart: UInt64; RegionSize: NativeUInt; const Artefacts: TPeArtefacts): Boolean;
    procedure DeletePreviousPage;
  public
    constructor Create(const Reader: INativeMirrorMemoryReader; const Details: TNativeMirrorProcessDetails; MemPage: TNativeMirrorMemPageData; ProcessReport: TNativeMirrorProcessScanReport);
    destructor Destroy; override;
    function ScanRemote: TNativeMirrorArtefactScanReport;
  end;

implementation

uses
  System.SysUtils,
  NativePe.BufferUtil,
  NativePe.PeHdrsHelper,
  NativeMirror.Scanner.Patterns;

const
  PAGE_SIZE_NPT = $1000;

procedure TNativeMirrorArtefactScanner.TArtefactMapping.Reset(Process64Bit: Boolean);
begin
  PeImageBase := NATIVE_MIRROR_PE_NOT_FOUND;
  DosHeader := nil;
  NtFileHeader := nil;
  SectionHeader := nil;
  SectionCount := 0;
  IsMzPeFound := False;
  Is64Bit := Process64Bit;
end;

function TNativeMirrorArtefactScanner.TArtefactMapping.FoundAny: Boolean;
begin
  Result := (SectionHeader <> nil) or (NtFileHeader <> nil);
end;

function TNativeMirrorArtefactScanner.TArtefactMapping.Score: NativeUInt;
begin
  Result := 0;
  if SectionHeader <> nil then
  begin
    Inc(Result);
    if SectionCount > 1 then
      Inc(Result, 2);
  end;
  if NtFileHeader <> nil then
    Inc(Result, 2);
  if DosHeader <> nil then
    Inc(Result);
end;

constructor TNativeMirrorArtefactScanReport.Create(ModuleBase: UInt64; ModuleSize: NativeUInt; Status: TNativeMirrorScanStatus; const Artefacts: TPeArtefacts);
var
  TotalRegionSize: UInt64;
begin
  inherited Create(ModuleBase, ModuleSize, Status);
  FArtefacts := Artefacts;
  FInitialRegionSize := ModuleSize;
  IsExecutable := True;
  Protection := 0;
  HasPe := True;
  HasShellcode := False;
  TotalRegionSize := UInt64(Artefacts.CalculatedImageSize) + Artefacts.PeBaseOffset;
  if TotalRegionSize > Self.ModuleSize then
    Self.ModuleSize := NativeUInt(TotalRegionSize);
end;

function TNativeMirrorArtefactScanReport.ReportType: TNativeMirrorScanReportType;
begin
  Result := nmReportArtefactScan;
end;

procedure TNativeMirrorArtefactScanReport.AddBaseJson(Json: TJSONObject);
var
  A: TJSONObject;
begin
  inherited;
  A := TJSONObject.Create;
  A.AddPair('pe_base_offset', IntToHex(FArtefacts.PeBaseOffset, 1).ToLower);
  if FArtefacts.HasNtHeaders then
    A.AddPair('nt_file_hdr', IntToHex(FArtefacts.NtFileHeadersOffset, 1).ToLower);
  A.AddPair('sections_hdrs', IntToHex(FArtefacts.SectionHeadersOffset, 1).ToLower);
  A.AddPair('sections_count', TJSONNumber.Create(FArtefacts.SectionCount));
  A.AddPair('is_dll', TJSONNumber.Create(Ord(FArtefacts.IsDll)));
  A.AddPair('is_64_bit', TJSONNumber.Create(Ord(FArtefacts.Is64Bit)));
  Json.AddPair('pe_artefacts', A);
end;

constructor TNativeMirrorArtefactScanner.Create(const Reader: INativeMirrorMemoryReader; const Details: TNativeMirrorProcessDetails; MemPage: TNativeMirrorMemPageData; ProcessReport: TNativeMirrorProcessScanReport);
begin
  inherited Create;
  FReader := Reader;
  FDetails := Details;
  FMemPage := MemPage;
  FProcessReport := ProcessReport;
  FIsProcess64Bit := (Reader <> nil) and (Reader.Architecture = nmaX64);
end;

destructor TNativeMirrorArtefactScanner.Destroy;
begin
  DeletePreviousPage;
  inherited;
end;

procedure TNativeMirrorArtefactScanner.DeletePreviousPage;
begin
  FPreviousPage.Free;
  FPreviousPage := nil;
  FArtefactPage := nil;
end;

function TNativeMirrorArtefactScanner.CalcOffset(Page: TNativeMirrorMemPageData; Field: Pointer): UInt64;
begin
  Result := NATIVE_MIRROR_INVALID_OFFSET;
  if (Page = nil) or (Field = nil) or not Page.ValidatePtr(Field, 1) then
    Exit;
  Result := NativeUInt(Field) - NativeUInt(Page.GetLoadedData);
end;

function TNativeMirrorArtefactScanner.CalcSectionHeadersOffset(Page: TNativeMirrorMemPageData; FileHeader: NativePe.Types.PImageFileHeader): UInt64;
var
  OptionalSize: NativeUInt;
  NtOffset: UInt64;
begin
  Result := NATIVE_MIRROR_INVALID_OFFSET;
  if FileHeader = nil then
    Exit;
  OptionalSize := FileHeader.SizeOfOptionalHeader;
  if OptionalSize = 0 then
    if FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64 then
      OptionalSize := SizeOf(NativePe.Types.TImageOptionalHeader64)
    else
      OptionalSize := SizeOf(NativePe.Types.TImageOptionalHeader32);
  NtOffset := CalcOffset(Page, FileHeader);
  if NtOffset = NATIVE_MIRROR_INVALID_OFFSET then
    Exit;
  Result := NtOffset + SizeOf(NativePe.Types.TImageFileHeader) + OptionalSize;
end;

function TNativeMirrorArtefactScanner.CalcNtHeaderOffset(Page: TNativeMirrorMemPageData; FirstSection: NativePe.Types.PImageSectionHeader; Is64Bit: Boolean): UInt64;
var
  SectionOffset, OptionalSize, HeadersSize: UInt64;
begin
  Result := NATIVE_MIRROR_INVALID_OFFSET;
  SectionOffset := CalcOffset(Page, FirstSection);
  if SectionOffset = NATIVE_MIRROR_INVALID_OFFSET then
    Exit;
  if Is64Bit then
    OptionalSize := SizeOf(NativePe.Types.TImageOptionalHeader64)
  else
    OptionalSize := SizeOf(NativePe.Types.TImageOptionalHeader32);
  HeadersSize := OptionalSize + SizeOf(NativePe.Types.TImageFileHeader);
  if SectionOffset < HeadersSize then
    Exit;
  Result := SectionOffset - HeadersSize;
end;

function TNativeMirrorArtefactScanner.ValidateHeadersAlignment(Page: TNativeMirrorMemPageData; FileHeader: NativePe.Types.PImageFileHeader; Section: NativePe.Types.PImageSectionHeader): Boolean;
begin
  Result := (FileHeader <> nil) and (Section <> nil) and (CalcSectionHeadersOffset(Page, FileHeader) = CalcOffset(Page, Section));
end;

function TNativeMirrorArtefactScanner.IsValidSection(Page: TNativeMirrorMemPageData; Section: NativePe.Types.PImageSectionHeader; Characteristics: DWORD): Boolean;
begin
  Result := False;
  if (Page = nil) or (Section = nil) or not Page.ValidatePtr(Section, SizeOf(NativePe.Types.TImageSectionHeader)) then
    Exit;
  if (Section.PointerToRelocations <> 0) or (Section.NumberOfRelocations <> 0) or (Section.PointerToLinenumbers <> 0) then
    Exit;
  if (Characteristics <> 0) and ((Section.Characteristics and Characteristics) = 0) then
    Exit;
  Result := True;
end;

function TNativeMirrorArtefactScanner.CountSectionHeaders(Page: TNativeMirrorMemPageData; Header: NativePe.Types.PImageSectionHeader): NativeUInt;
var
  Current: NativePe.Types.PImageSectionHeader;
begin
  Result := 0;
  if (Page = nil) or (Header = nil) then
    Exit;
  Current := Header;
  while IsValidSection(Page, Current, IMAGE_SCN_MEM_READ) do
  begin
    Inc(Result);
    Current := NativePe.Types.PImageSectionHeader(NativeUInt(Current) + SizeOf(NativePe.Types.TImageSectionHeader));
  end;
end;

function TNativeMirrorArtefactScanner.GetFirstSection(Page: TNativeMirrorMemPageData; Header: NativePe.Types.PImageSectionHeader): NativePe.Types.PImageSectionHeader;
var
  Previous: NativePe.Types.PImageSectionHeader;
begin
  Result := Header;
  if Header = nil then
    Exit;
  Previous := NativePe.Types.PImageSectionHeader(NativeUInt(Header) - SizeOf(NativePe.Types.TImageSectionHeader));
  while IsValidSection(Page, Previous, IMAGE_SCN_MEM_READ) do
  begin
    Result := Previous;
    if NativeUInt(Previous) < NativeUInt(Page.GetLoadedData) + SizeOf(NativePe.Types.TImageSectionHeader) then
      Break;
    Previous := NativePe.Types.PImageSectionHeader(NativeUInt(Previous) - SizeOf(NativePe.Types.TImageSectionHeader));
  end;
end;

function TNativeMirrorArtefactScanner.FindMzOffset(Page: TNativeMirrorMemPageData; Header: Pointer): UInt64;
var
  Offset, Start, Space: NativeUInt;
  Search: PByte;
begin
  Result := NATIVE_MIRROR_INVALID_OFFSET;
  Offset := CalcOffset(Page, Header);
  if (Offset = NATIVE_MIRROR_INVALID_OFFSET) or (Offset < 3) then
    Exit;
  Start := Offset - 3;
  Space := PAGE_SIZE_NPT;
  Search := PByte(NativeUInt(Page.GetLoadedData) + Start);
  while (NativeUInt(Search) >= NativeUInt(Page.GetLoadedData)) and (Space <> 0) do
  begin
    if (Search^ = Ord('M')) and (PByte(NativeUInt(Search) + 1)^ = Ord('Z')) and ((PByte(NativeUInt(Search) + 2)^ = $90) or (PByte(NativeUInt(Search) + 2)^ = 0)) then
      Exit(CalcOffset(Page, Search));
    if NativeUInt(Search) = NativeUInt(Page.GetLoadedData) then
      Break;
    Search := PByte(NativeUInt(Search) - 1);
    Dec(Space);
  end;
end;

function TNativeMirrorArtefactScanner.FindDosHeaderByPatterns(Page: TNativeMirrorMemPageData; StartOffset, HeadersOffset: NativeUInt): NativePe.Types.PImageDosHeader;
const
  Stub0: array[0..13] of Byte = ($0E,$1F,$BA,$0E,$00,$B4,$09,$CD,$21,$B8,$01,$4C,$CD,$21);
  Stub1: array[0..13] of Byte = ($BA,$10,$00,$0E,$1F,$B4,$09,$CD,$21,$B8,$01,$4C,$CD,$21);
var
  Search, Found: PByte;
  SearchSize: NativeUInt;
  I: Integer;
  Patterns: array[0..1] of PByte;
begin
  Result := nil;
  if (Page = nil) or not Page.Load or (HeadersOffset <= StartOffset) then
    Exit;
  Search := PByte(NativeUInt(Page.GetLoadedData) + StartOffset);
  SearchSize := HeadersOffset - StartOffset;
  if not Page.ValidatePtr(Search, SearchSize) then
    Exit;
  Patterns[0] := @Stub0[0];
  Patterns[1] := @Stub1[0];
  for I := 0 to 1 do
  begin
    Found := FindPattern(Search, SearchSize, Patterns[I], 14);
    if (Found = nil) or (NativeUInt(Found) < NativeUInt(Page.GetLoadedData) + SizeOf(NativePe.Types.TImageDosHeader)) then
      Continue;
    Result := NativePe.Types.PImageDosHeader(NativeUInt(Found) - SizeOf(NativePe.Types.TImageDosHeader));
    if Page.ValidatePtr(Result, SizeOf(NativePe.Types.TImageDosHeader)) then
      Exit;
    Result := nil;
  end;
end;

function TNativeMirrorArtefactScanner.CalcPeBase(Page: TNativeMirrorMemPageData; Section: Pointer): UInt64;
var
  FoundMz, HeaderOffset, SearchStart, DosOffset: UInt64;
  Dos: NativePe.Types.PImageDosHeader;
begin
  Result := 0;
  FoundMz := FindMzOffset(Page, Section);
  if FoundMz <> NATIVE_MIRROR_INVALID_OFFSET then
    Exit(Page.RegionStart + FoundMz);
  HeaderOffset := CalcOffset(Page, Section);
  if HeaderOffset = NATIVE_MIRROR_INVALID_OFFSET then
    Exit;
  if HeaderOffset > PAGE_SIZE_NPT then
    SearchStart := HeaderOffset - PAGE_SIZE_NPT
  else
    SearchStart := 0;
  Dos := FindDosHeaderByPatterns(Page, SearchStart, HeaderOffset);
  DosOffset := CalcOffset(Page, Dos);
  if DosOffset <> NATIVE_MIRROR_INVALID_OFFSET then
    Exit(Page.RegionStart + DosOffset);
  Result := Page.RegionStart + (HeaderOffset div PAGE_SIZE_NPT) * PAGE_SIZE_NPT;
end;

function TNativeMirrorArtefactScanner.ValidateSectionRegions(Page: TNativeMirrorMemPageData; Section: NativePe.Types.PImageSectionHeader; Count: NativeUInt; PeImageBase: UInt64; VirtualLayout: Boolean): Boolean;
var
  MainRegion, Region: TNativeMirrorMemoryRegion;
  I: NativeUInt;
  Current: NativePe.Types.PImageSectionHeader;
  SectionStart: DWORD;
  Address: UInt64;
begin
  Result := False;
  if (Section = nil) or (Count = 0) or (FReader = nil) or not FReader.QueryRegion(PeImageBase, MainRegion) then
    Exit;
  Current := Section;
  for I := 0 to Count - 1 do
  begin
    if Current.VirtualAddress <> 0 then
    begin
      if VirtualLayout then
        SectionStart := Current.VirtualAddress
      else
        SectionStart := Current.PointerToRawData;
      Address := PeImageBase + SectionStart;
      if not FReader.QueryRegion(Address, Region) or (Region.AllocationBase <> MainRegion.AllocationBase) then
        Exit;
    end;
    Current := NativePe.Types.PImageSectionHeader(NativeUInt(Current) + SizeOf(NativePe.Types.TImageSectionHeader));
  end;
  Result := True;
end;

function TNativeMirrorArtefactScanner.ValidateSectionRegions(Page: TNativeMirrorMemPageData; Section: NativePe.Types.PImageSectionHeader; Count: NativeUInt): Boolean;
var
  Current: NativePe.Types.PImageSectionHeader;
  I: NativeUInt;
  HasNonZero: Boolean;
  Base: UInt64;
begin
  Result := False;
  if (Page = nil) or (Page.GetLoadedData = nil) or (Section = nil) or (Count = 0) then
    Exit;
  Base := CalcPeBase(Page, Section);
  HasNonZero := False;
  Current := Section;
  for I := 0 to Count - 1 do
  begin
    if (Current.VirtualAddress <> 0) and (Current.Misc.VirtualSize <> 0) then
      HasNonZero := True;
    Current := NativePe.Types.PImageSectionHeader(NativeUInt(Current) + SizeOf(NativePe.Types.TImageSectionHeader));
  end;
  if not HasNonZero then
    Exit;
  Result := ValidateSectionRegions(Page, Section, Count, Base, True);
  if not Result then
    Result := ValidateSectionRegions(Page, Section, Count, Base, False);
end;

function TNativeMirrorArtefactScanner.FindSectionByPatterns(Page: TNativeMirrorMemPageData; MaxSearchSize, SearchOffset: NativeUInt): NativePe.Types.PImageSectionHeader;
const
  TextName: array[0..4] of Byte = ($2E,$74,$65,$78,$74);
  Char0: array[0..15] of Byte = ($00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$20,$00,$00,$60);
  Char1: array[0..15] of Byte = ($00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$40,$00,$00,$C0);
var
  Search, Found: PByte;
  Candidate, First: NativePe.Types.PImageSectionHeader;
  Count: NativeUInt;
  I: Integer;
  Patterns: array[0..1] of PByte;
begin
  Result := nil;
  if (Page = nil) or not Page.Load or (SearchOffset >= Page.GetLoadedSize) then
    Exit;
  Search := PByte(NativeUInt(Page.GetLoadedData) + SearchOffset);
  if MaxSearchSize > Page.GetLoadedSize - SearchOffset then
    MaxSearchSize := Page.GetLoadedSize - SearchOffset;
  if not Page.ValidatePtr(Search, MaxSearchSize) then
    Exit;
  Found := FindPattern(Search, MaxSearchSize, @TextName[0], Length(TextName));
  if Found <> nil then
  begin
    Candidate := NativePe.Types.PImageSectionHeader(Found);
    if IsValidSection(Page, Candidate, IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_EXECUTE) then
    begin
      First := GetFirstSection(Page, Candidate);
      Count := CountSectionHeaders(Page, First);
      if ValidateSectionRegions(Page, First, Count) then
        Exit(First);
    end;
  end;
  Patterns[0] := @Char0[0];
  Patterns[1] := @Char1[0];
  for I := 0 to 1 do
  begin
    Found := FindPattern(Search, MaxSearchSize, Patterns[I], 16);
    if (Found = nil) or (NativeUInt(Found) < NativeUInt(Page.GetLoadedData) + SizeOf(NativePe.Types.TImageSectionHeader) - 16) then
      Continue;
    Candidate := NativePe.Types.PImageSectionHeader(NativeUInt(Found) - (SizeOf(NativePe.Types.TImageSectionHeader) - 16));
    if not IsValidSection(Page, Candidate, IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_EXECUTE) then
      Continue;
    First := GetFirstSection(Page, Candidate);
    Count := CountSectionHeaders(Page, First);
    if ValidateSectionRegions(Page, First, Count) then
      Exit(First);
  end;
end;

function TNativeMirrorArtefactScanner.IsValidFileHeader(Page: TNativeMirrorMemPageData; Header: NativePe.Types.PImageFileHeader; Characteristics: DWORD): Boolean;
var
  OptionalSize: NativeUInt;
begin
  Result := False;
  if (Page = nil) or (Header = nil) or not Page.ValidatePtr(Header, SizeOf(NativePe.Types.TImageFileHeader)) then
    Exit;
  if Header.NumberOfSections > 100 then
    Exit;
  if (Header.NumberOfSymbols <> 0) or (Header.PointerToSymbolTable <> 0) then
    Exit;
  case Header.Machine of
    IMAGE_FILE_MACHINE_I386: OptionalSize := SizeOf(NativePe.Types.TImageOptionalHeader32);
    IMAGE_FILE_MACHINE_AMD64: OptionalSize := SizeOf(NativePe.Types.TImageOptionalHeader64);
  else
    Exit;
  end;
  if Header.SizeOfOptionalHeader > PAGE_SIZE_NPT then
    Exit;
  if not Page.ValidatePtr(Header, SizeOf(NativePe.Types.TImageFileHeader) + OptionalSize) then
    Exit;
  if Header.SizeOfOptionalHeader = OptionalSize then
    Exit(True);
  if (Characteristics <> 0) and ((Header.Characteristics and Characteristics) = 0) then
    Exit;
  Result := True;
end;

function TNativeMirrorArtefactScanner.FindNtFileHeader(Page: TNativeMirrorMemPageData; StartOffset: NativeUInt; StopOffset: UInt64): NativePe.Types.PImageFileHeader;
var
  Loaded, Search, Found: PByte;
  LoadedSize, SearchSize, MaxIterations: NativeUInt;
  Machine: Word;
  Characteristics: DWORD;
  Arch: Integer;
begin
  Result := nil;
  if Page = nil then
    Exit;
  Loaded := Page.GetLoadedData;
  LoadedSize := Page.GetLoadedSize;
  if Loaded = nil then
    Exit;
  MaxIterations := 0;
  if (StopOffset = NATIVE_MIRROR_INVALID_OFFSET) or (StopOffset = 0) then
  begin
    StopOffset := LoadedSize;
    MaxIterations := 1;
  end;
  if StopOffset > LoadedSize then
    StopOffset := LoadedSize;
  if (StartOffset >= LoadedSize) or (StopOffset <= StartOffset) then
    Exit;
  Search := PByte(NativeUInt(Loaded) + StartOffset);
  SearchSize := LoadedSize - StartOffset;
  for Arch := 0 to 1 do
  begin
    if Arch = 0 then
      Machine := IMAGE_FILE_MACHINE_I386
    else
      Machine := IMAGE_FILE_MACHINE_AMD64;
    Found := FindPattern(Search, SearchSize, @Machine, SizeOf(Machine), MaxIterations);
    if Found = nil then
      Continue;
    Characteristics := IMAGE_FILE_EXECUTABLE_IMAGE;
    if Arch = 0 then
      Characteristics := Characteristics or IMAGE_FILE_32BIT_MACHINE
    else
      Characteristics := Characteristics or IMAGE_FILE_LARGE_ADDRESS_AWARE;
    Result := NativePe.Types.PImageFileHeader(Found);
    if IsValidFileHeader(Page, Result, Characteristics) then
      Exit;
    Result := nil;
  end;
end;

function TNativeMirrorArtefactScanner.FindMzPeHeader(Page: TNativeMirrorMemPageData; SearchOffset: NativeUInt): NativePe.Types.PImageDosHeader;
var
  ScanSize, Remaining, I, MinSize: NativeUInt;
  Buffer, Candidate: PByte;
begin
  Result := nil;
  if (Page = nil) or not Page.Load or (Page.GetLoadedSize <= SearchOffset) then
    Exit;
  ScanSize := Page.GetLoadedSize - SearchOffset;
  Buffer := PByte(NativeUInt(Page.GetLoadedData) + SearchOffset);
  if not Page.ValidatePtr(Buffer, ScanSize) then
    Exit;
  MinSize := SizeOf(NativePe.Types.TImageDosHeader) + SizeOf(NativePe.Types.TImageFileHeader) + SizeOf(NativePe.Types.TImageOptionalHeader32);
  for I := 0 to ScanSize - 1 do
  begin
    Remaining := ScanSize - I;
    if Remaining < MinSize then
      Break;
    Candidate := PByte(NativeUInt(Buffer) + I);
    if GetNtHdrs(Candidate, Remaining) <> nil then
      Exit(NativePe.Types.PImageDosHeader(Candidate));
  end;
end;

function TNativeMirrorArtefactScanner.SetNtFileHeader(Page: TNativeMirrorMemPageData; var Mapping: TArtefactMapping; Header: NativePe.Types.PImageFileHeader): Boolean;
var
  Offset: UInt64;
begin
  Result := False;
  if Header = nil then
    Exit;
  Mapping.NtFileHeader := Header;
  if Mapping.SectionHeader = nil then
  begin
    Offset := CalcSectionHeadersOffset(Page, Header);
    if Offset <> NATIVE_MIRROR_INVALID_OFFSET then
      Mapping.SectionHeader := NativePe.Types.PImageSectionHeader(NativeUInt(Page.GetLoadedData) + Offset);
    Exit(True);
  end;
  if not ValidateHeadersAlignment(Page, Header, Mapping.SectionHeader) then
  begin
    Mapping.NtFileHeader := nil;
    Exit;
  end;
  Result := True;
end;

function TNativeMirrorArtefactScanner.SetMzPe(Page: TNativeMirrorMemPageData; var Mapping: TArtefactMapping; DosHeader: NativePe.Types.PImageDosHeader): Boolean;
var
  Offset: UInt64;
  NtHeaders: NativePe.Types.PImageNtHeaders32;
begin
  Result := False;
  if DosHeader = nil then
    Exit;
  Mapping.DosHeader := DosHeader;
  Offset := CalcOffset(Page, DosHeader);
  if Offset = NATIVE_MIRROR_INVALID_OFFSET then
    Exit;
  Mapping.PeImageBase := Page.RegionStart + Offset;
  if DosHeader.e_lfanew < 0 then
    Exit;
  NtHeaders := NativePe.Types.PImageNtHeaders32(NativeUInt(DosHeader) + NativeUInt(DosHeader.e_lfanew));
  if not Page.ValidatePtr(NtHeaders, SizeOf(NativePe.Types.TImageNtHeaders32)) then
    Exit;
  SetNtFileHeader(Page, Mapping, @NtHeaders.FileHeader);
  Result := True;
end;

function TNativeMirrorArtefactScanner.FindMzPe(Page: TNativeMirrorMemPageData; var Mapping: TArtefactMapping; SearchOffset: NativeUInt): Boolean;
var
  Dos: NativePe.Types.PImageDosHeader;
begin
  Dos := FindMzPeHeader(Page, SearchOffset);
  Result := (Dos <> nil) and Page.ValidatePtr(Dos, SizeOf(NativePe.Types.TImageDosHeader)) and SetMzPe(Page, Mapping, Dos);
  if Result then
    Mapping.IsMzPeFound := True;
end;

function TNativeMirrorArtefactScanner.SetSectionHeader(Page: TNativeMirrorMemPageData; var Mapping: TArtefactMapping; Section: NativePe.Types.PImageSectionHeader): Boolean;
var
  SectionOffset, SuggestedNt: UInt64;
  Count: NativeUInt;
begin
  Result := False;
  if Section = nil then
    Exit;
  SectionOffset := CalcOffset(Page, Section);
  if SectionOffset = NATIVE_MIRROR_INVALID_OFFSET then
    Exit;
  Count := CountSectionHeaders(Page, Section);
  if Count = 0 then
    Exit;
  if Mapping.NtFileHeader = nil then
  begin
    SuggestedNt := CalcNtHeaderOffset(Page, Section, FIsProcess64Bit);
    if (SuggestedNt <> NATIVE_MIRROR_INVALID_OFFSET) and (SectionOffset >= SuggestedNt) then
      Mapping.NtFileHeader := FindNtFileHeader(Page, SuggestedNt, SectionOffset);
  end;
  if (Mapping.NtFileHeader <> nil) and (NativeUInt(Mapping.NtFileHeader) > NativeUInt(Section)) then
    Exit;
  Mapping.SectionHeader := Section;
  Mapping.SectionCount := Count;
  if Mapping.PeImageBase = 0 then
    Mapping.PeImageBase := CalcPeBase(Page, Section);
  Result := True;
end;

function TNativeMirrorArtefactScanner.CalcImageSize(Page: TNativeMirrorMemPageData; Section: NativePe.Types.PImageSectionHeader; PeImageBase: UInt64): NativeUInt;
var
  MainRegion, Region: TNativeMirrorMemoryRegion;
  Current: NativePe.Types.PImageSectionHeader;
  MaxAddress: DWORD;
  LastSize: UInt64;
begin
  Result := 0;
  if (FReader = nil) or (Section = nil) or not FReader.QueryRegion(PeImageBase, MainRegion) then
    Exit;
  MaxAddress := 0;
  Current := Section;
  while IsValidSection(Page, Current, 0) do
  begin
    if (Current.Misc.VirtualSize <> 0) and (Current.VirtualAddress <> 0) then
    begin
      if not FReader.QueryRegion(PeImageBase + Current.VirtualAddress, Region) then
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
  LastSize := NativeMirrorRegionSize(FReader, PeImageBase + MaxAddress);
  if UInt64(MaxAddress) + LastSize <= High(NativeUInt) then
    Result := NativeUInt(UInt64(MaxAddress) + LastSize);
end;

function TNativeMirrorArtefactScanner.GenerateArtefacts(Page: TNativeMirrorMemPageData; var Mapping: TArtefactMapping; out Artefacts: TPeArtefacts): Boolean;
begin
  Artefacts.Reset;
  Result := False;
  if Mapping.SectionHeader = nil then
    Exit;
  Artefacts.RegionStart := Page.RegionStart;
  Artefacts.IsMzPeFound := Mapping.IsMzPeFound;
  Artefacts.SectionHeadersOffset := CalcOffset(Page, Mapping.SectionHeader);
  Artefacts.SectionCount := CountSectionHeaders(Page, Mapping.SectionHeader);
  Artefacts.NtFileHeadersOffset := CalcOffset(Page, Mapping.NtFileHeader);
  if Mapping.PeImageBase = 0 then
    Mapping.PeImageBase := CalcPeBase(Page, Mapping.SectionHeader);
  if Mapping.PeImageBase < Page.RegionStart then
    Exit;
  Artefacts.PeBaseOffset := Mapping.PeImageBase - Page.RegionStart;
  Artefacts.CalculatedImageSize := CalcImageSize(Page, Mapping.SectionHeader, Mapping.PeImageBase);
  if Mapping.NtFileHeader <> nil then
    Artefacts.IsDll := (Mapping.NtFileHeader.Characteristics and IMAGE_FILE_DLL) <> 0;
  if (Mapping.NtFileHeader <> nil) and (Mapping.NtFileHeader.Machine = IMAGE_FILE_MACHINE_I386) then
    Mapping.Is64Bit := False
  else if (Mapping.NtFileHeader <> nil) and (Mapping.NtFileHeader.Machine = IMAGE_FILE_MACHINE_AMD64) then
    Mapping.Is64Bit := True
  else
    Mapping.Is64Bit := FIsProcess64Bit;
  Artefacts.Is64Bit := Mapping.Is64Bit;
  Result := True;
end;

function TNativeMirrorArtefactScanner.FindArtefacts(Page: TNativeMirrorMemPageData; StartOffset: NativeUInt; out Artefacts: TPeArtefacts): Boolean;
var
  Best, Current: TArtefactMapping;
  MinOffset, DosOffset, NtOffset, SecOffset, MaxSectionSearch, AreaSize: UInt64;
  Section: NativePe.Types.PImageSectionHeader;
  Dos: NativePe.Types.PImageDosHeader;
  Nt: NativePe.Types.PImageNtHeaders32;
begin
  Result := False;
  Artefacts.Reset;
  if (Page = nil) or not Page.Load then
    Exit;
  Best.Reset(FIsProcess64Bit);
  MinOffset := StartOffset;
  while MinOffset < Page.GetLoadedSize do
  begin
    Current.Reset(FIsProcess64Bit);
    if FindMzPe(Page, Current, MinOffset) then
    begin
      DosOffset := CalcOffset(Page, Current.DosHeader);
      if DosOffset <> NATIVE_MIRROR_INVALID_OFFSET then
        MinOffset := DosOffset;
    end
    else
    begin
      Current.NtFileHeader := FindNtFileHeader(Page, MinOffset, Page.GetLoadedSize);
      SetNtFileHeader(Page, Current, Current.NtFileHeader);
    end;
    MaxSectionSearch := Page.GetLoadedSize;
    if Current.NtFileHeader <> nil then
    begin
      NtOffset := CalcOffset(Page, Current.NtFileHeader);
      if (NtOffset <> NATIVE_MIRROR_INVALID_OFFSET) and (NtOffset > MinOffset) then
        MinOffset := NtOffset;
      if PAGE_SIZE_NPT < Page.GetLoadedSize then
        MaxSectionSearch := PAGE_SIZE_NPT;
      if MaxSectionSearch + MinOffset <= Page.GetLoadedSize then
        Inc(MaxSectionSearch, MinOffset);
    end;
    if not SetSectionHeader(Page, Current, Current.SectionHeader) and (MaxSectionSearch > MinOffset) then
    begin
      Section := FindSectionByPatterns(Page, MaxSectionSearch - MinOffset, MinOffset);
      SetSectionHeader(Page, Current, Section);
    end;
    if Current.SectionHeader <> nil then
    begin
      SecOffset := CalcOffset(Page, Current.SectionHeader);
      if (SecOffset <> NATIVE_MIRROR_INVALID_OFFSET) and (SecOffset > MinOffset) then
      begin
        AreaSize := Current.SectionCount * SizeOf(NativePe.Types.TImageSectionHeader);
        MinOffset := SecOffset + AreaSize;
      end;
      if Current.DosHeader = nil then
      begin
        if SecOffset > PAGE_SIZE_NPT then
          DosOffset := SecOffset - PAGE_SIZE_NPT
        else
          DosOffset := 0;
        Dos := FindDosHeaderByPatterns(Page, DosOffset, SecOffset);
        Current.DosHeader := Dos;
        if (Dos <> nil) and (Current.NtFileHeader = nil) and (Dos.e_lfanew >= 0) then
        begin
          Nt := NativePe.Types.PImageNtHeaders32(NativeUInt(Dos) + NativeUInt(Dos.e_lfanew));
          if Page.ValidatePtr(Nt, SizeOf(NativePe.Types.TImageNtHeaders32)) then
            SetNtFileHeader(Page, Current, @Nt.FileHeader);
        end;
      end;
    end;
    if not SetSectionHeader(Page, Current, Current.SectionHeader) then
      Current.SectionHeader := nil;
    if Best.Score < Current.Score then
      Best := Current;
    if not Current.FoundAny then
      Break;
    NtOffset := CalcOffset(Page, Current.NtFileHeader);
    SecOffset := CalcOffset(Page, Current.SectionHeader);
    if (NtOffset <> NATIVE_MIRROR_INVALID_OFFSET) and (NtOffset > MinOffset) then
      MinOffset := NtOffset;
    if (SecOffset <> NATIVE_MIRROR_INVALID_OFFSET) and (SecOffset > MinOffset) then
      MinOffset := SecOffset;
    Inc(MinOffset);
  end;
  if Best.Score <= 1 then
    Exit;
  Result := GenerateArtefacts(Page, Best, Artefacts);
end;

function TNativeMirrorArtefactScanner.FindInPreviousPages(AddressStart, AddressStop: UInt64; out Artefacts: TPeArtefacts): Boolean;
var
  NextAddress, AreaSize: UInt64;
begin
  Result := False;
  Artefacts.Reset;
  DeletePreviousPage;
  if AddressStop < PAGE_SIZE_NPT then
    Exit;
  NextAddress := AddressStop - PAGE_SIZE_NPT;
  while NextAddress >= AddressStart do
  begin
    AreaSize := AddressStop - NextAddress;
    if FProcessReport.HasModuleContaining(NextAddress, NativeUInt(AreaSize)) then
      Break;
    FPreviousPage := TNativeMirrorMemPageData.Create(FReader, FDetails.IsReflection, NextAddress, AddressStop);
    if FindArtefacts(FPreviousPage, 0, Artefacts) then
      Exit(True);
    if not FPreviousPage.IsInfoFilled or (NextAddress < FPreviousPage.RegionStart) then
      Break;
    NextAddress := (NextAddress - FPreviousPage.RegionStart) + UInt64(PAGE_SIZE_NPT);
    DeletePreviousPage;
  end;
end;

function TNativeMirrorArtefactScanner.HasShellcode(RegionStart: UInt64; RegionSize: NativeUInt; const Artefacts: TPeArtefacts): Boolean;
begin
  Result := (Artefacts.PeBaseOffset > 0) or (RegionSize > Artefacts.CalculatedImageSize);
end;

function TNativeMirrorArtefactScanner.ScanRemote: TNativeMirrorArtefactScanReport;
var
  Artefacts: TPeArtefacts;
  RegionStart: UInt64;
  RegionSize: NativeUInt;
begin
  Result := nil;
  DeletePreviousPage;
  if FMemPage = nil then
    Exit;
  RegionStart := FMemPage.RegionStart;
  FArtefactPage := FMemPage;
  if not FindArtefacts(FMemPage, 0, Artefacts) and (RegionStart > FMemPage.AllocationBase) then
  begin
    if FindInPreviousPages(FMemPage.AllocationBase, FMemPage.RegionStart, Artefacts) and (FPreviousPage <> nil) then
    begin
      FArtefactPage := FPreviousPage;
      RegionStart := FPreviousPage.RegionStart;
    end
    else
      Exit;
  end;
  if FMemPage.RegionEnd <= RegionStart then
    Exit;
  if Artefacts.SectionCount = 0 then
    Exit;
  RegionSize := NativeUInt(FMemPage.RegionEnd - RegionStart);
  Result := TNativeMirrorArtefactScanReport.Create(RegionStart, RegionSize, NM_SCAN_SUSPICIOUS, Artefacts);
  Result.Protection := FMemPage.Protection;
  Result.HasShellcode := HasShellcode(RegionStart, RegionSize, Artefacts);
end;

end.
