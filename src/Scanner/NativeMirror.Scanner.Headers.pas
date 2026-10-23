{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Scanner.Headers;

interface

uses
  Winapi.Windows,
  System.JSON,
  NativeMirror.Core.Types,
  NativeMirror.Scanner.Reports,
  NativeMirror.Scanner.ModuleData;

type
  TNativeMirrorHeadersScanReport = class(TNativeMirrorModuleScanReport)
  private
    FDosHeaderModified: Boolean;
    FFileHeaderModified: Boolean;
    FNtHeaderModified: Boolean;
    FSectionHeadersModified: Boolean;
    FEntryPointModified: Boolean;
    FArchitectureMismatch: Boolean;
    FIs64Bit: Boolean;
    FIsInPeb: Boolean;
  protected
    procedure AddBaseJson(Json: TJSONObject); override;
  public
    function ReportType: TNativeMirrorScanReportType; override;
    function IsHeaderReplaced: Boolean;
    property DosHeaderModified: Boolean read FDosHeaderModified write FDosHeaderModified;
    property FileHeaderModified: Boolean read FFileHeaderModified write FFileHeaderModified;
    property NtHeaderModified: Boolean read FNtHeaderModified write FNtHeaderModified;
    property SectionHeadersModified: Boolean read FSectionHeadersModified write FSectionHeadersModified;
    property EntryPointModified: Boolean read FEntryPointModified write FEntryPointModified;
    property ArchitectureMismatch: Boolean read FArchitectureMismatch write FArchitectureMismatch;
    property Is64Bit: Boolean read FIs64Bit write FIs64Bit;
    property IsInPeb: Boolean read FIsInPeb write FIsInPeb;
  end;

  TNativeMirrorHeadersScanner = class
  private
    FModuleData: TNativeMirrorModuleData;
    FRemoteData: TNativeMirrorRemoteModuleData;
    function ZeroUnusedFields(Buffer: PByte; HeaderSize: NativeUInt): Boolean;
    function IsSectionHeaderModified(Buffer1, Buffer2: PByte; HeaderSize: NativeUInt): Boolean;
    function IsDosHeaderModified(Buffer1, Buffer2: PByte; HeaderSize: NativeUInt): Boolean;
    function IsFileHeaderModified(Buffer1, Buffer2: PByte; HeaderSize: NativeUInt; MaskArchitectureMismatch: Boolean = False): Boolean;
    function IsNtHeaderModified(Buffer1, Buffer2: PByte; HeaderSize: NativeUInt): Boolean;
  public
    constructor Create(ModuleData: TNativeMirrorModuleData; RemoteData: TNativeMirrorRemoteModuleData);
    function ScanRemote: TNativeMirrorHeadersScanReport;
  end;

implementation

uses
  System.SysUtils,
  NativePe.Types,
  NativePe.PeHdrsHelper;

procedure TNativeMirrorHeadersScanReport.AddBaseJson(Json: TJSONObject);
begin
  inherited;
  Json.AddPair('is_connected_to_peb', TJSONNumber.Create(Ord(FIsInPeb)));
  Json.AddPair('is_pe_replaced', TJSONNumber.Create(Ord(IsHeaderReplaced)));
  Json.AddPair('dos_hdr_modified', TJSONNumber.Create(Ord(FDosHeaderModified)));
  Json.AddPair('file_hdr_modified', TJSONNumber.Create(Ord(FFileHeaderModified)));
  Json.AddPair('nt_hdr_modified', TJSONNumber.Create(Ord(FNtHeaderModified)));
  Json.AddPair('ep_modified', TJSONNumber.Create(Ord(FEntryPointModified)));
  Json.AddPair('sec_hdr_modified', TJSONNumber.Create(Ord(FSectionHeadersModified)));
  if FArchitectureMismatch then
  begin
    Json.AddPair('arch_mismatch', TJSONNumber.Create(Ord(True)));
    Json.AddPair('is64b', TJSONNumber.Create(Ord(FIs64Bit)));
  end;
end;

function TNativeMirrorHeadersScanReport.ReportType: TNativeMirrorScanReportType;
begin
  Result := nmReportHeadersScan;
end;

function TNativeMirrorHeadersScanReport.IsHeaderReplaced: Boolean;
begin
  Result := FSectionHeadersModified;
end;

constructor TNativeMirrorHeadersScanner.Create(ModuleData: TNativeMirrorModuleData; RemoteData: TNativeMirrorRemoteModuleData);
begin
  inherited Create;
  FModuleData := ModuleData;
  FRemoteData := RemoteData;
end;

function TNativeMirrorHeadersScanner.ZeroUnusedFields(Buffer: PByte; HeaderSize: NativeUInt): Boolean;
var
  I: NativeUInt;
  Count: NativeUInt;
  Sec: NativePe.Types.PImageSectionHeader;
begin
  Result := False;
  Count := GetSectionsCount(Buffer, HeaderSize);
  if Count = 0 then
    Exit;
  for I := 0 to Count - 1 do
  begin
    Sec := GetSectionHdr(Buffer, HeaderSize, I);
    if (Sec <> nil) and (Sec.SizeOfRawData = 0) then
    begin
      Sec.PointerToRawData := 0;
      Result := True;
    end;
  end;
end;

function TNativeMirrorHeadersScanner.IsDosHeaderModified(Buffer1, Buffer2: PByte; HeaderSize: NativeUInt): Boolean;
var
  H1: NativePe.Types.PImageDosHeader;
  H2: NativePe.Types.PImageDosHeader;
  NewHeader: NativeUInt;
begin
  Result := False;
  if HeaderSize < SizeOf(NativePe.Types.TImageDosHeader) then
    Exit;
  H1 := NativePe.Types.PImageDosHeader(Buffer1);
  H2 := NativePe.Types.PImageDosHeader(Buffer2);
  if not CompareMem(H1, H2, SizeOf(NativePe.Types.TImageDosHeader)) then
    Exit(True);
  if H2.e_lfanew < 0 then
    Exit(True);
  NewHeader := NativeUInt(H2.e_lfanew);
  if NewHeader > HeaderSize then
    Exit(True);
  if not CompareMem(H1, H2, NewHeader) then
    Result := True;
end;

function TNativeMirrorHeadersScanner.IsSectionHeaderModified(Buffer1, Buffer2: PByte; HeaderSize: NativeUInt): Boolean;
var
  I: NativeUInt;
  Count1: NativeUInt;
  Count2: NativeUInt;
  S1: NativePe.Types.PImageSectionHeader;
  S2: NativePe.Types.PImageSectionHeader;
begin
  Count1 := GetSectionsCount(Buffer1, HeaderSize);
  Count2 := GetSectionsCount(Buffer2, HeaderSize);
  if Count1 <> Count2 then
    Exit(True);
  if Count1 = 0 then
    Exit(False);
  for I := 0 to Count1 - 1 do
  begin
    S1 := GetSectionHdr(Buffer1, HeaderSize, I);
    S2 := GetSectionHdr(Buffer2, HeaderSize, I);
    if (S1 = nil) and (S2 = nil) then
      Continue;
    if (S1 = nil) or (S2 = nil) then
      Exit(True);
    if (S1.VirtualAddress <> S2.VirtualAddress) or (S1.Misc.VirtualSize <> S2.Misc.VirtualSize) or (S1.PointerToRawData <> S2.PointerToRawData) then
      Exit(True);
  end;
  Result := False;
end;

function TNativeMirrorHeadersScanner.IsFileHeaderModified(Buffer1, Buffer2: PByte; HeaderSize: NativeUInt; MaskArchitectureMismatch: Boolean): Boolean;
var
  H1: NativePe.Types.PImageFileHeader;
  H2: NativePe.Types.PImageFileHeader;
begin
  H1 := GetFileHdr(Buffer1, HeaderSize);
  H2 := GetFileHdr(Buffer2, HeaderSize);
  if (H1 = nil) and (H2 = nil) then
    Exit(False);
  if (H1 = nil) or (H2 = nil) then
    Exit(True);
  if CompareMem(H1, H2, SizeOf(NativePe.Types.TImageFileHeader)) then
    Exit(False);
  if MaskArchitectureMismatch and (H1.Machine = H2.Machine) and (H1.Characteristics = H2.Characteristics) and (H1.NumberOfSections = H2.NumberOfSections) and (H1.TimeDateStamp = H2.TimeDateStamp) and (H1.SizeOfOptionalHeader <> H2.SizeOfOptionalHeader) then
    Exit(False);
  Result := True;
end;

function TNativeMirrorHeadersScanner.IsNtHeaderModified(Buffer1, Buffer2: PByte; HeaderSize: NativeUInt): Boolean;
var
  Is64: Boolean;
  H1: PByte;
  H2: PByte;
  NtSize: NativeUInt;
begin
  Is64 := NativePe.PeHdrsHelper.Is64Bit(Buffer1);
  if NativePe.PeHdrsHelper.Is64Bit(Buffer2) <> Is64 then
    Exit(True);
  H1 := GetNtHdrs(Buffer1, HeaderSize);
  H2 := GetNtHdrs(Buffer2, HeaderSize);
  if (H1 = nil) and (H2 = nil) then
    Exit(False);
  if (H1 = nil) or (H2 = nil) then
    Exit(True);
  if Is64 then
    NtSize := SizeOf(NativePe.Types.TImageNtHeaders64)
  else
    NtSize := SizeOf(NativePe.Types.TImageNtHeaders32);
  Result := not CompareMem(H1, H2, NtSize);
end;

function TNativeMirrorHeadersScanner.ScanRemote: TNativeMirrorHeadersScanReport;
var
  RemoteHeader: array[0..NM_MAX_HEADER_SIZE - 1] of Byte;
  OriginalHeader: array[0..NM_MAX_HEADER_SIZE - 1] of Byte;
  HeaderSize: NativeUInt;
  Ep1: DWORD;
  Ep2: DWORD;
  Arch1: Word;
  Arch2: Word;
  DotNetFileHeaderModified: Boolean;
begin
  Result := nil;
  if (FModuleData = nil) or (FRemoteData = nil) then
    Exit;
  if (FModuleData.OriginalModule = nil) and not FModuleData.LoadOriginal then
    Exit;
  if not FRemoteData.Initialize then
    Exit;
  Result := TNativeMirrorHeadersScanReport.Create(FModuleData.ModuleBase, FRemoteData.GetModuleSize);
  Result.IsInPeb := FModuleData.IsPebConnected;
  FillChar(RemoteHeader, SizeOf(RemoteHeader), 0);
  FillChar(OriginalHeader, SizeOf(OriginalHeader), 0);
  Move(FRemoteData.HeaderData^, RemoteHeader[0], SizeOf(RemoteHeader));
  Result.Is64Bit := NativePe.PeHdrsHelper.Is64Bit(@RemoteHeader[0]);
  Result.IsDotNetModule := FModuleData.IsDotNet;
  Result.OriginalBase := GetImageBase(FModuleData.OriginalModule);
  Result.RelocBase := FRemoteData.GetHeaderImageBase;
  HeaderSize := GetHdrsSize(@RemoteHeader[0]);
  if HeaderSize > NM_MAX_HEADER_SIZE then
    HeaderSize := NM_MAX_HEADER_SIZE;
  if HeaderSize > FModuleData.OriginalSize then
    HeaderSize := FModuleData.OriginalSize;
  if HeaderSize > 0 then
    Move(FModuleData.OriginalModule^, OriginalHeader[0], HeaderSize);
  Ep1 := GetEntryPointRva(@RemoteHeader[0]);
  Ep2 := GetEntryPointRva(@OriginalHeader[0]);
  Result.EntryPointModified := Ep1 <> Ep2;
  Arch1 := GetNtHdrArchitecture(@RemoteHeader[0]);
  Arch2 := GetNtHdrArchitecture(@OriginalHeader[0]);
  Result.ArchitectureMismatch := Arch1 <> Arch2;
  UpdateImageBase(@RemoteHeader[0], 0);
  UpdateImageBase(@OriginalHeader[0], 0);
  ZeroUnusedFields(@RemoteHeader[0], HeaderSize);
  ZeroUnusedFields(@OriginalHeader[0], HeaderSize);
  if CompareMem(@RemoteHeader[0], @OriginalHeader[0], HeaderSize) then
  begin
    Result.Status := NM_SCAN_NOT_SUSPICIOUS;
    Exit;
  end;
  Result.DosHeaderModified := IsDosHeaderModified(@RemoteHeader[0], @OriginalHeader[0], HeaderSize);
  Result.FileHeaderModified := IsFileHeaderModified(@RemoteHeader[0], @OriginalHeader[0], HeaderSize);
  Result.NtHeaderModified := IsNtHeaderModified(@RemoteHeader[0], @OriginalHeader[0], HeaderSize);
  Result.SectionHeadersModified := IsSectionHeaderModified(@RemoteHeader[0], @OriginalHeader[0], HeaderSize);
  if FModuleData.IsDotNet then
  begin
    DotNetFileHeaderModified := IsFileHeaderModified(@RemoteHeader[0], @OriginalHeader[0], HeaderSize, Result.ArchitectureMismatch);
    if not Result.IsHeaderReplaced and not Result.DosHeaderModified and not DotNetFileHeaderModified and (Result.EntryPointModified or (Result.ArchitectureMismatch and Result.NtHeaderModified)) then
    begin
      Result.Status := NM_SCAN_NOT_SUSPICIOUS;
      Exit;
    end;
  end;
  Result.Status := NM_SCAN_SUSPICIOUS;
end;

end.
