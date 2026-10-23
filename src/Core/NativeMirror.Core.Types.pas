{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Core.Types;

interface

uses
  Winapi.Windows;

const
  NATIVE_MIRROR_INVALID_OFFSET = UInt64($FFFFFFFFFFFFFFFF);
  NATIVE_MIRROR_PE_NOT_FOUND = UInt64(0);
  NATIVE_MIRROR_DEFAULT_REBASE = UInt64($10000000);
  NATIVE_MIRROR_MIN_IAT_THUNKS = 2;

  NM_SHOW_NONE = Cardinal(0);
  NM_SHOW_ERRORS = Cardinal(1);
  NM_SHOW_NOT_SUSPICIOUS = Cardinal(2);
  NM_SHOW_SUSPICIOUS = Cardinal(4);
  NM_SHOW_SUSPICIOUS_AND_ERRORS = NM_SHOW_ERRORS or NM_SHOW_SUSPICIOUS;
  NM_SHOW_SUCCESSFUL_ONLY = NM_SHOW_NOT_SUSPICIOUS or NM_SHOW_SUSPICIOUS;
  NM_SHOW_ALL = NM_SHOW_ERRORS or NM_SHOW_NOT_SUSPICIOUS or NM_SHOW_SUSPICIOUS;

  NM_SCAN_ERROR = -1;
  NM_SCAN_NOT_SUSPICIOUS = 0;
  NM_SCAN_SUSPICIOUS = 1;

type
  TNativeMirrorArchitecture = (nmaUnknown, nmaX86, nmaX64);
  TNativeMirrorOutputFilter = (nmOutFull, nmOutNoDumps, nmOutNoDir);
  TNativeMirrorShellcodeMode = (nmShellcodeNone, nmShellcodePatterns, nmShellcodeStats, nmShellcodePatternsOrStats, nmShellcodePatternsAndStats);
  TNativeMirrorObfuscationMode = (nmObfuscationNone, nmObfuscationStrong, nmObfuscationWeak, nmObfuscationAny);
  TNativeMirrorImportRecoveryMode = (nmImportNone, nmImportAuto, nmImportUnerase, nmImportRebuild0, nmImportRebuild1, nmImportRebuild2);
  TNativeMirrorDumpMode = (nmDumpAuto, nmDumpVirtual, nmDumpUnmap, nmDumpRealign);
  TNativeMirrorIatScanMode = (nmIatNone, nmIatCleanSystemFiltered, nmIatAllSystemFiltered, nmIatUnfiltered);
  TNativeMirrorDotNetPolicy = (nmDotNetNone, nmDotNetSkipMapping, nmDotNetSkipShellcode, nmDotNetSkipHooks, nmDotNetSkipAll);
  TNativeMirrorDataScanMode = (nmDataNoScan, nmDataDotNet, nmDataNoDep, nmDataAlways, nmDataInaccessible, nmDataInaccessibleOnly);
  TNativeMirrorJsonLevel = (nmJsonBasic, nmJsonDetails, nmJsonDetails2);
  TNativeMirrorReportOutput = (nmReportNone, nmReportScanned, nmReportDumped, nmReportAll);
  TNativeMirrorScanReportType = (nmReportMappingScan, nmReportHeadersScan, nmReportCodeScan, nmReportMemPageScan, nmReportArtefactScan, nmReportUnreachableScan, nmReportSkippedScan, nmReportIatScan, nmReportThreadsScan, nmReportUnknown);
  TNativeMirrorScanStatus = type Integer;
  TNativeMirrorResultsFilter = type Cardinal;

  TNativeMirrorImportRecoveryFilter = (nmImportFilter0, nmImportFilter1, nmImportFilter2);
  TNativeMirrorImportRecoveryResult = type Integer;
  TNativeMirrorSectionStatus = type Integer;
  TNativeMirrorProcessIntegrity = (nmIntegrityUnknown, nmIntegrityUntrusted, nmIntegrityLow, nmIntegrityMedium, nmIntegrityHigh, nmIntegritySystem, nmIntegrityProtected);

  TNativeMirrorMemoryRegion = record
    BaseAddress: UInt64;
    AllocationBase: UInt64;
    RegionSize: UInt64;
    State: DWORD;
    Protect: DWORD;
    AllocationProtect: DWORD;
    MappingType: DWORD;
  end;

  TPeArtefacts = record
    RegionStart: UInt64;
    PeBaseOffset: UInt64;
    NtFileHeadersOffset: UInt64;
    SectionHeadersOffset: UInt64;
    SectionCount: NativeUInt;
    CalculatedImageSize: NativeUInt;
    IsMzPeFound: Boolean;
    IsDll: Boolean;
    Is64Bit: Boolean;
    procedure Reset;
    function HasNtHeaders: Boolean;
    function HasSectionHeaders: Boolean;
    function PeImageBase: UInt64;
    function DropPeBase(OffsetWithPeBase: UInt64): UInt64;
  end;

  TNativeMirrorProcessSummary = record
    Pid: DWORD;
    IsManaged: Boolean;
    Is64Bit: Boolean;
    IsReflection: Boolean;
    Scanned: DWORD;
    Suspicious: DWORD;
    Replaced: DWORD;
    HeaderModified: DWORD;
    UnreachableFile: DWORD;
    Patched: DWORD;
    IatHooked: DWORD;
    Implanted: DWORD;
    ImplantedPe: DWORD;
    ImplantedShellcode: DWORD;
    Other: DWORD;
    Skipped: DWORD;
    Errors: DWORD;
  end;


const
  nmImportNotFound = TNativeMirrorImportRecoveryResult(-3);
  nmImportRecoveryError = TNativeMirrorImportRecoveryResult(-2);
  nmImportRecoveryNotApplicable = TNativeMirrorImportRecoveryResult(-1);
  nmImportRecoverySkipped = TNativeMirrorImportRecoveryResult(0);
  nmImportAlreadyOk = TNativeMirrorImportRecoveryResult(1);
  nmImportDirectoryFixed = TNativeMirrorImportRecoveryResult(2);
  nmImportFixed = TNativeMirrorImportRecoveryResult(3);
  nmImportRecreatedFilter0 = TNativeMirrorImportRecoveryResult(4);
  nmImportRecreatedFilter1 = TNativeMirrorImportRecoveryResult(5);
  nmImportRecreatedFilter2 = TNativeMirrorImportRecoveryResult(6);

  nmSectionScanError = TNativeMirrorSectionStatus(-1);
  nmSectionNotModified = TNativeMirrorSectionStatus(0);
  nmSectionPatched = TNativeMirrorSectionStatus(1);
  nmSectionUnpacked = TNativeMirrorSectionStatus(2);

function DumpModeName(Mode: TNativeMirrorDumpMode): string;
function ImportRecoveryResultName(Value: TNativeMirrorImportRecoveryResult): string;

implementation

procedure TPeArtefacts.Reset;
begin
  RegionStart := NATIVE_MIRROR_INVALID_OFFSET;
  PeBaseOffset := NATIVE_MIRROR_INVALID_OFFSET;
  NtFileHeadersOffset := NATIVE_MIRROR_INVALID_OFFSET;
  SectionHeadersOffset := NATIVE_MIRROR_INVALID_OFFSET;
  SectionCount := 0;
  CalculatedImageSize := 0;
  IsMzPeFound := False;
  IsDll := True;
  Is64Bit := False;
end;

function TPeArtefacts.HasNtHeaders: Boolean;
begin
  Result := NtFileHeadersOffset <> NATIVE_MIRROR_INVALID_OFFSET;
end;

function TPeArtefacts.HasSectionHeaders: Boolean;
begin
  Result := SectionHeadersOffset <> NATIVE_MIRROR_INVALID_OFFSET;
end;

function TPeArtefacts.PeImageBase: UInt64;
begin
  if PeBaseOffset = NATIVE_MIRROR_INVALID_OFFSET then
    Exit(NATIVE_MIRROR_INVALID_OFFSET);
  Result := RegionStart + PeBaseOffset;
end;

function TPeArtefacts.DropPeBase(OffsetWithPeBase: UInt64): UInt64;
begin
  if (PeBaseOffset = NATIVE_MIRROR_INVALID_OFFSET) or (OffsetWithPeBase = NATIVE_MIRROR_INVALID_OFFSET) or (OffsetWithPeBase < PeBaseOffset) then
    Exit(NATIVE_MIRROR_INVALID_OFFSET);
  Result := OffsetWithPeBase - PeBaseOffset;
end;


function DumpModeName(Mode: TNativeMirrorDumpMode): string;
begin
  case Mode of
    nmDumpVirtual: Result := 'VIRTUAL';
    nmDumpUnmap: Result := 'UNMAPPED';
    nmDumpRealign: Result := 'REALIGNED';
  else
    Result := '';
  end;
end;

function ImportRecoveryResultName(Value: TNativeMirrorImportRecoveryResult): string;
begin
  case Value of
    nmImportNotFound: Result := 'IMP_NOT_FOUND';
    nmImportRecoveryError: Result := 'IMP_RECOVERY_ERROR';
    nmImportRecoveryNotApplicable: Result := 'IMP_RECOVERY_NOT_APPLICABLE';
    nmImportRecoverySkipped: Result := '';
    nmImportAlreadyOk: Result := 'IMP_ALREADY_OK';
    nmImportDirectoryFixed: Result := 'IMP_DIR_FIXED';
    nmImportFixed: Result := 'IMP_FIXED';
    nmImportRecreatedFilter0: Result := 'IMP_RECREATED_FILTER0';
    nmImportRecreatedFilter1: Result := 'IMP_RECREATED_FILTER1';
    nmImportRecreatedFilter2: Result := 'IMP_RECREATED_FILTER2';
  else
    Result := 'Undefined';
  end;
end;

end.
