{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Platform.Threads;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Generics.Collections,
  Winapi.TlHelp32;

const
  NM_INVALID_SYSCALL = DWORD($FFFFFFFF);
  NM_THREAD_GET_CONTEXT = DWORD($0008);
  NM_THREAD_QUERY_INFORMATION = DWORD($0040);

type
  TNativeMirrorThreadInfoExt = record
    SysStartAddr: UInt64;
    State: DWORD;
    WaitReason: DWORD;
    WaitTime: DWORD;
    constructor Create(AState, AWaitReason, AWaitTime: DWORD; ASysStart: UInt64);
  end;

  TNativeMirrorThreadInfo = record
    Tid: DWORD;
    StartAddr: UInt64;
    LastSyscall: DWORD;
    IsExtended: Boolean;
    IsFilled: Boolean;
    Ext: TNativeMirrorThreadInfoExt;
    constructor Create(ATid: DWORD);
  end;

  TNativeMirrorThreadMap = TDictionary<DWORD, TNativeMirrorThreadInfo>;

function FetchThreadsBySnapshot(Pid: DWORD; Threads: TNativeMirrorThreadMap): Boolean;
function FetchThreadsInfo(Pid: DWORD; Threads: TNativeMirrorThreadMap): Boolean;
function QueryThreadsDetails(Threads: TNativeMirrorThreadMap): NativeUInt;
function NativeMirrorOpenThread(dwDesiredAccess: DWORD; bInheritHandle: BOOL; dwThreadId: DWORD): THandle; stdcall; external 'kernel32.dll' name 'OpenThread';

implementation

type
  TNtQueryInformationThread = function(
    ThreadHandle: THandle;
    ThreadInformationClass: DWORD;
    ThreadInformation: Pointer;
    ThreadInformationLength: ULONG;
    ReturnLength: PULONG): LONG; stdcall;

  TNtQuerySystemInformation = function(
    SystemInformationClass: DWORD;
    SystemInformation: Pointer;
    SystemInformationLength: ULONG;
    ReturnLength: PULONG): LONG; stdcall;

  TThreadLastSyscallInfo = record
    FirstArgument: Pointer;
    SystemCallNumber: WORD;
  end;

{$IF SizeOf(Pointer) = 8}
  TNmClientId = packed record
    UniqueProcess: UInt64;
    UniqueThread: UInt64;
  end;
  TNmSystemThreadInfo = packed record
    KernelTime: Int64;
    UserTime: Int64;
    CreateTime: Int64;
    WaitTime: ULONG;
    Padding1: ULONG;
    StartAddress: UInt64;
    ClientId: TNmClientId;
    Priority: LONG;
    BasePriority: LONG;
    ContextSwitches: ULONG;
    ThreadState: ULONG;
    WaitReason: ULONG;
    Reserved: ULONG;
  end;
  PNmSystemThreadInfo = ^TNmSystemThreadInfo;
  TNmSystemProcessInfo = packed record
    NextEntryOffset: ULONG;
    NumberOfThreads: ULONG;
    WorkingSetPrivateSize: Int64;
    HardFaultCount: ULONG;
    NumberOfThreadsHighWatermark: ULONG;
    CycleTime: UInt64;
    CreateTime: Int64;
    UserTime: Int64;
    KernelTime: Int64;
    ImageNameLength: USHORT;
    ImageNameMaxLength: USHORT;
    Padding2: DWORD;
    ImageNameBuffer: UInt64;
    BasePriority: LONG;
    Padding3: DWORD;
    UniqueProcessId: UInt64;
    InheritedFromProcessId: UInt64;
    HandleCount: ULONG;
    SessionId: ULONG;
    UniqueProcessKey: UInt64;
    PeakVirtualSize: UInt64;
    VirtualSize: UInt64;
    PageFaultCount: ULONG;
    Padding4: ULONG;
    PeakWorkingSetSize: UInt64;
    WorkingSetSize: UInt64;
    QuotaPeakPagedPool: UInt64;
    QuotaPagedPool: UInt64;
    QuotaPeakNonPaged: UInt64;
    QuotaNonPaged: UInt64;
    PagefileUsage: UInt64;
    PeakPagefileUsage: UInt64;
    PrivatePageCount: UInt64;
    ReadOpCount: Int64;
    WriteOpCount: Int64;
    OtherOpCount: Int64;
    ReadTransfer: Int64;
    WriteTransfer: Int64;
    OtherTransfer: Int64;
  end;
  PNmSystemProcessInfo = ^TNmSystemProcessInfo;
{$ELSE}
  TNmClientId = packed record
    UniqueProcess: DWORD;
    UniqueThread: DWORD;
  end;
  TNmSystemThreadInfo = packed record
    KernelTime: Int64;
    UserTime: Int64;
    CreateTime: Int64;
    WaitTime: ULONG;
    StartAddress: DWORD;
    ClientId: TNmClientId;
    Priority: LONG;
    BasePriority: LONG;
    ContextSwitches: ULONG;
    ThreadState: ULONG;
    WaitReason: ULONG;
    Padding2: ULONG;
  end;
  PNmSystemThreadInfo = ^TNmSystemThreadInfo;
  TNmSystemProcessInfo = packed record
    NextEntryOffset: ULONG;
    NumberOfThreads: ULONG;
    SpareLi: array[0..2] of Int64;
    CreateTime: Int64;
    UserTime: Int64;
    KernelTime: Int64;
    ImageNameLength: USHORT;
    ImageNameMaxLength: USHORT;
    ImageNameBuffer: DWORD;
    BasePriority: LONG;
    UniqueProcessId: DWORD;
    InheritedFromProcessId: DWORD;
    HandleCount: ULONG;
    SessionId: ULONG;
    UniqueProcessKey: DWORD;
    PeakVirtualSize: DWORD;
    VirtualSize: DWORD;
    PageFaultCount: ULONG;
    PeakWorkingSetSize: DWORD;
    WorkingSetSize: DWORD;
    QuotaPeakPagedPool: DWORD;
    QuotaPagedPool: DWORD;
    QuotaPeakNonPaged: DWORD;
    QuotaNonPaged: DWORD;
    PagefileUsage: DWORD;
    PeakPagefileUsage: DWORD;
    PrivatePageCount: DWORD;
    ReadOpCount: Int64;
    WriteOpCount: Int64;
    OtherOpCount: Int64;
    ReadTransfer: Int64;
    WriteTransfer: Int64;
    OtherTransfer: Int64;
  end;
  PNmSystemProcessInfo = ^TNmSystemProcessInfo;
{$ENDIF}

const
  STATUS_SUCCESS             = LONG(0);
  STATUS_INFO_LENGTH_MISMATCH = LONG($C0000004);
  SystemProcessInformation   = DWORD(5);
  ThreadQuerySetWin32StartAddress = DWORD(9);
  ThreadLastSystemCall       = DWORD(21);

var
  GNtQueryInfoThread: TNtQueryInformationThread = nil;
  GNtQuerySysInfo: TNtQuerySystemInformation = nil;

procedure LoadNtApis;
var
  Ntdll: HMODULE;
begin
  if Assigned(GNtQueryInfoThread) and Assigned(GNtQuerySysInfo) then Exit;
  Ntdll := GetModuleHandle('ntdll.dll');
  if Ntdll = 0 then Exit;
  GNtQueryInfoThread := TNtQueryInformationThread(GetProcAddress(Ntdll, 'NtQueryInformationThread'));
  GNtQuerySysInfo := TNtQuerySystemInformation(GetProcAddress(Ntdll, 'NtQuerySystemInformation'));
end;

function QuerySingleThreadDetails(Tid: DWORD; var Info: TNativeMirrorThreadInfo): Boolean;
const
  ThAccess: DWORD = NM_THREAD_QUERY_INFORMATION or NM_THREAD_GET_CONTEXT;
var
  hThread: THandle;
  StartAddr: Pointer;
  SyscallInfo: TThreadLastSyscallInfo;
  RetLen: ULONG;
  Status: LONG;
begin
  Result := False;
  if not Assigned(GNtQueryInfoThread) then Exit;
  hThread := NativeMirrorOpenThread(ThAccess, False, Tid);
  if hThread = 0 then
    hThread := NativeMirrorOpenThread(NM_THREAD_QUERY_INFORMATION, False, Tid);
  if hThread = 0 then Exit;
  try
    StartAddr := nil;
    RetLen := 0;
    Status := GNtQueryInfoThread(hThread, ThreadQuerySetWin32StartAddress,
      @StartAddr, SizeOf(StartAddr), @RetLen);
    if (Status = STATUS_SUCCESS) and (RetLen = SizeOf(StartAddr)) then
    begin
      Info.StartAddr := UInt64(NativeUInt(StartAddr));
      Result := True;
    end;
    FillChar(SyscallInfo, SizeOf(SyscallInfo), 0);
    RetLen := 0;
    Status := GNtQueryInfoThread(hThread, ThreadLastSystemCall,
      @SyscallInfo, SizeOf(SyscallInfo), @RetLen);
    if (Status = STATUS_SUCCESS) and (RetLen >= SizeOf(SyscallInfo)) then
    begin
      Info.LastSyscall := SyscallInfo.SystemCallNumber;
      Result := True;
    end;
    Info.IsFilled := Result;
  finally
    CloseHandle(hThread);
  end;
end;

function FetchThreadsBySnapshot(Pid: DWORD; Threads: TNativeMirrorThreadMap): Boolean;
var
  Snap: THandle;
  Entry: TThreadEntry32;
  Info: TNativeMirrorThreadInfo;
  Tid: DWORD;
begin
  Result := False;
  if Threads = nil then Exit;
  Snap := CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if Snap = INVALID_HANDLE_VALUE then Exit;
  try
    Entry.dwSize := SizeOf(TThreadEntry32);
    if not Thread32First(Snap, Entry) then Exit;
    repeat
      if Entry.th32OwnerProcessID <> Pid then Continue;
      Tid := Entry.th32ThreadID;
      if not Threads.ContainsKey(Tid) then
        Threads.Add(Tid, TNativeMirrorThreadInfo.Create(Tid));
      Result := True;
    until not Thread32Next(Snap, Entry);
  finally
    CloseHandle(Snap);
  end;
end;

function FetchThreadsInfo(Pid: DWORD; Threads: TNativeMirrorThreadMap): Boolean;
var
  Buf: TBytes;
  BufSize, RetLen: ULONG;
  Status: LONG;
  P, BufStart: PByte;
  BufStartAddr, BufEndAddr, CurrentAddr: NativeUInt;
  SpiPtr: PNmSystemProcessInfo;
  StiPtr: PNmSystemThreadInfo;
  ThreadBytes: UInt64;
  I: NativeUInt;
  Tid: DWORD;
  Info: TNativeMirrorThreadInfo;
begin
  Result := False;
  if not Assigned(GNtQuerySysInfo) or (Threads = nil) then Exit;
  BufSize := 64 * 1024;
  while True do
  begin
    SetLength(Buf, BufSize);
    RetLen := 0;
    Status := GNtQuerySysInfo(SystemProcessInformation, @Buf[0], BufSize, @RetLen);
    if Status = STATUS_INFO_LENGTH_MISMATCH then
    begin
      if RetLen > BufSize then
        BufSize := RetLen + 4096
      else if BufSize <= High(ULONG) div 2 then
        BufSize := BufSize * 2
      else
        Exit;
      Continue;
    end;
    Break;
  end;
  if Status <> STATUS_SUCCESS then Exit;
  BufStart := @Buf[0];
  BufStartAddr := NativeUInt(BufStart);
  BufEndAddr := BufStartAddr + NativeUInt(Length(Buf));
  P := BufStart;
  while True do
  begin
    CurrentAddr := NativeUInt(P);
    if (CurrentAddr < BufStartAddr) or (CurrentAddr > BufEndAddr)
      or (BufEndAddr - CurrentAddr < SizeOf(TNmSystemProcessInfo)) then Break;
    SpiPtr := PNmSystemProcessInfo(P);
    if NativeUInt(SpiPtr^.UniqueProcessId) = Pid then
    begin
      if SpiPtr^.NumberOfThreads = 0 then Break;
      ThreadBytes := UInt64(SpiPtr^.NumberOfThreads) * SizeOf(TNmSystemThreadInfo);
      if ThreadBytes > UInt64(BufEndAddr - CurrentAddr - SizeOf(TNmSystemProcessInfo)) then Break;
      StiPtr := PNmSystemThreadInfo(P + SizeOf(TNmSystemProcessInfo));
      I := 0;
      while I < SpiPtr^.NumberOfThreads do
      begin
        Tid := DWORD(StiPtr^.ClientId.UniqueThread);
        if not Threads.ContainsKey(Tid) then
          Threads.Add(Tid, TNativeMirrorThreadInfo.Create(Tid));
        Info := Threads[Tid];
        Info.IsExtended := True;
        Info.Ext.SysStartAddr := UInt64(StiPtr^.StartAddress);
        Info.Ext.State := StiPtr^.ThreadState;
        Info.Ext.WaitReason := StiPtr^.WaitReason;
        Info.Ext.WaitTime := StiPtr^.WaitTime;
        Info.IsFilled := True;
        Threads[Tid] := Info;
        Result := True;
        StiPtr := PNmSystemThreadInfo(PByte(StiPtr) + SizeOf(TNmSystemThreadInfo));
        Inc(I);
      end;
      Break;
    end;
    if SpiPtr^.NextEntryOffset = 0 then Break;
    if SpiPtr^.NextEntryOffset < SizeOf(TNmSystemProcessInfo) then Break;
    if SpiPtr^.NextEntryOffset > BufEndAddr - CurrentAddr then Break;
    CurrentAddr := CurrentAddr + SpiPtr^.NextEntryOffset;
    if CurrentAddr >= BufEndAddr then Break;
    P := PByte(CurrentAddr);
  end;
end;

function QueryThreadsDetails(Threads: TNativeMirrorThreadMap): NativeUInt;
var
  Tid: DWORD;
  Info: TNativeMirrorThreadInfo;
begin
  Result := 0;
  if Threads = nil then Exit;
  for Tid in Threads.Keys do
  begin
    Info := Threads[Tid];
    if QuerySingleThreadDetails(Tid, Info) then
    begin
      Threads[Tid] := Info;
      Inc(Result);
    end;
  end;
end;

{ TNativeMirrorThreadInfoExt }
constructor TNativeMirrorThreadInfoExt.Create(AState, AWaitReason, AWaitTime: DWORD; ASysStart: UInt64);
begin
  SysStartAddr := ASysStart;
  State := AState;
  WaitReason := AWaitReason;
  WaitTime := AWaitTime;
end;

{ TNativeMirrorThreadInfo }
constructor TNativeMirrorThreadInfo.Create(ATid: DWORD);
begin
  Tid := ATid;
  StartAddr := 0;
  LastSyscall := NM_INVALID_SYSCALL;
  IsExtended := False;
  IsFilled := False;
  FillChar(Ext, SizeOf(Ext), 0);
end;

initialization
  LoadNtApis;
end.
