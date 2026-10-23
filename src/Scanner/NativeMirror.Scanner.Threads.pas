{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Scanner.Threads;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.JSON,
  System.Generics.Collections,
  NativeMirror.Core.Types,
  NativeMirror.Scanner.Reports,
  NativeMirror.Scanner.Modules,
  NativeMirror.Platform.Threads,
  NativeMirror.Platform.Symbols,
  NativeMirror.Platform.Syscalls,
  NativePe.ExportsMapper;

const
  NM_THREAD_STATE_UNKNOWN = DWORD($FFFFFFFF);
  NM_THREAD_STATE_WAITING = DWORD(5);

type
  TNativeMirrorThSusIndicator = (
    thiNone,
    thiSusStart,
    thiSusIp,
    thiSusRet,
    thiSusCallstackShc,
    thiSusCallsIntegrity,
    thiSusCallstackCorrupt
  );

  TNativeMirrorCtxDetails = record
    Is64Bit: Boolean;
    Rip, Rsp, Rbp: UInt64;
    LastRet: UInt64;
    RetOnStack: UInt64;
    IsRetAsSyscall: Boolean;
    IsRetInFrame: Boolean;
    IsManaged: Boolean;
    CallStack: TArray<UInt64>;
    procedure Init(AIs64Bit: Boolean; ARip, ARsp, ARbp: UInt64);
  end;

  TNativeMirrorSuspAddrReport = class
  public
    ModuleBase: UInt64;
    ModuleSize: NativeUInt;
    SuspAddresses: TDictionary<UInt64, Byte>;
    AllocProtection: DWORD;
    CurrProtection: DWORD;
    IsCode: Boolean;
    Entropy: Double;
    StatsStart: NativeUInt;
    StatsSize: NativeUInt;
    constructor Create(ABase: UInt64; ASize: NativeUInt; AAllocProtect: DWORD);
    destructor Destroy; override;
    procedure AddSuspAddr(Addr: UInt64);
    procedure AddBaseJson(Json: TJSONObject; const Level: TNativeMirrorJsonLevel);
  end;

  TNativeMirrorThreadScanReport = class(TNativeMirrorModuleScanReport)
  private
    FSuspAreaReports: TObjectDictionary<UInt64, TNativeMirrorSuspAddrReport>;
    function CallstackToJson(const Details: TNativeMirrorCtxDetails; Level: TNativeMirrorJsonLevel): TJSONObject;
    function ThreadInfoToJson(Level: TNativeMirrorJsonLevel): TJSONObject;
  public
    Tid: DWORD;
    StackPtr: UInt64;
    ThreadState: DWORD;
    ThreadWaitReason: DWORD;
    ThreadWaitTime: DWORD;
    LastSyscall: string;
    LastFunction: string;
    CDetails: TNativeMirrorCtxDetails;
    HasNativeWow64Context: Boolean;
    NativeWow64Details: TNativeMirrorCtxDetails;
    AddrToSymbol: TDictionary<UInt64, string>;
    ShcCandidates: TDictionary<UInt64, Byte>;
    Indicators: TDictionary<TNativeMirrorThSusIndicator, Byte>;
    constructor Create(ATid: DWORD);
    destructor Destroy; override;
    function ReportType: TNativeMirrorScanReportType; override;
    function ToJson(Level: TNativeMirrorJsonLevel = nmJsonBasic): TJSONObject; override;
    function FindAreaForAddr(SuspAddr: UInt64): TNativeMirrorSuspAddrReport;
    property SuspAreaReports: TObjectDictionary<UInt64, TNativeMirrorSuspAddrReport>
      read FSuspAreaReports;
    class function TranslateThreadState(State: DWORD): string; static;
    class function TranslateWaitReason(Reason: DWORD): string; static;
    class function IndicatorToStr(Indicator: TNativeMirrorThSusIndicator): string; static;
  end;

  TNativeMirrorThreadScanner = class
  private
    FProcessHandle: THandle;
    FIsReflection: Boolean;
    FIsManaged: Boolean;
    FInfo: TNativeMirrorThreadInfo;
    FModulesInfo: TNativeMirrorModulesInfo;
    FExportsMap: TExportsMapper;
    FSymbols: TNativeMirrorSymbolsManager;
    function IsAddrInNamedModule(Addr: UInt64): Boolean;
    function ResolveLowLevelFuncName(Addr: UInt64; Displacement: PNativeUInt = nil): string;
    function ResolveAddrToString(Addr: UInt64): string;
    function FillCallStackInfo(hThread: THandle; CtxPtr: Pointer;
      var Details: TNativeMirrorCtxDetails): NativeUInt;
    function FetchNativeThreadCtxDetails(hProcess, hThread: THandle;
      var Details: TNativeMirrorCtxDetails): Boolean;
  {$IFDEF WIN64}
    function FetchWow64ThreadCtxDetails(hProcess, hThread: THandle;
      var Details: TNativeMirrorCtxDetails): Boolean;
  {$ENDIF}
    function FetchThreadCtxDetails(hProcess, hThread: THandle;
      Report: TNativeMirrorThreadScanReport): Boolean;
    procedure AnalyzeCallStackCore(var Details: TNativeMirrorCtxDetails;
      ShcCandidates: TDictionary<UInt64, Byte>);
    function AnalyzeCallStackInfo(Report: TNativeMirrorThreadScanReport): NativeUInt;
    function CheckReturnAddrIntegrity(const CallStack: TArray<UInt64>;
      Report: TNativeMirrorThreadScanReport): Boolean;
    function FillAreaStats(AreaReport: TNativeMirrorSuspAddrReport): Boolean;
    function ReportSuspiciousAddr(Report: TNativeMirrorThreadScanReport;
      SuspAddr: UInt64): Boolean;
    function FilterDotNet(Report: TNativeMirrorThreadScanReport): Boolean;
    function AssessIndicators(Report: TNativeMirrorThreadScanReport): Boolean;
    procedure InitReport(Report: TNativeMirrorThreadScanReport);
    procedure ReportResolvedCallstack(Report: TNativeMirrorThreadScanReport);
    function ScanRemoteThreadCtx(hThread: THandle;
      Report: TNativeMirrorThreadScanReport): Boolean;
    class function ChoosePreferredFuncName(const DbgSym, ManualSym: string): string; static;
    class function ShouldScanContext(const Info: TNativeMirrorThreadInfo): Boolean; static;
  public
    constructor Create(ProcessHandle: THandle; IsReflection, IsManaged: Boolean;
      const Info: TNativeMirrorThreadInfo; ModulesInfo: TNativeMirrorModulesInfo;
      ExportsMap: TExportsMapper; Symbols: TNativeMirrorSymbolsManager);
    function ScanRemote: TNativeMirrorThreadScanReport;
  end;

implementation

uses
  System.Math,
  NativeMirror.Core.Memory,
  NativeMirror.Platform.Process,
  NativeMirror.Scanner.MemPage,
  NativeMirror.Scanner.Patterns,
  NativeMirror.Stats.Core,
  NativePe.ExportedFunc;

const
  ENTROPY_THRESHOLD     = 3.0;
  ENTROPY_ENC_THRESHOLD = 6.0;
  MAX_CALLSTACK_FRAMES  = 128;
  MAX_DISP_SEARCH       = 25;
  NM_ADDR_MODE_FLAT     = DWORD(3);

// KWAIT_REASON values
const
  KWR_Executive        = 0;
  KWR_FreePage         = 1;
  KWR_PageIn           = 2;
  KWR_PoolAllocation   = 3;
  KWR_DelayExecution   = 4;
  KWR_Suspended        = 5;
  KWR_UserRequest      = 6;
  KWR_WrFreePage       = 8;
  KWR_WrPageIn         = 9;
  KWR_WrPoolAllocation = 10;
  KWR_WrDelayExecution = 11;
  KWR_WrSuspended      = 12;
  KWR_WrUserRequest    = 13;
  KWR_WrEventPair      = 14;
  KWR_WrQueue          = 15;
  KWR_WrAlertByThreadId = 37;
  KWR_MaximumWaitReason = 39;
  // KTHREAD_STATE
  KTS_Initialized           = 0;
  KTS_Ready                 = 1;
  KTS_Running               = 2;
  KTS_Standby               = 3;
  KTS_Terminated            = 4;
  KTS_Waiting               = 5;
  KTS_Transition            = 6;
  KTS_DeferredReady         = 7;
  KTS_GateWaitObsolete      = 8;
  KTS_WaitingForProcessInSwap = 9;

function IsThreadRunning(hThread: THandle): Boolean;
var
  ExitCode: DWORD;
begin
  Result := True;
  if GetExitCodeThread(hThread, ExitCode) then
    Result := ExitCode = STILL_ACTIVE;
end;

function GetPageDetails(ProcessHandle: THandle; StartVA: UInt64;
  out PageInfo: TMemoryBasicInformation): Boolean;
var
  OutSize: SIZE_T;
begin
  OutSize := VirtualQueryEx(ProcessHandle, Pointer(NativeUInt(StartVA)),
    PageInfo, SizeOf(TMemoryBasicInformation));
  Result := OutSize = SizeOf(TMemoryBasicInformation);
end;

{ TNativeMirrorCtxDetails }

procedure TNativeMirrorCtxDetails.Init(AIs64Bit: Boolean; ARip, ARsp, ARbp: UInt64);
begin
  Is64Bit := AIs64Bit;
  Rip := ARip;
  Rsp := ARsp;
  Rbp := ARbp;
  LastRet := 0;
  RetOnStack := 0;
  IsRetAsSyscall := True;
  IsRetInFrame := True;
  IsManaged := False;
  SetLength(CallStack, 0);
end;

{ TNativeMirrorSuspAddrReport }

constructor TNativeMirrorSuspAddrReport.Create(ABase: UInt64; ASize: NativeUInt;
  AAllocProtect: DWORD);
begin
  inherited Create;
  ModuleBase := ABase;
  ModuleSize := ASize;
  AllocProtection := AAllocProtect;
  CurrProtection := 0;
  IsCode := False;
  Entropy := 0;
  StatsStart := 0;
  StatsSize := 0;
  SuspAddresses := TDictionary<UInt64, Byte>.Create;
end;

destructor TNativeMirrorSuspAddrReport.Destroy;
begin
  SuspAddresses.Free;
  inherited;
end;

procedure TNativeMirrorSuspAddrReport.AddSuspAddr(Addr: UInt64);
begin
  if not SuspAddresses.ContainsKey(Addr) then
    SuspAddresses.Add(Addr, 1);
end;

procedure TNativeMirrorSuspAddrReport.AddBaseJson(Json: TJSONObject;
  const Level: TNativeMirrorJsonLevel);
var
  AddrArr: TJSONArray;
  Addr: UInt64;
  StatsJson: TJSONObject;
  AddrName: string;
  Addresses: TList<UInt64>;
begin
  if SuspAddresses.Count > 0 then
  begin
    if (ModuleBase <> 0) and (ModuleSize <> 0) then AddrName := 'susp_addr' else AddrName := 'susp_return_addr';
    AddrArr := TJSONArray.Create;
    Json.AddPair(AddrName, AddrArr);
    Addresses := TList<UInt64>.Create;
    try
      for Addr in SuspAddresses.Keys do if Addr <> 0 then Addresses.Add(Addr);
      Addresses.Sort;
      for Addr in Addresses do AddrArr.Add(IntToHex(Addr, 1).ToLower);
    finally
      Addresses.Free;
    end;
  end;
  if ModuleBase = 0 then Exit;
  Json.AddPair('module', IntToHex(ModuleBase, 1).ToLower);
  if ModuleSize <> 0 then Json.AddPair('module_size', IntToHex(ModuleSize, 1).ToLower);
  if AllocProtection <> CurrProtection then
  begin
    Json.AddPair('alloc_protection', IntToHex(AllocProtection, 1).ToLower);
    Json.AddPair('curr_protection', IntToHex(CurrProtection, 1).ToLower);
  end
  else
    Json.AddPair('protection', IntToHex(CurrProtection, 1).ToLower);
  if IsCode then Json.AddPair('is_code', '1') else Json.AddPair('is_code', '0');
  if StatsSize <> 0 then
  begin
    StatsJson := TJSONObject.Create;
    Json.AddPair('stats', StatsJson);
    StatsJson.AddPair('area_start', IntToHex(StatsStart, 1).ToLower);
    StatsJson.AddPair('area_size', IntToHex(StatsSize, 1).ToLower);
    StatsJson.AddPair('entropy', TJSONNumber.Create(FloatToStrF(Entropy, ffGeneral, 6, 0, TFormatSettings.Invariant)));
  end;
end;

{ TNativeMirrorThreadScanReport }

constructor TNativeMirrorThreadScanReport.Create(ATid: DWORD);
begin
  inherited Create(0, 0);
  Tid := ATid;
  StackPtr := 0;
  ThreadState := NM_THREAD_STATE_UNKNOWN;
  ThreadWaitReason := 0;
  ThreadWaitTime := 0;
  HasNativeWow64Context := False;
  FSuspAreaReports := TObjectDictionary<UInt64, TNativeMirrorSuspAddrReport>.Create([doOwnsValues]);
  AddrToSymbol := TDictionary<UInt64, string>.Create;
  ShcCandidates := TDictionary<UInt64, Byte>.Create;
  Indicators := TDictionary<TNativeMirrorThSusIndicator, Byte>.Create;
end;

destructor TNativeMirrorThreadScanReport.Destroy;
begin
  FSuspAreaReports.Free;
  AddrToSymbol.Free;
  ShcCandidates.Free;
  Indicators.Free;
  inherited;
end;

function TNativeMirrorThreadScanReport.ReportType: TNativeMirrorScanReportType;
begin
  Result := nmReportThreadsScan;
end;

function TNativeMirrorThreadScanReport.FindAreaForAddr(
  SuspAddr: UInt64): TNativeMirrorSuspAddrReport;
var
  Rep: TNativeMirrorSuspAddrReport;
begin
  if FSuspAreaReports.TryGetValue(SuspAddr, Result) then Exit;
  for Rep in FSuspAreaReports.Values do
  begin
    if (SuspAddr >= Rep.ModuleBase)
      and (SuspAddr < Rep.ModuleBase + Rep.ModuleSize) then
      Exit(Rep);
  end;
  Result := nil;
end;

function TNativeMirrorThreadScanReport.CallstackToJson(
  const Details: TNativeMirrorCtxDetails; Level: TNativeMirrorJsonLevel): TJSONObject;
var
  Frames: TJSONArray;
  I: Integer;
  Addr: UInt64;
  Value, SymbolName: string;
  PrintFrames: Boolean;
begin
  Result := TJSONObject.Create;
  try
    Result.AddPair('stack_ptr', IntToHex(Details.Rsp, 1).ToLower);
    if Length(Details.CallStack) = 0 then Exit;
    Result.AddPair('frames_count', TJSONNumber.Create(Length(Details.CallStack)));
    PrintFrames := (Level >= nmJsonDetails) or Indicators.ContainsKey(thiSusCallstackCorrupt) or Indicators.ContainsKey(thiSusCallstackShc);
    if not PrintFrames then Exit;
    Frames := TJSONArray.Create;
    Result.AddPair('frames', Frames);
    for I := High(Details.CallStack) downto 0 do
    begin
      Addr := Details.CallStack[I];
      Value := IntToHex(Addr, 1).ToLower;
      if AddrToSymbol.TryGetValue(Addr, SymbolName) and (SymbolName <> '') then Value := Value + ';' + SymbolName;
      Frames.Add(Value);
    end;
  except
    Result.Free;
    raise;
  end;
end;

function TNativeMirrorThreadScanReport.ThreadInfoToJson(
  Level: TNativeMirrorJsonLevel): TJSONObject;
var
  ShowLastCall: Boolean;
begin
  Result := TJSONObject.Create;
  try
    if ThreadState = NM_THREAD_STATE_UNKNOWN then Result.AddPair('state', 'UNKNOWN') else Result.AddPair('state', TranslateThreadState(ThreadState));
    if ThreadState = NM_THREAD_STATE_WAITING then Result.AddPair('wait_reason', TranslateWaitReason(ThreadWaitReason));
    if StackPtr <> 0 then Result.AddPair('callstack', CallstackToJson(CDetails, Level));
    if HasNativeWow64Context and (NativeWow64Details.Rsp <> 0) then Result.AddPair('native_callstack', CallstackToJson(NativeWow64Details, Level));
    ShowLastCall := (Level >= nmJsonDetails) or Indicators.ContainsKey(thiSusCallsIntegrity) or Indicators.ContainsKey(thiSusCallstackCorrupt);
    if ShowLastCall then
    begin
      if LastSyscall <> '' then Result.AddPair('last_sysc', LastSyscall);
      if (LastFunction <> '') and (LastFunction <> LastSyscall) then Result.AddPair('last_func', LastFunction);
    end;
  except
    Result.Free;
    raise;
  end;
end;

function TNativeMirrorThreadScanReport.ToJson(Level: TNativeMirrorJsonLevel): TJSONObject;
var
  Details, ThreadInfo, AreaJson: TJSONObject;
  IndicatorArr, AreaArr: TJSONArray;
  Ind: TNativeMirrorThSusIndicator;
  Bases: TList<UInt64>;
  Base: UInt64;
  AreaRep: TNativeMirrorSuspAddrReport;
begin
  Result := TJSONObject.Create;
  try
    Details := TJSONObject.Create;
    Result.AddPair('thread_scan', Details);
    Details.AddPair('status', TJSONNumber.Create(Status));
    Details.AddPair('thread_id', TJSONNumber.Create(Tid));
    ThreadInfo := ThreadInfoToJson(Level);
    Details.AddPair('thread_info', ThreadInfo);
    IndicatorArr := TJSONArray.Create;
    Details.AddPair('indicators', IndicatorArr);
    for Ind := Low(TNativeMirrorThSusIndicator) to High(TNativeMirrorThSusIndicator) do
      if Indicators.ContainsKey(Ind) then IndicatorArr.Add(IndicatorToStr(Ind));
    if FSuspAreaReports.Count <> 0 then
    begin
      Bases := TList<UInt64>.Create;
      try
        for Base in FSuspAreaReports.Keys do Bases.Add(Base);
        Bases.Sort;
        AreaArr := TJSONArray.Create;
        Details.AddPair('susp_areas', AreaArr);
        for Base in Bases do
          if FSuspAreaReports.TryGetValue(Base, AreaRep) and (AreaRep <> nil) then
          begin
            AreaJson := TJSONObject.Create;
            AreaArr.AddElement(AreaJson);
            AreaRep.AddBaseJson(AreaJson, Level);
          end;
      finally
        Bases.Free;
      end;
    end;
  except
    Result.Free;
    raise;
  end;
end;

class function TNativeMirrorThreadScanReport.TranslateThreadState(State: DWORD): string;
begin
  case State of
    KTS_Initialized:          Result := 'Initialized';
    KTS_Ready:                Result := 'Ready';
    KTS_Running:              Result := 'Running';
    KTS_Standby:              Result := 'Standby';
    KTS_Terminated:           Result := 'Terminated';
    KTS_Waiting:              Result := 'Waiting';
    KTS_Transition:           Result := 'Transition';
    KTS_DeferredReady:        Result := 'DeferredReady';
    KTS_GateWaitObsolete:     Result := 'GateWaitObsolete';
    KTS_WaitingForProcessInSwap: Result := 'WaitingForProcessInSwap';
    NM_THREAD_STATE_UNKNOWN:  Result := 'UNKNOWN';
  else
    Result := Format('Other: %d', [State]);
  end;
end;

class function TNativeMirrorThreadScanReport.TranslateWaitReason(Reason: DWORD): string;
begin
  case Reason of
    KWR_DelayExecution:   Result := 'DelayExecution';
    KWR_Suspended:        Result := 'Suspended';
    KWR_Executive:        Result := 'Executive';
    KWR_UserRequest:      Result := 'UserRequest';
    KWR_WrUserRequest:    Result := 'WrUserRequest';
    KWR_WrEventPair:      Result := 'WrEventPair';
    KWR_WrQueue:          Result := 'WrQueue';
    KWR_WrAlertByThreadId:Result := 'WrAlertByThreadId';
  else
    Result := Format('Other: %d', [Reason]);
  end;
end;

class function TNativeMirrorThreadScanReport.IndicatorToStr(
  Indicator: TNativeMirrorThSusIndicator): string;
begin
  case Indicator of
    thiNone:                   Result := 'NONE';
    thiSusStart:               Result := 'SUS_START';
    thiSusIp:                  Result := 'SUS_IP';
    thiSusRet:                 Result := 'SUS_RET';
    thiSusCallstackShc:        Result := 'SUS_CALLSTACK_SHC';
    thiSusCallsIntegrity:      Result := 'SUS_CALLS_INTEGRITY';
    thiSusCallstackCorrupt:    Result := 'SUS_CALLSTACK_CORRUPT';
  else
    Result := '';
  end;
end;

{ TNativeMirrorThreadScanner }

constructor TNativeMirrorThreadScanner.Create(ProcessHandle: THandle;
  IsReflection, IsManaged: Boolean; const Info: TNativeMirrorThreadInfo;
  ModulesInfo: TNativeMirrorModulesInfo; ExportsMap: TExportsMapper;
  Symbols: TNativeMirrorSymbolsManager);
begin
  inherited Create;
  FProcessHandle := ProcessHandle;
  FIsReflection := IsReflection;
  FIsManaged := IsManaged;
  FInfo := Info;
  FModulesInfo := ModulesInfo;
  FExportsMap := ExportsMap;
  FSymbols := Symbols;
end;

function TNativeMirrorThreadScanner.IsAddrInNamedModule(Addr: UInt64): Boolean;
var
  ModuleInfo: TNativeMirrorScannedModule;
begin
  ModuleInfo := FModulesInfo.FindModuleContaining(Addr);
  if ModuleInfo = nil then Exit(False);
  Result := ModuleInfo.ModuleName <> '';
end;

function TNativeMirrorThreadScanner.ResolveLowLevelFuncName(Addr: UInt64;
  Displacement: PNativeUInt): string;
var
  ModuleInfo: TNativeMirrorScannedModule;
  Disp, Va: NativeUInt;
  ExpSet: TExportedFuncSet;
  ExpPair: TPair<string, TExportedFunc>;
  ExpName: string;
begin
  Result := '';
  if FExportsMap = nil then Exit;
  ModuleInfo := FModulesInfo.FindModuleContaining(Addr);
  if ModuleInfo = nil then Exit;
  if not TNativeMirrorSyscallTable.IsSyscallDll(ModuleInfo.ModuleName) then Exit;
  Disp := 0;
  ExpName := '';
  while Disp < MAX_DISP_SEARCH do
  begin
    Va := Addr - Disp;
    ExpSet := FExportsMap.FindExportsByVa(Va);
    if ExpSet <> nil then
    begin
      for ExpPair in ExpSet do
      begin
        if not TNativeMirrorSyscallTable.IsSyscallDll(ExpPair.Value.LibName) then Continue;
        ExpName := ExpPair.Value.FuncName;
        if TNativeMirrorSyscallTable.IsSyscallFunc(ExpName) then
        begin
          if Displacement <> nil then Displacement^ := Disp;
          Exit(ExpName);
        end;
      end;
    end;
    Inc(Disp);
  end;
  if Displacement <> nil then Displacement^ := Disp;
  Result := ExpName;
end;

function TNativeMirrorThreadScanner.ResolveAddrToString(Addr: UInt64): string;
var
  ModuleInfo: TNativeMirrorScannedModule;
  FuncName: string;
  Disp: NativeUInt;
begin
  ModuleInfo := FModulesInfo.FindModuleContaining(Addr);
  if ModuleInfo = nil then Exit('');
  Result := ModuleInfo.ModuleName;
  Disp := 0;
  FuncName := '';
  if (FSymbols <> nil) and FSymbols.IsInitialized then
    FuncName := FSymbols.FuncNameFromAddr(Addr, @Disp);
  if FuncName = '' then
    FuncName := ResolveLowLevelFuncName(Addr, @Disp);
  if FuncName <> '' then
  begin
    Result := Result + '!' + FuncName;
    if Disp > 0 then
      Result := Result + '+0x' + IntToHex(Disp, 1).ToLower;
  end
  else
    Result := Result + '+0x' + IntToHex(Addr - ModuleInfo.Start, 1).ToLower;
end;

function TNativeMirrorThreadScanner.FillCallStackInfo(hThread: THandle;
  CtxPtr: Pointer; var Details: TNativeMirrorCtxDetails): NativeUInt;
var
  Frame: TNmStackFrame64;
  MachineType: DWORD;
  PrevPc, NextReturn: UInt64;
  FrameCount: NativeUInt;
  CallStack: TArray<UInt64>;
begin
  Result := 0;
  if (CtxPtr = nil) or (FSymbols = nil) or not FSymbols.IsInitialized then Exit;
  if Details.Is64Bit then MachineType := IMAGE_FILE_MACHINE_AMD64
  else MachineType := IMAGE_FILE_MACHINE_I386;
  FillChar(Frame, SizeOf(Frame), 0);
  Frame.AddrPC.Offset := Details.Rip;
  Frame.AddrPC.Mode := NM_ADDR_MODE_FLAT; // AddrModeFlat
  Frame.AddrStack.Offset := Details.Rsp;
  Frame.AddrStack.Mode := NM_ADDR_MODE_FLAT;
  Frame.AddrFrame.Offset := Details.Rbp;
  Frame.AddrFrame.Mode := NM_ADDR_MODE_FLAT;
  PrevPc := 0;
  FrameCount := 0;
  SetLength(CallStack, 0);
  while FSymbols.RunStackWalk64(MachineType, hThread, @Frame, CtxPtr) do
  begin
    NextReturn := Frame.AddrPC.Offset;
    if NextReturn = 0 then Break;
    if NextReturn = PrevPc then Break;
    PrevPc := NextReturn;
    Inc(FrameCount);
    if FrameCount > MAX_CALLSTACK_FRAMES then Break;
    SetLength(CallStack, Length(CallStack) + 1);
    CallStack[High(CallStack)] := NextReturn;
  end;
  Details.CallStack := CallStack;
  Result := Length(CallStack);
end;

function TNativeMirrorThreadScanner.FetchNativeThreadCtxDetails(hProcess, hThread: THandle;
  var Details: TNativeMirrorCtxDetails): Boolean;
var
  Ctx: TContext;
  RetAddr64: UInt64;
  RetAddr32: DWORD;
  BytesRead: NativeUInt;
begin
  FillChar(Ctx, SizeOf(Ctx), 0);
  Ctx.ContextFlags := CONTEXT_INTEGER or CONTEXT_CONTROL;
  if not GetThreadContext(hThread, Ctx) then Exit(False);
{$IFDEF WIN64}
  Details.Init(True, Ctx.Rip, Ctx.Rsp, Ctx.Rbp);
  BytesRead := 0;
  if ReadProcessMemory(hProcess, Pointer(NativeUInt(Ctx.Rsp)), @RetAddr64,
    SizeOf(RetAddr64), BytesRead) then
    Details.RetOnStack := RetAddr64;
{$ELSE}
  Details.Init(False, Ctx.Eip, Ctx.Esp, Ctx.Ebp);
  BytesRead := 0;
  if ReadProcessMemory(hProcess, Pointer(NativeUInt(Ctx.Esp)), @RetAddr32,
    SizeOf(RetAddr32), BytesRead) then
    Details.RetOnStack := RetAddr32;
{$ENDIF}
  FillCallStackInfo(hThread, @Ctx, Details);
  Result := True;
end;

{$IFDEF WIN64}
function TNativeMirrorThreadScanner.FetchWow64ThreadCtxDetails(hProcess, hThread: THandle;
  var Details: TNativeMirrorCtxDetails): Boolean;
const
  WOW64_CONTEXT_INTEGER = $00010000 or $00000002;
  WOW64_CONTEXT_CONTROL = $00010000 or $00000001;
type
  TNmWow64Context = packed record
    ContextFlags: DWORD;
    Dr0, Dr1, Dr2, Dr3, Dr6, Dr7: DWORD;
    FloatSave: array[0..111] of Byte;
    SegGs, SegFs, SegEs, SegDs: DWORD;
    Edi, Esi, Ebx, Edx, Ecx, Eax: DWORD;
    Ebp, Eip: DWORD;
    SegCs: DWORD;
    EFlags: DWORD;
    Esp: DWORD;
    SegSs: DWORD;
    ExtendedRegisters: array[0..511] of Byte;
  end;
var
  Ctx: TNmWow64Context;
  RetAddr32: DWORD;
  BytesRead: NativeUInt;
begin
  FillChar(Ctx, SizeOf(Ctx), 0);
  Ctx.ContextFlags := WOW64_CONTEXT_INTEGER or WOW64_CONTEXT_CONTROL;
  if not NativeMirror.Platform.Process.GetWow64ThreadContext(hThread, @Ctx) then Exit(False);
  Details.Init(False, Ctx.Eip, Ctx.Esp, Ctx.Ebp);
  BytesRead := 0;
  if ReadProcessMemory(hProcess, Pointer(NativeUInt(Ctx.Esp)), @RetAddr32, SizeOf(RetAddr32), BytesRead) then Details.RetOnStack := RetAddr32;
  FillCallStackInfo(hThread, @Ctx, Details);
  Result := True;
end;
{$ENDIF}

function TNativeMirrorThreadScanner.FetchThreadCtxDetails(hProcess, hThread: THandle;
  Report: TNativeMirrorThreadScanReport): Boolean;
{$IFDEF WIN64}
var
  IsWow64: BOOL;
  NativeOk, Wow64Ok: Boolean;
{$ENDIF}
begin
{$IFDEF WIN64}
  IsWow64 := False;
  IsWow64Process(hProcess, IsWow64);
  if IsWow64 then
  begin
    NativeOk := FetchNativeThreadCtxDetails(hProcess, hThread, Report.NativeWow64Details);
    Report.HasNativeWow64Context := NativeOk;
    Wow64Ok := FetchWow64ThreadCtxDetails(hProcess, hThread, Report.CDetails);
    if (not Wow64Ok) and NativeOk then
    begin
      Report.CDetails := Report.NativeWow64Details;
      Report.HasNativeWow64Context := False;
    end;
    Exit(Wow64Ok or NativeOk);
  end;
{$ENDIF}
  Result := FetchNativeThreadCtxDetails(hProcess, hThread, Report.CDetails);
end;

procedure TNativeMirrorThreadScanner.AnalyzeCallStackCore(
  var Details: TNativeMirrorCtxDetails; ShcCandidates: TDictionary<UInt64, Byte>);
var
  I: Integer;
  NextReturn: UInt64;
  ModuleInfo: TNativeMirrorScannedModule;
  ModName: string;
  IsShc: Boolean;
begin
  Details.IsManaged := False;
  Details.IsRetInFrame := False;
  for I := High(Details.CallStack) downto 0 do
  begin
    NextReturn := Details.CallStack[I];
    if Details.RetOnStack = NextReturn then Details.IsRetInFrame := True;
    IsShc := False;
    ModuleInfo := FModulesInfo.FindModuleContaining(NextReturn);
    ModName := '';
    if ModuleInfo <> nil then ModName := ModuleInfo.ModuleName;
    if ModName = '' then
    begin
      if not Details.IsManaged then
      begin
        IsShc := True;
        if not ShcCandidates.ContainsKey(NextReturn) then ShcCandidates.Add(NextReturn, 1);
      end;
    end;
    if not IsShc then Details.LastRet := NextReturn;
    if (ModName = 'clr.dll') or (ModName = 'coreclr.dll') then Details.IsManaged := True;
  end;
end;

function TNativeMirrorThreadScanner.CheckReturnAddrIntegrity(
  const CallStack: TArray<UInt64>; Report: TNativeMirrorThreadScanReport): Boolean;
var
  LastCalled: UInt64;
  DbgFuncName, ManualSym, LastFunc, SyscallFuncName: string;
  ModuleInfo: TNativeMirrorScannedModule;
  ModName: string;
  SyscallTable: TNativeMirrorSyscallTable;
  WR: DWORD;
begin
  Result := True;
  if (FInfo.LastSyscall = NM_INVALID_SYSCALL) or (Length(CallStack) = 0) or not FInfo.IsExtended then Exit;
  SyscallTable := GetGlobalSyscallTable;
  if (SyscallTable = nil) or not SyscallTable.IsReady then Exit;
  LastCalled := CallStack[0];
  DbgFuncName := '';
  if (FSymbols <> nil) and FSymbols.IsInitialized then DbgFuncName := FSymbols.FuncNameFromAddr(LastCalled);
  ManualSym := '';
  if FExportsMap <> nil then ManualSym := ResolveLowLevelFuncName(LastCalled);
  if (DbgFuncName = '') and (FExportsMap = nil) then Exit;
  LastFunc := ChoosePreferredFuncName(DbgFuncName, ManualSym);
  Report.LastFunction := LastFunc;
  if FInfo.LastSyscall = 0 then
  begin
    if (FInfo.Ext.WaitReason = KWR_Suspended) and (Length(CallStack) = 1) and (LastFunc = 'RtlUserThreadStart') then Exit(True);
    Exit(False);
  end;
  if FSymbols = nil then Exit(True);
  if LastFunc = '' then Exit(False);
{$IFNDEF WIN64}
  if not IsCurrentWow64 and (LastFunc = 'KiFastSystemCallRet') then Exit(True);
{$ENDIF}
  SyscallFuncName := Report.LastSyscall;
  if SyscallFuncName = '' then Exit(True);
  if TNativeMirrorSyscallTable.IsSameSyscallFunc(SyscallFuncName, LastFunc) then Exit(True);
  ModuleInfo := FModulesInfo.FindModuleContaining(LastCalled);
  ModName := '';
  if ModuleInfo <> nil then ModName := ModuleInfo.ModuleName;
  if SyscallFuncName = 'NtCallbackReturn' then
    if (ModName = 'win32u.dll') or (ModName = 'user32.dll') or (ModName = 'winsrv.dll') then Exit(True);
  if not TNativeMirrorSyscallTable.IsSyscallDll(ModName) then Exit(False);
  WR := FInfo.Ext.WaitReason;
  if (WR = KWR_WrUserRequest) or (WR = KWR_UserRequest) then
  begin
    if SyscallFuncName.StartsWith('NtUser') then
      if LastFunc.StartsWith('NtUser') or LastFunc.StartsWith('NtGdi') then Exit(True);
    if SyscallFuncName.StartsWith('NtGdi') then
      if LastFunc.StartsWith('NtGdi') or LastFunc.StartsWith('NtUser') then Exit(True);
  end;
  if WR = KWR_UserRequest then
  begin
    if SyscallFuncName.StartsWith('NtDxgkGet') and LastFunc.StartsWith('NtWaitFor') then Exit(True);
    if SyscallFuncName.Contains('WaitFor') and LastFunc.Contains('WaitFor') then Exit(True);
    if (SyscallFuncName = 'NtWaitForSingleObject') and (LastFunc.StartsWith('NtQuery') or (LastFunc = 'NtDelayExecution')) then Exit(True);
    if SyscallFuncName.StartsWith('NtUser') and (LastFunc = 'NtWaitForWorkViaWorkerFactory') then Exit(True);
    if SyscallFuncName.StartsWith('NtUserModify') and (LastFunc = 'NtDeviceIoControlFile') then Exit(True);
  end;
  if WR = KWR_WrQueue then
  begin
    if SyscallFuncName.StartsWith('NtWaitFor') and (LastFunc = 'NtWaitForWorkViaWorkerFactory') then Exit(True);
    if SyscallFuncName = 'NtWaitForWorkViaWorkerFactory' then
      if LastFunc.StartsWith('NtWaitFor') or LastFunc.StartsWith('NtUserMsgWaitFor') or LastFunc.StartsWith('NtUserCreate') then Exit(True);
  end;
  if WR = KWR_DelayExecution then
    if (SyscallFuncName = 'NtDelayExecution') and (LastFunc.StartsWith('NtUserMsgWaitFor') or LastFunc.StartsWith('NtWaitFor')) then Exit(True);
  Result := False;
end;

function TNativeMirrorThreadScanner.AnalyzeCallStackInfo(
  Report: TNativeMirrorThreadScanReport): NativeUInt;
var
  CheckCalls: Boolean;
  WR: DWORD;
begin
  AnalyzeCallStackCore(Report.CDetails, Report.ShcCandidates);
  Result := Length(Report.CDetails.CallStack);
  CheckCalls := True;
  if Report.CDetails.IsManaged then CheckCalls := False;
  if FInfo.IsExtended then
  begin
    WR := FInfo.Ext.WaitReason;
    if (WR > KWR_WrQueue) or (WR = KWR_FreePage) or (WR = KWR_PageIn)
      or (WR = KWR_PoolAllocation) or (WR = KWR_WrFreePage) or (WR = KWR_WrPageIn)
      or (WR = KWR_WrPoolAllocation) or (WR = KWR_Suspended) then
      CheckCalls := False;
  end;
  if CheckCalls then
    Report.CDetails.IsRetAsSyscall :=
      CheckReturnAddrIntegrity(Report.CDetails.CallStack, Report);
end;

function TNativeMirrorThreadScanner.FillAreaStats(
  AreaReport: TNativeMirrorSuspAddrReport): Boolean;
var
  Reader: INativeMirrorMemoryReader;
  MemPage: TNativeMirrorMemPageData;
  Stats: TNativeMirrorAreaMultiStats;
  Data: PByte;
  DataSize: NativeUInt;
begin
  Result := False;
  if (AreaReport = nil) or (AreaReport.ModuleSize = 0) then Exit;
  Reader := TNativeMirrorProcessMemoryReader.Create(FProcessHandle, False);
  MemPage := TNativeMirrorMemPageData.Create(Reader, FIsReflection, AreaReport.ModuleBase, AreaReport.ModuleBase + AreaReport.ModuleSize);
  try
    if not MemPage.IsInfoFilled or not MemPage.Load then Exit;
    Data := MemPage.GetLoadedData(True);
    DataSize := MemPage.GetLoadedSize(True);
    if (Data = nil) or (DataSize = 0) then Exit;
    Stats := TNativeMirrorAreaMultiStats.Create;
    try
      Stats.Fill(Data, DataSize, MemPage.GetStartOffset(True), nil);
      if not Stats.IsFilled then Exit;
      AreaReport.StatsStart := Stats.Area.Offset;
      AreaReport.StatsSize := Stats.Area.Size;
      AreaReport.Entropy := Stats.Area.Entropy;
      AreaReport.IsCode := NativeMirror.Scanner.Patterns.IsCode(Data, DataSize);
      Result := True;
    finally
      Stats.Free;
    end;
  finally
    MemPage.Free;
  end;
end;

function TNativeMirrorThreadScanner.ReportSuspiciousAddr(
  Report: TNativeMirrorThreadScanReport; SuspAddr: UInt64): Boolean;
var
  SusRep: TNativeMirrorSuspAddrReport;
  PageInfo: TMemoryBasicInformation;
  Base: UInt64;
begin
  Result := False;
  SusRep := Report.FindAreaForAddr(SuspAddr);
  if SusRep = nil then
  begin
    if not GetPageDetails(FProcessHandle, SuspAddr, PageInfo) then Exit;
    if (PageInfo.State and MEM_COMMIT) = 0 then Exit;
    Base := UInt64(NativeUInt(PageInfo.BaseAddress));
    SusRep := TNativeMirrorSuspAddrReport.Create(Base, PageInfo.RegionSize,
      PageInfo.AllocationProtect);
    SusRep.CurrProtection := PageInfo.Protect;
    Report.SuspAreaReports.Add(Base, SusRep);
    FillAreaStats(SusRep);
  end;
  if SusRep = nil then Exit;
  SusRep.AddSuspAddr(SuspAddr);
  Report.Status := NM_SCAN_SUSPICIOUS;
  Result := True;
end;

function TNativeMirrorThreadScanner.FilterDotNet(
  Report: TNativeMirrorThreadScanReport): Boolean;
var
  Ind: TNativeMirrorThSusIndicator;
  DnetCommon: NativeUInt;
begin
  Result := False;
  if not FIsManaged then Exit;
  DnetCommon := 0;
  for Ind in Report.Indicators.Keys do
    case Ind of
      thiSusCallstackShc, thiSusIp, thiSusStart: Inc(DnetCommon);
    end;
  if DnetCommon = NativeUInt(Report.Indicators.Count) then
  begin
    Report.Status := NM_SCAN_NOT_SUSPICIOUS;
    Result := True;
  end;
end;

function ScoreArea(Area: TNativeMirrorSuspAddrReport): Integer;
begin
  Result := 0;
  if Area.IsCode then Inc(Result, 15);
  if Area.Entropy >= ENTROPY_THRESHOLD then Inc(Result, 10);
  if Area.Entropy >= ENTROPY_ENC_THRESHOLD then Inc(Result, 10);
end;

function TNativeMirrorThreadScanner.AssessIndicators(
  Report: TNativeMirrorThreadScanReport): Boolean;
var
  Area: TNativeMirrorSuspAddrReport;
  BestBase: UInt64;
  BestModuleSize: NativeUInt;
  BestScore: Integer;
  BestEntropy: Double;
  Score: Integer;
  Ind: TNativeMirrorThSusIndicator;
  ValidatedIndicators: TDictionary<TNativeMirrorThSusIndicator, Byte>;
begin
  Result := False;
  if Report.Status = NM_SCAN_NOT_SUSPICIOUS then Exit;
  if FilterDotNet(Report) then Exit(True);
  BestBase := 0;
  BestModuleSize := 0;
  BestScore := 0;
  BestEntropy := 0;
  for Area in Report.SuspAreaReports.Values do
  begin
    Score := ScoreArea(Area);
    if Score = 0 then Continue;
    if (Score > BestScore) or ((Score = BestScore) and ((Area.Entropy > BestEntropy) or
      ((Area.Entropy = BestEntropy) and ((BestBase = 0) or (Area.ModuleBase < BestBase))))) then
    begin
      BestBase := Area.ModuleBase;
      BestModuleSize := Area.ModuleSize;
      BestScore := Score;
      BestEntropy := Area.Entropy;
    end;
  end;
  ValidatedIndicators := TDictionary<TNativeMirrorThSusIndicator, Byte>.Create;
  try
    for Ind in Report.Indicators.Keys do
      case Ind of
        thiSusStart, thiSusIp, thiSusRet, thiSusCallstackShc:
          if BestBase <> 0 then ValidatedIndicators.AddOrSetValue(Ind, 1);
      else
        ValidatedIndicators.AddOrSetValue(Ind, 1);
      end;
    if ValidatedIndicators.Count = 0 then
    begin
      Report.Status := NM_SCAN_NOT_SUSPICIOUS;
      Exit(True);
    end;
    Report.ModuleBase := BestBase;
    Report.ModuleSize := BestModuleSize;
  finally
    ValidatedIndicators.Free;
  end;
  Result := True;
end;

procedure TNativeMirrorThreadScanner.InitReport(Report: TNativeMirrorThreadScanReport);
begin
  if not FInfo.IsExtended then Exit;
  Report.ThreadState := FInfo.Ext.State;
  Report.ThreadWaitReason := FInfo.Ext.WaitReason;
  Report.ThreadWaitTime := FInfo.Ext.WaitTime;
  if FInfo.LastSyscall <> NM_INVALID_SYSCALL then
    Report.LastSyscall := GetGlobalSyscallTable.GetSyscallName(FInfo.LastSyscall);
end;

procedure TNativeMirrorThreadScanner.ReportResolvedCallstack(
  Report: TNativeMirrorThreadScanReport);
var
  Addr: UInt64;
begin
  for Addr in Report.CDetails.CallStack do
    Report.AddrToSymbol.AddOrSetValue(Addr, ResolveAddrToString(Addr));
  for Addr in Report.NativeWow64Details.CallStack do
    Report.AddrToSymbol.AddOrSetValue(Addr, ResolveAddrToString(Addr));
end;

function TNativeMirrorThreadScanner.ScanRemoteThreadCtx(hThread: THandle;
  Report: TNativeMirrorThreadScanReport): Boolean;
var
  Addr: UInt64;
  IsUnnamed: Boolean;
begin
  Result := False;
  if not FetchThreadCtxDetails(FProcessHandle, hThread, Report) then Exit;
  if not IsThreadRunning(hThread) then Exit;
  if AnalyzeCallStackInfo(Report) = 0 then Exit;
  Report.StackPtr := Report.CDetails.Rsp;
  IsUnnamed := not IsAddrInNamedModule(Report.CDetails.Rip);
  if IsUnnamed then
  begin
    Report.Indicators.AddOrSetValue(thiSusIp, 1);
    if ReportSuspiciousAddr(Report, Report.CDetails.Rip) then
      Report.Indicators.AddOrSetValue(thiSusCallstackShc, 1);
  end;
  for Addr in Report.ShcCandidates.Keys do
    if ReportSuspiciousAddr(Report, Addr) then
      Report.Indicators.AddOrSetValue(thiSusCallstackShc, 1);
  if FInfo.IsExtended and (FInfo.Ext.State = KTS_Waiting)
    and (FInfo.Ext.WaitReason <> KWR_Suspended)
    and not Report.CDetails.IsRetInFrame then
  begin
    IsUnnamed := not IsAddrInNamedModule(Report.CDetails.RetOnStack);
    if IsUnnamed then
    begin
      Report.Indicators.AddOrSetValue(thiSusRet, 1);
      if ReportSuspiciousAddr(Report, Report.CDetails.RetOnStack) then
        Report.Indicators.AddOrSetValue(thiSusCallstackShc, 1);
    end;
  end;
  if FInfo.IsExtended and not Report.CDetails.IsManaged
    and not Report.CDetails.IsRetAsSyscall then
  begin
    Report.Indicators.AddOrSetValue(thiSusCallsIntegrity, 1);
    Report.Status := NM_SCAN_SUSPICIOUS;
  end;
  Result := Report.Status = NM_SCAN_SUSPICIOUS;
end;

class function TNativeMirrorThreadScanner.ChoosePreferredFuncName(
  const DbgSym, ManualSym: string): string;
begin
  if DbgSym = '' then Exit(ManualSym);
  if not TNativeMirrorSyscallTable.IsSyscallFunc(DbgSym) then
    if TNativeMirrorSyscallTable.IsSyscallFunc(ManualSym) then
      Exit(ManualSym);
  Result := DbgSym;
end;

class function TNativeMirrorThreadScanner.ShouldScanContext(
  const Info: TNativeMirrorThreadInfo): Boolean;
begin
  if not Info.IsExtended then Exit(True);
  case Info.Ext.State of
    KTS_Ready: Exit(False);
    KTS_Terminated: Exit(False);
    KTS_Waiting: Exit(Info.Ext.WaitReason < KWR_MaximumWaitReason);
  else
    Exit(False);
  end;
end;

function TNativeMirrorThreadScanner.ScanRemote: TNativeMirrorThreadScanReport;
var
  Report: TNativeMirrorThreadScanReport;
  IsUnnamed: Boolean;
  hThread: THandle;
begin
  if GetCurrentThreadId = FInfo.Tid then Exit(nil);
  Report := TNativeMirrorThreadScanReport.Create(FInfo.Tid);
  try
    InitReport(Report);
    IsUnnamed := not IsAddrInNamedModule(FInfo.StartAddr);
    if IsUnnamed then
    begin
      Report.Indicators.AddOrSetValue(thiSusStart, 1);
      if ReportSuspiciousAddr(Report, FInfo.StartAddr) then Report.Indicators.AddOrSetValue(thiSusCallstackShc, 1);
    end;
    if ShouldScanContext(FInfo) then
    begin
      hThread := NativeMirrorOpenThread(NM_THREAD_GET_CONTEXT or NM_THREAD_QUERY_INFORMATION or SYNCHRONIZE, False, FInfo.Tid);
      if hThread <> 0 then
        try
          ScanRemoteThreadCtx(hThread, Report);
        finally
          CloseHandle(hThread);
        end;
    end;
    AssessIndicators(Report);
    ReportResolvedCallstack(Report);
    Result := Report;
  except
    Report.Free;
    raise;
  end;
end;

end.
