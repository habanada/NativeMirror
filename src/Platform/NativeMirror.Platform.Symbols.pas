{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Platform.Symbols;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  System.Generics.Collections,
  System.SyncObjs;

const
  MAX_SYM_NAME = 2000;
  SYMOPT_CASE_INSENSITIVE         = $00000001;
  SYMOPT_UNDNAME                  = $00000002;
  SYMOPT_DEFERRED_LOADS           = $00000004;
  SYMOPT_FAIL_CRITICAL_ERRORS     = $00000200;
  SYMOPT_AUTO_PUBLICS             = $00010000;
  SYMOPT_INCLUDE_32BIT_MODULES    = $00002000;
  SYMOPT_NO_PROMPTS               = $00080000;
  SYMOPT_DEBUG                    = $80000000;
  SYMOPT_DISABLE_SYMSRV_AUTODETECT = $40000000;
  IMAGE_FILE_MACHINE_AMD64        = $8664;
  IMAGE_FILE_MACHINE_I386         = $014C;

type
  TNmSymbolInfo = record
    SizeOfStruct: ULONG;
    TypeIndex: ULONG;
    Reserved: array[0..1] of UInt64;
    Index: ULONG;
    Size: ULONG;
    ModBase: UInt64;
    Flags: ULONG;
    Value: UInt64;
    Address: UInt64;
    Register_: ULONG;
    Scope: ULONG;
    Tag: ULONG;
    NameLen: ULONG;
    MaxNameLen: ULONG;
    Name: array[0..0] of AnsiChar;
  end;
  PNmSymbolInfo = ^TNmSymbolInfo;

  TNmKdHelp64 = record
    Thread: UInt64;
    ThCallbackStack: DWORD;
    ThCallbackBStore: DWORD;
    NextCallback: DWORD;
    FramePointer: DWORD;
    KiCallUserMode: UInt64;
    KeUserCallbackDispatcher: UInt64;
    SystemRangeStart: UInt64;
    KiUserExceptionDispatcher: UInt64;
    StackBase: UInt64;
    StackLimit: UInt64;
    BuildVersion: DWORD;
    RetpolineStubFunctionTableSize: DWORD;
    RetpolineStubFunctionTable: UInt64;
    RetpolineStubOffset: DWORD;
    RetpolineStubSize: DWORD;
    Reserved0: array[0..1] of UInt64;
  end;

  TNmImageHlpModule64 = record
    SizeOfStruct: DWORD;
    BaseOfImage: UInt64;
    ImageSize: DWORD;
    TimeDateStamp: DWORD;
    CheckSum: DWORD;
    NumSyms: DWORD;
    SymType: DWORD;
    ModuleName: array[0..31] of AnsiChar;
    ImageName: array[0..255] of AnsiChar;
    LoadedImageName: array[0..255] of AnsiChar;
    LoadedPdbName: array[0..255] of AnsiChar;
    CVSig: DWORD;
    CVData: array[0..MAX_PATH - 1] of AnsiChar;
    PdbSig: DWORD;
    PdbSig70: TGUID;
    PdbAge: DWORD;
    PdbUnmatched: BOOL;
    LineNumbers: BOOL;
    GlobalSymbols: BOOL;
    TypeInfo: BOOL;
    SourceIndexed: BOOL;
    Publics: BOOL;
    MachineType: DWORD;
    Reserved: DWORD;
  end;
  PNmImageHlpModule64 = ^TNmImageHlpModule64;

  TNmStackFrame64 = record
    AddrPC: record Offset: UInt64; Segment: WORD; Mode: DWORD; end;
    AddrReturn: record Offset: UInt64; Segment: WORD; Mode: DWORD; end;
    AddrFrame: record Offset: UInt64; Segment: WORD; Mode: DWORD; end;
    AddrStack: record Offset: UInt64; Segment: WORD; Mode: DWORD; end;
    AddrBStore: record Offset: UInt64; Segment: WORD; Mode: DWORD; end;
    FuncTableEntry: Pointer;
    Params: array[0..3] of UInt64;
    Far: BOOL;
    Virtual_: BOOL;
    Reserved: array[0..2] of UInt64;
    KdHelp: TNmKdHelp64;
  end;
  PNmStackFrame64 = ^TNmStackFrame64;

  TReadProcessMemoryRoutine64 = function(hProcess: THandle; qwBaseAddress: UInt64;
    lpBuffer: Pointer; nSize: DWORD; lpsNumberOfBytesRead: PDWORD): BOOL; stdcall;
  TFunctionTableAccessRoutine64 = function(hProcess: THandle;
    AddrBase: UInt64): Pointer; stdcall;
  TGetModuleBaseRoutine64 = function(hProcess: THandle;
    Address: UInt64): UInt64; stdcall;
  TTranslateAddressRoutine64 = function(hProcess, hThread: THandle;
    lpaddr: Pointer): UInt64; stdcall;

type
  TDbgHelpSymInitialize = function(hProcess: THandle; UserSearchPath: PAnsiChar;
    fInvadeProcess: BOOL): BOOL; stdcall;
  TDbgHelpSymCleanup = function(hProcess: THandle): BOOL; stdcall;
  TDbgHelpSymSetOptions = function(SymOptions: DWORD): DWORD; stdcall;
  TDbgHelpSymSetSearchPath = function(hProcess: THandle; SearchPath: PAnsiChar): BOOL; stdcall;
  TDbgHelpSymRefreshModuleList = function(hProcess: THandle): BOOL; stdcall;
  TDbgHelpSymFromAddr = function(hProcess: THandle; Address: UInt64;
    Displacement: PUInt64; Symbol: PNmSymbolInfo): BOOL; stdcall;
  TDbgHelpStackWalk64 = function(MachineType: DWORD; hProcess, hThread: THandle;
    StackFrame: PNmStackFrame64; ContextRecord: Pointer;
    ReadMemoryRoutine: TReadProcessMemoryRoutine64;
    FunctionTableAccess: TFunctionTableAccessRoutine64;
    GetModuleBase: TGetModuleBaseRoutine64;
    TranslateAddress: TTranslateAddressRoutine64): BOOL; stdcall;
  TDbgHelpSymFunctionTableAccess64 = function(hProcess: THandle;
    AddrBase: UInt64): Pointer; stdcall;
  TDbgHelpSymGetModuleBase64 = function(hProcess: THandle;
    dwAddr: UInt64): UInt64; stdcall;

  TNativeMirrorDbgHelpWrapper = class sealed
  private
    class var FLock: TCriticalSection;
    class var FSymInitialize: TDbgHelpSymInitialize;
    class var FSymCleanup: TDbgHelpSymCleanup;
    class var FSymSetOptions: TDbgHelpSymSetOptions;
    class var FSymSetSearchPath: TDbgHelpSymSetSearchPath;
    class var FSymRefreshModuleList: TDbgHelpSymRefreshModuleList;
    class var FSymFromAddr: TDbgHelpSymFromAddr;
    class var FStackWalk64: TDbgHelpStackWalk64;
    class var FSymFunctionTableAccess64: TDbgHelpSymFunctionTableAccess64;
    class var FSymGetModuleBase64: TDbgHelpSymGetModuleBase64;
    class var FLoaded: Boolean;
    class var FSessions: TDictionary<THandle, Integer>;
    class procedure Load; static;
  public
    class constructor Create;
    class destructor Destroy;
    class function IsLoaded: Boolean; static;
    class function InitializeProcess(hProcess: THandle; const SearchPath: string;
      SymOptions: DWORD): Boolean; static;
    class function CleanupProcess(hProcess: THandle): Boolean; static;
    class function RefreshModuleList(hProcess: THandle): Boolean; static;
    class function RunStackWalk64(MachineType: DWORD; hProcess, hThread: THandle;
      StackFrame: PNmStackFrame64; ContextRecord: Pointer): Boolean; static;
    class function FromAddress(hProcess: THandle; Address: UInt64;
      Symbol: PNmSymbolInfo; Displacement: PUInt64): Boolean; static;
    class function GetFunctionTableAccess64: TDbgHelpSymFunctionTableAccess64; static;
    class function GetGetModuleBase64: TDbgHelpSymGetModuleBase64; static;
  end;

  TNativeMirrorSymbolsManager = class
  private
    FProcess: THandle;
    FIsInit: Boolean;
    class function BuildSymOptions(EnableAutoDownload: Boolean; Lazy: Boolean): DWORD; static;
    class function BuildSymbolPath(EnableAutoDownload: Boolean): string; static;
    class function FilterSymbolPath(const Input: string; AllowDownload: Boolean): string; static;
    procedure NormalizeNtZwPrefix(var FuncName: string);
  public
    constructor Create;
    destructor Destroy; override;
    function InitSymbols(hProcess: THandle; EnableAutoDownload, Lazy: Boolean): Boolean;
    function RefreshModules: Boolean;
    function IsInitialized: Boolean;
    function RunStackWalk64(MachineType: DWORD; hThread: THandle;
      StackFrame: PNmStackFrame64; ContextRecord: Pointer): Boolean;
    function FuncNameFromAddr(Addr: UInt64; Displacement: PNativeUInt = nil): string;
  end;

implementation

class constructor TNativeMirrorDbgHelpWrapper.Create;
begin
  FLock := TCriticalSection.Create;
  FSessions := TDictionary<THandle, Integer>.Create;
  FLoaded := False;
  Load;
end;

class destructor TNativeMirrorDbgHelpWrapper.Destroy;
begin
  FSessions.Free;
  FLock.Free;
end;

class procedure TNativeMirrorDbgHelpWrapper.Load;
var
  Lib: HMODULE;
begin
  if FLoaded then Exit;
  Lib := LoadLibraryA('dbghelp.dll');
  if Lib = 0 then Exit;
  FSymInitialize        := TDbgHelpSymInitialize(GetProcAddress(Lib, 'SymInitialize'));
  FSymCleanup           := TDbgHelpSymCleanup(GetProcAddress(Lib, 'SymCleanup'));
  FSymSetOptions        := TDbgHelpSymSetOptions(GetProcAddress(Lib, 'SymSetOptions'));
  FSymSetSearchPath     := TDbgHelpSymSetSearchPath(GetProcAddress(Lib, 'SymSetSearchPath'));
  FSymRefreshModuleList := TDbgHelpSymRefreshModuleList(GetProcAddress(Lib, 'SymRefreshModuleList'));
  FSymFromAddr          := TDbgHelpSymFromAddr(GetProcAddress(Lib, 'SymFromAddr'));
  FStackWalk64          := TDbgHelpStackWalk64(GetProcAddress(Lib, 'StackWalk64'));
  FSymFunctionTableAccess64 := TDbgHelpSymFunctionTableAccess64(
    GetProcAddress(Lib, 'SymFunctionTableAccess64'));
  FSymGetModuleBase64   := TDbgHelpSymGetModuleBase64(GetProcAddress(Lib, 'SymGetModuleBase64'));
  FLoaded := Assigned(FSymInitialize) and Assigned(FSymCleanup)
    and Assigned(FSymSetOptions) and Assigned(FSymRefreshModuleList)
    and Assigned(FSymFromAddr) and Assigned(FStackWalk64)
    and Assigned(FSymFunctionTableAccess64) and Assigned(FSymGetModuleBase64);
end;

class function TNativeMirrorDbgHelpWrapper.IsLoaded: Boolean;
begin
  Result := FLoaded;
end;

class function TNativeMirrorDbgHelpWrapper.InitializeProcess(hProcess: THandle;
  const SearchPath: string; SymOptions: DWORD): Boolean;
var
  PathA: AnsiString;
  PA: PAnsiChar;
  RefCount: Integer;
begin
  Result := False;
  if not FLoaded then Exit;
  FLock.Enter;
  try
    if FSessions.TryGetValue(hProcess, RefCount) then
    begin
      FSessions[hProcess] := RefCount + 1;
      Exit(True);
    end;
    FSymSetOptions(SymOptions);
    if SearchPath <> '' then PathA := AnsiString(SearchPath) else PathA := '';
    PA := nil;
    if PathA <> '' then PA := PAnsiChar(PathA);
    Result := FSymInitialize(hProcess, PA, False);
    if Result then
    begin
      if (PA <> nil) and Assigned(FSymSetSearchPath) then
        FSymSetSearchPath(hProcess, PA);
      FSessions.Add(hProcess, 1);
    end;
  finally
    FLock.Leave;
  end;
end;

class function TNativeMirrorDbgHelpWrapper.CleanupProcess(hProcess: THandle): Boolean;
var
  RefCount: Integer;
begin
  Result := True;
  if not FLoaded then Exit;
  FLock.Enter;
  try
    if not FSessions.TryGetValue(hProcess, RefCount) then Exit(True);
    if RefCount > 1 then
    begin
      FSessions[hProcess] := RefCount - 1;
      Exit(True);
    end;
    Result := FSymCleanup(hProcess);
    if Result then
      FSessions.Remove(hProcess);
  finally
    FLock.Leave;
  end;
end;

class function TNativeMirrorDbgHelpWrapper.RefreshModuleList(hProcess: THandle): Boolean;
begin
  Result := False;
  if not FLoaded then Exit;
  FLock.Enter;
  try
    if Assigned(FSymRefreshModuleList) then
      Result := FSymRefreshModuleList(hProcess);
  finally
    FLock.Leave;
  end;
end;

class function TNativeMirrorDbgHelpWrapper.RunStackWalk64(MachineType: DWORD;
  hProcess, hThread: THandle; StackFrame: PNmStackFrame64; ContextRecord: Pointer): Boolean;
begin
  Result := False;
  if not FLoaded or not Assigned(FStackWalk64) then Exit;
  FLock.Enter;
  try
    Result := FStackWalk64(MachineType, hProcess, hThread, StackFrame, ContextRecord,
      nil, FSymFunctionTableAccess64, FSymGetModuleBase64, nil);
  finally
    FLock.Leave;
  end;
end;

class function TNativeMirrorDbgHelpWrapper.FromAddress(hProcess: THandle;
  Address: UInt64; Symbol: PNmSymbolInfo; Displacement: PUInt64): Boolean;
begin
  Result := False;
  if not FLoaded or not Assigned(FSymFromAddr) then Exit;
  FLock.Enter;
  try
    Result := FSymFromAddr(hProcess, Address, Displacement, Symbol);
  finally
    FLock.Leave;
  end;
end;

class function TNativeMirrorDbgHelpWrapper.GetFunctionTableAccess64: TDbgHelpSymFunctionTableAccess64;
begin
  Result := FSymFunctionTableAccess64;
end;

class function TNativeMirrorDbgHelpWrapper.GetGetModuleBase64: TDbgHelpSymGetModuleBase64;
begin
  Result := FSymGetModuleBase64;
end;

{ TNativeMirrorSymbolsManager }

constructor TNativeMirrorSymbolsManager.Create;
begin
  inherited Create;
  FProcess := 0;
  FIsInit := False;
end;

destructor TNativeMirrorSymbolsManager.Destroy;
begin
  if FIsInit then
  begin
    TNativeMirrorDbgHelpWrapper.CleanupProcess(FProcess);
    FIsInit := False;
  end;
  inherited;
end;

class function TNativeMirrorSymbolsManager.FilterSymbolPath(const Input: string;
  AllowDownload: Boolean): string;
var
  Parts: TArray<string>;
  Part, Trimmed: string;
  IsSrv: Boolean;
  StarIdx1, StarIdx2: Integer;
  Cache: string;
begin
  Result := '';
  Parts := Input.Split([';']);
  for Part in Parts do
  begin
    Trimmed := Trim(Part);
    if Trimmed = '' then Continue;
    IsSrv := Trimmed.ToLower.StartsWith('srv*');
    if IsSrv then
    begin
      if AllowDownload then
      begin
        if Result <> '' then Result := Result + ';';
        Result := Result + Trimmed;
      end
      else
      begin
        StarIdx1 := Pos('*', Trimmed);
        if StarIdx1 > 0 then
        begin
          StarIdx2 := Pos('*', Trimmed, StarIdx1 + 1);
          if StarIdx2 > StarIdx1 + 1 then
          begin
            Cache := Copy(Trimmed, StarIdx1 + 1, StarIdx2 - StarIdx1 - 1);
            if Cache <> '' then
            begin
              if Result <> '' then Result := Result + ';';
              Result := Result + Cache;
            end;
          end;
        end;
      end;
    end
    else
    begin
      if Result <> '' then Result := Result + ';';
      Result := Result + Trimmed;
    end;
  end;
end;

class function TNativeMirrorSymbolsManager.BuildSymbolPath(EnableAutoDownload: Boolean): string;
var
  Buf: array[0..4095] of Char;
  Path, Extra: string;
begin
  Path := '';
  if GetEnvironmentVariable('_NT_SYMBOL_PATH', Buf, SizeOf(Buf) div SizeOf(Char)) > 0 then
    Path := FilterSymbolPath(string(Buf), EnableAutoDownload);
  if GetEnvironmentVariable('_NT_ALTERNATE_SYMBOL_PATH', Buf, SizeOf(Buf) div SizeOf(Char)) > 0 then
  begin
    Extra := FilterSymbolPath(string(Buf), EnableAutoDownload);
    if Extra <> '' then
    begin
      if Path <> '' then Path := Path + ';';
      Path := Path + Extra;
    end;
  end;
  Result := Path;
end;

class function TNativeMirrorSymbolsManager.BuildSymOptions(EnableAutoDownload, Lazy: Boolean): DWORD;
begin
  Result := SYMOPT_CASE_INSENSITIVE or SYMOPT_UNDNAME or SYMOPT_FAIL_CRITICAL_ERRORS
    or SYMOPT_AUTO_PUBLICS or SYMOPT_INCLUDE_32BIT_MODULES or SYMOPT_NO_PROMPTS
    or SYMOPT_DEBUG;
  if EnableAutoDownload then
    Result := Result and not SYMOPT_DISABLE_SYMSRV_AUTODETECT
  else
    Result := Result or SYMOPT_DISABLE_SYMSRV_AUTODETECT;
  if Lazy then
    Result := Result or SYMOPT_DEFERRED_LOADS
  else
    Result := Result and not SYMOPT_DEFERRED_LOADS;
end;

function TNativeMirrorSymbolsManager.InitSymbols(hProcess: THandle;
  EnableAutoDownload, Lazy: Boolean): Boolean;
var
  Options: DWORD;
  Path: string;
begin
  Result := False;
  if FIsInit then Exit(True);
  if (hProcess = 0) or (hProcess = INVALID_HANDLE_VALUE) then Exit;
  if not TNativeMirrorDbgHelpWrapper.IsLoaded then Exit;
  Options := BuildSymOptions(EnableAutoDownload, Lazy);
  Path := BuildSymbolPath(EnableAutoDownload);
  if not TNativeMirrorDbgHelpWrapper.InitializeProcess(hProcess, Path, Options) then Exit;
  TNativeMirrorDbgHelpWrapper.RefreshModuleList(hProcess);
  FProcess := hProcess;
  FIsInit := True;
  Result := True;
end;

function TNativeMirrorSymbolsManager.RefreshModules: Boolean;
begin
  Result := FIsInit and TNativeMirrorDbgHelpWrapper.RefreshModuleList(FProcess);
end;

function TNativeMirrorSymbolsManager.IsInitialized: Boolean;
begin
  Result := FIsInit;
end;

function TNativeMirrorSymbolsManager.RunStackWalk64(MachineType: DWORD;
  hThread: THandle; StackFrame: PNmStackFrame64; ContextRecord: Pointer): Boolean;
begin
  Result := FIsInit and
    TNativeMirrorDbgHelpWrapper.RunStackWalk64(MachineType, FProcess, hThread,
      StackFrame, ContextRecord);
end;

procedure TNativeMirrorSymbolsManager.NormalizeNtZwPrefix(var FuncName: string);
begin
  if Length(FuncName) >= 2 then
    if (FuncName[1] = 'Z') and (FuncName[2] = 'w') then
    begin
      FuncName[1] := 'N';
      FuncName[2] := 't';
    end;
end;

function TNativeMirrorSymbolsManager.FuncNameFromAddr(Addr: UInt64;
  Displacement: PNativeUInt): string;
var
  Sym: PNmSymbolInfo;
  Disp: UInt64;
  BufferSize: NativeUInt;
  NameA: AnsiString;
begin
  Result := '';
  if not FIsInit then Exit;
  BufferSize := SizeOf(TNmSymbolInfo) + NativeUInt(MAX_SYM_NAME - 1) * SizeOf(AnsiChar);
  GetMem(Sym, BufferSize);
  try
    FillChar(Sym^, BufferSize, 0);
    Sym^.SizeOfStruct := SizeOf(TNmSymbolInfo);
    Sym^.MaxNameLen := MAX_SYM_NAME;
    Disp := 0;
    if not TNativeMirrorDbgHelpWrapper.FromAddress(FProcess, Addr, Sym, @Disp) then Exit;
    if Displacement <> nil then Displacement^ := NativeUInt(Disp);
    SetString(NameA, PAnsiChar(@Sym^.Name[0]), Sym^.NameLen);
    Result := string(NameA);
    NormalizeNtZwPrefix(Result);
  finally
    FreeMem(Sym);
  end;
end;

end.
