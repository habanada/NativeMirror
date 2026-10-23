{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Scanner.ModuleCache;

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  System.SyncObjs,
  NativeMirror.Core.Buffer;

type
  TNativeMirrorCachedModule = class
  private
    FRaw: TBytes;
    FLastUsage: Cardinal;
    function GetRawSize: Integer;
  public
    constructor Create(Buffer: Pointer; Size: NativeUInt);
    function Map(out MappedSize: NativeUInt): PByte;
    property LastUsage: Cardinal read FLastUsage write FLastUsage;
    property RawSize: Integer read GetRawSize;
  end;

  TNativeMirrorModulesCache = class
  private
    FLock: TCriticalSection;
    FUsage: TDictionary<string, NativeUInt>;
    FModules: TObjectDictionary<string, TNativeMirrorCachedModule>;
    function GetMappedCached(const ModuleName: string; out MappedSize: NativeUInt): PByte;
    function IsCacheAvailable(NeededSize: NativeUInt): Boolean;
    function PrepareCacheSpace(NeededSize: NativeUInt; ForceFree: Boolean): Boolean;
    function DeleteLeastRecent: Boolean;
  public
    constructor Create;
    destructor Destroy; override;
    function LoadCached(const ModuleName: string; out MappedSize: NativeUInt): PByte;
    procedure Clear;
  end;

implementation

uses
  Winapi.Windows,
  Winapi.PsAPI,
  NativePe.FileUtil,
  NativePe.PeLoader,
  NativePe.BufferUtil;

constructor TNativeMirrorCachedModule.Create(Buffer: Pointer; Size: NativeUInt);
begin
  inherited Create;
  if (Buffer <> nil) and (Size > 0) and (Size <= High(Integer)) then
  begin
    SetLength(FRaw, Integer(Size));
    Move(Buffer^, FRaw[0], Size);
  end;
  FLastUsage := GetTickCount;
end;

function TNativeMirrorCachedModule.GetRawSize: Integer;
begin
  Result := Length(FRaw);
end;

function TNativeMirrorCachedModule.Map(out MappedSize: NativeUInt): PByte;
begin
  MappedSize := 0;
  Result := nil;
  if Length(FRaw) = 0 then
    Exit;
  FLastUsage := GetTickCount;
  Result := LoadPeModule(@FRaw[0], Length(FRaw), MappedSize, False, False);
end;

constructor TNativeMirrorModulesCache.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FUsage := TDictionary<string, NativeUInt>.Create;
  FModules := TObjectDictionary<string, TNativeMirrorCachedModule>.Create([doOwnsValues]);
end;

destructor TNativeMirrorModulesCache.Destroy;
begin
  FModules.Free;
  FUsage.Free;
  FLock.Free;
  inherited;
end;

function TNativeMirrorModulesCache.GetMappedCached(const ModuleName: string; out MappedSize: NativeUInt): PByte;
var
  Cached: TNativeMirrorCachedModule;
begin
  Result := nil;
  MappedSize := 0;
  FLock.Acquire;
  try
    if FModules.TryGetValue(LowerCase(ModuleName), Cached) then
      Result := Cached.Map(MappedSize);
  finally
    FLock.Release;
  end;
end;

function TNativeMirrorModulesCache.IsCacheAvailable(NeededSize: NativeUInt): Boolean;
var
  MinSize, MaxSize: SIZE_T;
  Flags: DWORD;
  MemStatus: TMemoryStatusEx;
  Counters: TProcessMemoryCounters;
  Required, FreeMem, FreePeak: UInt64;
  PercentWorking, PercentPeak: UInt64;
begin
  Result := False;
  if UInt64(NeededSize) > High(UInt64) div 2 then
    Required := High(UInt64)
  else
    Required := UInt64(NeededSize) * 2;
  MinSize := 0;
  MaxSize := 0;
  Flags := 0;
  if not GetProcessWorkingSetSizeEx(GetCurrentProcess, MinSize, MaxSize, @Flags) then
    Exit;
  FillChar(MemStatus, SizeOf(MemStatus), 0);
  MemStatus.dwLength := SizeOf(MemStatus);
  if ((Flags and QUOTA_LIMITS_HARDWS_MAX_DISABLE) <> 0) and GlobalMemoryStatusEx(MemStatus) then
    if (MemStatus.ullAvailVirtual > Required) and (MemStatus.dwMemoryLoad < 50) then
      Result := True;
  FillChar(Counters, SizeOf(Counters), 0);
  Counters.cb := SizeOf(Counters);
  if not GetProcessMemoryInfo(GetCurrentProcess, @Counters, SizeOf(Counters)) then
    Exit;
  if (UInt64(MaxSize) > UInt64(Counters.PeakWorkingSetSize)) and (UInt64(MaxSize) > UInt64(Counters.WorkingSetSize)) then
  begin
    FreeMem := UInt64(MaxSize) - UInt64(Counters.WorkingSetSize);
    if MaxSize <> 0 then
      PercentWorking := (UInt64(Counters.WorkingSetSize) * 100) div UInt64(MaxSize)
    else
      PercentWorking := 100;
    if (FreeMem > Required) and (PercentWorking < 60) then
      Result := True;
  end;
  if (Counters.PeakWorkingSetSize <> 0) and (UInt64(Counters.PeakWorkingSetSize) >= UInt64(Counters.WorkingSetSize)) then
  begin
    FreePeak := UInt64(Counters.PeakWorkingSetSize) - UInt64(Counters.WorkingSetSize);
    PercentPeak := (UInt64(Counters.WorkingSetSize) * 100) div UInt64(Counters.PeakWorkingSetSize);
    if (FreePeak > Required) and (PercentPeak < 70) then
      Result := True;
  end;
end;

function TNativeMirrorModulesCache.DeleteLeastRecent: Boolean;
var
  Pair: TPair<string, TNativeMirrorCachedModule>;
  Selected: string;
  LeastStamp, GreatestStamp: Cardinal;
  Found: Boolean;
begin
  Result := False;
  Selected := '';
  LeastStamp := 0;
  GreatestStamp := 0;
  Found := False;
  for Pair in FModules do
  begin
    if not Found or (Pair.Value.LastUsage < LeastStamp) then
    begin
      LeastStamp := Pair.Value.LastUsage;
      Selected := Pair.Key;
    end;
    if not Found or (Pair.Value.LastUsage > GreatestStamp) then
      GreatestStamp := Pair.Value.LastUsage;
    Found := True;
  end;
  if not Found or (GreatestStamp = LeastStamp) then
    Exit;
  FModules.Remove(Selected);
  FUsage.AddOrSetValue(Selected, 0);
  Result := True;
end;

function TNativeMirrorModulesCache.PrepareCacheSpace(NeededSize: NativeUInt; ForceFree: Boolean): Boolean;
begin
  FLock.Acquire;
  try
    if ForceFree then
      DeleteLeastRecent;
    while not IsCacheAvailable(NeededSize) do
      if not DeleteLeastRecent then
        Exit(False);
    Result := True;
  finally
    FLock.Release;
  end;
end;

function TNativeMirrorModulesCache.LoadCached(const ModuleName: string; out MappedSize: NativeUInt): PByte;
var
  Raw: PByte;
  RawSize: NativeUInt;
  Key: string;
  UsageCount: NativeUInt;
  Cached: TNativeMirrorCachedModule;
  ForceFreeCache: Boolean;
begin
  Result := GetMappedCached(ModuleName, MappedSize);
  if Result <> nil then
    Exit;
  RawSize := 0;
  Raw := LoadFile(ModuleName, RawSize);
  if Raw = nil then
    Exit(nil);
  ForceFreeCache := False;
  try
    Key := LowerCase(ModuleName);
    FLock.Acquire;
    try
      if not FUsage.TryGetValue(Key, UsageCount) then
        UsageCount := 0;
      Inc(UsageCount);
      FUsage.AddOrSetValue(Key, UsageCount);
      if (UsageCount >= 3) and not FModules.ContainsKey(Key) and IsCacheAvailable(RawSize) then
      begin
        Cached := nil;
        try
          Cached := TNativeMirrorCachedModule.Create(Raw, RawSize);
        except
          on EOutOfMemory do
            ForceFreeCache := True;
        end;
        if Cached <> nil then
        begin
          if Cached.RawSize > 0 then
            FModules.Add(Key, Cached)
          else
          begin
            Cached.Free;
            ForceFreeCache := True;
          end;
        end;
      end;
    finally
      FLock.Release;
    end;
    PrepareCacheSpace(RawSize, ForceFreeCache);
    Result := LoadPeModule(Raw, RawSize, MappedSize, False, False);
  finally
    FreeFile(Raw);
  end;
end;

procedure TNativeMirrorModulesCache.Clear;
begin
  FLock.Acquire;
  try
    FModules.Clear;
    FUsage.Clear;
  finally
    FLock.Release;
  end;
end;

end.
