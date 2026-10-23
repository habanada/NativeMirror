{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Scanner.Patches;

interface

uses
  System.JSON,
  System.Classes,
  System.Generics.Collections,
  NativePe.ExportsMapper;

type
  TNativeMirrorPatchType = (nmPatchUnknown, nmHookInline, nmHookAddressReplacement, nmPatchPadding, nmPatchBreakpoint);

  TNativeMirrorPatch = class
  private
    FId: NativeUInt;
    FStartRva: Cardinal;
    FEndRva: Cardinal;
    FModuleBase: UInt64;
    FPatchType: TNativeMirrorPatchType;
    FIsDirect: Boolean;
    FHookTargetVa: UInt64;
    FPaddingValue: Byte;
    FHookedFunction: string;
    FHookTargetModule: UInt64;
    FTargetSuspicious: Boolean;
    FHookTargetModuleName: string;
    function GetFormattedName: string;
  public
    constructor Create(ModuleBase: UInt64; PatchId: NativeUInt; StartRva: Cardinal); overload;
    constructor Create(Source: TNativeMirrorPatch); overload;
    procedure SetEnd(EndRva: Cardinal);
    procedure SetHookTarget(TargetVa: UInt64; IsDirect: Boolean = True; PatchType: TNativeMirrorPatchType = nmHookInline);
    function SetHookTargetInfo(TargetModuleBase: UInt64; IsSuspicious: Boolean; const TargetModuleName: string): Boolean;
    function ResolveHookedExport(ExportsMap: TExportsMapper): Boolean;
    function ToJson(ShortInfo: Boolean): TJSONObject;
    function ToTag(Delimiter: Char = ';'): string;
    property Id: NativeUInt read FId;
    property StartRva: Cardinal read FStartRva;
    property EndRva: Cardinal read FEndRva;
    property ModuleBase: UInt64 read FModuleBase;
    property PatchType: TNativeMirrorPatchType read FPatchType write FPatchType;
    property IsDirect: Boolean read FIsDirect;
    property HookTargetVa: UInt64 read FHookTargetVa;
    property PaddingValue: Byte read FPaddingValue write FPaddingValue;
    property HookedFunction: string read FHookedFunction;
    property HookTargetModule: UInt64 read FHookTargetModule;
    property TargetSuspicious: Boolean read FTargetSuspicious;
    property HookTargetModuleName: string read FHookTargetModuleName;
  end;

  TNativeMirrorPatchList = class
  private
    FPatches: TObjectList<TNativeMirrorPatch>;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Assign(Source: TNativeMirrorPatchList);
    procedure Add(Patch: TNativeMirrorPatch);
    function Count: NativeUInt;
    function CheckForHookedExports(ExportsMap: TExportsMapper): NativeUInt;
    function SaveTags(const FileName: string; Delimiter: Char = ';'): NativeUInt;
    function ToJson(ShortInfo: Boolean): TJSONArray;
    function Item(Index: Integer): TNativeMirrorPatch;
    property Patches: TObjectList<TNativeMirrorPatch> read FPatches;
  end;

implementation

uses
  System.SysUtils,
  NativePe.ExportedFunc;

function Hex(Value: UInt64): string;
begin
  Result := IntToHex(Value, 1).ToLower;
end;

constructor TNativeMirrorPatch.Create(ModuleBase: UInt64; PatchId: NativeUInt; StartRva: Cardinal);
begin
  inherited Create;
  FModuleBase := ModuleBase;
  FId := PatchId;
  FStartRva := StartRva;
  FEndRva := StartRva;
  FPatchType := nmPatchUnknown;
  FIsDirect := True;
end;

constructor TNativeMirrorPatch.Create(Source: TNativeMirrorPatch);
begin
  inherited Create;
  FId := Source.FId;
  FStartRva := Source.FStartRva;
  FEndRva := Source.FEndRva;
  FModuleBase := Source.FModuleBase;
  FPatchType := Source.FPatchType;
  FIsDirect := Source.FIsDirect;
  FHookTargetVa := Source.FHookTargetVa;
  FPaddingValue := Source.FPaddingValue;
  FHookedFunction := Source.FHookedFunction;
  FHookTargetModule := Source.FHookTargetModule;
  FTargetSuspicious := Source.FTargetSuspicious;
  FHookTargetModuleName := Source.FHookTargetModuleName;
end;

procedure TNativeMirrorPatch.SetEnd(EndRva: Cardinal);
begin
  FEndRva := EndRva;
end;

procedure TNativeMirrorPatch.SetHookTarget(TargetVa: UInt64; IsDirect: Boolean; PatchType: TNativeMirrorPatchType);
begin
  FHookTargetVa := TargetVa;
  FIsDirect := IsDirect;
  FPatchType := PatchType;
end;

function TNativeMirrorPatch.SetHookTargetInfo(TargetModuleBase: UInt64; IsSuspicious: Boolean; const TargetModuleName: string): Boolean;
begin
  Result := False;
  if (FPatchType = nmPatchUnknown) or (TargetModuleBase = 0) or (TargetModuleBase > FHookTargetVa) then
    Exit;
  FHookTargetModule := TargetModuleBase;
  FTargetSuspicious := IsSuspicious;
  FHookTargetModuleName := TargetModuleName;
  Result := True;
end;

function TNativeMirrorPatch.ResolveHookedExport(ExportsMap: TExportsMapper): Boolean;
var
  Func: TExportedFunc;
begin
  Result := False;
  if ExportsMap = nil then
    Exit;
  Func := ExportsMap.FindExportByVa(FModuleBase + FStartRva);
  if Func = nil then
    Exit;
  FHookedFunction := Func.NameToString;
  Result := True;
end;

function TNativeMirrorPatch.GetFormattedName: string;
var
  Diff: UInt64;
begin
  if FPatchType = nmPatchPadding then
    Exit('padding:0x' + IntToHex(FPaddingValue, 1).ToLower);
  if FPatchType = nmPatchBreakpoint then
    Exit('breakpoint');
  if FHookedFunction <> '' then
    Result := FHookedFunction
  else
  begin
    case FPatchType of
      nmHookInline: Result := 'hook_';
      nmHookAddressReplacement: Result := 'addr_replaced_';
    else
      Result := 'patch_';
    end;
    Result := Result + FId.ToString;
  end;
  if FPatchType <> nmPatchUnknown then
  begin
    Result := Result + '->';
    if FIsDirect then
      Result := Result + Hex(FHookTargetVa)
    else
      Result := Result + 'via:' + Hex(FHookTargetVa);
  end;
  if FHookTargetModule <> 0 then
  begin
    Diff := FHookTargetVa - FHookTargetModule;
    Result := Result + '[' + Hex(FHookTargetModule) + '+' + Hex(Diff) + ':';
    if FHookTargetModuleName <> '' then
      Result := Result + FHookTargetModuleName
    else
      Result := Result + '(unnamed)';
    if FTargetSuspicious then
      Result := Result + ':1]'
    else
      Result := Result + ':0]';
  end;
end;

function TNativeMirrorPatch.ToJson(ShortInfo: Boolean): TJSONObject;
var
  Hook: TJSONObject;
  IsHook: Boolean;
begin
  Result := TJSONObject.Create;
  Result.AddPair('rva', Hex(FStartRva));
  Result.AddPair('size', TJSONNumber.Create(UInt64(FEndRva) - FStartRva));
  if ShortInfo then
  begin
    Result.AddPair('info', GetFormattedName);
    Exit;
  end;
  IsHook := FPatchType in [nmHookInline, nmHookAddressReplacement];
  if IsHook then
    Result.AddPair('is_hook', TJSONNumber.Create(1))
  else
    Result.AddPair('is_hook', TJSONNumber.Create(0));
  if FHookedFunction <> '' then
    Result.AddPair('func_name', FHookedFunction);
  if IsHook then
  begin
    Hook := TJSONObject.Create;
    if FHookTargetModuleName <> '' then
      Hook.AddPair('module_name', FHookTargetModuleName);
    Hook.AddPair('module', Hex(FHookTargetModule));
    Hook.AddPair('rva', Hex(FHookTargetVa - FHookTargetModule));
    if FTargetSuspicious then
      Hook.AddPair('status', TJSONNumber.Create(1))
    else
      Hook.AddPair('status', TJSONNumber.Create(0));
    Result.AddPair('hook_target', Hook);
  end;
end;

function TNativeMirrorPatch.ToTag(Delimiter: Char): string;
begin
  Result := Hex(FStartRva) + Delimiter + GetFormattedName + Delimiter + Hex(FEndRva - FStartRva);
end;

constructor TNativeMirrorPatchList.Create;
begin
  inherited Create;
  FPatches := TObjectList<TNativeMirrorPatch>.Create(True);
end;

destructor TNativeMirrorPatchList.Destroy;
begin
  FPatches.Free;
  inherited;
end;

procedure TNativeMirrorPatchList.Assign(Source: TNativeMirrorPatchList);
var
  Patch: TNativeMirrorPatch;
begin
  FPatches.Clear;
  if Source = nil then
    Exit;
  for Patch in Source.FPatches do
    FPatches.Add(TNativeMirrorPatch.Create(Patch));
end;

procedure TNativeMirrorPatchList.Add(Patch: TNativeMirrorPatch);
begin
  if Patch <> nil then
    FPatches.Add(Patch);
end;

function TNativeMirrorPatchList.Count: NativeUInt;
begin
  Result := FPatches.Count;
end;

function TNativeMirrorPatchList.CheckForHookedExports(ExportsMap: TExportsMapper): NativeUInt;
var
  Patch: TNativeMirrorPatch;
begin
  Result := 0;
  for Patch in FPatches do
    if Patch.ResolveHookedExport(ExportsMap) then
      Inc(Result);
end;

function TNativeMirrorPatchList.SaveTags(const FileName: string; Delimiter: Char): NativeUInt;
var
  Lines: TStringList;
  Patch: TNativeMirrorPatch;
begin
  Lines := TStringList.Create;
  try
    Lines.WriteBOM := False;
    for Patch in FPatches do
      Lines.Add(Patch.ToTag(Delimiter));
    try
      Lines.SaveToFile(FileName, TEncoding.UTF8);
      Result := FPatches.Count;
    except
      Result := 0;
    end;
  finally
    Lines.Free;
  end;
end;

function TNativeMirrorPatchList.ToJson(ShortInfo: Boolean): TJSONArray;
var
  Patch: TNativeMirrorPatch;
begin
  Result := TJSONArray.Create;
  for Patch in FPatches do
    Result.AddElement(Patch.ToJson(ShortInfo));
end;

function TNativeMirrorPatchList.Item(Index: Integer): TNativeMirrorPatch;
begin
  Result := FPatches[Index];
end;

end.
