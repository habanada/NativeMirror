{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Platform.Paths;

interface

function ExpandDevicePath(const Path: string): string;
function ConvertToWow64Path(const Path: string): string;
function NormalizeModulePath(const Path: string): string;

implementation

uses
  Winapi.Windows,
  System.SysUtils,
  System.IOUtils;

function DevicePrefixForDrive(const Drive: string): string;
var
  Buffer: array[0..4095] of Char;
begin
  Result := '';
  FillChar(Buffer, SizeOf(Buffer), 0);
  if QueryDosDevice(PChar(Drive), Buffer, Length(Buffer)) <> 0 then
    Result := Buffer;
end;

function ExpandDevicePath(const Path: string): string;
var
  Mask: DWORD;
  I: Integer;
  Drive: string;
  Prefix: string;
begin
  Result := Path;
  if not Path.StartsWith('\Device\', True) then
    Exit;
  Mask := GetLogicalDrives;
  for I := 0 to 25 do
  begin
    if (Mask and (DWORD(1) shl I)) = 0 then
      Continue;
    Drive := Char(Ord('A') + I) + ':';
    Prefix := DevicePrefixForDrive(Drive);
    if (Prefix <> '') and Path.StartsWith(Prefix, True) then
      Exit(Drive + Path.Substring(Prefix.Length));
  end;
end;

function ConvertToWow64Path(const Path: string): string;
var
  WindowsDir: array[0..MAX_PATH - 1] of Char;
  System32Path: string;
  Wow64Path: string;
begin
  Result := Path;
  FillChar(WindowsDir, SizeOf(WindowsDir), 0);
  if GetWindowsDirectory(WindowsDir, Length(WindowsDir)) = 0 then
    Exit;
  System32Path := IncludeTrailingPathDelimiter(WindowsDir) + 'System32';
  Wow64Path := IncludeTrailingPathDelimiter(WindowsDir) + 'SysWOW64';
  if Path.StartsWith(System32Path, True) then
    Result := Wow64Path + Path.Substring(System32Path.Length);
end;

function NormalizeModulePath(const Path: string): string;
var
  Expanded: string;
  Buffer: array[0..MAX_PATH - 1] of Char;
  LengthWritten: DWORD;
begin
  Expanded := Path;
  if Expanded.StartsWith('\\?\', False) then
    Expanded := Expanded.Substring(4);
  if Expanded.StartsWith('GLOBALROOT\', True) then
    Expanded := '\' + Expanded.Substring(11);
  Expanded := ExpandDevicePath(Expanded);
  if Expanded.StartsWith('\Device\', True) then
    Exit(Path);
  try
    Result := TPath.GetFullPath(Expanded);
  except
    Result := Expanded;
  end;
  LengthWritten := GetLongPathName(PChar(Result), Buffer, Length(Buffer));
  if (LengthWritten <> 0) and (LengthWritten < DWORD(Length(Buffer))) then
    SetString(Result, Buffer, LengthWritten);
end;

end.
