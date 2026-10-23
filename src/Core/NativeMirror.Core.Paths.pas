{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Core.Paths;

interface

function EnsureDirectory(const Path: string): Boolean;
function StripPrefix(const Path, Prefix: string): string;
function EscapePathSeparators(const Path: string): string;

implementation

uses
  System.SysUtils,
  System.IOUtils;

function EnsureDirectory(const Path: string): Boolean;
begin
  if Path = '' then
    Exit(True);
  try
    if not TDirectory.Exists(Path) then
      TDirectory.CreateDirectory(Path);
    Result := TDirectory.Exists(Path);
  except
    Result := False;
  end;
end;

function StripPrefix(const Path, Prefix: string): string;
begin
  Result := Path;
  if (Prefix <> '') and Path.StartsWith(Prefix, True) then
    Delete(Result, 1, Prefix.Length);
end;

function EscapePathSeparators(const Path: string): string;
begin
  Result := StringReplace(Path, '\', '\\', [rfReplaceAll]);
end;

end.
