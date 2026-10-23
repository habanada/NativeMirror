{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: BSD-2-Clause

  This file is part of NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Scanner.ProcessDetails;

interface

type
  TNativeMirrorProcessDetails = record
    IsReflection: Boolean;
    IsDep: Boolean;
    class function Create(AIsReflection, AIsDep: Boolean): TNativeMirrorProcessDetails; static;
  end;

implementation

class function TNativeMirrorProcessDetails.Create(AIsReflection, AIsDep: Boolean): TNativeMirrorProcessDetails;
begin
  Result.IsReflection := AIsReflection;
  Result.IsDep := AIsDep;
end;

end.
