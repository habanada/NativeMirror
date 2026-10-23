{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-License-Identifier: BSD-2-Clause

  This file contains tests for NativeMirror, an Object Pascal adaptation
  of PE-sieve 0.4.1.5 by hasherezade.
  PE-sieve: https://github.com/hasherezade/pe-sieve
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativeMirror.Tests.Integration;

interface

uses
  System.SysUtils,
  DUnitX.TestFramework,
  NativeMirror.Tests.Support;

type
  TScenarioValidator = reference to procedure(Result: TScanResult; Target: TTargetProcess);

  [TestFixture]
  TNativeMirrorScannerIntegrationTests = class
  private
    procedure RunAndCompare(const Scenario: string; const Validate: TScenarioValidator; Is32Bit: Boolean = False);
  public
    [Test] procedure CleanProcess;
    [Test] procedure HeaderModification;
    [Test] procedure NtHeaderModification;
    [Test] procedure SectionReplacement;
    [Test] procedure LastSectionReplacement;
    [Test] procedure ExecutableCodePatch;
    [Test] procedure MultipleExecutableCodePatches;
    [Test] procedure IatRedirect;
    [Test] procedure PrivatePeImage;
    [Test] procedure MultiplePrivatePeImages;
    [Test] procedure PrivateExecutableMemory;
    [Test] procedure PrivateExecutablePageBoundary;
    [Test] procedure PrivateExecutableRegionTail;
    [Test] procedure MultiplePrivateExecutableMemory;
    [Test] procedure PrivateExecutableControl;
    [Test] procedure PrivateThreadStart;
    [Test] procedure MixedArtifacts;
    [Test] procedure ExtendedMixedArtifacts;
    [Test] procedure CleanProcess32;
    [Test] procedure ExecutableCodePatch32;
    [Test] procedure IatRedirect32;
    [Test] procedure PrivatePeImage32;
    [Test] procedure PrivateExecutableMemory32;
  end;

implementation

procedure TNativeMirrorScannerIntegrationTests.RunAndCompare(const Scenario: string; const Validate: TScenarioValidator; Is32Bit: Boolean);
var
  Target: TTargetProcess;
  NativeResult, PeResult: TScanResult;
begin
  if Is32Bit then
    Target := TScannerHarness.StartTarget32(Scenario)
  else
    Target := TScannerHarness.StartTarget(Scenario);
  try
    NativeResult := TScannerHarness.ScanNativeMirror(Target);
    try
      Assert.AreEqual(Integer(Target.Pid), Integer(NativeResult.Summary.Pid), 'NativeMirror PID mismatch');
      Assert.AreEqual(0, NativeResult.Summary.Errors, 'NativeMirror reported scan errors');
      Validate(NativeResult, Target);
      PeResult := TScannerHarness.ScanPeSieve(Target);
      try
        if PeResult <> nil then
        begin
          Assert.AreEqual(Integer(Target.Pid), Integer(PeResult.Summary.Pid), 'PE-Sieve PID mismatch');
          Assert.AreEqual(0, PeResult.Summary.Errors, 'PE-Sieve reported scan errors');
          TScannerHarness.AssertParity(NativeResult, PeResult);
        end;
      finally
        PeResult.Free;
      end;
    finally
      NativeResult.Free;
    end;
  finally
    Target.Free;
  end;
end;

procedure TNativeMirrorScannerIntegrationTests.CleanProcess;
begin
  RunAndCompare('Clean',
    procedure(Result: TScanResult; Target: TTargetProcess)
    begin
      Assert.AreEqual(0, Result.Summary.Suspicious, 'Clean target must not be suspicious');
      Assert.AreEqual(0, Result.Summary.Patched, 'Clean target must not contain code patches');
      Assert.AreEqual(0, Result.Summary.IatHooked, 'Clean target must not contain IAT hooks');
      Assert.AreEqual(0, Result.Summary.HeaderModified, 'Clean target must not contain header modifications');
      Assert.AreEqual(0, Result.Summary.ImplantedPe, 'Clean target must not contain private PE images');
      Assert.AreEqual(0, Result.Summary.ImplantedShellcode, 'Clean target must not contain private thread findings');
    end);
end;

procedure TNativeMirrorScannerIntegrationTests.HeaderModification;
begin
  RunAndCompare('HeaderPatch',
    procedure(Result: TScanResult; Target: TTargetProcess)
    begin
      Assert.IsTrue(Result.Summary.HeaderModified > 0, 'DOS header modification was not detected');
      Assert.IsTrue(Result.HasModuleFinding('headers_scan', Target.ModulePath), 'Header finding is not attached to the test target');
    end);
end;

procedure TNativeMirrorScannerIntegrationTests.NtHeaderModification;
begin
  RunAndCompare('NtHeaderPatch',
    procedure(Result: TScanResult; Target: TTargetProcess)
    begin
      Assert.IsTrue(Result.Summary.HeaderModified > 0, 'NT optional-header modification was not detected');
      Assert.IsTrue(Result.HasModuleFinding('headers_scan', Target.ModulePath), 'NT header finding is not attached to the test target');
    end);
end;

procedure TNativeMirrorScannerIntegrationTests.SectionReplacement;
begin
  RunAndCompare('SectionReplacement',
    procedure(Result: TScanResult; Target: TTargetProcess)
    begin
      Assert.IsTrue(Result.Summary.Replaced > 0, 'Section-header replacement artifact was not detected');
      Assert.IsTrue(Result.HasModuleFinding('headers_scan', Target.ModulePath), 'Replacement finding is not attached to the test target');
    end);
end;

procedure TNativeMirrorScannerIntegrationTests.LastSectionReplacement;
begin
  RunAndCompare('LastSectionReplacement',
    procedure(Result: TScanResult; Target: TTargetProcess)
    begin
      Assert.IsTrue(Result.Summary.Replaced > 0, 'Last-section replacement artifact was not detected');
      Assert.IsTrue(Result.HasModuleFinding('headers_scan', Target.ModulePath), 'Last-section finding is not attached to the test target');
    end);
end;

procedure TNativeMirrorScannerIntegrationTests.ExecutableCodePatch;
begin
  RunAndCompare('CodePatch',
    procedure(Result: TScanResult; Target: TTargetProcess)
    begin
      Assert.IsTrue(Result.Summary.Patched > 0, 'Executable code patch was not detected');
      Assert.IsTrue(Result.HasModuleFinding('code_scan', Target.ModulePath), 'Code patch finding is not attached to the test target');
    end);
end;

procedure TNativeMirrorScannerIntegrationTests.MultipleExecutableCodePatches;
begin
  RunAndCompare('MultipleCodePatches',
    procedure(Result: TScanResult; Target: TTargetProcess)
    var
      PatchCount: Integer;
    begin
      Assert.IsTrue(Result.Summary.Patched > 0, 'Multiple executable code patches were not detected');
      Assert.IsTrue(Result.HasModuleFinding('code_scan', Target.ModulePath), 'Multiple code-patch finding is not attached to the test target');
      PatchCount := Result.ModuleFindingInt('code_scan', Target.ModulePath, 'patches');
      Assert.IsTrue(PatchCount >= 2, Format('Expected at least two code patches, got %d', [PatchCount]));
    end);
end;

procedure TNativeMirrorScannerIntegrationTests.IatRedirect;
begin
  RunAndCompare('IatRedirect',
    procedure(Result: TScanResult; Target: TTargetProcess)
    begin
      Assert.IsTrue(Result.Summary.IatHooked > 0, 'IAT redirect was not detected');
      Assert.IsTrue(Result.HasModuleFinding('iat_scan', Target.ModulePath), 'IAT finding is not attached to the test target');
    end);
end;

procedure TNativeMirrorScannerIntegrationTests.PrivatePeImage;
begin
  RunAndCompare('PrivatePe',
    procedure(Result: TScanResult; Target: TTargetProcess)
    begin
      Assert.IsTrue(Target.PrimaryAddress <> 0, 'Private PE address was not published');
      Assert.IsTrue(Result.Summary.ImplantedPe > 0, 'Private PE image was not detected');
      Assert.IsTrue(Result.HasAddressFinding('workingset_scan', Target.PrimaryAddress), 'Private PE finding does not point to the mapped test image');
    end);
end;

procedure TNativeMirrorScannerIntegrationTests.MultiplePrivatePeImages;
begin
  RunAndCompare('MultiplePrivatePe',
    procedure(Result: TScanResult; Target: TTargetProcess)
    begin
      Assert.IsTrue(Target.PrimaryAddress <> 0, 'First private PE address was not published');
      Assert.IsTrue(Target.SecondaryAddress <> 0, 'Second private PE address was not published');
      Assert.IsTrue(Target.PrimaryAddress <> Target.SecondaryAddress, 'Private PE mappings must be distinct');
      Assert.IsTrue(Result.Summary.ImplantedPe >= 2, 'Multiple private PE images were not detected');
      Assert.IsTrue(Result.HasAddressFinding('workingset_scan', Target.PrimaryAddress), 'First private PE finding is missing');
      Assert.IsTrue(Result.HasAddressFinding('workingset_scan', Target.SecondaryAddress), 'Second private PE finding is missing');
    end);
end;

procedure TNativeMirrorScannerIntegrationTests.PrivateExecutableMemory;
begin
  RunAndCompare('PrivateExecutable',
    procedure(Result: TScanResult; Target: TTargetProcess)
    begin
      Assert.IsTrue(Target.PrimaryAddress <> 0, 'Private executable address was not published');
      Assert.IsTrue(Result.Summary.ImplantedShellcode > 0, 'Pattern-matched private executable artifact was not detected');
      Assert.IsTrue(Result.HasAddressFinding('workingset_scan', Target.PrimaryAddress), 'Private executable finding points to the wrong region');
    end);
end;

procedure TNativeMirrorScannerIntegrationTests.PrivateExecutablePageBoundary;
begin
  RunAndCompare('PrivateExecutablePageBoundary',
    procedure(Result: TScanResult; Target: TTargetProcess)
    begin
      Assert.IsTrue(Target.PrimaryAddress <> 0, 'Page-boundary executable address was not published');
      Assert.IsTrue(Result.Summary.ImplantedShellcode > 0, 'Pattern spanning an executable page boundary was not detected');
      Assert.IsTrue(Result.HasAddressFinding('workingset_scan', Target.PrimaryAddress), 'Page-boundary finding points to the wrong region');
    end);
end;

procedure TNativeMirrorScannerIntegrationTests.PrivateExecutableRegionTail;
begin
  RunAndCompare('PrivateExecutableRegionTail',
    procedure(Result: TScanResult; Target: TTargetProcess)
    begin
      Assert.IsTrue(Target.PrimaryAddress <> 0, 'Region-tail executable address was not published');
      Assert.IsTrue(Result.Summary.ImplantedShellcode > 0, 'Pattern ending at the executable region boundary was not detected');
      Assert.IsTrue(Result.HasAddressFinding('workingset_scan', Target.PrimaryAddress), 'Region-tail finding points to the wrong region');
    end);
end;

procedure TNativeMirrorScannerIntegrationTests.MultiplePrivateExecutableMemory;
begin
  RunAndCompare('MultiplePrivateExecutable',
    procedure(Result: TScanResult; Target: TTargetProcess)
    begin
      Assert.IsTrue(Target.PrimaryAddress <> 0, 'First private executable address was not published');
      Assert.IsTrue(Target.SecondaryAddress <> 0, 'Second private executable address was not published');
      Assert.IsTrue(Target.PrimaryAddress <> Target.SecondaryAddress, 'Private executable regions must be distinct');
      Assert.IsTrue(Result.Summary.ImplantedShellcode >= 2, 'Multiple private executable artifacts were not detected');
      Assert.IsTrue(Result.HasAddressFinding('workingset_scan', Target.PrimaryAddress), 'First private executable finding is missing');
      Assert.IsTrue(Result.HasAddressFinding('workingset_scan', Target.SecondaryAddress), 'Second private executable finding is missing');
    end);
end;

procedure TNativeMirrorScannerIntegrationTests.PrivateExecutableControl;
begin
  RunAndCompare('PrivateExecutableControl',
    procedure(Result: TScanResult; Target: TTargetProcess)
    begin
      Assert.IsTrue(Target.PrimaryAddress <> 0, 'Private executable control address was not published');
      Assert.AreEqual(0, Result.Summary.ImplantedShellcode, 'Unmatched private executable control must not be classified as shellcode');
      Assert.IsFalse(Result.HasAddressFinding('workingset_scan', Target.PrimaryAddress), 'Unmatched private executable control produced a suspicious memory finding');
    end);
end;

procedure TNativeMirrorScannerIntegrationTests.PrivateThreadStart;
begin
  RunAndCompare('PrivateThread',
    procedure(Result: TScanResult; Target: TTargetProcess)
    begin
      Assert.IsTrue(Target.PrimaryAddress <> 0, 'Private thread code address was not published');
      Assert.IsTrue(Target.ThreadId <> 0, 'Private thread ID was not published');
      Assert.IsTrue(Result.Summary.ImplantedShellcode > 0, 'Private executable thread start was not detected');
      Assert.IsTrue(Result.HasThreadFinding(Target.ThreadId), 'Thread finding does not point to the controlled private thread');
    end);
end;

procedure TNativeMirrorScannerIntegrationTests.MixedArtifacts;
begin
  RunAndCompare('Mixed',
    procedure(Result: TScanResult; Target: TTargetProcess)
    begin
      Assert.IsTrue(Result.Summary.Patched > 0, 'Mixed scenario missed the code patch');
      Assert.IsTrue(Result.Summary.IatHooked > 0, 'Mixed scenario missed the IAT redirect');
      Assert.IsTrue(Result.Summary.ImplantedPe > 0, 'Mixed scenario missed the private PE image');
      Assert.IsTrue(Result.Summary.ImplantedShellcode > 0, 'Mixed scenario missed the private thread');
      Assert.IsTrue(Target.SecondaryAddress <> 0, 'Mixed private thread code address was not published');
      Assert.IsTrue(Result.HasModuleFinding('code_scan', Target.ModulePath), 'Mixed code finding is not attached to the test target');
      Assert.IsTrue(Result.HasModuleFinding('iat_scan', Target.ModulePath), 'Mixed IAT finding is not attached to the test target');
      Assert.IsTrue(Result.HasAddressFinding('workingset_scan', Target.PrimaryAddress), 'Mixed PE finding points to the wrong region');
      Assert.IsTrue(Result.HasThreadFinding(Target.ThreadId), 'Mixed thread finding points to the wrong thread');
    end);
end;

procedure TNativeMirrorScannerIntegrationTests.ExtendedMixedArtifacts;
begin
  RunAndCompare('MixedExtended',
    procedure(Result: TScanResult; Target: TTargetProcess)
    begin
      Assert.IsTrue(Result.Summary.Patched > 0, 'Extended mixed scenario missed code patches');
      Assert.IsTrue(Result.Summary.IatHooked > 0, 'Extended mixed scenario missed the IAT redirect');
      Assert.IsTrue(Result.Summary.ImplantedPe >= 2, 'Extended mixed scenario missed private PE images');
      Assert.IsTrue(Result.Summary.ImplantedShellcode > 0, 'Extended mixed scenario missed private executable artifacts');
      Assert.IsTrue(Target.PrimaryAddress <> 0, 'Extended mixed first PE address was not published');
      Assert.IsTrue(Target.SecondaryAddress <> 0, 'Extended mixed second PE address was not published');
      Assert.IsTrue(Target.ThirdAddress <> 0, 'Extended mixed pattern address was not published');
      Assert.IsTrue(Target.ThreadId <> 0, 'Extended mixed thread ID was not published');
      Assert.IsTrue(Result.HasModuleFinding('code_scan', Target.ModulePath), 'Extended mixed code finding is not attached to the target');
      Assert.IsTrue(Result.HasModuleFinding('iat_scan', Target.ModulePath), 'Extended mixed IAT finding is not attached to the target');
      Assert.IsTrue(Result.HasAddressFinding('workingset_scan', Target.PrimaryAddress), 'Extended mixed first PE finding is missing');
      Assert.IsTrue(Result.HasAddressFinding('workingset_scan', Target.SecondaryAddress), 'Extended mixed second PE finding is missing');
      Assert.IsTrue(Result.HasAddressFinding('workingset_scan', Target.ThirdAddress), 'Extended mixed pattern finding is missing');
      Assert.IsTrue(Result.HasThreadFinding(Target.ThreadId), 'Extended mixed thread finding points to the wrong thread');
    end);
end;

procedure TNativeMirrorScannerIntegrationTests.CleanProcess32;
begin
  RunAndCompare('Clean',
    procedure(Result: TScanResult; Target: TTargetProcess)
    begin
      Assert.AreEqual(0, Result.Summary.Suspicious, 'Win32 clean target must not be suspicious');
    end, True);
end;

procedure TNativeMirrorScannerIntegrationTests.ExecutableCodePatch32;
begin
  RunAndCompare('CodePatch',
    procedure(Result: TScanResult; Target: TTargetProcess)
    begin
      Assert.IsTrue(Result.Summary.Patched > 0, 'Win32 executable code patch was not detected');
      Assert.IsTrue(Result.HasModuleFinding('code_scan', Target.ModulePath), 'Win32 code patch finding is not attached to the target');
    end, True);
end;

procedure TNativeMirrorScannerIntegrationTests.IatRedirect32;
begin
  RunAndCompare('IatRedirect',
    procedure(Result: TScanResult; Target: TTargetProcess)
    begin
      Assert.IsTrue(Result.Summary.IatHooked > 0, 'Win32 IAT redirect was not detected');
      Assert.IsTrue(Result.HasModuleFinding('iat_scan', Target.ModulePath), 'Win32 IAT finding is not attached to the target');
    end, True);
end;

procedure TNativeMirrorScannerIntegrationTests.PrivatePeImage32;
begin
  RunAndCompare('PrivatePe',
    procedure(Result: TScanResult; Target: TTargetProcess)
    begin
      Assert.IsTrue(Target.PrimaryAddress <> 0, 'Win32 private PE address was not published');
      Assert.IsTrue(Result.Summary.ImplantedPe > 0, 'Win32 private PE image was not detected');
      Assert.IsTrue(Result.HasAddressFinding('workingset_scan', Target.PrimaryAddress), 'Win32 private PE finding points to the wrong region');
    end, True);
end;

procedure TNativeMirrorScannerIntegrationTests.PrivateExecutableMemory32;
begin
  RunAndCompare('PrivateExecutable',
    procedure(Result: TScanResult; Target: TTargetProcess)
    begin
      Assert.IsTrue(Target.PrimaryAddress <> 0, 'Win32 private executable address was not published');
      Assert.IsTrue(Result.Summary.ImplantedShellcode > 0, 'Win32 pattern-matched private executable artifact was not detected');
      Assert.IsTrue(Result.HasAddressFinding('workingset_scan', Target.PrimaryAddress), 'Win32 private executable finding points to the wrong region');
    end, True);
end;

initialization
  TDUnitX.RegisterTestFixture(TNativeMirrorScannerIntegrationTests);

end.
