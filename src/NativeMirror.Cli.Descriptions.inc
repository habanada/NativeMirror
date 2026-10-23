function ParamDescription(Index: Integer; Extended: Boolean): string;
begin
  Result := '';
  case Index of
    0:
      begin
        Result :=
          'data <*data_scan_mode>' + sLineBreak +
          '' + #9 + ' : Set if non-executable pages should be scanned.' + sLineBreak;
        if Extended then Result := Result +
          '*data_scan_mode:' + sLineBreak +
          '' + #9 + '0 - none: do not scan non-executable pages' + sLineBreak +
          '' + #9 + '1 - .NET: scan non-executable in .NET applications' + sLineBreak +
          '' + #9 + '2 - if no DEP: scan non-exec if DEP is disabled (or if is .NET)' + sLineBreak +
          '' + #9 + '3 - always: scan non-executable pages unconditionally' + sLineBreak +
          '' + #9 + '4 - include inaccessible: scan non-executable pages unconditionally;' + sLineBreak +
          '' + #9 + '    in reflection mode (/refl): scan also inaccessible pages' + sLineBreak +
          '' + #9 + '5 - scan inaccessible pages, but exclude other non-executable;' + sLineBreak +
          '' + #9 + '    works in reflection mode (/refl) only' + sLineBreak;
      end;
    1:
      begin
        Result :=
          'dir <string>' + sLineBreak +
          '' + #9 + ' : Set a root directory for the output (default: current directory).' + sLineBreak;
      end;
    2:
      begin
        Result :=
          'dmode <*dump_mode>' + sLineBreak +
          '' + #9 + ' : Set in which mode the detected PE files should be dumped.' + sLineBreak;
        if Extended then Result := Result +
          '*dump_mode:' + sLineBreak +
          '' + #9 + '0 (A) - autodetect (default)' + sLineBreak +
          '' + #9 + '1 (V) - virtual (as is in the memory, no unmapping)' + sLineBreak +
          '' + #9 + '2 (U) - unmapped (converted to raw using sections'' raw headers)' + sLineBreak +
          '' + #9 + '3 (R) - realigned raw (converted raw format to be the same as virtual)' + sLineBreak;
      end;
    3:
      begin
        Result :=
          'dnet <*dotnet_policy>' + sLineBreak +
          '' + #9 + ' : Set the policy for scanning managed processes (.NET).' + sLineBreak;
        if Extended then Result := Result +
          '*dotnet_policy:' + sLineBreak +
          '' + #9 + '0 - none: treat managed processes same as native' + sLineBreak +
          '' + #9 + '1 - skip mapping mismatch (in .NET modules only)' + sLineBreak +
          '' + #9 + '2 - skip shellcodes (in all modules within the managed process)' + sLineBreak +
          '' + #9 + '3 - skip hooked modules (in all modules within the managed process)' + sLineBreak +
          '' + #9 + '4 - skip all the above (mapping, shellcodes, hooks)' + sLineBreak;
      end;
    4:
      begin
        Result :=
          'iat <*iat_scan_mode>' + sLineBreak +
          '' + #9 + ' : Scan for IAT hooks.' + sLineBreak;
        if Extended then Result := Result +
          '*iat_scan_mode:' + sLineBreak +
          '' + #9 + '0 - none: do not scan for IAT Hooks (default)' + sLineBreak +
          '' + #9 + '1 - scan IAT, filter hooks that lead to unpatched system module' + sLineBreak +
          '' + #9 + '2 - scan IAT, filter hooks that lead to ANY system module' + sLineBreak +
          '' + #9 + '3 - unfiltered: scan for IAT Hooks, report all' + sLineBreak;
      end;
    5:
      begin
        Result :=
          'imp <*imprec_mode>' + sLineBreak +
          '' + #9 + ' : Set in which mode the ImportTable should be recovered' + sLineBreak;
        if Extended then Result := Result +
          '*imprec_mode:' + sLineBreak +
          '' + #9 + '0 (N) - none: do not recover imports (default)' + sLineBreak +
          '' + #9 + '1 (A) - try to autodetect the most suitable mode' + sLineBreak +
          '' + #9 + '2 (U) - unerase the erased parts of the partialy damaged ImportTable' + sLineBreak +
          '' + #9 + '3 (R0) - build the ImportTable from scratch, basing on the found IATs:' + sLineBreak +
          '' + #9 + '         use only terminated blocks (restrictive mode)' + sLineBreak +
          '' + #9 + '4 (R1) - build the ImportTable from scratch, basing on the found IATs:' + sLineBreak +
          '' + #9 + '         use terminated blocks, or blocks with more than 1 thunk' + sLineBreak +
          '' + #9 + '5 (R2) - build the ImportTable from scratch, basing on the found IATs:' + sLineBreak +
          '' + #9 + '         use all found blocks (aggressive mode)' + sLineBreak;
      end;
    6:
      begin
        Result :=
          'jlvl <*json_lvl>' + sLineBreak +
          '' + #9 + ' : Level of details of the JSON report.' + sLineBreak;
        if Extended then Result := Result +
          '*json_lvl:' + sLineBreak +
          '' + #9 + '0 - basic (default)' + sLineBreak +
          '' + #9 + '1 - details #1 (medium)' + sLineBreak +
          '' + #9 + '2 - details #2 (verbose)' + sLineBreak;
      end;
    7:
      begin
        Result :=
          'json' + sLineBreak +
          '' + #9 + ' : Print the JSON report as the summary.' + sLineBreak;
      end;
    8:
      begin
        Result :=
          'mignore <list: separated by '';''>' + sLineBreak +
          '' + #9 + ' : Do not scan module/s with given name/s.' + sLineBreak;
        if Extended then Result := Result +
          '' + #9 + '   Example: kernel32.dll;user32.dll' + sLineBreak;
      end;
    9:
      begin
        Result :=
          'minidmp' + sLineBreak +
          '' + #9 + ' : Create a minidump of the full suspicious process.' + sLineBreak;
      end;
    10:
      begin
        Result :=
          'obfusc <*obfusc_mode>' + sLineBreak +
          '' + #9 + ' : Detect encrypted content, and possible obfuscated shellcodes.' + sLineBreak;
        if Extended then Result := Result +
          '*obfusc_mode:' + sLineBreak +
          '' + #9 + '0 (N) - none: do not detect obfuscated areas' + sLineBreak +
          '' + #9 + '1 (S) - detect areas possibly encrypted with strong encryption' + sLineBreak +
          '' + #9 + '2 (W) - detect areas possibly encrypted with weak encryption (lower entropy, possible XOR patterns)' + sLineBreak +
          '' + #9 + '3 (A) - detect any: possible strong or weak encryption' + sLineBreak;
      end;
    11:
      begin
        Result :=
          'ofilter <*ofilter_id>' + sLineBreak +
          '' + #9 + ' : Filter the dumped output.' + sLineBreak;
        if Extended then Result := Result +
          '*ofilter_id:' + sLineBreak +
          '' + #9 + '0 - no filter: dump everything (default)' + sLineBreak +
          '' + #9 + '1 - don''t dump the modified PEs, but save the report' + sLineBreak +
          '' + #9 + '2 - don''t dump any files' + sLineBreak;
      end;
    12:
      begin
        Result :=
          'pattern <string>' + sLineBreak +
          '' + #9 + ' : Set additional shellcode patterns (file in the SIG format).' + sLineBreak;
      end;
    13:
      begin
        Result :=
          'pid <integer: decimal, or hexadecimal with ''0x'' prefix>' + sLineBreak +
          '' + #9 + ' : Set the PID of the target process.' + sLineBreak;
      end;
    14:
      begin
        Result :=
          'quiet' + sLineBreak +
          '' + #9 + ' : Print only the summary. Do not log on stdout during the scan.' + sLineBreak;
      end;
    15:
      begin
        Result :=
          'rebase' + sLineBreak +
          '' + #9 + ' : Rebase the module to its original base (if known).' + sLineBreak;
      end;
    16:
      begin
        Result :=
          'refl' + sLineBreak +
          '' + #9 + ' : Make a process reflection before scan.' + sLineBreak;
        if Extended then Result := Result +
          '' + #9 + '   This allows i.e. to force-read inaccessible pages.' + sLineBreak;
      end;
    17:
      begin
        Result :=
          'report <*result_type>' + sLineBreak +
          '' + #9 + ' : Define what type of results are reported.' + sLineBreak;
        if Extended then Result := Result +
          '*result_type:' + sLineBreak +
          '' + #9 + '4 (S) - only suspicious (default)' + sLineBreak +
          '' + #9 + '5 (SE) - suspicious and errors' + sLineBreak +
          '' + #9 + '7 (L) - all scanned' + sLineBreak;
      end;
    18:
      begin
        Result :=
          'shellc <*shellc_mode>' + sLineBreak +
          '' + #9 + ' : Detect shellcode implants (by patterns or statistics). ' + sLineBreak;
        if Extended then Result := Result +
          '*shellc_mode:' + sLineBreak +
          '' + #9 + '0 (N) - none: do not detect shellcodes' + sLineBreak +
          '' + #9 + '1 (P) - detect shellcodes by patterns' + sLineBreak +
          '' + #9 + '2 (S) - detect shellcodes by stats' + sLineBreak +
          '' + #9 + '3 (A) - detect shellcodes by patterns or stats (any match)' + sLineBreak +
          '' + #9 + '4 (B) - detect shellcodes by patterns and stats (both match)' + sLineBreak;
      end;
    19:
      begin
        Result :=
          'sym' + sLineBreak +
          '' + #9 + ' : Autodownload symbols for scanned modules.' + sLineBreak;
      end;
    20:
      begin
        Result :=
          'threads' + sLineBreak +
          '' + #9 + ' : Scan threads'' callstack. Detect shellcodes, incl. ''sleeping beacons''.' + sLineBreak;
      end;
  end;
end;
