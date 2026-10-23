unit NativeMirror.Core.Text;

interface

uses
  System.Generics.Collections;

function ToLowerInvariant(const Value: string): string;
function IsStringInList(const Value: string; Values: TList<string>; IgnoreCase: Boolean = True): Boolean;
function StringToList(const Value: string; Delimiter: Char; Values: TList<string>; ToLower: Boolean = False): NativeUInt;

implementation

uses
  System.SysUtils;

function ToLowerInvariant(const Value: string): string;
begin
  Result := LowerCase(Value);
end;

function IsStringInList(const Value: string; Values: TList<string>; IgnoreCase: Boolean): Boolean;
var
  Item: string;
begin
  Result := False;
  if Values = nil then
    Exit;
  for Item in Values do
    if (IgnoreCase and SameText(Value, Item)) or ((not IgnoreCase) and (Value = Item)) then
      Exit(True);
end;

function StringToList(const Value: string; Delimiter: Char; Values: TList<string>; ToLower: Boolean): NativeUInt;
var
  Parts: TArray<string>;
  Part: string;
  Item: string;
begin
  Result := 0;
  if Values = nil then
    Exit;
  Parts := Value.Split([Delimiter]);
  for Part in Parts do
  begin
    Item := Trim(Part);
    if Item = '' then
      Continue;
    if ToLower then
      Item := LowerCase(Item);
    if Values.IndexOf(Item) < 0 then
    begin
      Values.Add(Item);
      Inc(Result);
    end;
  end;
end;

end.
