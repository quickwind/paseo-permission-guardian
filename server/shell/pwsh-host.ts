import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { createServer, type Server, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { win32 } from "node:path";

export type PwshShellVariant = "pwsh5" | "pwsh7";

export interface PwshHostParseError {
  errorId: string;
  startOffset: number;
  endOffset: number;
}

export interface PwshHostEnvRead {
  name: string;
  site: "bare" | "expandable" | "hereDouble";
}

export interface PwshHostEnvWrite {
  name: string;
  operator: string;
  valueStatic: string | null;
  isNull: boolean;
}

export interface PwshHostVarWrite {
  varName: string;
  rootVarName: string;
  isIndexed: boolean;
  operator: string;
  valueStatic: string | null;
  isConstant: boolean;
}

export interface PwshHostCommandElement {
  kind: "parameter" | "arg";
  parameterName?: string;
  hasColonArg?: boolean;
  argStaticValue?: string | null;
  astType?: string;
  staticValue?: string | null;
  stringConstantType?: string;
  isConstant?: boolean;
  arrayStaticValues?: string[] | null;
  hashtableEntries?: Array<{ key: string; valueStatic: string | null; isNull: boolean; isConstant: boolean }>;
  hashtableAllKeysStatic?: boolean;
}

export interface PwshHostRedirection {
  operator: string;
  targetStatic: string | null;
}

export interface PwshHostCommand {
  name: string | null;
  rawName: string;
  invocationOperator: string;
  pipelineId: number;
  pipelineIndex: number;
  scriptBlockDepth: number;
  inConditionalOrLoop: boolean;
  nativeArgQuirk: boolean;
  elements: PwshHostCommandElement[];
  redirections: PwshHostRedirection[];
}

export interface PwshHostMemberInvocation {
  static: boolean;
  typeName: string;
  isLiteralType?: boolean;
  member: string;
  isAssignmentTarget: boolean;
  scriptBlockDepth?: number;
  inConditionalOrLoop?: boolean;
  args: Array<{ isConstant: boolean; staticValue: string | null }>;
}

export interface PwshHostAstPayload {
  psEdition: string;
  psVersion: string;
  languageMode: string;
  parseErrors: PwshHostParseError[];
  nodeTypeCensus: string[];
  stopParsingSpans: string[];
  backtickCommandSkew: boolean;
  charCastCount: number;
  hasSplatting: boolean;
  envReads: PwshHostEnvRead[];
  envWrites: PwshHostEnvWrite[];
  varWrites: PwshHostVarWrite[];
  commands: PwshHostCommand[];
  memberInvocations: PwshHostMemberInvocation[];
  functionDefs: string[];
  usingModules: string[];
}

export type PwshHostResult =
  | { ok: true; payload: PwshHostAstPayload }
  | { ok: false; reason: string };

export interface PwshHostOptions {
  allowPosixHost?: boolean;
  binaryPath?: string;
  warmTimeoutMs?: number;
  coldTimeoutMs?: number;
}

export const PS_HOST_BOOTSTRAP_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
try {
  $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
  $inR = [System.IO.StreamReader]::new([Console]::OpenStandardInput(), $utf8NoBom)
  $outW = [System.IO.StreamWriter]::new([Console]::OpenStandardOutput(), $utf8NoBom)
  $outW.AutoFlush = $true
  $b64 = $inR.ReadLine()
  if ($null -eq $b64) { exit 0 }
  $code = $utf8NoBom.GetString([Convert]::FromBase64String($b64))
  & ([scriptblock]::Create($code)) $inR $outW
} catch {
  [Console]::Error.WriteLine($_.Exception.GetType().FullName + ':' + $_.Exception.Message)
  exit 2
}
`;

export function getBootstrapEncodedCommandLength(): number {
  return Buffer.from(PS_HOST_BOOTSTRAP_SCRIPT, "utf16le").toString("base64").length;
}

// Parse-only NDJSON script compatible with BOTH Windows PowerShell 5.1 (.NET 4.x) and PowerShell 7+
const PS_HOST_SCRIPT = String.raw`
param($inReader, $outWriter)
$ErrorActionPreference = 'Stop'
$script:inReader = $inReader
$script:outWriter = $outWriter
if ($null -eq $script:inReader) {
  $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
  $script:inReader = [System.IO.StreamReader]::new([Console]::OpenStandardInput(), $utf8NoBom)
  $script:outWriter = [System.IO.StreamWriter]::new([Console]::OpenStandardOutput(), $utf8NoBom)
  $script:outWriter.AutoFlush = $true
}
$script:isPs5 = ($PSVersionTable.PSVersion.Major -lt 6)
$script:traceCold = $script:isPs5
if ($script:traceCold) { $script:outWriter.WriteLine('__ST:host_enter') }
$script:jsSer = $null
if ($script:isPs5) {
  [void][System.Reflection.Assembly]::Load('System.Web.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35')
  $script:jsSer = [System.Web.Script.Serialization.JavaScriptSerializer]::new()
  $script:jsSer.MaxJsonLength = 8388608
  $script:jsSer.RecursionLimit = 100
  if ($script:traceCold) { $script:outWriter.WriteLine('__ST:host_ser_ok') }
}

function Decode-HostJson([string]$json) {
  if ($script:isPs5) { return $script:jsSer.DeserializeObject($json) }
  return ($json | ConvertFrom-Json)
}

function Encode-HostJson($obj) {
  if ($script:isPs5) { return $script:jsSer.Serialize($obj) }
  return ($obj | ConvertTo-Json -Depth 12 -Compress)
}

$script:SAFE_STATIC_ENV_RX = '^(?:SystemRoot|WINDIR|USERPROFILE|APPDATA|LOCALAPPDATA|PROGRAMDATA|PROGRAMFILES|TEMP|TMP|HOMEDRIVE|HOMEPATH)$'

function Get-StaticVal($node) {
  if ($null -eq $node) { return $null }
  $t = $node.GetType().Name
  if ($t -eq 'CommandExpressionAst') { return Get-StaticVal $node.Expression }
  if ($t -eq 'ParenExpressionAst') {
    if ($node.Pipeline -and $node.Pipeline.PipelineElements.Count -eq 1) {
      return Get-StaticVal $node.Pipeline.PipelineElements[0]
    }
    return $null
  }
  if ($t -eq 'StringConstantExpressionAst') { return [string]$node.Value }
  if ($t -eq 'ConstantExpressionAst') {
    if ($null -eq $node.Value) { return '' }
    return [string]$node.Value
  }
  if ($t -eq 'ExpandableStringExpressionAst') {
    if ($node.NestedExpressions.Count -eq 0) { return [string]$node.Value }
    foreach ($ne in $node.NestedExpressions) {
      if ($ne.GetType().Name -ne 'VariableExpressionAst') { return $null }
      $vp = $ne.VariablePath
      if ($vp.IsDriveQualified) {
        if ($vp.DriveName -ine 'env') { return $null }
        $en = $vp.UserPath -replace '^[eE][nN][vV]:', ''
        if (-not ($en -match $script:SAFE_STATIC_ENV_RX)) { return $null }
      } elseif ($vp.UserPath -ine 'HOME') {
        return $null
      }
    }
    return [string]$node.Value
  }
  if ($t -eq 'VariableExpressionAst') {
    $vp = $node.VariablePath.UserPath
    if ($vp -ieq 'null') { return '' }
    if ($vp -ieq 'true') { return 'True' }
    if ($vp -ieq 'false') { return 'False' }
    return $null
  }
  return $null
}

function Get-MemberTypeInfo($expr) {
  $cur = $expr
  while ($null -ne $cur) {
    $ct = $cur.GetType().Name
    if ($ct -eq 'ParenExpressionAst' -and $cur.Pipeline -and $cur.Pipeline.PipelineElements.Count -eq 1) {
      $cur = $cur.Pipeline.PipelineElements[0]
      continue
    }
    if ($ct -eq 'CommandExpressionAst') {
      $cur = $cur.Expression
      continue
    }
    break
  }
  if ($null -ne $cur -and $cur.GetType().Name -eq 'TypeExpressionAst') {
    return @{ isLit = $true; name = [string]$cur.TypeName.FullName }
  }
  return @{ isLit = $false; name = [string]$expr.Extent.Text }
}

function Test-IsNullExpr($node) {
  if ($null -eq $node) { return $true }
  $t = $node.GetType().Name
  if ($t -eq 'CommandExpressionAst') { return Test-IsNullExpr $node.Expression }
  if ($t -eq 'VariableExpressionAst') { return $node.VariablePath.UserPath -ieq 'null' }
  return $false
}

function Test-SafeEncodingExpr($node) {
  if ($null -eq $node) { return $false }
  $cur = $node
  while ($null -ne $cur) {
    $ct = $cur.GetType().Name
    if ($ct -eq 'CommandExpressionAst') {
      $cur = $cur.Expression
      continue
    }
    if ($ct -eq 'ParenExpressionAst') {
      if ($cur.Pipeline -and $cur.Pipeline.PipelineElements.Count -eq 1) {
        $cur = $cur.Pipeline.PipelineElements[0]
        continue
      }
      return $false
    }
    break
  }
  if ($null -eq $cur -or $cur.GetType().Name -ne 'MemberExpressionAst') { return $false }
  if (-not $cur.Static) { return $false }
  if ($cur.Expression.GetType().Name -ne 'TypeExpressionAst') { return $false }
  if (-not ($cur.Expression.TypeName.FullName -match '^(?:System\.)?Text\.Encoding$')) { return $false }
  return ($cur.Member.GetType().Name -eq 'StringConstantExpressionAst')
}

function Get-AncestorInfo($node) {
  $depth = 0
  $condOrLoop = $false
  $cur = $node.Parent
  while ($null -ne $cur) {
    $cn = $cur.GetType().Name
    if ($cn -eq 'ScriptBlockAst') { $depth++ }
    if ($cn -eq 'IfStatementAst' -or $cn -eq 'ForStatementAst' -or $cn -eq 'ForEachStatementAst' -or $cn -eq 'WhileStatementAst' -or $cn -eq 'DoWhileStatementAst' -or $cn -eq 'DoUntilStatementAst' -or $cn -eq 'SwitchStatementAst' -or $cn -eq 'CatchClauseAst' -or $cn -eq 'TrapStatementAst' -or $cn -eq 'FunctionDefinitionAst' -or $cn -eq 'ScriptBlockExpressionAst') {
      $condOrLoop = $true
    }
    if ($cn -eq 'PipelineChainAst') {
      if ($cur.Operator.ToString() -eq 'OrOr' -or $cur.Background) { $condOrLoop = $true }
    }
    $cur = $cur.Parent
  }
  return @{ depth = $depth; cond = $condOrLoop }
}

while ($true) {
  if ($script:traceCold) { $script:outWriter.WriteLine('__ST:host_wait_req') }
  $line = $script:inReader.ReadLine()
  if ($null -eq $line) { break }
  if ($line.Length -eq 0) { continue }
  if ($script:traceCold) { $script:outWriter.WriteLine('__ST:host_got_req') }
  $reqId = ''
  try {
    $req = Decode-HostJson $line
    if ($req -is [System.Collections.IDictionary]) {
      $reqId = [string]$req['id']
      $src = [string]$req['source']
    } else {
      $reqId = [string]$req.id
      $src = [string]$req.source
    }

    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$tokens, [ref]$errors)
    if ($script:traceCold) { $script:outWriter.WriteLine('__ST:host_parsed') }

    $allNodes = @($ast.FindAll({ $true }, $true))
    $censusSet = [System.Collections.Generic.HashSet[string]]::new()
    $assignNodes = @()
    $varNodes = @()
    $convNodes = @()
    $invokeNodes = @()
    $pipeNodes = @()
    $cmdNodes = @()
    $fnNames = @()
    $usingMods = @()
    foreach ($nd in $allNodes) {
      $nt = $nd.GetType().Name
      [void]$censusSet.Add($nt)
      if ($nt -eq 'AssignmentStatementAst') { $assignNodes += $nd }
      elseif ($nt -eq 'VariableExpressionAst') { $varNodes += $nd }
      elseif ($nt -eq 'ConvertExpressionAst') { $convNodes += $nd }
      elseif ($nt -eq 'InvokeMemberExpressionAst' -or $nt -eq 'MemberExpressionAst') { $invokeNodes += $nd }
      elseif ($nt -eq 'PipelineAst') { $pipeNodes += $nd }
      elseif ($nt -eq 'CommandAst') { $cmdNodes += $nd }
      elseif ($nt -eq 'FunctionDefinitionAst') { $fnNames += [string]$nd.Name }
      elseif ($nt -eq 'UsingStatementAst') { $usingMods += "$($nd.UsingStatementKind):$($nd.Name.Value)" }
    }
    $census = [string[]]::new($censusSet.Count)
    $censusSet.CopyTo($census)
    [Array]::Sort($census)

    $errList = @()
    if ($errors) {
      foreach ($e in $errors) {
        $errList += @{
          errorId = [string]$e.ErrorId
          startOffset = [int]$e.Extent.StartOffset
          endOffset = [int]$e.Extent.EndOffset
        }
      }
    }

    $stopSpans = @()
    if ($tokens) {
      foreach ($tok in $tokens) {
        if ($tok.Text -eq '--%' -and $tok.Kind.ToString() -eq 'Generic') {
          $startOff = [int]$tok.Extent.EndOffset
          if ($startOff -lt $src.Length) {
            $nlIdx = $src.IndexOf([char]10, $startOff)
            $spanLen = if ($nlIdx -ge 0) { $nlIdx - $startOff } else { $src.Length - $startOff }
            $stopSpans += $src.Substring($startOff, $spanLen).Trim()
          }
        }
      }
    }

    # Build lookup of Equals-assignment LHS nodes so $env:X = 'val' is not counted as an envRead
    $equalsLeftIds = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($an in $assignNodes) {
      if ($an.Operator.ToString() -eq 'Equals') {
        $key = "$($an.Left.Extent.StartOffset):$($an.Left.Extent.EndOffset)"
        [void]$equalsLeftIds.Add($key)
      }
    }

    $envReads = @()
    $hasSplatting = $false
    $charCastCount = 0
    foreach ($vn in $varNodes) {
      if ($vn.Splatted) { $hasSplatting = $true }
      $vp = $vn.VariablePath
      if ($vp.IsDriveQualified -and $vp.DriveName -ieq 'env') {
        $vKey = "$($vn.Extent.StartOffset):$($vn.Extent.EndOffset)"
        if (-not $equalsLeftIds.Contains($vKey)) {
          $envName = $vp.UserPath -replace '^[eE][nN][vV]:', ''
          $site = 'bare'
          $p = $vn.Parent
          while ($null -ne $p) {
            if ($p.GetType().Name -eq 'ExpandableStringExpressionAst') {
              $site = if ($p.StringConstantType.ToString() -eq 'DoubleQuotedHereString') { 'hereDouble' } else { 'expandable' }
              break
            }
            $p = $p.Parent
          }
          $envReads += @{ name = $envName; site = $site }
        }
      }
    }

    foreach ($cn in $convNodes) {
      if ($cn.Type.TypeName.Name -ieq 'char') { $charCastCount++ }
    }

    $envWrites = @()
    $varWrites = @()
    $memberAssignKeys = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($an in $assignNodes) {
      $left = $an.Left
      $lt = $left.GetType().Name
      $op = $an.Operator.ToString()
      $valStatic = Get-StaticVal $an.Right
      $isNull = Test-IsNullExpr $an.Right
      $isConst = ($null -ne $valStatic)

      if ($lt -eq 'VariableExpressionAst' -and $left.VariablePath.IsDriveQualified -and $left.VariablePath.DriveName -ieq 'env') {
        $envName = $left.VariablePath.UserPath -replace '^[eE][nN][vV]:', ''
        $envWrites += @{
          name = $envName
          operator = $op
          valueStatic = $valStatic
          isNull = $isNull
        }
      } elseif ($lt -eq 'VariableExpressionAst') {
        $varWrites += @{
          varName = [string]$left.VariablePath.UserPath
          rootVarName = [string]$left.VariablePath.UserPath
          isIndexed = $false
          operator = $op
          valueStatic = $valStatic
          isConstant = $isConst
        }
      } elseif ($lt -eq 'IndexExpressionAst') {
        $rootName = if ($left.Target.GetType().Name -eq 'VariableExpressionAst') { [string]$left.Target.VariablePath.UserPath } else { [string]$left.Target.Extent.Text }
        $varWrites += @{
          varName = [string]$left.Extent.Text
          rootVarName = $rootName
          isIndexed = $true
          operator = $op
          valueStatic = $valStatic
          isConstant = $isConst
        }
      } elseif ($lt -eq 'MemberExpressionAst') {
        $mKey = "$($left.Extent.StartOffset):$($left.Extent.EndOffset)"
        [void]$memberAssignKeys.Add($mKey)
        $mTypeInfo = Get-MemberTypeInfo $left.Expression
        $typeNm = $mTypeInfo.name
        $memName = [string]$left.Member.Extent.Text
        $memIsConst = $isConst
        if (-not $memIsConst -and $mTypeInfo.isLit -and $typeNm -match '^(?:System\.)?Console$' -and $memName -match '^(?:OutputEncoding|InputEncoding)$') {
          if (Test-SafeEncodingExpr $an.Right) { $memIsConst = $true }
        }
        $varWrites += @{
          varName = "$($typeNm)::$($memName)"
          rootVarName = $typeNm
          isIndexed = $false
          operator = $op
          valueStatic = $valStatic
          isConstant = $memIsConst
        }
      }
    }

    $memberCalls = @()
    foreach ($mn in $invokeNodes) {
      $isInvoke = ($mn.GetType().Name -eq 'InvokeMemberExpressionAst')
      $mKey = "$($mn.Extent.StartOffset):$($mn.Extent.EndOffset)"
      $isAssign = $memberAssignKeys.Contains($mKey)
      if (-not $isInvoke -and -not $isAssign) { continue }
      $mTypeInfo = Get-MemberTypeInfo $mn.Expression
      $mAnc = Get-AncestorInfo $mn
      $argList = @()
      if ($isInvoke -and $mn.Arguments) {
        foreach ($arg in $mn.Arguments) {
          $av = Get-StaticVal $arg
          $argList += @{ isConstant = ($null -ne $av); staticValue = $av }
        }
      } elseif ($isAssign -and $mn.Parent.GetType().Name -eq 'AssignmentStatementAst') {
        $av = Get-StaticVal $mn.Parent.Right
        $argList += @{ isConstant = ($null -ne $av); staticValue = $av }
      }
      $memberCalls += @{
        static = [bool]$mn.Static
        typeName = $mTypeInfo.name
        isLiteralType = [bool]$mTypeInfo.isLit
        member = [string]$mn.Member.Extent.Text
        isAssignmentTarget = $isAssign
        scriptBlockDepth = [int]$mAnc.depth
        inConditionalOrLoop = [bool]$mAnc.cond
        args = $argList
      }
    }

    $pipeIdMap = @{}
    $nextPipeId = 1
    foreach ($pn in $pipeNodes) {
      $pKey = "$($pn.Extent.StartOffset):$($pn.Extent.EndOffset)"
      $pipeIdMap[$pKey] = $nextPipeId
      $nextPipeId++
    }

    $cmdList = @()
    $backtickSkew = $false
    foreach ($cm in $cmdNodes) {
      $cmdName = $cm.GetCommandName()
      $rawFirst = if ($cm.CommandElements.Count -gt 0) { [string]$cm.CommandElements[0].Extent.Text } else { '' }
      if ($rawFirst.Contains([char]96) -and $null -ne $cmdName -and -not ($rawFirst -match '^[''"]')) {
        $backtickSkew = $true
      }

      $anc = Get-AncestorInfo $cm
      $pipeId = 0
      $pipeIdx = 0
      if ($cm.Parent -and $cm.Parent.GetType().Name -eq 'PipelineAst') {
        $pk = "$($cm.Parent.Extent.StartOffset):$($cm.Parent.Extent.EndOffset)"
        if ($pipeIdMap.ContainsKey($pk)) { $pipeId = $pipeIdMap[$pk] }
        $elemsInPipe = $cm.Parent.PipelineElements
        for ($pi = 0; $pi -lt $elemsInPipe.Count; $pi++) {
          if ($elemsInPipe[$pi] -eq $cm) { $pipeIdx = $pi; break }
        }
      }

      $nativeQuirk = $false
      $outElems = @()
      $elemIdx = 0
      foreach ($el in $cm.CommandElements) {
        $et = $el.GetType().Name
        if ($et -eq 'CommandParameterAst') {
          $argVal = Get-StaticVal $el.Argument
          $outElems += @{
            kind = 'parameter'
            parameterName = [string]$el.ParameterName
            hasColonArg = ($null -ne $el.Argument)
            argStaticValue = $argVal
          }
        } elseif ($et -eq 'HashtableAst') {
          $entries = @()
          $allStatic = $true
          foreach ($kv in $el.KeyValuePairs) {
            $kVal = Get-StaticVal $kv.Item1
            if ($null -eq $kVal) { $allStatic = $false; continue }
            $vVal = Get-StaticVal $kv.Item2
            $entries += @{
              key = $kVal
              valueStatic = $vVal
              isNull = (Test-IsNullExpr $kv.Item2)
              isConstant = ($null -ne $vVal)
            }
          }
          $outElems += @{
            kind = 'arg'
            astType = $et
            isConstant = $false
            hashtableEntries = $entries
            hashtableAllKeysStatic = $allStatic
          }
        } else {
          $sv = Get-StaticVal $el
          $arrStatic = $null
          if ($et -eq 'ArrayLiteralAst') {
            $arrVals = @()
            $arrOk = $true
            foreach ($ae in $el.Elements) {
              $av = Get-StaticVal $ae
              if ($null -eq $av) { $arrOk = $false; break }
              $arrVals += $av
            }
            if ($arrOk -and $arrVals.Count -gt 0) {
              $arrStatic = [string[]]$arrVals
            }
          }
          $scType = if ($et -eq 'StringConstantExpressionAst') { $el.StringConstantType.ToString() } else { '' }
          if ($elemIdx -gt 0 -and $et -eq 'StringConstantExpressionAst') {
            if ($sv -eq '' -or ($null -ne $sv -and $sv.Contains('"'))) { $nativeQuirk = $true }
          }
          $outElems += @{
            kind = 'arg'
            astType = $et
            staticValue = $sv
            arrayStaticValues = $arrStatic
            stringConstantType = $scType
            isConstant = ($null -ne $sv)
          }
        }
        $elemIdx++
      }

      $redirs = @()
      foreach ($rd in $cm.Redirections) {
        $rt = $rd.GetType().Name
        if ($rt -eq 'FileRedirectionAst') {
          $opStr = if ($rd.Append) { "$($rd.FromStream)>>" } else { "$($rd.FromStream)>" }
          $redirs += @{
            operator = $opStr
            targetStatic = (Get-StaticVal $rd.Location)
          }
        } elseif ($rt -eq 'MergingRedirectionAst') {
          $redirs += @{
            operator = "$($rd.FromStream)>&$($rd.ToStream)"
            targetStatic = $null
          }
        }
      }

      $cmdList += @{
        name = $cmdName
        rawName = $rawFirst
        invocationOperator = $cm.InvocationOperator.ToString()
        pipelineId = $pipeId
        pipelineIndex = $pipeIdx
        scriptBlockDepth = [int]$anc.depth
        inConditionalOrLoop = [bool]$anc.cond
        nativeArgQuirk = $nativeQuirk
        elements = $outElems
        redirections = $redirs
      }
    }

    $payload = @{
      psEdition = [string]$PSVersionTable.PSEdition
      psVersion = [string]$PSVersionTable.PSVersion.ToString()
      languageMode = [string]$ExecutionContext.SessionState.LanguageMode
      parseErrors = $errList
      nodeTypeCensus = $census
      stopParsingSpans = $stopSpans
      backtickCommandSkew = $backtickSkew
      charCastCount = $charCastCount
      hasSplatting = $hasSplatting
      envReads = $envReads
      envWrites = $envWrites
      varWrites = $varWrites
      commands = $cmdList
      memberInvocations = $memberCalls
      functionDefs = $fnNames
      usingModules = $usingMods
    }

    $resp = @{ id = $reqId; ok = $true; payload = $payload }
    $script:outWriter.WriteLine((Encode-HostJson $resp))
    $script:outWriter.Flush()
    $script:traceCold = $false
  } catch {
    $errType = $_.Exception.GetType().Name
    $errResp = @{ id = $reqId; ok = $false; error = "host_exception:$errType" }
    $script:outWriter.WriteLine((Encode-HostJson $errResp))
    $script:outWriter.Flush()
    $script:traceCold = $false
  }
}
`;

const SYSTEM_POSIX_PWSH_PATHS = [
  "/opt/homebrew/bin/pwsh",
  "/usr/local/bin/pwsh",
  "/usr/bin/pwsh",
];

/**
 * Construct an explicit minimal environment for spawning the PowerShell parser host,
 * stripping COR_*, CORECLR_*, DOTNET_*, COMPLUS_*, PSModulePath, PSExecutionPolicyPreference, etc.
 */
export function buildSanitizedPwshEnv(
  platform: NodeJS.Platform = process.platform,
  sourceEnv: Record<string, string | undefined> = process.env,
): NodeJS.ProcessEnv {
  const clean: NodeJS.ProcessEnv = {};
  const allowKeys =
    platform === "win32"
      ? ["SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "COMSPEC", "OS", "TEMP", "TMP"]
      : ["LANG", "LC_ALL", "TMPDIR"];

  for (const key of allowKeys) {
    for (const [envK, envV] of Object.entries(sourceEnv)) {
      if (envK.toUpperCase() === key && typeof envV === "string" && envV.length > 0) {
        clean[key] = envV;
        break;
      }
    }
  }

  if (platform === "win32") {
    const sysRoot = clean.SYSTEMROOT ?? "C:\\Windows";
    clean.SYSTEMROOT = sysRoot;
    clean.WINDIR = clean.WINDIR ?? sysRoot;
    clean.PATHEXT = ".COM;.EXE";
  }

  return clean;
}

function getValidatedWindowsSystemRoot(): string {
  const raw = process.env.SystemRoot || process.env.SYSTEMROOT;
  if (raw && /^[A-Za-z]:\\(?:Windows|WINNT)$/i.test(raw.trim())) {
    return win32.normalize(raw.trim());
  }
  return "C:\\Windows";
}

function getValidatedWindowsProgramFiles(x86: boolean): string {
  const raw = x86 ? process.env["ProgramFiles(x86)"] : process.env.ProgramFiles;
  const rx = x86 ? /^[A-Za-z]:\\Program Files \(x86\)$/i : /^[A-Za-z]:\\Program Files$/i;
  if (raw && rx.test(raw.trim())) {
    return win32.normalize(raw.trim());
  }
  return x86 ? "C:\\Program Files (x86)" : "C:\\Program Files";
}

/**
 * Resolve PowerShell binary strictly from verified absolute system/install locations.
 * Never searches `PATH` or `cwd`.
 */
export function resolvePwshBinaryPath(
  shell: PwshShellVariant,
  options?: { allowPosixHost?: boolean; binaryPath?: string },
): string | null {
  if (options?.binaryPath) {
    return existsSync(options.binaryPath) ? options.binaryPath : null;
  }

  if (process.platform === "win32") {
    const sysRoot = getValidatedWindowsSystemRoot();
    if (shell === "pwsh5") {
      const ps5 = win32.join(sysRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
      return existsSync(ps5) ? ps5 : null;
    }

    const pfDirs = [
      getValidatedWindowsProgramFiles(false),
      getValidatedWindowsProgramFiles(true),
    ];
    const candidates: string[] = [];
    for (const pf of pfDirs) {
      candidates.push(win32.join(pf, "PowerShell", "7", "pwsh.exe"));
      candidates.push(win32.join(pf, "PowerShell", "7-preview", "pwsh.exe"));
    }
    for (const cand of candidates) {
      if (existsSync(cand)) return cand;
    }
    return null;
  }

  if (!options?.allowPosixHost || shell === "pwsh5") {
    return null;
  }

  for (const cand of SYSTEM_POSIX_PWSH_PATHS) {
    if (existsSync(cand)) return cand;
  }
  return null;
}

function asArray<T>(val: unknown): T[] {
  if (Array.isArray(val)) return val as T[];
  if (val === null || val === undefined) return [];
  return [val as T];
}

function normalizePayload(raw: Record<string, unknown>): PwshHostAstPayload {
  const rawCommands = asArray<Record<string, unknown>>(raw.commands).map((c) => ({
    name: typeof c.name === "string" ? c.name : null,
    rawName: typeof c.rawName === "string" ? c.rawName : "",
    invocationOperator: typeof c.invocationOperator === "string" ? c.invocationOperator : "Unknown",
    pipelineId: Number(c.pipelineId ?? 0),
    pipelineIndex: Number(c.pipelineIndex ?? 0),
    scriptBlockDepth: Number(c.scriptBlockDepth ?? 1),
    inConditionalOrLoop: Boolean(c.inConditionalOrLoop),
    nativeArgQuirk: Boolean(c.nativeArgQuirk),
    elements: asArray<Record<string, unknown>>(c.elements).map((el) => ({
      kind: (el.kind === "parameter" ? "parameter" : "arg") as "parameter" | "arg",
      ...(typeof el.parameterName === "string" ? { parameterName: el.parameterName } : {}),
      ...(el.hasColonArg !== undefined ? { hasColonArg: Boolean(el.hasColonArg) } : {}),
      ...(el.argStaticValue !== undefined
        ? { argStaticValue: typeof el.argStaticValue === "string" ? el.argStaticValue : null }
        : {}),
      ...(typeof el.astType === "string" ? { astType: el.astType } : {}),
      ...(el.staticValue !== undefined
        ? { staticValue: typeof el.staticValue === "string" ? el.staticValue : null }
        : {}),
      ...(Array.isArray(el.arrayStaticValues) || typeof el.arrayStaticValues === "string"
        ? {
            arrayStaticValues: asArray<unknown>(el.arrayStaticValues).filter(
              (x): x is string => typeof x === "string",
            ),
          }
        : el.arrayStaticValues !== undefined
          ? { arrayStaticValues: null }
          : {}),
      ...(typeof el.stringConstantType === "string"
        ? { stringConstantType: el.stringConstantType }
        : {}),
      ...(el.isConstant !== undefined ? { isConstant: Boolean(el.isConstant) } : {}),
      ...(el.hashtableEntries !== undefined
        ? {
            hashtableEntries: asArray<Record<string, unknown>>(el.hashtableEntries).map((h) => ({
              key: String(h.key ?? ""),
              valueStatic: typeof h.valueStatic === "string" ? h.valueStatic : null,
              isNull: Boolean(h.isNull),
              isConstant: Boolean(h.isConstant),
            })),
          }
        : {}),
      ...(el.hashtableAllKeysStatic !== undefined
        ? { hashtableAllKeysStatic: Boolean(el.hashtableAllKeysStatic) }
        : {}),
    })),
    redirections: asArray<Record<string, unknown>>(c.redirections).map((r) => ({
      operator: String(r.operator ?? ">"),
      targetStatic: typeof r.targetStatic === "string" ? r.targetStatic : null,
    })),
  }));

  return {
    psEdition: String(raw.psEdition ?? ""),
    psVersion: String(raw.psVersion ?? ""),
    languageMode: String(raw.languageMode ?? "FullLanguage"),
    parseErrors: asArray<Record<string, unknown>>(raw.parseErrors).map((e) => ({
      errorId: String(e.errorId ?? "parse_error"),
      startOffset: Number(e.startOffset ?? 0),
      endOffset: Number(e.endOffset ?? 0),
    })),
    nodeTypeCensus: asArray<string>(raw.nodeTypeCensus).map(String),
    stopParsingSpans: asArray<string>(raw.stopParsingSpans).map(String),
    backtickCommandSkew: Boolean(raw.backtickCommandSkew),
    charCastCount: Number(raw.charCastCount ?? 0),
    hasSplatting: Boolean(raw.hasSplatting),
    envReads: asArray<Record<string, unknown>>(raw.envReads).map((r) => ({
      name: String(r.name ?? ""),
      site: (r.site === "hereDouble" || r.site === "expandable" ? r.site : "bare") as
        | "bare"
        | "expandable"
        | "hereDouble",
    })),
    envWrites: asArray<Record<string, unknown>>(raw.envWrites).map((w) => ({
      name: String(w.name ?? ""),
      operator: String(w.operator ?? "Equals"),
      valueStatic: typeof w.valueStatic === "string" ? w.valueStatic : null,
      isNull: Boolean(w.isNull),
    })),
    varWrites: asArray<Record<string, unknown>>(raw.varWrites).map((w) => ({
      varName: String(w.varName ?? ""),
      rootVarName: String(w.rootVarName ?? ""),
      isIndexed: Boolean(w.isIndexed),
      operator: String(w.operator ?? "Equals"),
      valueStatic: typeof w.valueStatic === "string" ? w.valueStatic : null,
      isConstant: Boolean(w.isConstant),
    })),
    commands: rawCommands,
    memberInvocations: asArray<Record<string, unknown>>(raw.memberInvocations).map((m) => ({
      static: Boolean(m.static),
      typeName: String(m.typeName ?? ""),
      isLiteralType: m.isLiteralType !== undefined ? Boolean(m.isLiteralType) : true,
      member: String(m.member ?? ""),
      isAssignmentTarget: Boolean(m.isAssignmentTarget),
      scriptBlockDepth: m.scriptBlockDepth !== undefined ? Number(m.scriptBlockDepth) : 1,
      inConditionalOrLoop: Boolean(m.inConditionalOrLoop),
      args: asArray<Record<string, unknown>>(m.args).map((a) => ({
        isConstant: Boolean(a.isConstant),
        staticValue: typeof a.staticValue === "string" ? a.staticValue : null,
      })),
    })),
    functionDefs: asArray<string>(raw.functionDefs).map(String),
    usingModules: asArray<string>(raw.usingModules).map(String),
  };
}

const MAX_HOST_LINE_BYTES = 2 * 1024 * 1024;
const MAX_QUEUE_DEPTH = 64;

function buildPwsh5PipeBootstrapScript(pipeName: string, authToken: string): string {
  return [
    "$ErrorActionPreference = 'Stop'",
    "try {",
    "  $utf8NoBom = [System.Text.UTF8Encoding]::new($false)",
    `  $pipe = [System.IO.Pipes.NamedPipeClientStream]::new('.', '${pipeName}', [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::Asynchronous)`,
    "  $pipe.Connect(15000)",
    "  $inR = [System.IO.StreamReader]::new($pipe, $utf8NoBom)",
    "  $outW = [System.IO.StreamWriter]::new($pipe, $utf8NoBom)",
    "  $outW.AutoFlush = $true",
    `  $outW.WriteLine('${authToken}')`,
    "  $outW.WriteLine('__ST:boot_connected')",
    "  $b64 = $inR.ReadLine()",
    "  if ($null -eq $b64) { exit 0 }",
    "  $code = $utf8NoBom.GetString([Convert]::FromBase64String($b64))",
    "  $outW.WriteLine('__ST:boot_b64_ok')",
    "  $sb = [scriptblock]::Create($code)",
    "  $outW.WriteLine('__ST:boot_sb_created')",
    "  & $sb $inR $outW",
    "} catch {",
    "  [Console]::Error.WriteLine($_.Exception.GetType().FullName + ':' + $_.Exception.Message)",
    "  exit 2",
    "}",
  ].join("\n");
}

function appendBoundedTail(current: string, addition: string, maxLen = 1024): string {
  const combined = current && addition ? `${current}${addition}` : current || addition;
  return combined.length > maxLen ? combined.slice(-maxLen) : combined;
}

export class PwshParserHost {
  private readonly shell: PwshShellVariant;
  private readonly binaryPath: string;
  private readonly warmTimeoutMs: number;
  private readonly coldTimeoutMs: number;
  private child: ChildProcess | null = null;
  private pipeServer: Server | null = null;
  private pipeSocket: Socket | null = null;
  private pipeConnected = false;
  private hadPipeConnectionForChild = false;
  private queue: Promise<void> = Promise.resolve();
  private queuedCount = 0;
  private pending: {
    id: string;
    child: ChildProcess;
    resolve: (res: PwshHostResult) => void;
    timer: ReturnType<typeof setTimeout>;
    requestLine?: string;
  } | null = null;
  private nextReqId = 1;
  private isCold = true;
  private failureTimestamps: number[] = [];
  private circuitOpenUntil = 0;
  private lastStderr = "";
  private lastNonJsonStdout = "";

  constructor(shell: PwshShellVariant, binaryPath: string, options: PwshHostOptions = {}) {
    this.shell = shell;
    this.binaryPath = binaryPath;
    this.warmTimeoutMs = options.warmTimeoutMs ?? 1500;
    this.coldTimeoutMs = options.coldTimeoutMs ?? (shell === "pwsh5" ? 20_000 : 10_000);
  }

  getShell(): PwshShellVariant {
    return this.shell;
  }

  getLastDiagnostic(): {
    pipeConnected: boolean;
    stderr: string;
    nonJsonStdout: string;
    binaryPath: string;
  } {
    return {
      binaryPath: this.binaryPath,
      pipeConnected: this.hadPipeConnectionForChild,
      stderr: this.lastStderr,
      nonJsonStdout: this.lastNonJsonStdout,
    };
  }

  async parse(source: string): Promise<PwshHostResult> {
    const now = Date.now();
    if (now < this.circuitOpenUntil) {
      return { ok: false, reason: "pwsh_host_circuit_open" };
    }
    if (this.queuedCount >= MAX_QUEUE_DEPTH) {
      return { ok: false, reason: "pwsh_host_queue_full" };
    }

    this.queuedCount += 1;
    return await new Promise<PwshHostResult>((resolve) => {
      this.queue = this.queue.then(async () => {
        try {
          const res = await this.executeSerialized(source);
          resolve(res);
        } catch {
          resolve({ ok: false, reason: "pwsh_host_internal_error" });
        } finally {
          this.queuedCount = Math.max(0, this.queuedCount - 1);
        }
      });
    });
  }

  private recordFailure(): void {
    const now = Date.now();
    this.failureTimestamps = this.failureTimestamps.filter((ts) => now - ts < 60_000);
    this.failureTimestamps.push(now);
    if (this.failureTimestamps.length >= 3) {
      this.circuitOpenUntil = now + 30_000;
    }
  }

  private cleanupTransport(): void {
    if (this.pipeSocket) {
      try {
        this.pipeSocket.destroy();
      } catch {
        // ignore
      }
      this.pipeSocket = null;
    }
    if (this.pipeServer) {
      try {
        this.pipeServer.close();
      } catch {
        // ignore
      }
      this.pipeServer = null;
    }
    this.pipeConnected = false;
  }

  private killChild(): void {
    this.cleanupTransport();
    if (this.child) {
      try {
        this.child.kill("SIGKILL");
      } catch {
        // ignore
      }
      this.child = null;
    }
    this.isCold = true;
  }

  private attachLineFraming(
    stream: NodeJS.ReadableStream,
    isActive: () => boolean,
    onLine: (line: string) => void,
    onOverflow: () => void,
  ): void {
    let chunks: Buffer[] = [];
    let totalBytes = 0;

    stream.on("data", (chunk: Buffer) => {
      if (!isActive()) return;
      chunks.push(chunk);
      totalBytes += chunk.length;
      if (totalBytes > MAX_HOST_LINE_BYTES) {
        chunks = [];
        totalBytes = 0;
        onOverflow();
        return;
      }

      let combined = Buffer.concat(chunks, totalBytes);
      let nlIdx = combined.indexOf(0x0a);
      while (nlIdx >= 0) {
        const lineBuf = combined.subarray(0, nlIdx);
        const lineStr = lineBuf.toString("utf8").replace(/\r$/, "");
        onLine(lineStr);
        combined = combined.subarray(nlIdx + 1);
        nlIdx = combined.indexOf(0x0a);
      }
      chunks = combined.length > 0 ? [combined] : [];
      totalBytes = combined.length;
    });
  }

  private async ensureChild(): Promise<ChildProcess> {
    if (this.child && this.child.exitCode === null && !this.child.killed) {
      return this.child;
    }

    const useNamedPipe = this.shell === "pwsh5" && process.platform === "win32";
    const hostScriptB64 = Buffer.from(PS_HOST_SCRIPT, "utf8").toString("base64");
    const cwd =
      process.platform === "win32"
        ? win32.join(getValidatedWindowsSystemRoot(), "System32")
        : tmpdir();

    this.cleanupTransport();
    this.hadPipeConnectionForChild = false;
    this.lastStderr = "";
    this.lastNonJsonStdout = "";

    let pipeServer: Server | null = null;
    let authToken = "";
    let spawnArgs: string[];

    if (useNamedPipe) {
      const pipeName = `paseo-pwsh5-${process.pid}-${randomBytes(12).toString("hex")}`;
      const pipePath = `\\\\.\\pipe\\${pipeName}`;
      authToken = randomBytes(16).toString("hex");
      const pipeBootstrap = Buffer.from(
        buildPwsh5PipeBootstrapScript(pipeName, authToken),
        "utf16le",
      ).toString("base64");
      spawnArgs = ["-NoProfile", "-NonInteractive", "-NoLogo", "-EncodedCommand", pipeBootstrap];

      pipeServer = createServer();
      await new Promise<void>((resolve, reject) => {
        const onError = (err: Error) => {
          pipeServer?.off("listening", onListening);
          reject(err);
        };
        const onListening = () => {
          pipeServer?.off("error", onError);
          resolve();
        };
        pipeServer!.once("error", onError);
        pipeServer!.once("listening", onListening);
        pipeServer!.listen(pipePath);
      });
      this.pipeServer = pipeServer;
    } else {
      const encodedBootstrap = Buffer.from(PS_HOST_BOOTSTRAP_SCRIPT, "utf16le").toString("base64");
      spawnArgs = [
        "-NoProfile",
        "-NonInteractive",
        "-NoLogo",
        "-InputFormat",
        "None",
        "-EncodedCommand",
        encodedBootstrap,
      ];
    }

    const child = spawn(this.binaryPath, spawnArgs, {
      cwd,
      env: {
        ...buildSanitizedPwshEnv(),
        POWERSHELL_TELEMETRY_OPTOUT: "1",
        POWERSHELL_UPDATECHECK: "Off",
      },
      stdio: useNamedPipe ? ["ignore", "pipe", "pipe"] : ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });

    this.child = child;
    this.isCold = true;
    const spawnedAt = Date.now();

    const failActivePending = (reason: string) => {
      if (this.pending && this.pending.child === child) {
        const active = this.pending;
        this.pending = null;
        clearTimeout(active.timer);
        this.recordFailure();
        active.resolve({ ok: false, reason });
      }
    };

    const handleJsonLine = (line: string) => {
      if (this.child !== child || !this.pending || this.pending.child !== child || !line.trim()) {
        return;
      }
      try {
        const parsed = JSON.parse(line) as {
          id?: string;
          ok?: boolean;
          payload?: Record<string, unknown>;
          error?: string;
        };
        if (parsed.id !== this.pending.id) return;
        const active = this.pending;
        this.pending = null;
        clearTimeout(active.timer);

        if (parsed.ok && parsed.payload) {
          this.isCold = false;
          active.resolve({ ok: true, payload: normalizePayload(parsed.payload) });
        } else {
          active.resolve({
            ok: false,
            reason: parsed.error ?? "pwsh_host_parse_failed",
          });
        }
      } catch {
        // Ignore malformed non-JSON lines; keep bounded tail for test diagnostics
        const stamped = line.startsWith("__ST:") ? `${line}@${Date.now() - spawnedAt}ms` : line;
        this.lastNonJsonStdout = appendBoundedTail(
          this.lastNonJsonStdout,
          this.lastNonJsonStdout ? `\n${stamped}` : stamped,
        );
      }
    };

    child.stderr?.on("data", (chunk: Buffer) => {
      if (this.child !== child) return;
      this.lastStderr = appendBoundedTail(
        this.lastStderr,
        chunk
          .toString("utf8")
          .split(/\r?\n/)
          .filter((l) => l.length > 0)
          .map((l) => `${l}@${Date.now() - spawnedAt}ms`)
          .join("\n") + "\n",
      );
    });

    if (useNamedPipe && pipeServer) {
      pipeServer.on("error", () => {
        if (this.child !== child) return;
        this.killChild();
        failActivePending("pwsh_host_pipe_error");
      });

      pipeServer.on("connection", (socket: Socket) => {
        if (this.child !== child || this.pipeSocket !== null) {
          socket.destroy();
          return;
        }

        let authenticated = false;
        this.attachLineFraming(
          socket,
          () => this.child === child && (!authenticated || this.pipeSocket === socket),
          (lineStr) => {
            if (!authenticated) {
              if (lineStr !== authToken) {
                socket.destroy();
                return;
              }
              authenticated = true;
              this.lastNonJsonStdout = appendBoundedTail(
                this.lastNonJsonStdout,
                `${this.lastNonJsonStdout ? "\n" : ""}__NODE:authed@${Date.now() - spawnedAt}ms`,
              );
              this.pipeSocket = socket;
              this.pipeConnected = true;
              this.hadPipeConnectionForChild = true;
              try {
                pipeServer?.close();
              } catch {
                // ignore
              }
              if (this.pipeServer === pipeServer) {
                this.pipeServer = null;
              }
              try {
                socket.write(`${hostScriptB64}\n`, "utf8");
                if (this.pending && this.pending.child === child && this.pending.requestLine) {
                  const reqLine = this.pending.requestLine;
                  this.pending.requestLine = undefined;
                  socket.write(reqLine, "utf8");
                }
              } catch {
                this.killChild();
                failActivePending("pwsh_host_stdin_error");
              }
              return;
            }
            handleJsonLine(lineStr);
          },
          () => {
            this.killChild();
            failActivePending("pwsh_host_response_too_large");
          },
        );

        socket.on("error", () => {
          if (this.child === child && this.pipeSocket === socket) {
            this.killChild();
            failActivePending("pwsh_host_pipe_closed");
          } else {
            socket.destroy();
          }
        });

        socket.on("close", () => {
          if (this.child === child && this.pipeSocket === socket) {
            this.pipeSocket = null;
            this.pipeConnected = false;
            this.killChild();
            failActivePending("pwsh_host_pipe_closed");
          }
        });
      });

      child.stdout?.on("data", (chunk: Buffer) => {
        if (this.child !== child) return;
        this.lastNonJsonStdout = appendBoundedTail(this.lastNonJsonStdout, chunk.toString("utf8"));
      });
    } else {
      child.stdin?.on("error", () => {
        // Handled by exit/error/pending checks
      });

      // Feed full parse-only host script via stdin to bypass Windows 32,767-char CLI limit
      child.stdin?.write(`${hostScriptB64}\n`, "utf8");

      if (child.stdout) {
        this.attachLineFraming(
          child.stdout,
          () => this.child === child,
          handleJsonLine,
          () => {
            this.killChild();
            failActivePending("pwsh_host_response_too_large");
          },
        );
      }
    }

    child.once("exit", () => {
      if (this.child === child) {
        this.cleanupTransport();
        this.child = null;
        this.isCold = true;
      }
      failActivePending("pwsh_host_crashed");
    });

    child.once("error", () => {
      if (this.child === child) {
        this.cleanupTransport();
        this.child = null;
        this.isCold = true;
      }
      failActivePending("pwsh_host_spawn_error");
    });

    return child;
  }

  private async executeSerialized(source: string): Promise<PwshHostResult> {
    if (Date.now() < this.circuitOpenUntil) {
      return { ok: false, reason: "pwsh_host_circuit_open" };
    }

    let child: ChildProcess;
    try {
      child = await this.ensureChild();
    } catch {
      this.recordFailure();
      return { ok: false, reason: "pwsh_host_spawn_error" };
    }

    const useNamedPipe = this.shell === "pwsh5" && process.platform === "win32";
    const reqId = `ps-${this.nextReqId++}`;
    const timeoutMs = this.isCold ? this.coldTimeoutMs : this.warmTimeoutMs;
    const requestLine = `${JSON.stringify({ id: reqId, source })}\n`;

    return await new Promise<PwshHostResult>((resolve) => {
      const timer = setTimeout(() => {
        if (this.pending && this.pending.id === reqId && this.pending.child === child) {
          this.pending = null;
          this.recordFailure();
          if (this.child === child) this.killChild();
          resolve({ ok: false, reason: "pwsh_host_timeout" });
        }
      }, timeoutMs);

      this.pending = {
        id: reqId,
        child,
        resolve,
        timer,
        ...(useNamedPipe ? { requestLine } : {}),
      };

      try {
        if (useNamedPipe) {
          if (this.pipeSocket && !this.pipeSocket.destroyed) {
            this.pending.requestLine = undefined;
            this.pipeSocket.write(requestLine, "utf8");
          }
        } else {
          if (!child.stdin) {
            throw new Error("missing stdin");
          }
          child.stdin.write(requestLine, "utf8");
        }
      } catch {
        if (this.pending && this.pending.id === reqId && this.pending.child === child) {
          this.pending = null;
          clearTimeout(timer);
          this.recordFailure();
          if (this.child === child) this.killChild();
          resolve({ ok: false, reason: "pwsh_host_stdin_error" });
        }
      }
    });
  }

  async dispose(): Promise<void> {
    if (this.pending) {
      const active = this.pending;
      this.pending = null;
      clearTimeout(active.timer);
      active.resolve({ ok: false, reason: "pwsh_host_disposed" });
    }
    this.killChild();
  }
}

/** Minimal host surface used by the PowerShell parse path (lets replay inject isolated hosts). */
export interface PwshHostLike {
  parse(source: string): Promise<PwshHostResult>;
  dispose(): Promise<void>;
}

export type PwshHostProvider = (shell: PwshShellVariant) => PwshHostLike | null;

/**
 * Create a new, unshared PowerShell parser host (own queue and circuit breaker). Not registered in
 * the shared host map; the caller owns it and must `dispose()` it. Returns null when no verified
 * binary is available.
 */
export function createIsolatedPwshHost(
  shell: PwshShellVariant,
  options?: PwshHostOptions,
): PwshParserHost | null {
  const bin = resolvePwshBinaryPath(shell, options);
  if (!bin) return null;
  return new PwshParserHost(shell, bin, options);
}

const sharedHosts = new Map<string, PwshParserHost>();

export function getSharedPwshHost(
  shell: PwshShellVariant,
  options?: PwshHostOptions,
): PwshParserHost | null {
  const bin = resolvePwshBinaryPath(shell, options);
  if (!bin) return null;

  const key = `${shell}::${bin}`;
  let host = sharedHosts.get(key);
  if (!host) {
    host = new PwshParserHost(shell, bin, options);
    sharedHosts.set(key, host);
  }
  return host;
}

export function getSharedPwshHostDiagnostic(
  shell: PwshShellVariant,
  binaryPath?: string,
): { pipeConnected: boolean; stderr: string; nonJsonStdout: string; binaryPath: string } | null {
  // Hosts are keyed by `${shell}::${binaryPath}`; a test may legitimately create several hosts for
  // the same shell variant with different binaries, so prefer the exact default binary.
  const preferredBin = binaryPath ?? resolvePwshBinaryPath(shell);
  const exact = preferredBin ? sharedHosts.get(`${shell}::${preferredBin}`) : undefined;
  if (exact) return exact.getLastDiagnostic();
  for (const [key, host] of sharedHosts.entries()) {
    if (key.startsWith(`${shell}::`)) {
      return host.getLastDiagnostic();
    }
  }
  return null;
}

export async function disposeSharedPwshHost(): Promise<void> {
  const hosts = Array.from(sharedHosts.values());
  sharedHosts.clear();
  await Promise.all(hosts.map((h) => h.dispose()));
}
