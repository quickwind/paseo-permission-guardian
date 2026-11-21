import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync } from "node:fs";
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
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$script:inReader = New-Object System.IO.StreamReader([Console]::OpenStandardInput(), $utf8NoBom)
$script:outWriter = New-Object System.IO.StreamWriter([Console]::OpenStandardOutput(), $utf8NoBom)
$script:outWriter.AutoFlush = $true
$b64 = $script:inReader.ReadLine()
if ($null -eq $b64) { exit 0 }
$code = $utf8NoBom.GetString([Convert]::FromBase64String($b64))
& ([scriptblock]::Create($code))
`;

export function getBootstrapEncodedCommandLength(): number {
  return Buffer.from(PS_HOST_BOOTSTRAP_SCRIPT, "utf16le").toString("base64").length;
}

// Parse-only NDJSON script compatible with BOTH Windows PowerShell 5.1 (.NET 4.x) and PowerShell 7+
const PS_HOST_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
if ($null -eq $script:inReader) {
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  $script:inReader = New-Object System.IO.StreamReader([Console]::OpenStandardInput(), $utf8NoBom)
  $script:outWriter = New-Object System.IO.StreamWriter([Console]::OpenStandardOutput(), $utf8NoBom)
  $script:outWriter.AutoFlush = $true
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
  $line = $script:inReader.ReadLine()
  if ($null -eq $line) { break }
  if ($line.Length -eq 0) { continue }
  $reqId = ''
  try {
    $req = $line | ConvertFrom-Json
    $reqId = [string]$req.id
    $src = [string]$req.source

    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$tokens, [ref]$errors)

    $allNodes = @($ast.FindAll({ $true }, $true))
    $census = @($allNodes | ForEach-Object { $_.GetType().Name } | Sort-Object -Unique)

    $errList = @()
    if ($errors) {
      foreach ($e in $errors) {
        $errList += [PSCustomObject]@{
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
    $equalsLeftIds = New-Object System.Collections.Generic.HashSet[string]
    $assignNodes = @($allNodes | Where-Object { $_.GetType().Name -eq 'AssignmentStatementAst' })
    foreach ($an in $assignNodes) {
      if ($an.Operator.ToString() -eq 'Equals') {
        $key = "$($an.Left.Extent.StartOffset):$($an.Left.Extent.EndOffset)"
        [void]$equalsLeftIds.Add($key)
      }
    }

    $envReads = @()
    $hasSplatting = $false
    $charCastCount = 0
    $varNodes = @($allNodes | Where-Object { $_.GetType().Name -eq 'VariableExpressionAst' })
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
          $envReads += [PSCustomObject]@{ name = $envName; site = $site }
        }
      }
    }

    $convNodes = @($allNodes | Where-Object { $_.GetType().Name -eq 'ConvertExpressionAst' })
    foreach ($cn in $convNodes) {
      if ($cn.Type.TypeName.Name -ieq 'char') { $charCastCount++ }
    }

    $envWrites = @()
    $varWrites = @()
    $memberAssignKeys = New-Object System.Collections.Generic.HashSet[string]
    foreach ($an in $assignNodes) {
      $left = $an.Left
      $lt = $left.GetType().Name
      $op = $an.Operator.ToString()
      $valStatic = Get-StaticVal $an.Right
      $isNull = Test-IsNullExpr $an.Right
      $isConst = ($null -ne $valStatic)

      if ($lt -eq 'VariableExpressionAst' -and $left.VariablePath.IsDriveQualified -and $left.VariablePath.DriveName -ieq 'env') {
        $envName = $left.VariablePath.UserPath -replace '^[eE][nN][vV]:', ''
        $envWrites += [PSCustomObject]@{
          name = $envName
          operator = $op
          valueStatic = $valStatic
          isNull = $isNull
        }
      } elseif ($lt -eq 'VariableExpressionAst') {
        $varWrites += [PSCustomObject]@{
          varName = [string]$left.VariablePath.UserPath
          rootVarName = [string]$left.VariablePath.UserPath
          isIndexed = $false
          operator = $op
          valueStatic = $valStatic
          isConstant = $isConst
        }
      } elseif ($lt -eq 'IndexExpressionAst') {
        $rootName = if ($left.Target.GetType().Name -eq 'VariableExpressionAst') { [string]$left.Target.VariablePath.UserPath } else { [string]$left.Target.Extent.Text }
        $varWrites += [PSCustomObject]@{
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
        $varWrites += [PSCustomObject]@{
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
    $invokeNodes = @($allNodes | Where-Object { $_.GetType().Name -eq 'InvokeMemberExpressionAst' -or $_.GetType().Name -eq 'MemberExpressionAst' })
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
          $argList += [PSCustomObject]@{ isConstant = ($null -ne $av); staticValue = $av }
        }
      } elseif ($isAssign -and $mn.Parent.GetType().Name -eq 'AssignmentStatementAst') {
        $av = Get-StaticVal $mn.Parent.Right
        $argList += [PSCustomObject]@{ isConstant = ($null -ne $av); staticValue = $av }
      }
      $memberCalls += [PSCustomObject]@{
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
    $pipeNodes = @($allNodes | Where-Object { $_.GetType().Name -eq 'PipelineAst' })
    foreach ($pn in $pipeNodes) {
      $pKey = "$($pn.Extent.StartOffset):$($pn.Extent.EndOffset)"
      $pipeIdMap[$pKey] = $nextPipeId
      $nextPipeId++
    }

    $cmdList = @()
    $backtickSkew = $false
    $cmdNodes = @($allNodes | Where-Object { $_.GetType().Name -eq 'CommandAst' })
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
          $outElems += [PSCustomObject]@{
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
            $entries += [PSCustomObject]@{
              key = $kVal
              valueStatic = $vVal
              isNull = (Test-IsNullExpr $kv.Item2)
              isConstant = ($null -ne $vVal)
            }
          }
          $outElems += [PSCustomObject]@{
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
          $outElems += [PSCustomObject]@{
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
          $redirs += [PSCustomObject]@{
            operator = $opStr
            targetStatic = (Get-StaticVal $rd.Location)
          }
        } elseif ($rt -eq 'MergingRedirectionAst') {
          $redirs += [PSCustomObject]@{
            operator = "$($rd.FromStream)>&$($rd.ToStream)"
            targetStatic = $null
          }
        }
      }

      $cmdList += [PSCustomObject]@{
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

    $fnNames = @($allNodes | Where-Object { $_.GetType().Name -eq 'FunctionDefinitionAst' } | ForEach-Object { [string]$_.Name })
    $usingMods = @($allNodes | Where-Object { $_.GetType().Name -eq 'UsingStatementAst' } | ForEach-Object { "$($_.UsingStatementKind):$($_.Name.Value)" })

    $payload = [PSCustomObject]@{
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

    $resp = [PSCustomObject]@{ id = $reqId; ok = $true; payload = $payload }
    $script:outWriter.WriteLine(($resp | ConvertTo-Json -Depth 12 -Compress))
    $script:outWriter.Flush()
  } catch {
    $errType = $_.Exception.GetType().Name
    $errResp = [PSCustomObject]@{ id = $reqId; ok = $false; error = "host_exception:$errType" }
    $script:outWriter.WriteLine(($errResp | ConvertTo-Json -Compress))
    $script:outWriter.Flush()
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

export class PwshParserHost {
  private readonly shell: PwshShellVariant;
  private readonly binaryPath: string;
  private readonly warmTimeoutMs: number;
  private readonly coldTimeoutMs: number;
  private child: ChildProcessWithoutNullStreams | null = null;
  private queue: Promise<void> = Promise.resolve();
  private queuedCount = 0;
  private pending: {
    id: string;
    child: ChildProcessWithoutNullStreams;
    resolve: (res: PwshHostResult) => void;
    timer: ReturnType<typeof setTimeout>;
  } | null = null;
  private nextReqId = 1;
  private isCold = true;
  private failureTimestamps: number[] = [];
  private circuitOpenUntil = 0;

  constructor(shell: PwshShellVariant, binaryPath: string, options: PwshHostOptions = {}) {
    this.shell = shell;
    this.binaryPath = binaryPath;
    this.warmTimeoutMs = options.warmTimeoutMs ?? 1500;
    this.coldTimeoutMs = options.coldTimeoutMs ?? 10000;
  }

  getShell(): PwshShellVariant {
    return this.shell;
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

  private killChild(): void {
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

  private ensureChild(): ChildProcessWithoutNullStreams {
    if (this.child && this.child.exitCode === null && !this.child.killed) {
      return this.child;
    }

    const encodedBootstrap = Buffer.from(PS_HOST_BOOTSTRAP_SCRIPT, "utf16le").toString("base64");
    const hostScriptB64 = Buffer.from(PS_HOST_SCRIPT, "utf8").toString("base64");
    const cwd =
      process.platform === "win32"
        ? win32.join(getValidatedWindowsSystemRoot(), "System32")
        : tmpdir();

    const child = spawn(
      this.binaryPath,
      ["-NoProfile", "-NonInteractive", "-NoLogo", "-EncodedCommand", encodedBootstrap],
      {
        cwd,
        env: buildSanitizedPwshEnv(),
        stdio: ["pipe", "pipe", "pipe"],
        windowsHide: true,
      },
    );

    child.stdin.on("error", () => {
      // Handled by exit/error/pending checks
    });

    // Feed full parse-only host script via stdin to bypass Windows 32,767-char CLI limit
    child.stdin.write(`${hostScriptB64}\n`, "utf8");

    let stdoutChunks: Buffer[] = [];
    let stdoutBytes = 0;

    const handleLine = (line: string) => {
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
        // Ignore malformed non-JSON lines until timeout or exit
      }
    };

    child.stdout.on("data", (chunk: Buffer) => {
      if (this.child !== child) return;
      stdoutChunks.push(chunk);
      stdoutBytes += chunk.length;
      if (stdoutBytes > MAX_HOST_LINE_BYTES) {
        stdoutChunks = [];
        stdoutBytes = 0;
        if (this.pending && this.pending.child === child) {
          const active = this.pending;
          this.pending = null;
          clearTimeout(active.timer);
          this.recordFailure();
          this.killChild();
          active.resolve({ ok: false, reason: "pwsh_host_response_too_large" });
        } else {
          this.killChild();
        }
        return;
      }

      let combined = Buffer.concat(stdoutChunks, stdoutBytes);
      let nlIdx = combined.indexOf(0x0a);
      while (nlIdx >= 0) {
        const lineBuf = combined.subarray(0, nlIdx);
        const lineStr = lineBuf.toString("utf8").replace(/\r$/, "");
        handleLine(lineStr);
        combined = combined.subarray(nlIdx + 1);
        nlIdx = combined.indexOf(0x0a);
      }
      stdoutChunks = combined.length > 0 ? [combined] : [];
      stdoutBytes = combined.length;
    });

    child.once("exit", () => {
      stdoutChunks = [];
      stdoutBytes = 0;
      if (this.child === child) {
        this.child = null;
        this.isCold = true;
      }
      if (this.pending && this.pending.child === child) {
        const active = this.pending;
        this.pending = null;
        clearTimeout(active.timer);
        this.recordFailure();
        active.resolve({ ok: false, reason: "pwsh_host_crashed" });
      }
    });

    child.once("error", () => {
      if (this.child === child) {
        this.child = null;
        this.isCold = true;
      }
      if (this.pending && this.pending.child === child) {
        const active = this.pending;
        this.pending = null;
        clearTimeout(active.timer);
        this.recordFailure();
        active.resolve({ ok: false, reason: "pwsh_host_spawn_error" });
      }
    });

    this.child = child;
    this.isCold = true;
    return child;
  }

  private async executeSerialized(source: string): Promise<PwshHostResult> {
    if (Date.now() < this.circuitOpenUntil) {
      return { ok: false, reason: "pwsh_host_circuit_open" };
    }

    let child: ChildProcessWithoutNullStreams;
    try {
      child = this.ensureChild();
    } catch {
      this.recordFailure();
      return { ok: false, reason: "pwsh_host_spawn_error" };
    }

    const reqId = `ps-${this.nextReqId++}`;
    const timeoutMs = this.isCold ? this.coldTimeoutMs : this.warmTimeoutMs;

    return await new Promise<PwshHostResult>((resolve) => {
      const timer = setTimeout(() => {
        if (this.pending && this.pending.id === reqId && this.pending.child === child) {
          this.pending = null;
          this.recordFailure();
          if (this.child === child) this.killChild();
          resolve({ ok: false, reason: "pwsh_host_timeout" });
        }
      }, timeoutMs);

      this.pending = { id: reqId, child, resolve, timer };

      try {
        child.stdin.write(`${JSON.stringify({ id: reqId, source })}\n`, "utf8");
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

export async function disposeSharedPwshHost(): Promise<void> {
  const hosts = Array.from(sharedHosts.values());
  sharedHosts.clear();
  await Promise.all(hosts.map((h) => h.dispose()));
}
