import { win32 } from "node:path";
import type { EffectTag } from "../../shared/types.js";
import type { SessionState } from "../context/session.js";
import {
  classifyPath,
  resolveAncestorRealPath,
  stripProviderDrive,
  type WindowsPathContext,
} from "../paths/index.js";
import { isPersistentEnvTarget, isSensitiveEnvVarName } from "../secrets/patterns.js";
import { scanCmdPercentExpansions } from "./cmd.js";
import {
  getSharedPwshHost,
  type PwshHostAstPayload,
  type PwshHostProvider,
  type PwshHostCommand,
  type PwshHostOptions,
  type PwshShellVariant,
} from "./pwsh-host.js";
import type { AssignmentFact, CommandFact, PipelineFact, RedirectionFact } from "./types.js";

export type PwshHostMode = "auto" | "disabled";

export interface PwshParseOptions extends PwshHostOptions {
  cwd: string;
  worktreeRoot?: string;
  home?: string;
  pwshHostMode?: PwshHostMode;
  /** When set, used instead of the shared host (e.g. replay's isolated hosts). */
  hostProvider?: PwshHostProvider;
  envSnapshot?: Record<string, string | undefined>;
  session?: SessionState;
}

export interface PwshParseOutput {
  commands: CommandFact[];
  pipelines: PipelineFact[];
  effects: EffectTag[];
  opaque: string[];
  envReads: string[];
  assignments: AssignmentFact[];
  unescapedSources: string[];
  cwdChanged: boolean;
}

const BASE_AST_NODES_51 = new Set([
  "ScriptBlockAst",
  "NamedBlockAst",
  "StatementBlockAst",
  "PipelineAst",
  "CommandAst",
  "CommandExpressionAst",
  "CommandParameterAst",
  "FileRedirectionAst",
  "MergingRedirectionAst",
  "StringConstantExpressionAst",
  "ExpandableStringExpressionAst",
  "VariableExpressionAst",
  "ConstantExpressionAst",
  "SubExpressionAst",
  "ParenExpressionAst",
  "ArrayExpressionAst",
  "ArrayLiteralAst",
  "HashtableAst",
  "ScriptBlockExpressionAst",
  "UsingExpressionAst",
  "UsingStatementAst",
  "InvokeMemberExpressionAst",
  "MemberExpressionAst",
  "TypeExpressionAst",
  "ConvertExpressionAst",
  "TypeConstraintAst",
  "IndexExpressionAst",
  "AssignmentStatementAst",
  "BinaryExpressionAst",
  "UnaryExpressionAst",
  "IfStatementAst",
  "ForStatementAst",
  "ForEachStatementAst",
  "WhileStatementAst",
  "DoWhileStatementAst",
  "DoUntilStatementAst",
  "SwitchStatementAst",
  "TryStatementAst",
  "CatchClauseAst",
  "TrapStatementAst",
  "BreakStatementAst",
  "ContinueStatementAst",
  "ReturnStatementAst",
  "ThrowStatementAst",
  "ExitStatementAst",
  "DataStatementAst",
  "FunctionDefinitionAst",
  "ParamBlockAst",
  "ParameterAst",
  "AttributeAst",
  "NamedAttributeArgumentAst",
  "ErrorStatementAst",
  "ErrorExpressionAst",
]);

const ALLOWED_AST_NODES_7 = new Set([
  ...BASE_AST_NODES_51,
  "PipelineChainAst",
  "TernaryExpressionAst",
  "CleanStatementAst",
]);

const PWSH_COMMON_ALIASES: Record<string, string> = {
  gci: "Get-ChildItem",
  ls: "Get-ChildItem",
  dir: "Get-ChildItem",
  gi: "Get-Item",
  gc: "Get-Content",
  cat: "Get-Content",
  type: "Get-Content",
  si: "Set-Item",
  ni: "New-Item",
  sc: "Set-Content",
  ac: "Add-Content",
  ri: "Remove-Item",
  rm: "Remove-Item",
  del: "Remove-Item",
  erase: "Remove-Item",
  rd: "Remove-Item",
  rmdir: "Remove-Item",
  cp: "Copy-Item",
  copy: "Copy-Item",
  cpi: "Copy-Item",
  mv: "Move-Item",
  move: "Move-Item",
  mi: "Move-Item",
  ren: "Rename-Item",
  rni: "Rename-Item",
  gp: "Get-ItemProperty",
  sp: "Set-ItemProperty",
  iwr: "Invoke-WebRequest",
  irm: "Invoke-RestMethod",
  iex: "Invoke-Expression",
  icm: "Invoke-Command",
  sal: "Set-Alias",
  nal: "New-Alias",
  ipmo: "Import-Module",
  gv: "Get-Variable",
  gps: "Get-Process",
  ps: "Get-Process",
  sls: "Select-String",
  cd: "Set-Location",
  sl: "Set-Location",
  chdir: "Set-Location",
  pushd: "Push-Location",
  popd: "Pop-Location",
  gl: "Get-Location",
  pwd: "Get-Location",
  gcm: "Get-Command",
  saps: "Start-Process",
  start: "Start-Process",
  echo: "Write-Output",
  write: "Write-Output",
  gwmi: "Get-WmiObject",
  gcim: "Get-CimInstance",
};

const COMMON_SWITCH_PARAMS = ["Verbose", "Debug"] as const;

const COMMON_VALUED_PARAMS = [
  "ErrorAction",
  "WarningAction",
  "InformationAction",
  "ErrorVariable",
  "WarningVariable",
  "InformationVariable",
  "OutVariable",
  "OutBuffer",
  "PipelineVariable",
] as const;

interface CmdletParamSpec {
  switches: ReadonlySet<string>;
  valued: ReadonlySet<string>;
  allKnown: string[];
}

function defineParamSpec(switches: string[], valued: string[]): CmdletParamSpec {
  const switchSet = new Set([...switches, ...COMMON_SWITCH_PARAMS]);
  const valuedSet = new Set([...valued, ...COMMON_VALUED_PARAMS]);
  return {
    switches: switchSet,
    valued: valuedSet,
    allKnown: [...switchSet, ...valuedSet],
  };
}

const CMDLET_PARAM_SPECS: Record<string, CmdletParamSpec> = {
  "Remove-Item": defineParamSpec(
    ["Recurse", "Force", "WhatIf", "Confirm"],
    ["Path", "LiteralPath", "Filter", "Include", "Exclude", "Stream"],
  ),
  "Get-ChildItem": defineParamSpec(
    ["Recurse", "Force", "Name", "Directory", "File", "Hidden", "ReadOnly", "System", "FollowSymlink"],
    ["Path", "LiteralPath", "Filter", "Include", "Exclude", "Depth", "Attributes"],
  ),
  "Get-Content": defineParamSpec(
    ["Force", "Raw", "Wait", "AsByteStream"],
    ["Path", "LiteralPath", "ReadCount", "TotalCount", "Tail", "Filter", "Include", "Exclude", "Encoding", "Stream", "Delimiter"],
  ),
  "Get-Item": defineParamSpec(
    ["Force"],
    ["Path", "LiteralPath", "Filter", "Include", "Exclude", "Stream"],
  ),
  "Set-Item": defineParamSpec(
    ["PassThru", "Force", "WhatIf", "Confirm"],
    ["Path", "LiteralPath", "Value"],
  ),
  "New-Item": defineParamSpec(
    ["Force", "WhatIf", "Confirm"],
    ["Path", "Name", "ItemType", "Value"],
  ),
  "Set-Content": defineParamSpec(
    ["PassThru", "Force", "NoNewline", "WhatIf", "Confirm", "AsByteStream"],
    ["Path", "LiteralPath", "Value", "Filter", "Include", "Exclude", "Encoding", "Stream"],
  ),
  "Add-Content": defineParamSpec(
    ["PassThru", "Force", "NoNewline", "WhatIf", "Confirm", "AsByteStream"],
    ["Path", "LiteralPath", "Value", "Filter", "Include", "Exclude", "Encoding", "Stream"],
  ),
  "Out-File": defineParamSpec(
    ["Append", "Force", "NoClobber", "NoNewline", "WhatIf", "Confirm"],
    ["FilePath", "LiteralPath", "Encoding", "Width", "InputObject"],
  ),
  "Copy-Item": defineParamSpec(
    ["Container", "Force", "Recurse", "PassThru", "WhatIf", "Confirm"],
    ["Path", "LiteralPath", "Destination", "Filter", "Include", "Exclude"],
  ),
  "Move-Item": defineParamSpec(
    ["Force", "PassThru", "WhatIf", "Confirm"],
    ["Path", "LiteralPath", "Destination", "Filter", "Include", "Exclude"],
  ),
  "Rename-Item": defineParamSpec(
    ["Force", "PassThru", "WhatIf", "Confirm"],
    ["Path", "LiteralPath", "NewName"],
  ),
  "Get-ItemProperty": defineParamSpec(
    [],
    ["Path", "LiteralPath", "Name", "Filter", "Include", "Exclude"],
  ),
  "Set-ItemProperty": defineParamSpec(
    ["PassThru", "Force", "WhatIf", "Confirm"],
    ["Path", "LiteralPath", "Name", "Value"],
  ),
  "New-ItemProperty": defineParamSpec(
    ["Force", "WhatIf", "Confirm"],
    ["Path", "LiteralPath", "Name", "PropertyType", "Value"],
  ),
  "Invoke-WebRequest": defineParamSpec(
    ["UseBasicParsing", "UseDefaultCredentials", "SkipCertificateCheck"],
    ["Uri", "Method", "Headers", "Body", "InFile", "OutFile", "ContentType", "TimeoutSec", "Credential", "MaximumRedirection", "MaximumRetryCount", "MaximumFollowRelLink", "Proxy", "SessionVariable", "WebSession"],
  ),
  "Invoke-RestMethod": defineParamSpec(
    ["UseBasicParsing", "UseDefaultCredentials", "SkipCertificateCheck"],
    ["Uri", "Method", "Headers", "Body", "InFile", "OutFile", "ContentType", "TimeoutSec", "Credential", "MaximumRedirection", "MaximumRetryCount", "MaximumFollowRelLink", "Proxy", "SessionVariable", "WebSession"],
  ),
  "Start-Process": defineParamSpec(
    ["Wait", "NoNewWindow", "PassThru", "UseNewEnvironment", "LoadUserProfile"],
    ["FilePath", "ArgumentList", "WorkingDirectory", "Verb", "WindowStyle", "RedirectStandardOutput", "RedirectStandardError", "RedirectStandardInput", "Environment", "Credential"],
  ),
  "Get-CimInstance": defineParamSpec(
    ["KeyOnly", "Shallow"],
    ["ClassName", "Namespace", "Filter", "Query", "Property", "ComputerName", "CimSession"],
  ),
  "Get-WmiObject": defineParamSpec(
    ["DirectRead", "Amended", "EnableAllPrivileges", "Recurse"],
    ["Class", "Namespace", "Filter", "Query", "Property", "ComputerName", "Credential"],
  ),
  "Set-ExecutionPolicy": defineParamSpec(
    ["Force", "WhatIf", "Confirm"],
    ["ExecutionPolicy", "Scope"],
  ),
  "ConvertTo-SecureString": defineParamSpec(
    ["AsPlainText", "Force"],
    ["String", "Key", "SecureKey"],
  ),
  "ConvertFrom-SecureString": defineParamSpec(
    ["AsPlainText"],
    ["SecureString", "Key", "SecureKey"],
  ),
  "Export-PfxCertificate": defineParamSpec(
    ["NoClobber", "Force"],
    ["Cert", "FilePath", "Password", "ChainOption", "ProtectTo"],
  ),
  "Import-Certificate": defineParamSpec(
    ["WhatIf", "Confirm"],
    ["FilePath", "CertStoreLocation"],
  ),
  "Invoke-Command": defineParamSpec(
    ["AsJob", "HideComputerName", "NoNewScope"],
    ["ScriptBlock", "ComputerName", "FilePath", "ArgumentList", "Session", "Credential"],
  ),
  "Unblock-File": defineParamSpec(
    ["WhatIf", "Confirm"],
    ["Path", "LiteralPath"],
  ),
  "Get-Variable": defineParamSpec(
    ["ValueOnly"],
    ["Name", "Include", "Exclude", "Scope"],
  ),
  "Set-Location": defineParamSpec(
    ["PassThru"],
    ["Path", "LiteralPath", "StackName"],
  ),
  "Push-Location": defineParamSpec(
    ["PassThru"],
    ["Path", "LiteralPath", "StackName"],
  ),
  "Pop-Location": defineParamSpec(
    ["PassThru"],
    ["StackName"],
  ),
  "Select-String": defineParamSpec(
    ["SimpleMatch", "CaseSensitive", "Quiet", "List", "AllMatches", "NotMatch", "Raw", "NoEmphasis"],
    ["Pattern", "Path", "LiteralPath", "Encoding", "Context"],
  ),
  "Test-Path": defineParamSpec(
    ["IsValid", "OlderThan", "NewerThan"],
    ["Path", "LiteralPath", "PathType", "Filter", "Include", "Exclude"],
  ),
  "Resolve-Path": defineParamSpec(
    ["Relative"],
    ["Path", "LiteralPath"],
  ),
  "Get-Process": defineParamSpec(
    ["Module", "FileVersionInfo", "IncludeUserName"],
    ["Name", "Id", "InputObject"],
  ),
  "Get-Command": defineParamSpec(
    ["All", "Syntax", "ShowCommandInfo"],
    ["Name", "Verb", "Noun", "Module", "CommandType"],
  ),
  "Write-Output": defineParamSpec(
    ["NoEnumerate"],
    ["InputObject"],
  ),
  "Get-Credential": defineParamSpec(
    [],
    ["UserName", "Message", "Title"],
  ),
};

const SAFE_L0_PREFERENCE_VARS = new Set([
  "erroractionpreference",
  "progresspreference",
  "warningpreference",
  "informationpreference",
  "verbosepreference",
  "debugpreference",
  "outputencoding",
  "psstyle.outputrendering",
  "console::outputencoding",
  "system.console::outputencoding",
  "console::inputencoding",
  "system.console::inputencoding",
]);

export function resolvePwshCommandCanonical(
  rawName: string,
  shell: PwshShellVariant,
): string {
  const lower = rawName.trim().toLowerCase();
  if (shell === "pwsh5" && (lower === "curl" || lower === "wget")) {
    return "Invoke-WebRequest";
  }
  if (lower === "cd.." || lower === "cd\\" || lower === "cd/") {
    return "Set-Location";
  }
  return PWSH_COMMON_ALIASES[lower] ?? rawName;
}

export interface DisambiguatedParams {
  params: Record<string, string | boolean>;
  paramArrays: Record<string, string[]>;
  positionals: string[];
  positionalConstants: boolean[];
  orderedArgv: string[];
  orderedArgvDynamic: boolean[];
  opaqueReasons: string[];
}

function tokenizeStopParsingSpan(span: string): string[] {
  const out: string[] = [];
  let cur = "";
  let inQuotes = false;
  let hasToken = false;
  for (let i = 0; i < span.length; i++) {
    const ch = span[i];
    if (ch === '"') {
      inQuotes = !inQuotes;
      hasToken = true;
      continue;
    }
    if (!inQuotes && /\s/.test(ch)) {
      if (hasToken) {
        out.push(cur);
        cur = "";
        hasToken = false;
      }
      continue;
    }
    cur += ch;
    hasToken = true;
  }
  if (hasToken) {
    out.push(cur);
  }
  return out;
}

export function disambiguatePwshParams(
  canonicalCmd: string,
  cmd: PwshHostCommand,
): DisambiguatedParams {
  const spec = CMDLET_PARAM_SPECS[canonicalCmd];
  const params: Record<string, string | boolean> = {};
  const paramArrays: Record<string, string[]> = {};
  const positionals: string[] = [];
  const positionalConstants: boolean[] = [];
  const orderedArgv: string[] = [];
  const orderedArgvDynamic: boolean[] = [];
  const opaqueReasons: string[] = [];

  const els = cmd.elements.slice(1); // skip command name
  let afterDoubleDash = false;
  let afterStopParsing = false;

  for (let i = 0; i < els.length; i++) {
    const el = els[i];

    if (
      !spec &&
      !afterStopParsing &&
      el.kind === "arg" &&
      el.astType === "StringConstantExpressionAst" &&
      el.staticValue === "--%"
    ) {
      afterStopParsing = true;
      continue;
    }

    if (afterStopParsing && !spec) {
      if (el.isConstant && el.staticValue !== null && el.staticValue !== undefined) {
        const splitToks = tokenizeStopParsingSpan(el.staticValue);
        for (const t of splitToks) {
          positionals.push(t);
          positionalConstants.push(true);
          orderedArgv.push(t);
          orderedArgvDynamic.push(false);
        }
      } else {
        positionals.push("<dynamic>");
        positionalConstants.push(false);
        orderedArgv.push("<dynamic>");
        orderedArgvDynamic.push(true);
      }
      continue;
    }

    if (
      !afterDoubleDash &&
      el.kind === "arg" &&
      el.astType === "StringConstantExpressionAst" &&
      el.staticValue === "--"
    ) {
      afterDoubleDash = true;
      if (!spec) {
        orderedArgv.push("--");
        orderedArgvDynamic.push(false);
      }
      continue;
    }

    if (!afterDoubleDash && el.kind === "parameter" && el.parameterName) {
      const rawParam = el.parameterName;
      if (!spec) {
        // Non-cmdlet / external executable: preserve exact token order without hoisting flags
        if (el.hasColonArg) {
          if (el.argStaticValue !== null && el.argStaticValue !== undefined) {
            params[rawParam] = el.argStaticValue;
            orderedArgv.push(`-${rawParam}:${el.argStaticValue}`);
            orderedArgvDynamic.push(false);
          } else {
            params[rawParam] = "<dynamic>";
            opaqueReasons.push(`pwsh_dynamic_param_arg:${rawParam}`);
            orderedArgv.push(`-${rawParam}:<dynamic>`);
            orderedArgvDynamic.push(true);
          }
        } else {
          params[rawParam] = true;
          orderedArgv.push(`-${rawParam}`);
          orderedArgvDynamic.push(false);
        }
        continue;
      }

      let resolvedName: string | null = null;
      const lower = rawParam.toLowerCase();
      const exact = spec.allKnown.find((k) => k.toLowerCase() === lower);
      if (exact) {
        resolvedName = exact;
      } else {
        const matches = spec.allKnown.filter((k) => k.toLowerCase().startsWith(lower));
        if (matches.length === 1) {
          resolvedName = matches[0];
        } else if (matches.length > 1) {
          opaqueReasons.push(`pwsh_ambiguous_param:${canonicalCmd}:${rawParam}`);
          continue;
        } else {
          opaqueReasons.push(`pwsh_unknown_param:${canonicalCmd}:${rawParam}`);
          continue;
        }
      }

      const isSwitch = spec.switches.has(resolvedName);
      const isValued = spec.valued.has(resolvedName);

      if (el.hasColonArg) {
        if (el.argStaticValue === null || el.argStaticValue === undefined) {
          params[resolvedName] = "<dynamic>";
          opaqueReasons.push(`pwsh_dynamic_param_arg:${resolvedName}`);
          orderedArgv.push(`-${resolvedName}`, "<dynamic>");
          orderedArgvDynamic.push(false, true);
          continue;
        }
        if (isSwitch) {
          const normBool = el.argStaticValue.trim().toLowerCase();
          if (normBool === "true" || normBool === "1") {
            params[resolvedName] = true;
          } else if (normBool === "false" || normBool === "0" || normBool === "") {
            params[resolvedName] = false;
          } else {
            params[resolvedName] = "<dynamic>";
            opaqueReasons.push(`pwsh_dynamic_param_arg:${resolvedName}`);
          }
          orderedArgv.push(`-${resolvedName}:${el.argStaticValue}`);
          orderedArgvDynamic.push(false);
          continue;
        }
        params[resolvedName] = el.argStaticValue;
        orderedArgv.push(`-${resolvedName}`, el.argStaticValue);
        orderedArgvDynamic.push(false, false);
        continue;
      }

      if (isSwitch) {
        params[resolvedName] = true;
        orderedArgv.push(`-${resolvedName}`);
        orderedArgvDynamic.push(false);
        continue;
      }

      if (!isValued) {
        opaqueReasons.push(`pwsh_unknown_param_type:${canonicalCmd}:${resolvedName}`);
        continue;
      }

      const next = els[i + 1];
      if (next && next.kind === "arg") {
        if (next.hashtableEntries !== undefined) {
          params[resolvedName] = "[hashtable]";
          orderedArgv.push(`-${resolvedName}`, "[hashtable]");
          orderedArgvDynamic.push(false, true);
          i += 1;
          continue;
        }
        if (Array.isArray(next.arrayStaticValues) && next.arrayStaticValues.length > 0) {
          const joined = next.arrayStaticValues.join(",");
          params[resolvedName] = joined;
          paramArrays[resolvedName] = next.arrayStaticValues;
          orderedArgv.push(`-${resolvedName}`, joined);
          orderedArgvDynamic.push(false, false);
          i += 1;
          continue;
        }
        if (next.isConstant && next.staticValue !== null && next.staticValue !== undefined) {
          params[resolvedName] = next.staticValue;
          orderedArgv.push(`-${resolvedName}`, next.staticValue);
          orderedArgvDynamic.push(false, false);
          i += 1;
          continue;
        }
        params[resolvedName] = "<dynamic>";
        opaqueReasons.push(`pwsh_dynamic_param_arg:${resolvedName}`);
        orderedArgv.push(`-${resolvedName}`, "<dynamic>");
        orderedArgvDynamic.push(false, true);
        i += 1;
        continue;
      }

      params[resolvedName] = true;
      orderedArgv.push(`-${resolvedName}`);
      orderedArgvDynamic.push(false);
      continue;
    }

    if (el.hashtableEntries !== undefined) {
      positionals.push("[hashtable]");
      positionalConstants.push(false);
      orderedArgv.push("[hashtable]");
      orderedArgvDynamic.push(true);
      if (spec) {
        opaqueReasons.push(`pwsh_dynamic_positional:${canonicalCmd}`);
      }
    } else if (Array.isArray(el.arrayStaticValues) && el.arrayStaticValues.length > 0) {
      for (const item of el.arrayStaticValues) {
        positionals.push(item);
        positionalConstants.push(true);
        orderedArgv.push(item);
        orderedArgvDynamic.push(false);
      }
    } else if (el.isConstant && el.staticValue !== null && el.staticValue !== undefined) {
      positionals.push(el.staticValue);
      positionalConstants.push(true);
      orderedArgv.push(el.staticValue);
      orderedArgvDynamic.push(false);
    } else {
      const val = el.staticValue ?? "<dynamic>";
      positionals.push(val);
      positionalConstants.push(false);
      orderedArgv.push(val);
      orderedArgvDynamic.push(true);
      if (spec) {
        opaqueReasons.push(`pwsh_dynamic_positional:${canonicalCmd}`);
      }
    }
  }

  return {
    params,
    paramArrays,
    positionals,
    positionalConstants,
    orderedArgv,
    orderedArgvDynamic,
    opaqueReasons,
  };
}

function normalizeStaticPwshCwd(currentCwd: string, target: string): string | null {
  if (!target || /[$`%!]/.test(target) || stripProviderDrive(target)) {
    return null;
  }
  const clean = target.replaceAll("/", "\\");
  if (/^\\\\/.test(clean) || /^[A-Za-z]:(?![\\/])/.test(clean)) {
    return null;
  }
  if (/^[A-Za-z]:/.test(clean)) {
    return win32.normalize(clean);
  }
  const cwdClean = currentCwd.replaceAll("/", "\\");
  return /^[A-Za-z]:/.test(cwdClean) ? win32.resolve(cwdClean, clean) : win32.resolve(cwdClean, clean);
}

function isTrustedVenvActivation(
  scriptPathRaw: string,
  options: PwshParseOptions,
): boolean {
  if (options.session?.untrustedTaint) {
    return false;
  }
  const worktree = options.worktreeRoot ?? options.cwd;
  const pathCtx: WindowsPathContext = {
    os: "windows",
    cwd: options.cwd,
    worktreeRoot: worktree,
    home: options.home,
    envSnapshot: options.envSnapshot,
  };
  const classified = classifyPath(scriptPathRaw, pathCtx);
  if (!classified.inWorktree) {
    return false;
  }

  const fwdNorm = classified.normalized.replaceAll("\\", "/").toLowerCase();
  const worktreeFwd = worktree.replaceAll("\\", "/").replace(/\/+$/, "").toLowerCase();
  const rel = fwdNorm.startsWith(`${worktreeFwd}/`) ? fwdNorm.slice(worktreeFwd.length + 1) : fwdNorm;

  if (!/^(?:\.venv|venv|env)\/scripts\/activate\.ps1$/.test(rel)) {
    return false;
  }

  // Ensure nothing under the venv directory was modified during this session
  const venvDirRel = rel.split("/")[0];
  const worktreeRealFwd = resolveAncestorRealPath(worktree).replaceAll("\\", "/").replace(/\/+$/, "").toLowerCase();
  const venvPrefixes = Array.from(
    new Set([`${worktreeFwd}/${venvDirRel}/`, `${worktreeRealFwd}/${venvDirRel}/`]),
  );
  for (const modified of options.session?.modifiedFiles ?? []) {
    const modFwd = modified.replaceAll("\\", "/").toLowerCase();
    if (venvPrefixes.some((prefix) => modFwd.startsWith(prefix))) {
      return false;
    }
  }
  return true;
}

function normalizeDotNetTypeName(rawType: string): string {
  return rawType
    .trim()
    .replace(/^[\[(]+|[\])]+$/g, "")
    .replace(/^System\./i, "")
    .toLowerCase();
}

function classifyRegistryPathTarget(hiveTarget: string, shell: PwshShellVariant, options: PwshParseOptions) {
  return classifyPath(hiveTarget, {
    os: "windows",
    shell,
    cwd: options.cwd,
    worktreeRoot: options.worktreeRoot,
    home: options.home,
    envSnapshot: options.envSnapshot,
  });
}

export async function parsePowerShell(
  shell: PwshShellVariant,
  source: string,
  depth = 0,
  options: PwshParseOptions,
): Promise<PwshParseOutput> {
  const opaque: string[] = [];
  const commands: CommandFact[] = [];
  const pipelines: PipelineFact[] = [];
  const effects: EffectTag[] = [];
  const envReads = new Set<string>();
  const assignments: AssignmentFact[] = [];
  const unescapedSources: string[] = [];
  let cwdChanged = false;

  if (!source.trim()) {
    return { commands, pipelines, effects, opaque, envReads: [], assignments, unescapedSources, cwdChanged };
  }

  // Always check raw string for obfuscated backtick-stripped literal secrets
  unescapedSources.push(source.replace(/`([A-Za-z0-9_])/g, "$1"));

  if (options.pwshHostMode === "disabled") {
    opaque.push("pwsh_host_disabled");
    return { commands, pipelines, effects, opaque, envReads: [], assignments, unescapedSources, cwdChanged };
  }

  const host = options.hostProvider
    ? options.hostProvider(shell)
    : getSharedPwshHost(shell, {
        allowPosixHost: options.allowPosixHost,
        binaryPath: options.binaryPath,
        warmTimeoutMs: options.warmTimeoutMs,
        coldTimeoutMs: options.coldTimeoutMs,
      });
  if (!host) {
    opaque.push("pwsh_host_unavailable");
    return { commands, pipelines, effects, opaque, envReads: [], assignments, unescapedSources, cwdChanged };
  }

  const hostRes = await host.parse(source);
  if (!hostRes.ok) {
    opaque.push(hostRes.reason);
    return { commands, pipelines, effects, opaque, envReads: [], assignments, unescapedSources, cwdChanged };
  }

  const ast = hostRes.payload;

  // 1. Parse errors -> fail safe to opaque
  if (ast.parseErrors.length > 0) {
    opaque.push(`pwsh_parse_error:${ast.parseErrors[0].errorId}`);
  }

  // 2. Versioned AST nodeTypeCensus gate (ADR-0006 §3)
  const allowedNodes = shell === "pwsh5" ? BASE_AST_NODES_51 : ALLOWED_AST_NODES_7;
  for (const nodeType of ast.nodeTypeCensus) {
    if (!allowedNodes.has(nodeType)) {
      opaque.push(`unknown_ast_node:${nodeType}`);
    }
  }

  // 3. Obfuscation signals
  if (ast.backtickCommandSkew) {
    opaque.push("pwsh_backtick_obfuscation");
  }
  if (ast.charCastCount >= 3) {
    opaque.push("pwsh_char_cast_obfuscation");
  }
  if (ast.hasSplatting) {
    opaque.push("pwsh_splatting");
  }
  for (const mod of ast.usingModules) {
    opaque.push(`pwsh_using:${mod}`);
    effects.push({ tag: "exec_inline", layer: depth, target: mod, detail: "pwsh_using_module" });
  }

  // 4. Forward `--%` stop-parsing spans to cmd `%VAR%` scanner
  for (const span of ast.stopParsingSpans) {
    const scan = scanCmdPercentExpansions(span, { envSnapshot: options.envSnapshot });
    for (const v of scan.envReads) envReads.add(v);
    opaque.push(...scan.opaque);
  }

  // 5. Env reads & writes
  for (const r of ast.envReads) {
    envReads.add(r.name);
  }
  for (const w of ast.envWrites) {
    const val = w.isNull ? "" : (w.valueStatic ?? (w.operator === "PlusEquals" ? "+=dynamic" : "dynamic"));
    assignments.push({
      name: w.name,
      value: val,
      standalone: true,
      depth,
      source: "standalone",
    });
    if (!w.isNull && w.valueStatic === null) {
      // Dynamic value assigned to sensitive or unknown env var -> keep opaque if not already caught
      if (isSensitiveEnvVarName(w.name)) {
        opaque.push(`dynamic_env_assignment:${w.name}`);
      }
    }
  }

  // 6. Variable / preference writes
  for (const vw of ast.varWrites) {
    const rootLower = vw.rootVarName.toLowerCase();
    if (rootLower === "psdefaultparametervalues") {
      opaque.push("pwsh_default_parameter_values");
      continue;
    }
    if (rootLower === "whatifpreference") {
      // ADR-0006: $WhatIfPreference = $true must NEVER lower effects
      continue;
    }
    if (SAFE_L0_PREFERENCE_VARS.has(rootLower) || SAFE_L0_PREFERENCE_VARS.has(vw.varName.toLowerCase())) {
      if (vw.isConstant) {
        effects.push({ tag: "read", layer: depth, target: vw.varName });
      } else {
        opaque.push(`pwsh_dynamic_pref:${vw.varName}`);
      }
      continue;
    }
    if (
      rootLower === "environment::currentdirectory" ||
      rootLower === "io.directory::currentdirectory"
    ) {
      const next = vw.valueStatic ? normalizeStaticPwshCwd(options.cwd, vw.valueStatic) : null;
      if (!next) cwdChanged = true;
    }
  }

  // 7. Member invocations (.NET static & instance calls)
  let currentCwd = options.cwd;
  const cwdStack: string[] = [];

  for (const mi of ast.memberInvocations) {
    const normType = normalizeDotNetTypeName(mi.typeName);
    const memberLower = mi.member.toLowerCase();
    const isLitType = mi.isLiteralType !== false;

    if (mi.isAssignmentTarget && mi.static && isLitType && SAFE_L0_PREFERENCE_VARS.has(`${normType}::${memberLower}`)) {
      continue;
    }

    if (mi.static && isLitType && normType === "environment") {
      if (memberLower === "getenvironmentvariables") {
        effects.push({
          tag: "read_secret",
          layer: depth,
          target: "[Environment]::GetEnvironmentVariables",
          detail: "env_dump",
        });
        continue;
      }
      if (memberLower === "getenvironmentvariable") {
        const arg0 = mi.args[0];
        if (!arg0 || !arg0.isConstant || !arg0.staticValue) {
          opaque.push("pwsh_dynamic_env_get");
        } else if (isSensitiveEnvVarName(arg0.staticValue)) {
          effects.push({
            tag: "read_secret",
            layer: depth,
            target: arg0.staticValue,
            detail: "sensitive_env_expansion",
          });
        } else {
          effects.push({
            tag: "read",
            layer: depth,
            target: "[Environment]::GetEnvironmentVariable",
          });
        }
        continue;
      }
      if (memberLower === "expandenvironmentvariables") {
        const arg0 = mi.args[0];
        if (!arg0 || !arg0.isConstant || arg0.staticValue === null) {
          opaque.push("pwsh_dynamic_env_expand");
        } else {
          const scan = scanCmdPercentExpansions(arg0.staticValue, {
            envSnapshot: options.envSnapshot,
          });
          for (const v of scan.envReads) envReads.add(v);
          opaque.push(...scan.opaque);
        }
        continue;
      }
      if (memberLower === "setenvironmentvariable") {
        const nameArg = mi.args[0];
        const valArg = mi.args[1];
        const targetArg = mi.args[2];

        const varName = nameArg?.isConstant ? nameArg.staticValue : null;
        const varVal = valArg?.isConstant ? (valArg.staticValue ?? "") : null;
        const targetScope = targetArg?.isConstant && targetArg.staticValue
          ? isPersistentEnvTarget(targetArg.staticValue)
          : targetArg
            ? "user"
            : null;

        if (targetScope === "user" || targetScope === "machine") {
          effects.push({
            tag: "write_protected",
            layer: depth,
            target: varName ?? "Environment",
            detail: `env_persist:${targetScope}`,
          });
          if (targetScope === "machine") {
            effects.push({
              tag: "privilege",
              layer: depth,
              target: varName ?? "Environment",
              detail: "env_persist:machine",
            });
          }
        }

        if (varName) {
          assignments.push({
            name: varName,
            value: varVal ?? "dynamic",
            standalone: true,
            depth,
            source: "standalone",
          });
        } else {
          opaque.push("pwsh_dynamic_env_set");
        }
        continue;
      }
    }

    if (
      mi.static &&
      isLitType &&
      ((normType === "io.directory" && memberLower === "setcurrentdirectory") ||
        (normType === "environment" && memberLower === "currentdirectory"))
    ) {
      cwdChanged = true;
      continue;
    }

    // IO.File / IO.Directory static read family
    if (
      mi.static &&
      isLitType &&
      (normType === "io.file" || normType === "io.directory") &&
      (memberLower === "readalltext" ||
        memberLower === "readallbytes" ||
        memberLower === "readalllines" ||
        memberLower === "readlines" ||
        memberLower === "openread" ||
        memberLower === "opentext" ||
        memberLower === "exists" ||
        memberLower === "getfiles" ||
        memberLower === "getdirectories" ||
        memberLower === "getfilesystementries" ||
        memberLower === "enumeratefiles" ||
        memberLower === "enumeratedirectories" ||
        memberLower === "enumeratefilesystementries")
    ) {
      const targetArg = mi.args[0];
      if (!targetArg?.isConstant || !targetArg.staticValue) {
        opaque.push(`pwsh_dynamic_dotnet_io:${mi.member}`);
      } else {
        const p = classifyPath(targetArg.staticValue, {
          os: "windows",
          shell,
          cwd: currentCwd,
          worktreeRoot: options.worktreeRoot,
          home: options.home,
          envSnapshot: options.envSnapshot,
        });
        if (p.isSensitive) {
          effects.push({ tag: "read_secret", layer: depth, target: p.realPath });
        } else {
          effects.push({ tag: "read", layer: depth, target: p.realPath });
        }
      }
      continue;
    }

    // IO.File / IO.Directory static delete/write/move/copy family
    if (
      mi.static &&
      isLitType &&
      (normType === "io.file" || normType === "io.directory") &&
      (memberLower === "delete" ||
        memberLower.startsWith("write") ||
        memberLower.startsWith("append") ||
        memberLower === "move" ||
        memberLower === "copy" ||
        memberLower === "replace" ||
        memberLower.startsWith("create") ||
        memberLower === "openwrite" ||
        memberLower === "open")
    ) {
      if (memberLower === "open" && mi.args.length > 1) {
        opaque.push("pwsh_dotnet_file_open");
      }
      const targetArg = mi.args[0];
      if (!targetArg?.isConstant || !targetArg.staticValue) {
        opaque.push(`pwsh_dynamic_dotnet_io:${mi.member}`);
      } else {
        const p = classifyPath(targetArg.staticValue, {
          os: "windows",
          shell,
          cwd: currentCwd,
          worktreeRoot: options.worktreeRoot,
          home: options.home,
          envSnapshot: options.envSnapshot,
        });
        const isDelete = memberLower === "delete";
        const isCopyOrMove = memberLower === "copy" || memberLower === "move" || memberLower === "replace";
        const recursive = isDelete && normType === "io.directory" && mi.args[1]?.staticValue?.toLowerCase() === "true";

        if (isCopyOrMove) {
          if (p.isSensitive) {
            effects.push({ tag: "read_secret", layer: depth, target: p.realPath });
          }
          if (memberLower !== "copy") {
            if (p.isProtected || p.isSensitive) {
              effects.push({ tag: "write_protected", layer: depth, target: p.realPath, pluginSelf: p.isPluginSelf });
            } else if (!p.inWorktree) {
              effects.push({ tag: "delete_outside", layer: depth, target: p.realPath });
            } else {
              effects.push({ tag: "write_worktree", layer: depth, target: p.realPath });
            }
          }
          const destArg = mi.args[1];
          if (!destArg?.isConstant || !destArg.staticValue) {
            opaque.push(`pwsh_dynamic_dotnet_io:${mi.member}:dest`);
          } else {
            const destP = classifyPath(destArg.staticValue, {
              os: "windows",
              shell,
              cwd: currentCwd,
              worktreeRoot: options.worktreeRoot,
              home: options.home,
              envSnapshot: options.envSnapshot,
            });
            if (destP.isProtected || destP.isSensitive) {
              effects.push({ tag: "write_protected", layer: depth, target: destP.realPath, pluginSelf: destP.isPluginSelf });
            } else if (destP.inWorktree) {
              effects.push({ tag: "write_worktree", layer: depth, target: destP.realPath });
            } else {
              effects.push({ tag: "write_outside", layer: depth, target: destP.realPath });
            }
          }
        } else if (
          isDelete &&
          /^[A-Za-z]:\\(?:windows(?:\\system32|\\syswow64)?|program files(?: \(x86\))?|users|programdata)?$/i.test(p.realPath)
        ) {
          effects.push({
            tag: "system_destructive",
            layer: depth,
            target: p.realPath,
            reversibility: "irreversible",
            recursive,
            detail: `delete targeting system root ${p.realPath}`,
          });
        } else if (p.isProtected || p.isSensitive) {
          effects.push({ tag: "write_protected", layer: depth, target: p.realPath, pluginSelf: p.isPluginSelf });
        } else if (p.inWorktree) {
          effects.push({
            tag: isDelete ? "delete_worktree" : "write_worktree",
            layer: depth,
            target: p.realPath,
            ...(isDelete ? { recursive } : {}),
          });
        } else {
          effects.push({
            tag: isDelete ? "delete_outside" : "write_outside",
            layer: depth,
            target: p.realPath,
            ...(isDelete ? { recursive } : {}),
          });
        }
      }
      continue;
    }

    // Diagnostics.Process::Start -> exec_inline + unwrap command & args when static
    if (mi.static && isLitType && normType === "diagnostics.process" && memberLower === "start") {
      effects.push({ tag: "exec_inline", layer: depth, target: "[Diagnostics.Process]::Start" });
      const exeArg = mi.args[0];
      const argsArg = mi.args[1];
      if (!exeArg?.isConstant || !exeArg.staticValue || mi.args.length > 2) {
        opaque.push("pwsh_dynamic_process_start");
      } else {
        let parsedArgv: string[] = [];
        if (argsArg !== undefined) {
          if (argsArg.isConstant && argsArg.staticValue !== null) {
            parsedArgv = tokenizeStopParsingSpan(argsArg.staticValue);
          } else {
            opaque.push("pwsh_dynamic_process_start");
          }
        }
        commands.push({
          name: exeArg.staticValue,
          argv: parsedArgv,
          rawText: `${exeArg.staticValue} ${parsedArgv.join(" ")}`.trim(),
          redirections: [],
          assignments: {},
          envReads: [],
          depth,
          layer: shell,
          ...(cwdChanged || mi.inConditionalOrLoop || (mi.scriptBlockDepth ?? 1) > 1
            ? { cwdChanged: true, effectiveCwd: currentCwd }
            : { effectiveCwd: currentCwd }),
        });
      }
      continue;
    }

    // Microsoft.Win32.Registry::SetValue / GetValue
    if (
      mi.static &&
      isLitType &&
      normType === "microsoft.win32.registry" &&
      (memberLower === "setvalue" || memberLower === "getvalue")
    ) {
      const keyArg = mi.args[0];
      if (!keyArg?.isConstant || !keyArg.staticValue) {
        opaque.push(`pwsh_dynamic_registry:${mi.member}`);
      } else {
        const regCls = classifyRegistryPathTarget(keyArg.staticValue, shell, options);
        if (memberLower === "setvalue") {
          effects.push({ tag: "write_protected", layer: depth, target: regCls.realPath, detail: "dotnet_registry_set" });
          if (/^(?:hkey_local_machine|hklm)\b/i.test(keyArg.staticValue)) {
            effects.push({ tag: "privilege", layer: depth, target: regCls.realPath });
          }
        } else if (regCls.isSensitive) {
          effects.push({ tag: "read_secret", layer: depth, target: regCls.realPath });
        } else {
          effects.push({ tag: "read", layer: depth, target: regCls.realPath });
        }
      }
      continue;
    }

    // Reflection.Assembly::Load / LoadFrom / UnsafeLoadFrom
    if (
      mi.static &&
      isLitType &&
      normType === "reflection.assembly" &&
      memberLower.startsWith("load")
    ) {
      effects.push({ tag: "exec_inline", layer: depth, target: `[Reflection.Assembly]::${mi.member}` });
      opaque.push(`pwsh_dotnet_assembly_${memberLower}`);
      continue;
    }

    if (
      normType === "net.webclient" ||
      normType === "net.http.httpclient" ||
      memberLower === "downloadstring" ||
      memberLower === "downloadfile" ||
      memberLower === "downloaddata" ||
      memberLower === "uploadstring" ||
      memberLower === "uploadfile" ||
      memberLower === "uploaddata" ||
      memberLower === "uploadvalues" ||
      memberLower === "postasync" ||
      memberLower === "putasync" ||
      memberLower === "sendasync" ||
      memberLower === "getstringasync" ||
      memberLower === "getbytearrayasync"
    ) {
      const isUpload =
        memberLower.startsWith("upload") ||
        memberLower === "postasync" ||
        memberLower === "putasync" ||
        memberLower === "sendasync";
      effects.push({
        tag: isUpload ? "net_egress" : "net_read",
        layer: depth,
        target: `${normType}::${mi.member}`,
      });
      continue;
    }

    if (
      (mi.static && isLitType && normType === "scriptblock" && memberLower === "create") ||
      (mi.static &&
        isLitType &&
        normType === "net.servicepointmanager" &&
        (memberLower === "servercertificatevalidationcallback" || memberLower === "certificatepolicy"))
    ) {
      if (memberLower === "create") {
        effects.push({ tag: "exec_inline", layer: depth, target: "[scriptblock]::Create" });
      }
      opaque.push(`pwsh_dotnet_${memberLower}`);
      continue;
    }

    if (
      (mi.static &&
        isLitType &&
        normType === "runtime.interopservices.marshal" &&
        (memberLower === "ptrtostringauto" || memberLower === "ptrtostringbstr" || memberLower === "securestringtobstr")) ||
      (mi.static && isLitType && normType === "security.cryptography.protecteddata" && memberLower === "unprotect") ||
      memberLower === "getnetworkcredential" ||
      normType === "windows.security.credentials.passwordvault"
    ) {
      effects.push({
        tag: "read_secret",
        layer: depth,
        target: `${normType}::${mi.member}`,
        detail: "windows_credential_api",
      });
      continue;
    }

    // Fail-safe catch-all for ALL unrecognized static/instance member invocations & non-literal types (C-1)
    const label = mi.static && isLitType ? `${normType}::${mi.member}` : `instance::${mi.member}`;
    const reason = `pwsh_unknown_member:${label}`;
    opaque.push(reason);
    effects.push({ tag: "opaque", layer: depth, target: label, detail: reason });
  }

  // 8. Check shadowed functions invoked later in same input
  const definedFuncs = new Set(ast.functionDefs.map((f) => f.toLowerCase()));
  const pipeBuckets = new Map<number, Array<{ idx: number; name: string }>>();

  for (const cmd of ast.commands) {
    if (cmd.name === null) {
      opaque.push("pwsh_dynamic_command_name");
      continue;
    }

    const rawCmdName = cmd.name;
    const rawCmdLower = rawCmdName.trim().toLowerCase();
    const canonical = resolvePwshCommandCanonical(rawCmdName, shell);
    const lowerCanon = canonical.toLowerCase();
    const nonLinearCwd = cmd.inConditionalOrLoop || cmd.scriptBlockDepth > 1;

    if (definedFuncs.has(rawCmdName.toLowerCase()) || definedFuncs.has(lowerCanon)) {
      opaque.push(`pwsh_shadowed_function:${rawCmdName}`);
    }

    const disamb = disambiguatePwshParams(canonical, cmd);
    opaque.push(...disamb.opaqueReasons);

    // Handle PowerShell dot-sourcing
    if (cmd.invocationOperator === "Dot") {
      if (isTrustedVenvActivation(rawCmdName, options)) {
        commands.push({
          name: rawCmdName,
          argv: disamb.positionals,
          rawText: rawCmdName,
          redirections: [],
          assignments: {},
          envReads: [],
          depth,
          layer: shell,
          effectiveCwd: currentCwd,
          ...(cwdChanged || nonLinearCwd ? { cwdChanged: true } : {}),
          pwshCanonicalName: canonical,
          pwshAllowVenvActivate: true,
        });
        continue;
      }
      opaque.push(`pwsh_dot_source:${rawCmdName}`);
    }

    if (cmd.nativeArgQuirk && !CMDLET_PARAM_SPECS[canonical]) {
      opaque.push(`pwsh_native_arg_quirk:${rawCmdName}`);
    }

    // Track `Start-Process -Environment @{ ... }`
    if (canonical === "Start-Process") {
      const envElem = cmd.elements.find((el) => el.hashtableEntries !== undefined);
      if (envElem) {
        if (!envElem.hashtableAllKeysStatic) {
          opaque.push("pwsh_start_process_dynamic_env");
        }
        for (const kv of envElem.hashtableEntries ?? []) {
          if (kv.isNull) continue;
          assignments.push({
            name: kv.key,
            value: kv.valueStatic ?? "dynamic",
            standalone: false,
            depth,
            source: "wrapper",
          });
          if (!kv.isConstant && isSensitiveEnvVarName(kv.key)) {
            opaque.push(`dynamic_env_assignment:${kv.key}`);
          }
        }
      }
    }

    // Track `Set-Item` / `New-Item` / `Set-Content` writing to `Env:...`
    if (
      canonical === "Set-Item" ||
      canonical === "New-Item" ||
      canonical === "Set-Content"
    ) {
      const targetPath =
        (typeof disamb.params.Path === "string" ? disamb.params.Path : undefined) ??
        (typeof disamb.params.LiteralPath === "string" ? disamb.params.LiteralPath : undefined) ??
        disamb.positionals[0];
      const nameParam = typeof disamb.params.Name === "string" ? disamb.params.Name : undefined;
      const valParam = typeof disamb.params.Value === "string" ? disamb.params.Value : undefined;
      const prov = targetPath ? stripProviderDrive(targetPath) : null;
      if (prov && prov.provider === "env") {
        const cleanKey = prov.remainder.replace(/^[\\/]+/, "") || nameParam;
        if (cleanKey) {
          assignments.push({
            name: cleanKey,
            value: valParam ?? disamb.positionals[1] ?? "dynamic",
            standalone: true,
            depth,
            source: "standalone",
          });
        } else {
          opaque.push("pwsh_dynamic_env_write");
        }
      }
    }

    // Build redirections
    const redirs: RedirectionFact[] = [];
    for (const r of cmd.redirections) {
      if (r.targetStatic) {
        redirs.push({
          operator: r.operator,
          target: r.targetStatic,
          isWrite: r.operator.includes(">"),
          isRead: r.operator.includes("<"),
        });
      } else if (!r.operator.includes(">&")) {
        opaque.push("pwsh_dynamic_redirection");
      }
    }

    const isKnownCmdlet = Boolean(CMDLET_PARAM_SPECS[canonical]);
    const argv: string[] = [];
    if (isKnownCmdlet) {
      for (const [k, v] of Object.entries(disamb.params)) {
        if (v === true) {
          argv.push(`-${k}`);
        } else if (typeof v === "string") {
          argv.push(`-${k}`, v);
        }
      }
      argv.push(...disamb.positionals);
    } else {
      argv.push(...disamb.orderedArgv);
    }

    const fact: CommandFact = {
      name: rawCmdName,
      argv,
      ...(isKnownCmdlet ? {} : { argvDynamic: disamb.orderedArgvDynamic }),
      rawText: `${rawCmdName} ${argv.join(" ")}`.trim(),
      redirections: redirs,
      assignments: {},
      envReads: [],
      pipelineId: cmd.pipelineId > 0 ? cmd.pipelineId : undefined,
      pipelineIndex: cmd.pipelineId > 0 ? cmd.pipelineIndex : undefined,
      depth,
      layer: shell,
      effectiveCwd: currentCwd,
      ...(cwdChanged || nonLinearCwd ? { cwdChanged: true } : {}),
      pwshCanonicalName: canonical,
      pwshParams: disamb.params,
      ...(Object.keys(disamb.paramArrays).length > 0 ? { pwshArrayParams: disamb.paramArrays } : {}),
      pwshExplicitWhatIf: disamb.params.WhatIf === true,
      pwshPositionalArgs: disamb.positionals,
      ...(disamb.positionalConstants.some((c) => !c)
        ? { pwshPositionalDynamic: disamb.positionalConstants.map((c) => !c) }
        : {}),
    };
    commands.push(fact);

    if (cmd.pipelineId > 0) {
      const list = pipeBuckets.get(cmd.pipelineId) ?? [];
      list.push({ idx: cmd.pipelineIndex, name: canonical });
      pipeBuckets.set(cmd.pipelineId, list);
    }

    // Update linear cwd on Set-Location / Push-Location / Pop-Location (including cd.. / cd\)
    if (canonical === "Set-Location" || canonical === "Push-Location") {
      const dest =
        rawCmdLower === "cd.."
          ? ".."
          : rawCmdLower === "cd\\" || rawCmdLower === "cd/"
            ? "\\"
            : ((typeof disamb.params.Path === "string" ? disamb.params.Path : undefined) ??
              (typeof disamb.params.LiteralPath === "string" ? disamb.params.LiteralPath : undefined) ??
              disamb.positionals[0]);

      const prov = dest ? stripProviderDrive(dest) : null;
      if (prov) {
        cwdChanged = true;
        if (prov.provider === "env") {
          effects.push({ tag: "read_secret", layer: depth, target: dest, detail: "env_provider_cd" });
        } else if (prov.provider === "hklm" || prov.provider === "hkcu") {
          effects.push({ tag: "privilege", layer: depth, target: dest, detail: "registry_provider_cd" });
        } else {
          opaque.push(`pwsh_provider_cd:${prov.provider}`);
        }
      } else if (nonLinearCwd || !dest || disamb.positionalConstants[0] === false) {
        cwdChanged = true;
      } else {
        const next = normalizeStaticPwshCwd(currentCwd, dest);
        if (next) {
          if (canonical === "Push-Location") {
            cwdStack.push(currentCwd);
          }
          currentCwd = next;
        } else {
          cwdChanged = true;
        }
      }
    } else if (/^cd[.\\/]/i.test(rawCmdLower)) {
      cwdChanged = true;
    } else if (canonical === "Pop-Location") {
      if (!cwdChanged && !nonLinearCwd && cwdStack.length > 0) {
        currentCwd = cwdStack.pop()!;
      } else {
        cwdChanged = true;
      }
    }
  }

  for (const [pid, list] of pipeBuckets.entries()) {
    list.sort((a, b) => a.idx - b.idx);
    if (list.length > 0) {
      pipelines.push({
        id: pid,
        depth,
        commands: list.map((x) => x.name),
      });
    }
  }

  return {
    commands,
    pipelines,
    effects,
    opaque: Array.from(new Set(opaque)),
    envReads: Array.from(envReads),
    assignments,
    unescapedSources,
    cwdChanged,
  };
}
