// Baseline declarative command definitions using the safe-chains TOML schema.
// Adapted from safe-chains (MIT OR Apache-2.0); see THIRD_PARTY_NOTICES.
// Stored as an exported TOML string so bundled plugin runtimes need no relative file I/O.

export const BUILTINS_TOML = `
[[commands]]
name = "pwd"
level = "Inert"
bare = true
bare_flags = ["-L", "-P"]

[[commands]]
name = "echo"
level = "Inert"
allow_all = true

[[commands]]
name = "printf"
level = "Inert"
allow_all = true

[[commands]]
name = "true"
level = "Inert"
allow_all = true

[[commands]]
name = "false"
level = "Inert"
allow_all = true

[[commands]]
name = "uname"
level = "Inert"
bare = true
bare_flags = ["-a", "-s", "-n", "-r", "-v", "-m", "-p", "-i", "-o"]

[[commands]]
name = "date"
level = "Inert"
bare = true
bare_flags = ["-u", "--utc", "-I", "-R"]
valued = ["-r", "-d", "--date"]

[[commands]]
name = "which"
level = "Inert"
bare_flags = ["-a", "-s"]

[[commands]]
name = "whoami"
level = "Inert"
bare = true

[[commands]]
name = "ls"
level = "SafeRead"
bare = true
bare_flags = ["-l", "-a", "-A", "-h", "-t", "-r", "-R", "-1", "-S", "-d", "-F", "--color", "--all", "--human-readable"]
valued = ["--color", "--sort", "--time-style"]

[[commands]]
name = "cat"
level = "SafeRead"
bare_flags = ["-n", "-b", "-s", "-A", "-E", "-T", "-v"]

[[commands]]
name = "head"
level = "SafeRead"
bare_flags = ["-q", "-v"]
valued = ["-n", "-c", "--lines", "--bytes"]

[[commands]]
name = "tail"
level = "SafeRead"
bare_flags = ["-q", "-v"]
valued = ["-n", "-c", "--lines", "--bytes"]

[[commands]]
name = "wc"
level = "SafeRead"
bare = true
bare_flags = ["-l", "-w", "-c", "-m", "-L"]

[[commands]]
name = "stat"
level = "SafeRead"
bare_flags = ["-L", "-f", "-x"]
valued = ["-c", "--format", "-f"]

[[commands]]
name = "file"
level = "SafeRead"
bare_flags = ["-b", "-i", "-L", "--mime", "--mime-type"]

[[commands]]
name = "grep"
aliases = ["egrep", "fgrep"]
level = "SafeRead"
bare_flags = ["-i", "-n", "-r", "-R", "-l", "-L", "-c", "-v", "-w", "-x", "-E", "-F", "-P", "-o", "-H", "-h", "-q", "-s", "--color"]
valued = ["-e", "-f", "-m", "-A", "-B", "-C", "--include", "--exclude", "--exclude-dir", "--color"]

[[commands]]
name = "rg"
level = "SafeRead"
bare_flags = ["-i", "-n", "-l", "-c", "-v", "-w", "-F", "-S", "-s", "-u", "--hidden", "--no-ignore", "--files", "--json", "--vimgrep", "--stats"]
valued = ["-e", "-f", "-g", "--glob", "-t", "--type", "-T", "--type-not", "-A", "-B", "-C", "-m", "--max-count", "--max-depth"]

[[commands]]
name = "fd"
level = "SafeRead"
bare = true
bare_flags = ["-H", "--hidden", "-I", "--no-ignore", "-i", "-s", "-a", "--absolute-path", "-p", "--full-path", "-F"]
valued = ["-t", "--type", "-e", "--extension", "-d", "--max-depth", "-E", "--exclude"]

[[commands]]
name = "find"
level = "SafeRead"
bare = true
bare_flags = ["-L", "-P", "-H", "-print", "-print0", "-ls", "-empty", "-not"]
valued = ["-name", "-iname", "-path", "-ipath", "-type", "-maxdepth", "-mindepth", "-size", "-mtime"]
deny = ["-exec", "-execdir", "-ok", "-okdir", "-delete"]

[[commands]]
name = "jq"
level = "SafeRead"
bare_flags = ["-r", "-c", "-e", "-s", "-S", "-n", "-M", "--raw-output", "--compact-output", "--sort-keys"]
valued = ["-f", "--arg", "--argjson"]

[[commands]]
name = "diff"
level = "SafeRead"
bare_flags = ["-u", "-r", "-N", "-q", "-w", "-b", "-B", "-i", "--unified"]
valued = ["-U"]

[[commands]]
name = "git"
level = "SafeRead"
valued = ["-C"]
deny = ["-c", "--config-env"]

  [[commands.sub]]
  name = "status"
  level = "SafeRead"
  bare = true
  bare_flags = ["-s", "--short", "-b", "--branch", "--porcelain", "-u", "--untracked-files", "--ignored"]

  [[commands.sub]]
  name = "diff"
  level = "SafeRead"
  bare = true
  bare_flags = ["--staged", "--cached", "--stat", "--name-only", "--name-status", "--shortstat", "-w", "--color", "--no-pager"]
  valued = ["-U", "--unified"]

  [[commands.sub]]
  name = "log"
  level = "SafeRead"
  bare = true
  bare_flags = ["--oneline", "--graph", "--decorate", "--all", "--stat", "-p", "--patch", "--name-only", "--name-status"]
  valued = ["-n", "--max-count", "--format", "--pretty", "--since", "--until", "--author", "--grep"]

  [[commands.sub]]
  name = "show"
  level = "SafeRead"
  bare = true
  bare_flags = ["--stat", "--name-only", "--name-status", "--oneline", "--no-patch", "-s"]
  valued = ["--format", "--pretty"]

  [[commands.sub]]
  name = "branch"
  level = "SafeRead"
  bare = true
  bare_flags = ["-a", "--all", "-r", "--remotes", "-v", "-vv", "--list", "--show-current"]
  deny = ["-d", "-D", "--delete", "-m", "-M", "-f", "--force"]

  [[commands.sub]]
  name = "rev-parse"
  level = "SafeRead"
  bare_flags = ["--show-toplevel", "--abbrev-ref", "--short", "--git-dir", "--is-inside-work-tree", "--verify"]

  [[commands.sub]]
  name = "ls-files"
  level = "SafeRead"
  bare = true
  bare_flags = ["-m", "-o", "-c", "-d", "--others", "--exclude-standard", "-z"]

  [[commands.sub]]
  name = "blame"
  level = "SafeRead"
  bare_flags = ["-s", "-w", "-e", "--line-porcelain"]
  valued = ["-L"]

  [[commands.sub]]
  name = "add"
  level = "SafeWrite"
  bare_flags = ["-A", "--all", "-u", "--update", "-p", "--patch", "-N"]

  [[commands.sub]]
  name = "restore"
  level = "SafeWrite"
  bare_flags = ["--staged", "-S"]
  valued = ["--source", "-s"]

[[commands]]
name = "mkdir"
level = "SafeWrite"
bare_flags = ["-p", "--parents", "-v", "--verbose"]
valued = ["-m", "--mode"]

[[commands]]
name = "touch"
level = "SafeWrite"
bare_flags = ["-c", "-a", "-m"]

[[commands]]
name = "cp"
level = "SafeWrite"
bare_flags = ["-r", "-R", "-p", "-a", "-v", "-n", "--no-clobber"]

[[commands]]
name = "mv"
level = "SafeWrite"
bare_flags = ["-v", "-n", "--no-clobber"]

[[commands]]
name = "npm"
level = "SafeRead"

  [[commands.sub]]
  name = "test"
  level = "ExecProject"
  bare = true
  tolerate_unknown_flags = true

  [[commands.sub]]
  name = "run"
  level = "ExecProject"
  first_arg = ["test", "lint", "typecheck", "build", "check", "format", "verify"]
  tolerate_unknown_flags = true

[[commands]]
name = "pnpm"
level = "SafeRead"

  [[commands.sub]]
  name = "test"
  level = "ExecProject"
  bare = true
  tolerate_unknown_flags = true

  [[commands.sub]]
  name = "run"
  level = "ExecProject"
  first_arg = ["test", "lint", "typecheck", "build", "check", "format", "verify"]
  tolerate_unknown_flags = true

[[commands]]
name = "yarn"
level = "SafeRead"

  [[commands.sub]]
  name = "test"
  level = "ExecProject"
  bare = true
  tolerate_unknown_flags = true

[[commands]]
name = "vitest"
level = "ExecProject"
bare = true
bare_flags = ["run", "--run", "--watch=false", "--silent", "--reporter=verbose"]
valued = ["-t", "--testNamePattern", "--reporter", "--config"]
tolerate_unknown_flags = true

[[commands]]
name = "pytest"
level = "ExecProject"
bare = true
bare_flags = ["-v", "-vv", "-q", "-s", "-x", "--tb=short", "--tb=no"]
valued = ["-k", "-m", "--maxfail", "-c"]
tolerate_unknown_flags = true

[[commands]]
name = "cargo"
level = "SafeRead"

  [[commands.sub]]
  name = "test"
  level = "ExecProject"
  bare = true
  tolerate_unknown_flags = true

  [[commands.sub]]
  name = "check"
  level = "ExecProject"
  bare = true
  tolerate_unknown_flags = true

  [[commands.sub]]
  name = "clippy"
  level = "ExecProject"
  bare = true
  tolerate_unknown_flags = true

  [[commands.sub]]
  name = "build"
  level = "ExecProject"
  bare = true
  tolerate_unknown_flags = true

[[commands]]
name = "go"
level = "SafeRead"

  [[commands.sub]]
  name = "test"
  level = "ExecProject"
  bare = true
  tolerate_unknown_flags = true

  [[commands.sub]]
  name = "vet"
  level = "ExecProject"
  bare = true
  tolerate_unknown_flags = true

  [[commands.sub]]
  name = "build"
  level = "ExecProject"
  bare = true
  tolerate_unknown_flags = true
`;
