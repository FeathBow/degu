pub(super) const TOP_LEVEL_HELP_TEMPLATE: &str = "{about-with-newline}
{usage-heading} {usage}

Inspect:
  scan         Inspect known caches and selected project roots
  doctor       Check account readiness for sealed staging
  quota        Report authoritative filesystem quota for one path

Clean and recover:
  reclaim      Preview an explicitly selected tool-native cache action
  clean        Preview or execute a cleanup plan
  undo         Restore the latest staged clean operation
  trash        Inspect or permanently purge trash entries

Configure:
  relocate     Print shell config for future cache writes

Administration:
  admin        Perform an explicit root-only administrative operation

Reference:
  ops          Show recorded clean, restore, and purge operations
  adapters     List adapter IDs accepted by --only and configuration
  completions  Generate shell completions
  man          Generate a man page for degu or one command path
  help         Show command help

Options:
{options}{after-help}";
