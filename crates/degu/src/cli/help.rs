pub(super) const TOP_LEVEL_HELP_TEMPLATE: &str = "{about-with-newline}
{usage-heading} {usage}

Inspect:
  scan         Inspect known caches and selected project roots
  quota        Report authoritative filesystem quota for one path

Clean and recover:
  clean        Preview or execute a cleanup plan
  undo         Restore the latest staged clean operation
  trash        Inspect or permanently purge trash entries

Configure:
  relocate     Print shell config for future cache writes

Reference:
  ops          Show recorded clean, restore, and purge operations
  adapters     List adapter IDs accepted by --only and configuration
  completions  Generate shell completions
  man          Generate a man page for degu or one command path
  help         Show command help

Options:
{options}{after-help}";
