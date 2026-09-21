pub(super) const TOP_LEVEL_HELP_TEMPLATE: &str = "{about-with-newline}
{usage-heading} {usage}

Inspect:
  scan         Inspect known caches and selected project roots
  tui          Review findings interactively and clean what you choose
  doctor       Check whether required account setup is ready
  quota        Report authoritative filesystem quota for one path

Account setup:
  init         Provision this account's fixed self-managed authority

Clean and recover:
  clean        Preview or execute a cleanup plan
  undo         Restore the latest staged clean operation
  trash        Inspect or permanently purge trash entries

Advanced irreversible actions:
  reclaim      Preview an explicitly selected tool-native cache action

Configure:
  relocate     Print shell config for future cache writes

Administration:
  admin        Provision explicit root-only account setup

Reference:
  ops          Show recorded clean, restore, and purge operations
  adapters     List adapter IDs accepted by --only and configuration
  completions  Generate shell completions
  man          Generate a man page for degu or one command path
  help         Show command help

Options:
{options}{after-help}";

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    /// Every subcommand is named in the template.
    ///
    /// The groups above are written out by hand, so a command added to the
    /// enum reaches `--help` only if someone also adds it here. `tui` shipped
    /// without that, and the ordering test guarding this file was a hand-kept
    /// list too, so it missed the same command. Ask clap instead.
    #[test]
    fn the_help_template_names_every_subcommand() {
        let command = crate::cli::Cli::command();
        let missing: Vec<&str> = command
            .get_subcommands()
            .map(clap::Command::get_name)
            .filter(|name| !super::TOP_LEVEL_HELP_TEMPLATE.contains(&format!("\n  {name} ")))
            .collect();
        assert!(
            missing.is_empty(),
            "the top-level help lists no {missing:?}; add them to a group in this file"
        );
    }
}
