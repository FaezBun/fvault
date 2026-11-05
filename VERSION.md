# fvault Version History

## Update 1.1.4

06/11/2026 01:04

### Changes

- Password generator button on the web entry form (length + symbols options).
- Emergency kit printed after vault creation; new `fvault kit` command.
- Tag management: `fvault tag list|rename|delete`, sidebar tag cloud, and a
  `/tags` page to rename or remove tags everywhere at once.
- Docker deployment: `Dockerfile` (multi-stage, non-root, healthcheck) and
  `docker-compose.yml`.
- Change the Master Password from the web (click your username in the nav);
  all sessions are logged out afterwards.
- Account recovery with 3 security questions: **mandatory setup at first
  run**, `fvault recovery setup|reset|disable|status`, and a "Forgot Master
  Password?" flow on the login page (rate limited).
- README: complete import/export reference, account recovery guide, and a
  Docker section.

## Update 1.1.3

05/11/2026 21:52

### Changes

- Fixed folder right-click menu not closing when clicking elsewhere
  (CSS `hidden` override plus mousedown/scroll/contextmenu listeners).
- Removed the search scope dropdown; the search bar is now a single fuzzy
  search across entry names and tags.
- Live search now updates results in place with fetch (no page reload, cursor
  stays where you type).
- Theme is applied before first paint, so dark mode no longer flickers on
  every search refresh.
- Markdown import accepts simple `Name : Password` lines (headings and key
  lines optional) with automatic name sanitising.
- CSV import needs only a name/username column and a password column.
- README now documents every import format (Markdown, CSV, JSON, Bitwarden,
  1Password) and the export formats in one reference section.

## Update 1.1.1

05/11/2026 21:18

### Changes

- Folder context menu: right-click a folder to open it, add an entry, rename it, or delete it.
- Entry edit can move an entry to another folder with a dropdown (no copy and recreate).
- Search limited to name or tags, with a scope selector and live search while typing.
- Sort by Tags and by Updated columns.
- Eye icon toggle for password fields (login, entry form, backup export).
- Web login rate limit: 10 attempts before a 15 minute lockout.
- Tags, pinned/favorite entries, and entry templates (server, database, api-token, ssh-key).
- CSV, JSON, Bitwarden and 1Password import and export.
- Password history, duplicate detection, and an audit log.
- Folder rename in the CLI (`fvault folder rename <old> <new>`), the menu, and the web UI.
- Dark mode, keyboard shortcuts, PWA manifest, and clipboard auto-clear.
- Export and restore for moving to a new computer (CLI, menu, and web download).
- README split into "New users" and "Existing users" with a migration guide.
