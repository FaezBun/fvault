# Troubleshooting

## `vault not found` / `run 'fvault init' first`

`fvault` looks for `vault.json` in `./data` unless you set `FVAULT_HOME` or pass
`--home`. Make sure every command uses the same data directory.

```bash
export FVAULT_HOME=/var/lib/fvault
fvault doctor
```

## `Error: EOF` while adding an entry

The command prompts for each missing field. When piping input, supply every
prompt or pass the flags:

```bash
fvault add server-1/app --username admin --url https://example.com --generate
```

## Master Password is rejected

- The password is case-sensitive; check keyboard layout and Caps Lock.
- The vault may belong to a different data directory. Check `FVAULT_HOME`.
- If the vault was restored from another machine, use the password that was
  active when that snapshot was taken.
- There is no recovery mechanism. Keep backups and the Master Password safe.

## Login is locked for 15 minutes

Three failed web logins lock the source IP. Wait for the lockout, or restart the
service to reset in-memory state:

```bash
sudo systemctl restart fvault
```

If the server is behind a proxy, start it with `--trust-proxy` so the real client
IP is used instead of the proxy IP.

## Everyone is logged out after a restart

Sessions are stored in memory by design. Restarting the service invalidates all
sessions. Log in again.

## `Your session has expired` after changing the password

`fvault passwd` re-encrypts the vault with a new salt and key. Existing web
sessions can no longer decrypt it, so they are invalidated. Log in with the new
Master Password.

## `fvault: command not found`

Install the binary and web assets once:

```bash
./scripts/install.sh
```

The script installs to `~/.local/bin/fvault` and
`~/.local/share/fvault/{templates,static}`. If `~/.local/bin` is not in your
`PATH`, add it to your shell profile and open a new terminal.

## `could not load templates` / `static directory is missing`

The web server looks for assets in this order:

1. `--templates` / `--static`
2. `FVAULT_TEMPLATES` / `FVAULT_STATIC`
3. `./templates` and `./static` in the current directory
4. next to the `fvault` binary
5. `~/.local/share/fvault/templates` and `static`

Run `./scripts/install.sh` to install the assets, or run from the project
directory with the binary in `./bin`.

## Port already in use

`--port auto` scans `8000-8099` and then falls back to an OS-assigned port.
Behind a reverse proxy, use a fixed port such as `17384` so nginx can reach it.

```bash
fvault serve --host 127.0.0.1 --port 17384
```

## `502 Bad Gateway` from nginx

- Confirm the service is running: `systemctl status fvault`.
- Confirm the port in `proxy_pass` matches `FVAULT_PORT` / `--port`.
- Check the service logs: `journalctl -u fvault -n 100 --no-pager`.
- Make sure nginx and fvault agree on `127.0.0.1`.

## Login works over HTTP but not HTTPS

Start fvault with `--cookie-secure` and `--trust-proxy` behind nginx. Without
`--cookie-secure`, the cookie is usable over HTTPS but less strict. Without
`--trust-proxy`, all clients share the proxy IP and one lockout affects everyone.

## Remote backup is `UNAVAILABLE`

- The remote folder must be mounted and writable by the `fvault` user.
- The `.fvault-target` marker must exist. Re-run `fvault backup setup` or
  `fvault backup config set --remote-dir ...` to recreate it.
- Remote failures are warnings by default; local saves continue.
- Use `fvault backup status` and `fvault backup sync` to inspect.

## Backups stop growing

`fvault` skips snapshots whose content hash matches the newest snapshot. If the
vault did not change, no new snapshot is created. Check with:

```bash
fvault backup list
fvault backup status
```

## `doctor` reports permissions

The data directory and backups should be private:

```bash
chmod 700 /var/lib/fvault
chmod 600 /var/lib/fvault/vault.json
chmod 600 /var/lib/fvault/settings.json
chmod 600 /var/lib/fvault/secret.key
```

The service unit uses `UMask=0077`, so new files are private automatically.

## Clipboard copy fails

Install a clipboard utility:

```bash
sudo apt install xclip        # X11
sudo apt install wl-clipboard # Wayland
```

On a headless server there is no clipboard. Use `fvault get` to print the value
or use the web UI from a browser.

## `vault not found` after install

`fvault start` uses `./data` in the current directory unless `FVAULT_HOME` or
`--home` is set. Run it from the directory where you want the vault, or set a
stable location:

```bash
export FVAULT_HOME="$HOME/.local/share/fvault"
fvault start
```

## Build fails with `go: command not found`

If Go is installed in `~/.local/go`, add it to `PATH`:

```bash
export PATH="$HOME/.local/go/bin:$PATH"
```

The scripts also detect this location automatically.

## Recovering from a bad settings file

`settings.json` only contains backup configuration and can be recreated:

```bash
fvault backup setup
```

Never delete `vault.json` unless you have a verified backup and the Master
Password.
