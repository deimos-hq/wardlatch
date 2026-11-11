# Reach

`npx wardlatch@latest --reach` answers one question: **if a program ran in this terminal or CI job right now, which
guarded data and credential files could it open?**

A program that steals credentials can take only what the process it runs in can open. A package's install script runs
in your terminal, with your terminal's permissions. `--reach` measures those permissions directly, for a fixed list of
places such programs go for, and prints one line per place.

It is not a malware scan. It has no signatures and looks for no known bad file. "Reachable" means *this process can
open it*. It never means anything opened it, and `--reach` makes no statement about what has happened to a machine.

It is off unless you ask for it, and it runs **instead of** the incident checks, never beside them (see
[Why it runs on its own](#why-it-runs-on-its-own)).

## What it does to each place

Three system calls, in this order, and no others (`lib/reach.mjs`):

1. `lstat`: what is at the path (a file, a folder, a link, something else), without following a link.
2. `realpath`: only to learn whether a link on the way leads outside your home folder.
3. `open` for reading (`O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_NOCTTY`, and `O_DIRECTORY` for a folder), then `close`
   at once.

It never reads a byte. It never lists a folder, so it never learns a name inside one. It does not stat what is inside
a folder. It opens no network connection and writes nothing. Two tests hold it to this: the code is run against a
stand-in for the disk that fails on any call but those four, and the command is run under a spy that fails if anything
under the home folder is read or listed. Each test is shown to be able to fail (`test/reach.test.mjs`, R16 to R18).

What Wardlatch cannot promise is what the operating system does when a file is opened. Opening does not change a
file's times. On macOS, a refused attempt may be noted by the system, and the app the terminal runs in may then appear,
switched off, in a Privacy & Security list. This is from general experience of macOS, not from Apple's documentation,
and was not measured here.

## What a line says

| State | Means | Decided by |
|---|---|---|
| `reachable` | This process opened it. A REVIEW line, with one fix line. | `open` succeeded. |
| `blocked` | This process was refused. The line says what is known about why, or that it is not known. | `EACCES` or `EPERM`, from `lstat`, `realpath` or `open`. Nothing else. |
| `not there` | Nothing is at that path. | `ENOENT` or `ENOTDIR` from `lstat`, unless one of the two rules below applies. |
| `could not tell` | Wardlatch has no answer. A REVIEW line, with the reason and the errno. | Everything else (below). |
| `not applicable` | The place does not exist on this operating system (Messages on Linux). | The list has no path for this system. |

`EACCES` and `EPERM` are told apart because they mean different things. Apple's developer support describes it this
way: an operation "blocked by BSD permissions or ACLs" fails with `EACCES`, and one "blocked by something else" fails
with `EPERM` ([On File System Permissions](https://developer.apple.com/forums/thread/678819), an Apple staff post, not a
manual page). So:

- **`EACCES`** is file permissions or an access list, on the place or on a folder on the way. The line says that
  whoever owns the file can change them. It holds only while they stay as they are.
- **`EPERM`** is the system refusing above the permission bits. On macOS that is its privacy protection, or a sandbox
  the run is inside. Wardlatch cannot tell those apart, and says so on every such line.

### Could not tell

"Could not tell" is never folded into "not there" or "blocked". It is said for:

- **Any other errno** (`ELOOP`, `ENAMETOOLONG`, `EIO`, `ENXIO`, `EMFILE`, and so on), named, with the call it came from.
- **"No such file" for a place the system keeps in every account.** One place is marked this way: the privacy
  permissions database at `~/Library/Application Support/com.apple.TCC/TCC.db`. macOS 26 and earlier keep it in every
  account, so "no such file" there cannot be believed. On macOS 27 Apple's release notes say "Apps can no longer access
  the local TCC database directly", and third parties report that the file moved out of the home folder, which would
  make "no such file" true. `--reach` does not read the macOS version and does not choose between the two.
- **"No such file" while a variable says the tool keeps it elsewhere.** If `AWS_SHARED_CREDENTIALS_FILE` is set, an
  empty `~/.aws/credentials` says nothing about where your AWS keys are. Only whether the variable is set is looked at,
  never its value, and the other place is not followed. The variables are the ones each vendor documents:
  `NPM_CONFIG_USERCONFIG`, `GH_CONFIG_DIR`, `XDG_CONFIG_HOME`, `DOCKER_CONFIG`, `AWS_SHARED_CREDENTIALS_FILE`,
  `CLOUDSDK_CONFIG`, `AZURE_CONFIG_DIR`, `KUBECONFIG`, `CARGO_HOME`, `CHROME_USER_DATA_DIR`.
- **"No such file" from `open` after `lstat` saw the file.** Something changed, or something is hiding it.
- **A link that leads outside the home folder.** It is not followed. `--reach` promises to touch only the listed places
  under your home folder, and a link can point at a device, a network share or another account. A link that stays
  inside the home folder (a dotfiles folder linked into place) is followed, because it is the same credential. A
  program that opens the path would follow either kind, which is why the answer is "could not tell" and not "blocked".
- **A link to nothing.**
- **A FIFO, socket or device, or a file where a folder is expected.** It is not opened. Opening a FIFO for reading
  waits for a writer; `O_NONBLOCK` is also set, in case one appears between the look and the open.
- **No home folder**, or **Windows** (not supported: nothing is opened).

## Whose reach it is

The first lines of the output say what was measured: this process only, started from this shell, as this user (or as
root, with what that changes). Another terminal, an editor's built-in terminal, an agent's app, a CI runner: each has
its own permissions and may get different answers. Run `--reach` in the place whose reach you want to know.

A "blocked" or "not there" line is about this process and these exact paths. It is no all-clear. Other browser
profiles, other tools and other places are not on the list.

## Why it runs on its own

Wardlatch's incident checks print SAFE, EXPOSED or UNKNOWN ("could not be tested"), and set the exit code: 1 for
EXPOSED, 2 for UNKNOWN. `--reach` is a different kind of statement and must not be able to move those.

- It runs instead of the incident checks, so there is no SAFE, EXPOSED or UNKNOWN line in its output to add to, change
  or soften. `--reach` with `--incident`, `--paths` or `--no-containers` is refused (exit 2) before anything runs.
- A `reachable` and a `could not tell` are REVIEW lines. The other three states carry no status word.
- The exit code is 0 whatever it finds. Being able to open your own `~/.ssh` is the usual state of a developer's
  machine, not a failure of a pipeline. Only a wrong option or a crash exits 2.
- `--json` gives `mode: "reach"`, `counts` and a `reach` list, and no `results` list, so a reader of the incident
  checks' output cannot take one for the other.

## The list

The list is data, in [`lib/reach/items.json`](../lib/reach/items.json): each place has the page it comes from
(`source`), what that page says (`sourceSays`), and for a `reachable` line a fix and the page the fix comes from. Paths
are fixed and relative to the home folder; nothing is searched for. Checked on 11 November 2026.

### macOS-guarded data (macOS only)

| Place | Path | Source |
|---|---|---|
| Messages history | `~/Library/Messages/chat.db` | [Mac User Guide](https://support.apple.com/guide/mac-help/mchl211c911f/mac) |
| Mail folder | `~/Library/Mail` | same |
| Safari history | `~/Library/Safari/History.db` | same |
| Safari cookies | `~/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies` | [macOS 27 release notes](https://developer.apple.com/documentation/macos-release-notes/macos-27-release-notes) |
| Notes database | `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite` | same |
| Privacy permissions database, where macOS 26 and earlier keep it | `~/Library/Application Support/com.apple.TCC/TCC.db` | same |

Apple's Mac User Guide says Full Disk Access lets an app "access all files on your computer, including data from other
apps (for example, Mail, Messages, Safari, and Home)". Apple's Platform Security guide,
[Controlling app access to files in macOS](https://support.apple.com/guide/security/controlling-app-access-to-files-secddd1d86a6/web),
describes the consent macOS requires. Apple names the data, not the paths: the paths above are where macOS keeps it,
and Apple does not publish them. Apple does not name Notes; its database is in an app group container, and the macOS 27
release notes say access to other developers' "app data containers and app group containers" is "denied by default".

A `reachable` line here means the app this terminal runs in has been let in. The fix line says where to look:
Apple menu > System Settings > Privacy & Security > Full Disk Access (the Mac User Guide page above).

### Browser data

| Place | macOS | Linux | Source |
|---|---|---|---|
| Google Chrome data folder | `~/Library/Application Support/Google/Chrome` | `~/.config/google-chrome` | [Chromium docs](https://chromium.googlesource.com/chromium/src/+/main/docs/user_data_dir.md) |
| Chrome cookies, first profile | `…/Default/Cookies` or `…/Default/Network/Cookies` | same, under the Linux folder | [Chromium source](https://chromium.googlesource.com/chromium/src/+/main/chrome/common/chrome_constants.h) |
| Chrome saved logins, first profile | `…/Default/Login Data` | same | [Chromium source](https://chromium.googlesource.com/chromium/src/+/main/components/password_manager/core/browser/password_manager_constants.cc) |
| Chromium data folder | `~/Library/Application Support/Chromium` | `~/.config/chromium` | Chromium docs |
| Microsoft Edge data folder | `~/Library/Application Support/Microsoft Edge` | `~/.config/microsoft-edge` | [Microsoft](https://learn.microsoft.com/en-us/microsoft-edge/extensions/developer-guide/alternate-distribution-options) (names the folders, not as the user data folder) |
| Brave data folder | `~/Library/Application Support/BraveSoftware/Brave-Browser` | not listed | [Brave help](https://support.brave.app/hc/en-us/articles/4413256282765-How-do-I-delete-my-data-in-Brave) |
| Vivaldi data folder | `~/Library/Application Support/Vivaldi` | `~/.config/vivaldi` | [Vivaldi help](https://help.vivaldi.com/desktop/privacy/preventing-vivaldi-profiles-from-being-uploaded-to-git-repositories/) |
| Firefox data folder | `~/Library/Application Support/Firefox` | `~/.mozilla/firefox` | [Mozilla](https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data) |

Only the browser's folder is opened, except for Chrome's first profile (`Default`). Other profiles have names that
Wardlatch would have to list the folder to learn, and it never lists one. Opera and Arc are not on the list: no page of
theirs was found that states the folder. Brave's Linux folder is left out because Brave's help page and Brave's own
issue tracker spell it differently. Snap and Flatpak installs keep their data elsewhere and are not looked at.

**Why a browser's folder may be blocked on macOS 27.** On the Mac this was built on (macOS 27.2.1), Chrome's cookies and
saved logins were refused to a plain command-line process. What is confirmed and what is not:

- *Confirmed, Apple:* the macOS 27 release notes say "XProtect may now restrict access to app data that is commonly
  targeted by malicious software. Accessing files created by other developer teams' apps may be denied by default but
  may be managed by the user in Privacy & Security settings."
- *Confirmed, Apple:* the same notes list a known issue: in the Files & Folders pane, "a process without a bundle ID
  cannot be granted access to specific app data containers or app group containers owned by other developer teams",
  with Full Disk Access as the workaround.
- *Not confirmed by Apple:* that Chrome's folder under `~/Library/Application Support` is one of the protected places.
  Apple's notes name no app and no folder. Third-party write-ups name Chrome, Brave, Edge and Firefox.
- *Not confirmed:* whether Full Disk Access lifts it. Sources disagree.
- *Not found:* any change of Chrome's own that would refuse the open. By every source read, macOS applies it.
- *Cannot be told apart by this tool:* a sandbox the terminal runs in refuses with the same `EPERM`.

So a blocked browser line on a Mac says: "not confirmed", then Apple's sentence, then that Apple does not name the
folder. On macOS 26 and earlier, and on Linux, no protection of these folders was found in any vendor's documentation,
and a `reachable` line says so instead of inventing a fix.

### Keychain (macOS only)

`~/Library/Keychains/login.keychain-db`. Apple says keychains are "in the Keychains folder in the Library folder in
your home folder" and "typically end with .keychain-db"
([Keychain Access User Guide](https://support.apple.com/guide/keychain-access/copy-keychains-kyca1121/mac)); the name
`login.keychain-db` itself was not found on an Apple documentation page. Apple describes keychain items as encrypted
([Keychain data protection](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)). Being
able to open the file is the usual state, and the fix line says nothing to switch off was found.

### Developer credentials (macOS and Linux)

| Place | Path | Source | What the vendor says instead |
|---|---|---|---|
| SSH folder | `~/.ssh` | [ssh(1)](https://man.openbsd.org/ssh.1#FILES) | A passphrase encrypts the key file; a FIDO key's private part "cannot be exported from the authenticator hardware" ([ssh-keygen(1)](https://man.openbsd.org/ssh-keygen.1)) |
| npm user config | `~/.npmrc` | [npm](https://docs.npmjs.com/cli/v11/configuring-npm/npmrc) | [Trusted publishing](https://docs.npmjs.com/trusted-publishers) for CI; granular tokens with an expiry |
| GitHub CLI hosts file | `~/.config/gh/hosts.yml` | [gh manual](https://cli.github.com/manual/gh_help_environment) for the folder; the file name is from [the vendor's source](https://github.com/cli/go-gh/blob/trunk/pkg/config/config.go) | The system credential store, which is the default ([gh auth login](https://cli.github.com/manual/gh_auth_login)) |
| Docker CLI config | `~/.docker/config.json` | [docker login](https://docs.docker.com/reference/cli/docker/login/) | A credential store or helper (same page) |
| AWS shared credentials | `~/.aws/credentials` | [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html) | IAM Identity Center; long-term keys are "not recommended" ([AWS](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-authentication.html)) |
| AWS sign-in token cache | `~/.aws/sso/cache` | same | Nothing found: this is where the recommended sign-in caches its token |
| .netrc | `~/.netrc` | [curl](https://curl.se/docs/manpage.html#-n) | No alternative found in curl's manual |
| Git credential store | `~/.git-credentials`, `~/.config/git/credentials` | [git-credential-store](https://git-scm.com/docs/git-credential-store) | git-credential-cache, or a helper that uses the system's secure storage (same page) |
| Google Cloud application default credentials | `~/.config/gcloud/application_default_credentials.json` | [Google Cloud](https://cloud.google.com/docs/authentication/application-default-credentials) | "choose a more secure alternative" to service account keys ([Google](https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys)) |
| Google Cloud CLI config folder | `~/.config/gcloud` | [gcloud](https://cloud.google.com/sdk/docs/configurations) | Nothing found; Google says to treat everything in it as a secret ([Google](https://cloud.google.com/sdk/crypto)) |
| Azure CLI folder | `~/.azure` | [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/azure-cli-configuration) | No encrypted store named for Linux and macOS ([Microsoft](https://learn.microsoft.com/en-us/cli/azure/msal-based-azure-cli)) |
| Kubernetes kubeconfig | `~/.kube/config` | [Kubernetes](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/) | No alternative found on that page |
| PyPI upload config | `~/.pypirc` | [Python packaging guide](https://packaging.python.org/en/latest/specifications/pypirc/) | keyring; [Trusted Publishing](https://docs.pypi.org/trusted-publishers/) for CI |
| Cargo registry credentials | `~/.cargo/credentials.toml` | [Cargo](https://doc.rust-lang.org/cargo/reference/config.html#credentials) | A credential provider ([Cargo](https://doc.rust-lang.org/cargo/reference/registry-authentication.html)) |

A fix line repeats what the vendor's page says and links it. Where no vendor recommendation was found, the line says
that. Wardlatch does not read these files, so it does not know whether one holds a token: `~/.config/gh/hosts.yml` is
there on a machine whose token is in the system's credential store, and "reachable" is true of it all the same.

## What is printed

Only the fixed labels and paths from the list, with the home folder written as `~`, a state, an errno name and counts.
No user name, no real path, no file size or time, nothing from inside a file, no name from inside a folder, and no
value of an environment variable. A test fills a home folder with marked content and marked names and fails if any of
it, or the home folder's own path, is printed (`test/reach.test.mjs`, R19).

## Not covered

- Anything not on the list: other browser profiles, password managers, wallets, chat apps, cloud-synced folders,
  `~/.gnupg`, shell history, `.env` files in projects, and the Linux desktop keyrings.
- Secrets in environment variables, which every program a shell starts is handed without opening anything.
- Credentials a tool keeps somewhere a variable names. The line says "could not tell" and names the variable.
- What the system's credential store would release if asked. `--reach` asks it nothing.
- A file on a network share that never answers. `open` on it can wait; `--reach` sets no timer.
- Whether anything was ever taken. This measures what can be opened now, by this process.
