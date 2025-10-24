# Default Linux rules
Audit rules are loaded by the auditd service. These rules are located in `/etc/audit/rules.d/`. You can either make separate rules files and name them by priority (ex. `10-sshconf.rules`, `20-passwd.rules`), or put everything into one `audit.rules` file. The latter is the approach that the app uses. The reason for this is easier rule management - you only need to modify/maintain/check one rule file, and since the app is designed for smaller environments, multiple extensive rule files are not used. You can however, do so manually if you wish.

The rule templates defined here are **VERY general**, and you should, if possible, customize them yourself according to your own environment (you might want to monitor `npm` usage or the `www-data` user if you're running a webserver, for example). These are some excellent sources for audit rules and their creation:

Florian Roth's general auditd ruleset - https://github.com/Neo23x0/auditd

Various rulesets, including ones that are designed for popular security standards - https://github.com/linux-audit/audit-userspace/tree/master/rules

Audit.conf configuration and how auditd works in general - https://documentation.suse.com/sles/12-SP5/html/SLES-all/cha-audit-scenarios.html#sec-audit-scenauconf

For Windows monitoring, the app uses [SwiftOnSecurity's sysmon config](https://github.com/SwiftOnSecurity/sysmon-config). This file is downloaded directly to the Windows endpoint.

# Rule writing

## Architecture
There are three rulesets in two directories, `x32` and `x64`. These directories are used for sorting rules by 32-bit and 64-bit systems. If you're using a 64-bit system, make sure to use 64-bit rules, and vice versa. By default, the `x64/audit_default.rules` ruleset is loaded. By using rules that exclusively monitor syscalls specific to your system's architecure, [better performance is achieved](https://man7.org/linux/man-pages/man7/audit.rules.7.html).

Instead of monitoring all arch types in your rules like this (same rule is re-run twice for separate architectures, inefficient as it effectively doubles the amount of rules and resources used):
```
-a always,exit -F arch=b64 -S all -F path=/etc/passwd -F perm=wa -F auid!=unset -k identity_mod
-a always,exit -F arch=b32 -S all -F path=/etc/passwd -F perm=wa -F auid!=unset -k identity_mod
```
You can catch all syscalls made in a different architecture than the one your endpoint has (which can be an irregular and suspicious activity) in a [single rule](https://github.com/linux-audit/audit-userspace/blob/c014eec64b3a16c004f4a75e5792a4ac2fcc0df2/rules/21-no32bit.rules):
```
-a always,exit -F arch=b32 -S all -k 32bit_abi
```

This way you both achieve better performance and monitor potentially suspicious activity related to [ABI](https://stackoverflow.com/questions/2171177/what-is-an-application-binary-interface-abi) abuse.

## File watch rules vs Syscall format rules

And older format of watching files/directories was this:
```bash
-w /etc/passwd -p wa -k passwd_changes
# -w - file path to watch.
# -p - what to log, in this case `wa` means log any Write and Access changes.
# -k - assigns a key to the rule. used for easier formatting/log filtering.
```
This is a shortened format of a regular syscall rule. This format is considered [deprecated](https://man7.org/linux/man-pages/man8/auditctl.8.html), because it watches both architectures (which the downsides of doing so we discussed earlier), and doesn't allow for filtering, which can be extremely useful when trying to generate less noise (we can filter out system daemons by using `auid!=unset` for example). 

A more performance-friendly version of the same rule on a 64-bit system can look like this:
```bash
-a always,exit -F arch=b64 -F path=/etc/passwd -F perm=wa -F auid!=unset -k identity_mod
# -a - Here it logs on syscall exit
# -F arch=b64 - specifies to log only 64-bit syscalls
# -F path=/etc/passwd - specifies file to monitor
# -F perm=wa - what sort of changes to log. `wa` means log any Write and Access syslog events.
# -F auid!=unset - system daemons have an unset auid. this filters out system daemon calls to this file, which is usually safe. daemons started by the user (after user login) inherit their auid, so these syscalls are still logged. Root user actions (auid=0) are also still logged.
# -k identity_mod - key to assign to the rule. used for easier formatting/log filtering.
```
It is generally recommended to either use the syscall rule format or convert existing `-w` rules to it.

## Rule types

There main types of syscall format rules are:

### File watch rules

These are the rules we discussed earlier. These rules do as the name describes - they watch files according to specified changes. The changes to watch for are specified after the `-F perm=` flag:
```
    -w - log any Write syslog events.
    -a - log any Access syslog events.
    -r - log any Read syslog events.
    -x - log any Execute syslog events.
```
These can also be combined:
```
-wa - log any Write and Access syslog events.
```
These arguments are only a way to specify what type of syslogs to monitor for the file. The longer, more unwieldy way of doing this would be:
```
-S open, openat, open_by_handle_at, open_by_handle_at, write, pwrite, writev, pwritev, pwritev2
```

Basically, something like `-F perm=war` says "watch all syscalls that are associated with opening/reading/accessing the file", instead of "watch this specific syscall, and this specific syscall, and this and so on". Also, this way of monitoring is quicker than with the `-S` flag, since the kernel knows to automatically skip all syscalls that are not file-related.

The file to watch is specified after the `-F path=` flag. Path watches can also be used for executables, but we will later discuss why this shouldn't be done.

A full file watch rule might look like this:
```bash
-a always,exit -F path=/etc/passwd -F perm=wa -F auid!=unset -k identity_mod
```

This would watch for any Write and Access events (`-F perm=wa`) made by any user (excluding system daemons, `-F auid!=unset`) to the `/etc/passwd` file, and assign it the `identity_mod` key. The `-a always,exit` flag just means that it will log on syscall exit.

### Directory watch rules

Directory watch rules are similar to file watch rules - they just watch directories instead of files. These rules audit **all** files and subdirectories within the specified directory. For example, this rule:

```bash
-a always,exit -F dir=/etc/ -F perm=wa -F auid!=unset -k config_mod
```

Will log all write and access events (`-F perm=wa`) made by any user (excluding system daemons, `-F auid!=unset`) to any file or subdirectory within the `/etc` directory, and assign it the `config_mod` key. 

Due to these rules being recursive, a frequent surprise with directory watches is the volume of events they can produce. Because of this, you should try to monitor only sensitive directories that experience little change, or only monitor specific directories (`/etc/passwd` instead of `/etc`, for example).

### Executable watch rules

While file and dir rules automatically match all syscalls related to files, executable rules differ in this regard. Here, we need to specify a specific executable, and the syscalls we wish to monitor for it. If we want to monitor all syscalls related to the `ls` command, for example, we would do something like this:

```bash
-a always,exit -F exe=/usr/bin/ls -F auid!=unset -k ls_exec
```
The result is that whenever `ls` runs, you’ll get a trail of all system calls it invokes (file opens, reads, writes, etc.). This is useful for tracing what a particular program did.

However, with common binaries, it can generate a lot of noise. If you wish to just log whenever an executable runs, you can use the `-S exec,execve` flag. This will monitor only the execute syscalls made towards that file.

```bash
-a always,exit -S exec,execve -F exe=/usr/bin/ls -F auid!=unset -k ls_exec
```
Now, we would only get logs that show when `ls` runs. Note that the command's arguments can still be seen and used to understand what `ls` was used for.

To summarize, think of the `exe` filter as identifying which process to audit, whereas `perm` identifies what kind of file operation to audit.

You might wonder when to use an `-F exe` rule versus a directory execute watch ( `-w /some/dir -p x` ). A directory watch is broad – for example, `-w /usr/bin -p x` will log any program executed from /usr/bin (i.e., nearly every command on the system). That is a lot of data and not selective. An -F exe rule, by contrast, is very specific – e.g., “monitor this exact program.” 

Use directory execution watches if you need a catch-all in less busy or sensitive directories, but prefer exe rules for targeted auditing of specific programs.

### File watch rules vs executable watch rules

Earlier we mentioned briefly how you shouldn't use `path=` rules for tracking file executions. The main reason is this - `exe=` rules log runs of the specified program, **no matter how it was invoked**. If we specify the `/usr/bin/ls` file, it will log runs of `ls`, `./ls`, `./usr/bin/ls`, etc. `path=` rules, on the other hand, will only log runs of `/usr/bin/ls` if it was invoked as `/usr/bin/ls`. This is extremely useful, because instead of having to write:

```bash
-a always,exit -F path=/usr/bin/ls -F perm=x -F auid!=unset -k ls_exec
-a always,exit -F path=/usr/bin/./ls -F perm=x -F auid!=unset -k ls_exec
-a always,exit -F path=/usr/bin/./usr/bin/ls -F perm=x -F auid!=unset -k ls_exec
```
You can just combine this into a single rule:

```bash
-a always,exit -S exec,execve -F exe=/usr/bin/ls -F auid!=unset -k ls_exec
```
This is both easier to maintain and more performant - instead of having to check three rules, the kernel only has to check one. In simpler terms, `exe=` rules catch symlinks, `path=` rules don't.

More niche advantages also include the ability to monitor the same file across inodes. If you update a binary, it's path remains the same, but it's inode changes. `path=` rules use inodes to watch files, while `exe=` rules use paths (you'd think it would be the reverse!). This means you don't have to restart the audit service to properly monitor a new version of a binary if you're using `exe=` rules.

Since `exe=` rules don't attach themselves to an inode, this also means you can pre-emptively specify rules for files before they're even created. For example, if you don't have python installed on your system, but suspect someone could do so and then use that for launching a script, you can specify an `exe=` rule for `/usr/bin/python3` before it's installed. 

It's worth noting that `exe=` rules are not supported by older versions of auditd. If you see an error like “unknown field: exe” when loading a rule, it likely means the installed audit service is too old to support it.

## Custom rules

You can write and save your custom rules to `/rulesets/` directory. These rules will automatically appear in the web interface upon refresh. If you wish to apply a custom ruleset (or change rules in general), you can just re-run the `enlist.sh` script after changing the ruleset through the UI.

You can change the alert priorities in the `/config/audit_priorities.conf` file.

# Windows rules

Windows monitoring uses the SwiftOnSecurity [SysmonConfig](https://github.com/SwiftOnSecurity/SysmonConfig). This is a general config that should cover most use-cases. Rules can only be changed locally. Be wary that re-running `enlist-windows.ps1` might overwrite any custom additions.

You can change the alert priorities in the `/config/sysmon_priorities.conf` file.

# Sources

Auditctl man page: https://www.man7.org/linux/man-pages/man8/auditctl.8.html

Redhat security guide's system auditing chapter: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/security_guide/chap-system_auditing

Audit.rules man page: https://www.man7.org/linux/man-pages/man7/audit.rules.7.html

OpenSUSE's "The Linux Audit Framework" chapter: https://documentation.suse.com/sles/12-SP5/html/SLES-all/cha-audit-comp.html

