# Default rules
Audit rules are loaded by the auditd service. These rules are located in `/etc/audit/rules.d/`. You can either make separate rules files and name them by priority (ex. `10-sshconf.rules`, `20-passwd.rules`), or put everything into one `audit.rules` file. The latter is the approach that the app uses. The reason for this is easier rule management - you only need to modify/maintain/check one rule file, and since the app is designed for smaller environments, multiple extensive rule files are not used. You can however, do so manually if you wish.

The rule templates defined here are **VERY general**, and you should, if possible, customize them yourself according to your own environment (you might want to monitor `npm` usage or the `www-data` user if you're running a webserver, for example). These are some excellent sources for audit rules and their creation:

Florian Roth's general auditd ruleset - https://github.com/Neo23x0/auditd

Various rulesets, including ones that are designed for popular security standards - https://github.com/linux-audit/audit-userspace/tree/master/rules

Audit.conf configuration and how auditd works in general - https://documentation.suse.com/sles/12-SP5/html/SLES-all/cha-audit-scenarios.html#sec-audit-scenauconf

For Windows monitoring, the app uses [SwiftOnSecurity's sysmon config](https://github.com/SwiftOnSecurity/sysmon-config). This file is downloaded directly to the Windows endpoint.

## Architecture
There are three rulesets in two directories, `x32` and `x64`. These directories are used for sorting rules by 32-bit and 64-bit systems. If you're using a 64-bit system, make sure to use 64-bit rules, and vice versa. By default, the `x64/audit_default.rules` ruleset is loaded. By using rules that exclusively monitor syscalls specific to your system's architecure, [better performance is achieved](https://man7.org/linux/man-pages/man7/audit.rules.7.html).

Instead of monitoring all arch types in your rules like this (same rule is re-run twice for separate architectures, inefficient as it effectively doubles the amount of rules and resources used):
```
-a always,exit -F arch=b64 -S all -F path=/etc/passwd -F perm=wa -F auid!=unset -k identity_mod
-a always,exit -F arch=b32 -S all -F path=/etc/passwd -F perm=wa -F auid!=unset -k identity_mod
```
You can catch all syscalls made in a different architecture than the one your endpoint has (which is an irregular and suspicious activity) in a [single rule](https://github.com/linux-audit/audit-userspace/blob/c014eec64b3a16c004f4a75e5792a4ac2fcc0df2/rules/21-no32bit.rules):
```
-a always,exit -F arch=b32 -S all -k 32bit_abi
```

This way you both achieve much better performance and monitor potentially suspicious activity related to [ABI](https://stackoverflow.com/questions/2171177/what-is-an-application-binary-interface-abi) abuse.

## File watch rules vs Syscall rules

And older format of watching files/directories was this:
```bash
-w /etc/passwd -p wa -k passwd_changes
# -w - file path to watch.
# -p - what to log, in this case `wa` means log any Write and Access changes.
# -k - assigns a key to the rule. used for easier formatting/log filtering.
```
This is a shortened format of a regular syscall rule. This format is considered [deprecated](https://man7.org/linux/man-pages/man8/auditctl.8.html), because it watches both architectures (which the downsides of doing so we discussed earlier), and doesn't allow for filtering by `auid`, which can be extremely useful when trying to generate less noise (we can filter out system daemons by using `auid!=unset` for example). It also watches for all syscalls made towards the specified file, which might not always be necessary. 

A more performance-friendly version of the same rule on a 64-bit system can look like this:
```bash
-a always,exit -F path=/etc/passwd -F perm=wa -F auid!=unset -k identity_mod
# -a - Here it logs on syscall exit
# -F arch=b64 - specifies to log only 64-bit syscalls
# -F path=/etc/passwd - specifies directory to monitor
# -F perm=wa - what sort of changes to log. `wa` means log any Write and Access changes.
# -F auid!=unset - system daemons have an unset auid. this filters out system daemon calls to this file, which is usually safe. daemons started by the user (after user login) inherit their auid, so these syscalls are still logged. Root user actions (auid=0) are also still logged.
# -k identity_mod - key to assign to the rule. used for easier formatting/log filtering.
```
It is generally recommended to either use the syscall rule format or convert existing `-w` rules to it.