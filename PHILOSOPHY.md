# Philosophy

Rule development can be hotly debated and there are many ideas for what makes a detection rule *good*. We hear about arguments between *Indicators of Compromise* vs. *Indicators of Attack* and *signatures* vs. *rules*. Instead of boring ourselves with those re-hashed discussions, we want to share our approach for rule writing and our expectations of this repository.

### The Zen of Security Rules

We incorporate the [Zen of Security Rules](https://zenofsecurity.io/rules) into all of our rule development and planning. We strive to follow these principles to ensure practical rule design for resiliency at scale. 


## Approach

Our goal is to improve detection within Elastic Security, while combating alert fatigue. When we create a rule, we often approach it from this perspective. To make sure a rule is a complete and a good candidate for Detection Rules, consider asking these questions: 

* Does this rule improve our detection or visibility?
* Does it strike a good balance between true positives, false positives, and false negatives?
* How difficult is it for an attacker to evade the rule?
* Is the rule written with [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/ecs-reference.html) in mind? Is the logic data source-agnostic or does it depend on specific beats or agents?

### Behavioral rules

Based on our approach, we tend to prefer rules that are more *behavioral* in nature. Behavioral rules are rules that focus on the attacker technique, and less on a specific tool or indicator. This might mean more research and effort is needed to figure out how a technique works. By taking this approach, we do a better job detecting and stopping the attacks of today and tomorrow, instead of the attacks of yesterday.

### Signatures and indicators

Even though we gravitate towards behavioral or technique-based rules, we don't want to automatically disqualify a rule just because it uses indicators of a specific actor or tool. Though those are typically more brittle, they tend to have less noise, because they are specifically written to detect exactly one thing. Sometimes tools are used across multiple actors or red teams, and a signature could go a long way.

One example would be a detection for the common open source tool [mimikatz](http://github.com/gentilkiwi/mimikatz), which is used by many red teams and in real world incidents. It dumps credentials by requesting read access to the `lsass.exe` process and decrypts passwords from memory. This technique is often too low-level for some tools. One way to detect it would be to look for special flags in the command line or inside the file itself, such as `sekurlsa::logonpasswords` or `sekurlsa::wdigest`. Those indicator-based detections are less effective these days, because `mimikatz` mostly runs in memory, so there's no command line or even a file to observe.

A better approach is to focus on the technique: remotely reading memory for `lsass.exe`. Defenders now have tools and solutions that can detect a process requesting memory access to `lsass.exe` and block or defend the behavior natively. One tool, Microsoft Sysmon, has Event ID 10: [ProcessAccess](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-10-processaccess) which can detect the access request to `lsass.exe`. From there, the logic needs to tune out legitimate software that requests access or tune out specific flags from the process access request. Then, you get a detection that doesn't just find `mimikatz`, but can also detect other tools like ProcDump.exe requesting memory access to `lsass.exe`.


## Review questions

There are a few ways that we strive to improve our detection rates and performance when writing rules. We ask a handful of questions while developing or reviewing rules. When contributing, consider this questionnaire:

### Does the rule detect what it's supposed to?

This probably seems like an obvious question, but is a crucial and regular part of any review for a new rule. Sometimes we work backwards from a specific indicator to a general rule. But when we get there, how do we know that we're detecting other instances of the technique?

Another good reason for asking this question: others may have experience with this type of data. Someone else may be aware of false positives which original author didn't anticipate.

Maybe you're looking for suspicious privilege escalation on Windows by looking for services that spawn with `cmd /c ...` in the command line. This is behavior metasploit does when calling `getsystem`. You might write a rule like this: `process.parent.name: services.exe and process.child.name: cmd.exe`, and it would detect what you expected. But what *else* did it detect? There are [failure actions](https://docs.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_failure_actionsw) for services that can run arbitrary commands when a service fails.

Knowing this, there are a few good options to take:
* Try switching to registry events to look for the `binPath` key
* Look for Windows Event Logs for [Event ID 4697](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4697) to detect service creations
* Leave the logic in there. Maybe you're more worried about failure actions also being used maliciously and don't want to risk the false negatives by making the rule more precise

Regardless of the approach you took, document any caveats in the rule's description, false positive notes, or investigation notes. This information helps users to both understand what the rule is trying to detect and will also give good information when triaging an alert.


### Does a rule have trivial evasions?

We don't want our rules to be trivial to evade. When looking for evasions in a rule, try putting on the hat of the adversary and ask yourself: *How could I perform this action while going undetected by this rule?*

One way that we've seen evasions before is when matching the command line for process events. Those rules can be trivial to evade. For instance, consider the command `wmic process call create whoami.exe`.

If you search for the substring `process call create`, then all an attacker has to do is add a few more spaces: `process  call   create`. Voilà! Undetected.

Maybe the next iteration of the rule tried to avoid whitespace evasions and then opted for `* process *` and `* call *` and `* create *`. But the rule is still easy to evade by quoting the individual args with the command `wmic "process" "call" "create" "whoami.exe"`.

The **ideal** way to write the rule would be to use a parsed command line and not rely on wildcards or regular expressions. Thankfully, [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html) has the [`process.args`](https://www.elastic.co/guide/en/ecs/current/ecs-process.html#_process_field_details) field which contains exactly this. Then the KQL for the rule is simple: `process.args:(process and call and create)`.


## Resources

- [MITRE ATT&CK®](https://attack.mitre.org)
- [MITRE ATT&CK philosophy](https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf)
- [Finding Cyber Threats with ATT&CK-Based Analytics](https://www.mitre.org/publications/technical-papers/finding-cyber-threats-with-attck-based-analytics)
