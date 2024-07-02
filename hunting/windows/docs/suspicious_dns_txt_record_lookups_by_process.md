# Suspicious DNS TXT Record Lookups by Process

---

## Metadata

- **Author:** Elastic
- **Description:** Leveraging aggregation by process executable entities, this hunt identifies identifies a high number of DNS TXT record queries from same process.
Adversaries may leverage DNS TXT queries to stage malicious content or exfiltrate data.

- **UUID:** `7a2c8397-d219-47ad-a8e2-93562e568d08`
- **Integration:** [endpoint](https://docs.elastic.co/integrations/endpoint), [windows](https://docs.elastic.co/integrations/windows)
- **Language:** `[ES|QL]`

## Query

```sql
f```

```sql
r```

```sql
o```

```sql
m```

```sql
 ```

```sql
l```

```sql
o```

```sql
g```

```sql
s```

```sql
-```

```sql
e```

```sql
n```

```sql
d```

```sql
p```

```sql
o```

```sql
i```

```sql
n```

```sql
t```

```sql
.```

```sql
e```

```sql
v```

```sql
e```

```sql
n```

```sql
t```

```sql
s```

```sql
.```

```sql
n```

```sql
e```

```sql
t```

```sql
w```

```sql
o```

```sql
r```

```sql
k```

```sql
-```

```sql
*```

```sql
,```

```sql
 ```

```sql
l```

```sql
o```

```sql
g```

```sql
s```

```sql
-```

```sql
w```

```sql
i```

```sql
n```

```sql
d```

```sql
o```

```sql
w```

```sql
s```

```sql
.```

```sql
s```

```sql
y```

```sql
s```

```sql
m```

```sql
o```

```sql
n```

```sql
_```

```sql
o```

```sql
p```

```sql
e```

```sql
r```

```sql
a```

```sql
t```

```sql
i```

```sql
o```

```sql
n```

```sql
a```

```sql
l```

```sql
-```

```sql
*```

```sql

```

```sql
|```

```sql
 ```

```sql
w```

```sql
h```

```sql
e```

```sql
r```

```sql
e```

```sql
 ```

```sql
h```

```sql
o```

```sql
s```

```sql
t```

```sql
.```

```sql
o```

```sql
s```

```sql
.```

```sql
f```

```sql
a```

```sql
m```

```sql
i```

```sql
l```

```sql
y```

```sql
 ```

```sql
=```

```sql
=```

```sql
 ```

```sql
"```

```sql
w```

```sql
i```

```sql
n```

```sql
d```

```sql
o```

```sql
w```

```sql
s```

```sql
"```

```sql
 ```

```sql
a```

```sql
n```

```sql
d```

```sql
 ```

```sql
e```

```sql
v```

```sql
e```

```sql
n```

```sql
t```

```sql
.```

```sql
c```

```sql
a```

```sql
t```

```sql
e```

```sql
g```

```sql
o```

```sql
r```

```sql
y```

```sql
 ```

```sql
=```

```sql
=```

```sql
 ```

```sql
"```

```sql
n```

```sql
e```

```sql
t```

```sql
w```

```sql
o```

```sql
r```

```sql
k```

```sql
"```

```sql
 ```

```sql
a```

```sql
n```

```sql
d```

```sql

```

```sql
 ```

```sql
 ```

```sql
e```

```sql
v```

```sql
e```

```sql
n```

```sql
t```

```sql
.```

```sql
a```

```sql
c```

```sql
t```

```sql
i```

```sql
o```

```sql
n```

```sql
 ```

```sql
i```

```sql
n```

```sql
 ```

```sql
(```

```sql
"```

```sql
l```

```sql
o```

```sql
o```

```sql
k```

```sql
u```

```sql
p```

```sql
_```

```sql
r```

```sql
e```

```sql
q```

```sql
u```

```sql
e```

```sql
s```

```sql
t```

```sql
e```

```sql
d```

```sql
"```

```sql
,```

```sql
 ```

```sql
"```

```sql
D```

```sql
N```

```sql
S```

```sql
E```

```sql
v```

```sql
e```

```sql
n```

```sql
t```

```sql
 ```

```sql
(```

```sql
D```

```sql
N```

```sql
S```

```sql
 ```

```sql
q```

```sql
u```

```sql
e```

```sql
r```

```sql
y```

```sql
)```

```sql
"```

```sql
)```

```sql
 ```

```sql
a```

```sql
n```

```sql
d```

```sql

```

```sql
 ```

```sql
 ```

```sql
(```

```sql
d```

```sql
n```

```sql
s```

```sql
.```

```sql
q```

```sql
u```

```sql
e```

```sql
s```

```sql
t```

```sql
i```

```sql
o```

```sql
n```

```sql
.```

```sql
t```

```sql
y```

```sql
p```

```sql
e```

```sql
 ```

```sql
=```

```sql
=```

```sql
 ```

```sql
"```

```sql
T```

```sql
X```

```sql
T```

```sql
"```

```sql
 ```

```sql
o```

```sql
r```

```sql
 ```

```sql
d```

```sql
n```

```sql
s```

```sql
.```

```sql
a```

```sql
n```

```sql
s```

```sql
w```

```sql
e```

```sql
r```

```sql
s```

```sql
.```

```sql
t```

```sql
y```

```sql
p```

```sql
e```

```sql
 ```

```sql
=```

```sql
=```

```sql
 ```

```sql
"```

```sql
T```

```sql
X```

```sql
T```

```sql
"```

```sql
)```

```sql
 ```

```sql
a```

```sql
n```

```sql
d```

```sql
 ```

```sql
p```

```sql
r```

```sql
o```

```sql
c```

```sql
e```

```sql
s```

```sql
s```

```sql
.```

```sql
e```

```sql
x```

```sql
e```

```sql
c```

```sql
u```

```sql
t```

```sql
a```

```sql
b```

```sql
l```

```sql
e```

```sql
 ```

```sql
!```

```sql
=```

```sql
 ```

```sql
"```

```sql
C```

```sql
:```

```sql
\```

```sql
\```

```sql
W```

```sql
i```

```sql
n```

```sql
d```

```sql
o```

```sql
w```

```sql
s```

```sql
\```

```sql
\```

```sql
s```

```sql
y```

```sql
s```

```sql
t```

```sql
e```

```sql
m```

```sql
3```

```sql
2```

```sql
\```

```sql
\```

```sql
s```

```sql
v```

```sql
c```

```sql
h```

```sql
o```

```sql
s```

```sql
t```

```sql
.```

```sql
e```

```sql
x```

```sql
e```

```sql
"```

```sql

```

```sql
|```

```sql
 ```

```sql
k```

```sql
e```

```sql
e```

```sql
p```

```sql
 ```

```sql
p```

```sql
r```

```sql
o```

```sql
c```

```sql
e```

```sql
s```

```sql
s```

```sql
.```

```sql
e```

```sql
x```

```sql
e```

```sql
c```

```sql
u```

```sql
t```

```sql
a```

```sql
b```

```sql
l```

```sql
e```

```sql
,```

```sql
 ```

```sql
 ```

```sql
p```

```sql
r```

```sql
o```

```sql
c```

```sql
e```

```sql
s```

```sql
s```

```sql
.```

```sql
e```

```sql
n```

```sql
t```

```sql
i```

```sql
t```

```sql
y```

```sql
_```

```sql
i```

```sql
d```

```sql

```

```sql
|```

```sql
 ```

```sql
s```

```sql
t```

```sql
a```

```sql
t```

```sql
s```

```sql
 ```

```sql
o```

```sql
c```

```sql
c```

```sql
u```

```sql
r```

```sql
r```

```sql
e```

```sql
n```

```sql
c```

```sql
e```

```sql
s```

```sql
 ```

```sql
=```

```sql
 ```

```sql
c```

```sql
o```

```sql
u```

```sql
n```

```sql
t```

```sql
(```

```sql
*```

```sql
)```

```sql
 ```

```sql
b```

```sql
y```

```sql
 ```

```sql
p```

```sql
r```

```sql
o```

```sql
c```

```sql
e```

```sql
s```

```sql
s```

```sql
.```

```sql
e```

```sql
n```

```sql
t```

```sql
i```

```sql
t```

```sql
y```

```sql
_```

```sql
i```

```sql
d```

```sql
,```

```sql
 ```

```sql
p```

```sql
r```

```sql
o```

```sql
c```

```sql
e```

```sql
s```

```sql
s```

```sql
.```

```sql
e```

```sql
x```

```sql
e```

```sql
c```

```sql
u```

```sql
t```

```sql
a```

```sql
b```

```sql
l```

```sql
e```

```sql

```

```sql
 ```

```sql
/```

```sql
*```

```sql
 ```

```sql
t```

```sql
h```

```sql
r```

```sql
e```

```sql
s```

```sql
h```

```sql
o```

```sql
l```

```sql
d```

```sql
 ```

```sql
c```

```sql
a```

```sql
n```

```sql
 ```

```sql
b```

```sql
e```

```sql
 ```

```sql
a```

```sql
d```

```sql
j```

```sql
u```

```sql
s```

```sql
t```

```sql
e```

```sql
d```

```sql
 ```

```sql
t```

```sql
o```

```sql
 ```

```sql
y```

```sql
o```

```sql
u```

```sql
r```

```sql
 ```

```sql
e```

```sql
n```

```sql
v```

```sql
 ```

```sql
*```

```sql
/```

```sql

```

```sql
|```

```sql
 ```

```sql
w```

```sql
h```

```sql
e```

```sql
r```

```sql
e```

```sql
 ```

```sql
o```

```sql
c```

```sql
c```

```sql
u```

```sql
r```

```sql
r```

```sql
e```

```sql
n```

```sql
c```

```sql
e```

```sql
s```

```sql
 ```

```sql
>```

```sql
=```

```sql
 ```

```sql
5```

```sql
0```

```sql

```

## Notes

- This hunt returns a list of processes unique pids and executable paths that performs a high number of DNS TXT lookups.
- Pivoting by `process.entity_id` will allow further investigation (parent process, hash, child processes, other network events etc.).
## MITRE ATT&CK Techniques

- [T1071](https://attack.mitre.org/techniques/T1071)
- [T1071.004](https://attack.mitre.org/techniques/T1071/004)

## License

- `Elastic License v2`
