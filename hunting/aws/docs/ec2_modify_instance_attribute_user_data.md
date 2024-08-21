# EC2 Modify Instance Attribute User Data

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies when a user modifies the user data attribute of an EC2 instance. The user data attribute is a script that runs when the instance is launched. Modifying the user data attribute could indicate an adversary attempting to gain persistence or execute malicious code on the instance.

- **UUID:** `f11ac62c-5f42-11ef-9d72-f661ea17fbce`
- **Integration:** [aws.cloudtrail](https://docs.elastic.co/integrations/aws/cloudtrail)
- **Language:** `[ES|QL]`
- **Source File:** [EC2 Modify Instance Attribute User Data](../queries/ec2_modify_instance_attribute_user_data.toml)

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
a```

```sql
w```

```sql
s```

```sql
.```

```sql
c```

```sql
l```

```sql
o```

```sql
u```

```sql
d```

```sql
t```

```sql
r```

```sql
a```

```sql
i```

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
 ```

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
p```

```sql
r```

```sql
o```

```sql
v```

```sql
i```

```sql
d```

```sql
e```

```sql
r```

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
e```

```sql
c```

```sql
2```

```sql
.```

```sql
a```

```sql
m```

```sql
a```

```sql
z```

```sql
o```

```sql
n```

```sql
a```

```sql
w```

```sql
s```

```sql
.```

```sql
c```

```sql
o```

```sql
m```

```sql
"```

```sql

```

```sql
 ```

```sql
 ```

```sql
 ```

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
=```

```sql
=```

```sql
 ```

```sql
"```

```sql
M```

```sql
o```

```sql
d```

```sql
i```

```sql
f```

```sql
y```

```sql
I```

```sql
n```

```sql
s```

```sql
t```

```sql
a```

```sql
n```

```sql
c```

```sql
e```

```sql
A```

```sql
t```

```sql
t```

```sql
r```

```sql
i```

```sql
b```

```sql
u```

```sql
t```

```sql
e```

```sql
"```

```sql

```

```sql
 ```

```sql
 ```

```sql
 ```

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
a```

```sql
w```

```sql
s```

```sql
.```

```sql
c```

```sql
l```

```sql
o```

```sql
u```

```sql
d```

```sql
t```

```sql
r```

```sql
a```

```sql
i```

```sql
l```

```sql
.```

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
_```

```sql
p```

```sql
a```

```sql
r```

```sql
a```

```sql
m```

```sql
e```

```sql
t```

```sql
e```

```sql
r```

```sql
s```

```sql
 ```

```sql
R```

```sql
L```

```sql
I```

```sql
K```

```sql
E```

```sql
 ```

```sql
"```

```sql
.```

```sql
*```

```sql
a```

```sql
t```

```sql
t```

```sql
r```

```sql
i```

```sql
b```

```sql
u```

```sql
t```

```sql
e```

```sql
=```

```sql
u```

```sql
s```

```sql
e```

```sql
r```

```sql
D```

```sql
a```

```sql
t```

```sql
a```

```sql
.```

```sql
*```

```sql
"```

```sql

```

```sql
|```

```sql
 ```

```sql
d```

```sql
i```

```sql
s```

```sql
s```

```sql
e```

```sql
c```

```sql
t```

```sql
 ```

```sql
a```

```sql
w```

```sql
s```

```sql
.```

```sql
c```

```sql
l```

```sql
o```

```sql
u```

```sql
d```

```sql
t```

```sql
r```

```sql
a```

```sql
i```

```sql
l```

```sql
.```

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
_```

```sql
p```

```sql
a```

```sql
r```

```sql
a```

```sql
m```

```sql
e```

```sql
t```

```sql
e```

```sql
r```

```sql
s```

```sql
 ```

```sql
"```

```sql
{```

```sql
%```

```sql
{```

```sql
i```

```sql
n```

```sql
s```

```sql
t```

```sql
a```

```sql
n```

```sql
c```

```sql
e```

```sql
_```

```sql
i```

```sql
d```

```sql
_```

```sql
k```

```sql
e```

```sql
y```

```sql
}```

```sql
=```

```sql
%```

```sql
{```

```sql
i```

```sql
n```

```sql
s```

```sql
t```

```sql
a```

```sql
n```

```sql
c```

```sql
e```

```sql
_```

```sql
i```

```sql
d```

```sql
}```

```sql
,```

```sql
 ```

```sql
%```

```sql
{```

```sql
a```

```sql
t```

```sql
t```

```sql
r```

```sql
i```

```sql
b```

```sql
u```

```sql
t```

```sql
e```

```sql
_```

```sql
k```

```sql
e```

```sql
y```

```sql
}```

```sql
=```

```sql
%```

```sql
{```

```sql
a```

```sql
t```

```sql
t```

```sql
r```

```sql
i```

```sql
b```

```sql
u```

```sql
t```

```sql
e```

```sql
}```

```sql
,```

```sql
 ```

```sql
%```

```sql
{```

```sql
v```

```sql
a```

```sql
l```

```sql
u```

```sql
e```

```sql
_```

```sql
k```

```sql
e```

```sql
y```

```sql
}```

```sql
=```

```sql
%```

```sql
{```

```sql
v```

```sql
a```

```sql
l```

```sql
u```

```sql
e```

```sql
}```

```sql
}```

```sql
"```

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
u```

```sql
s```

```sql
e```

```sql
r```

```sql
_```

```sql
d```

```sql
a```

```sql
t```

```sql
a```

```sql
_```

```sql
u```

```sql
p```

```sql
l```

```sql
o```

```sql
a```

```sql
d```

```sql
_```

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
a```

```sql
w```

```sql
s```

```sql
.```

```sql
c```

```sql
l```

```sql
o```

```sql
u```

```sql
d```

```sql
t```

```sql
r```

```sql
a```

```sql
i```

```sql
l```

```sql
.```

```sql
u```

```sql
s```

```sql
e```

```sql
r```

```sql
_```

```sql
i```

```sql
d```

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
.```

```sql
a```

```sql
r```

```sql
n```

```sql
,```

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
o```

```sql
u```

```sql
t```

```sql
c```

```sql
o```

```sql
m```

```sql
e```

```sql

```

## Notes

- Use the `instance_id` field to identify the EC2 instance for which the user data attribute was modified
- Pivot into the EC2 instance if possible and examine the user data script ('/var/lib/cloud/instance/scripts/userdata.txt') for malicious content
- To modify an EC2 instance's user data attribute, the instance must be stopped, therefore check for `StopInstances` API calls in `event.action` field to determine if the instance was stopped and started
- AWS redacts the value of the `user_data` attribute in the CloudTrail logs, so the actual script content will not be visible in the logs

## MITRE ATT&CK Techniques

- [T1059.009](https://attack.mitre.org/techniques/T1059/009)
- [T1037](https://attack.mitre.org/techniques/T1037)

## License

- `Elastic License v2`
