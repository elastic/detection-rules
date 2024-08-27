# SSM Start Remote Session to EC2 Instance

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies when a user starts a remote session to an EC2 instance using the AWS Systems Manager (SSM) service. The `StartSession` API call allows users to connect to an EC2 instance using the SSM service. Multiple `StartSession` requests to the same EC2 instance may indicate an adversary attempting to gain access to the instance for malicious purposes. By default on certain AMI types, the SSM agent is pre-installed and running, allowing for easy access to the instance without the need for SSH or RDP.

- **UUID:** `f9eae44e-5e4d-11ef-878f-f661ea17fbce`
- **Integration:** [aws.cloudtrail](https://docs.elastic.co/integrations/aws/cloudtrail)
- **Language:** `[ES|QL]`
- **Source File:** [SSM Start Remote Session to EC2 Instance](../queries/ssm_start_remote_session_to_ec2_instance.toml)

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
@```

```sql
t```

```sql
i```

```sql
m```

```sql
e```

```sql
s```

```sql
t```

```sql
a```

```sql
m```

```sql
p```

```sql
 ```

```sql
>```

```sql
 ```

```sql
n```

```sql
o```

```sql
w```

```sql
(```

```sql
)```

```sql
 ```

```sql
-```

```sql
 ```

```sql
7```

```sql
 ```

```sql
d```

```sql
a```

```sql
y```

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
s```

```sql
s```

```sql
m```

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
S```

```sql
t```

```sql
a```

```sql
r```

```sql
t```

```sql
S```

```sql
e```

```sql
s```

```sql
s```

```sql
i```

```sql
o```

```sql
n```

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
t```

```sql
a```

```sql
r```

```sql
g```

```sql
e```

```sql
t```

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
t```

```sql
a```

```sql
r```

```sql
g```

```sql
e```

```sql
t```

```sql
_```

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
t```

```sql
a```

```sql
r```

```sql
g```

```sql
e```

```sql
t```

```sql
_```

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
,```

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
t```

```sql
y```

```sql
p```

```sql
e```

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

- Use the `target_instance` field to identify the EC2 instance that the user connected to using the SSM service
- Review the `aws.cloudtrail.user_identity*` fields to identify the user making the requests and their role permissions
- The `event.outcome` field can provide additional context on the success or failure of the `StartSession` request
- Identify if the EC2 instance was recently launched by filtering `event.action` field for `RunInstances` API calls. If the instance was not recently launched, investigate further
- Sessions started from IAM users may be benign, but sessions where the `aws.cloudtrail.user_identity.type` is `AssumedRole` are suspicious as they indicate instance to instance connections.

## MITRE ATT&CK Techniques

- [T1021.007](https://attack.mitre.org/techniques/T1021/007)

## License

- `Elastic License v2`
