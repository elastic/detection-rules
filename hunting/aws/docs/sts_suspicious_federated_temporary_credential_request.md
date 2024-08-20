# STS Suspicious Federated Temporary Credential Request

---

## Metadata

- **Author:** Elastic
- **Description:** This hunting query identifies when a user requests temporary federated credentials with a duration greater than 24 hours or with the `AdministratorAccess` policy attached. Federated users are typically given temporary credentials to access AWS services. A duration greater than 24 hours or the `AdministratorAccess` policy attached may indicate an adversary attempting to maintain access to AWS services for an extended period of time or escalate privileges.

- **UUID:** `3f8393b2-5f0b-11ef-8a25-f661ea17fbce`
- **Integration:** [aws.cloudtrail](https://docs.elastic.co/integrations/aws/cloudtrail)
- **Language:** `[ES|QL]`
- **Source File:** [STS Suspicious Federated Temporary Credential Request](../queries/sts_suspicious_federated_temporary_credential_request.toml)

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
d```

```sql
a```

```sql
t```

```sql
a```

```sql
s```

```sql
e```

```sql
t```

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
t```

```sql
s```

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
G```

```sql
e```

```sql
t```

```sql
F```

```sql
e```

```sql
d```

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
T```

```sql
o```

```sql
k```

```sql
e```

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
}```

```sql
n```

```sql
a```

```sql
m```

```sql
e```

```sql
=```

```sql
%```

```sql
{```

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
n```

```sql
a```

```sql
m```

```sql
e```

```sql
}```

```sql
,```

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
}```

```sql
d```

```sql
u```

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
S```

```sql
e```

```sql
c```

```sql
o```

```sql
n```

```sql
d```

```sql
s```

```sql
=```

```sql
%```

```sql
{```

```sql
d```

```sql
u```

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
}```

```sql
,```

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
}```

```sql
p```

```sql
o```

```sql
l```

```sql
i```

```sql
c```

```sql
y```

```sql
A```

```sql
r```

```sql
n```

```sql
s```

```sql
=```

```sql
[```

```sql
%```

```sql
{```

```sql
p```

```sql
o```

```sql
l```

```sql
i```

```sql
c```

```sql
i```

```sql
e```

```sql
s```

```sql
_```

```sql
a```

```sql
p```

```sql
p```

```sql
l```

```sql
i```

```sql
e```

```sql
d```

```sql
}```

```sql
]```

```sql
"```

```sql

```

```sql
|```

```sql
 ```

```sql
e```

```sql
v```

```sql
a```

```sql
l```

```sql
 ```

```sql
d```

```sql
u```

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
_```

```sql
m```

```sql
i```

```sql
n```

```sql
u```

```sql
t```

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
t```

```sql
o```

```sql
_```

```sql
i```

```sql
n```

```sql
t```

```sql
e```

```sql
g```

```sql
e```

```sql
r```

```sql
(```

```sql
d```

```sql
u```

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
)```

```sql
 ```

```sql
/```

```sql
 ```

```sql
6```

```sql
0```

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
(```

```sql
d```

```sql
u```

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
_```

```sql
m```

```sql
i```

```sql
n```

```sql
u```

```sql
t```

```sql
e```

```sql
s```

```sql
 ```

```sql
>```

```sql
 ```

```sql
1```

```sql
4```

```sql
4```

```sql
0```

```sql
)```

```sql
 ```

```sql
o```

```sql
r```

```sql
 ```

```sql
(```

```sql
p```

```sql
o```

```sql
l```

```sql
i```

```sql
c```

```sql
i```

```sql
e```

```sql
s```

```sql
_```

```sql
a```

```sql
p```

```sql
p```

```sql
l```

```sql
i```

```sql
e```

```sql
d```

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
A```

```sql
d```

```sql
m```

```sql
i```

```sql
n```

```sql
i```

```sql
s```

```sql
t```

```sql
r```

```sql
a```

```sql
t```

```sql
o```

```sql
r```

```sql
A```

```sql
c```

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
*```

```sql
"```

```sql
)```

```sql

```

## Notes

- If the `aws.cloudtrail.user_identity.arn` does not match the `user_name` field, this may indicate an adversary attempting to escalate privileges by requesting temporary credentials for a different user.
- Review `event.outcome` field to identify if the request was successful or failed.
- The `aws.cloudtrail.user_identity.session_context.session_issuer.arn` field represents the ARN of the IAM entity that created the federated session. This IAM entity could be compromised and used to create federated sessions. This could indicate the compromised credentials or role used to create the federated session.
- An additional query for `event.provider` being `signin.amazonaws.com` and `event.action` being `GetSigninToken` can be used to identify if the temporary credentials are being exchanged for console access.

## MITRE ATT&CK Techniques

- [T1550.001](https://attack.mitre.org/techniques/T1550/001)

## License

- `Elastic License v2`
