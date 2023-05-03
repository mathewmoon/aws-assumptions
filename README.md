# aws-assumptions

Easily switch between roles, or a chain of roles and create boto3 clients and resources off of those assumed identities.
Along with being able to use this package as an import a cli script is included.

## CLI Usage

Available commands
```
~  > assumptions -h
usage: assumptions [-h] {whoami,assume} ...

positional arguments:
  {whoami,assume}

optional arguments:
  -h, --help       show this help message and exit

Switch roles, or through a chain or roles, or print identity information from AWS STS
```

Getting current identity
```
> assumptions whoami -h
usage: assumptions whoami [-h]

optional arguments:
  -h, --help  show this help message and exit

Prints get-caller-identity info in JSON format
```

Assuming a role
```
~  > assumptions assume -h
usage: assumptions assume [-h] -r ROLE_ARN [-n ROLE_SESSION_NAME] [-p POLICY_ARN] [-t TAG] [-T TRANSITIVE_TAG_KEY] [-E EXTERNAL_ID] [-d DURATION_SECONDS] [-e]

optional arguments:
  -h, --help            show this help message and exit
  -r ROLE_ARN, --role-arn ROLE_ARN
                        Role to assume. If declared multiple times each role will assume the next in the order given. All other options will be applied to all roles in the chain.
  -n ROLE_SESSION_NAME, --role-session-name ROLE_SESSION_NAME
                        The session name to use with the role.
  -p POLICY_ARN, --policy-arn POLICY_ARN
                        Optional policy to attach to a session. Can be declared multiple times.
  -t TAG, --tag TAG     Optional tag to add to the session in the format of `mytagkey=myvalue`. Can be declared multiple times for multiple tags.
  -T TRANSITIVE_TAG_KEY, --transitive-tag-key TRANSITIVE_TAG_KEY
                        Transitive tag key. Can be declared multiple times.
  -E EXTERNAL_ID, --external-id EXTERNAL_ID
                        Optional External ID for the session. Required by some AssumeRole policies
  -d DURATION_SECONDS, --duration-seconds DURATION_SECONDS
                        Optional duration for the session.
  -e, --env-vars        Output env vars usable from a terminal. If not set the output will match the output of aws-cli's `aws sts assume-role` JSON

Assume a role or a chain of roles with optional attributes, outputting the newly acquired credentials. Maintains parity with boto3's sts.assume_role except for MFA
```

Example of assuming a role with env vars
```
> assumptions assume -r "arn:aws:iam::123456789876:role/my-role" -n bob@nowhere.com -e > creds.env
> . creds.env
```

or

```
$(assumptions assume -r "arn:aws:iam::123456789876:role/my-role" -n bob@nowhere.com)
```

## Switching through multiple roles
If you need to chain roles (EG: Assume a role that assumes a role that assumes a role) you can pass the `-r` flag multiple times.
Note however that all other options, such as `--external-id` or `--tag` will be applied to every session in the chain.

## As a library

Assuming a role and creating clients
```python
from aws_assumptions.identity import Identity

session = Identity(
  RoleArn="arn:aws:iam::123456789876:role/my-role",
  RoleSessionName="bob"
)

res = session.client("eks").list_clusters()
current_role = session.whoami()
session_that_made_current_rule = session.whomademe()
```

Chaining roles

```python
from aws_assumptions.identity import Identity

session = Identity(
  RoleArn=[
    "arn:aws:iam::123456789876:role/my-role",
    "arn:aws:iam::123456789876:role/my-second-role"
  ],
  RoleSessionName="bob"
)

res = session.client("eks").list_clusters()
current_role = session.whoami()
session_that_made_current_rule = session.whomademe()
```

