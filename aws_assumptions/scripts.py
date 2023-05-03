#!/usr/bin/env python3
from argparse import ArgumentParser
from json import dumps
from textwrap import dedent
from .identity import Identity, PolicyArn, Tag, DEFAULT_CLIENT


def main():
  cmd_funcs = {
    "whoami": whoami,
    "assume": assume_role
  }


  parser = ArgumentParser(epilog="Switch roles, or through a chain or roles, or print identity information from AWS STS")
  subparsers = parser.add_subparsers(dest="command")

  subparsers.add_parser("whoami", epilog="Prints get-caller-identity info in JSON format")

  assume = subparsers.add_parser(
    "assume",
    epilog=dedent("""
      Assume a role or a chain of roles with optional attributes, outputting the newly acquired credentials.
      Maintains parity with boto3's sts.assume_role except for MFA"
    """)
  )

  assume.add_argument("-r", "--role-arn", action="append", required=True)
  assume.add_argument(
    "-n",
    "--role-session-name",
    type=str,
    default="assumed-role"
  )
  assume.add_argument("-p", "--policy-arn", type=str, action="append")
  assume.add_argument("-t", "--tag", type=str, action="append")
  assume.add_argument("-T", "--transitive-tag-key", type=str, action="append")
  assume.add_argument("-E", "--external-id", type=str, default=None)
  assume.add_argument("-d", "--duration-seconds", type=int, default=3600)
  assume.add_argument("-e", "--env-vars", help="Output env vars usable from a terminal", action="store_true")

  args = parser.parse_args()

  return cmd_funcs[args.command](args)


def assume_role(args):
  opts = dict(
      RoleArn=args.role_arn,
      RoleSessionName=args.role_session_name,
      PolicyArns=[PolicyArn(arn) for arn in (args.policy_arn or [])],
      Tags=[
          Tag(*pair) for pair in [tag.split("=") for tag in (args.tag or [])]
      ],
      TransitiveTagKeys=args.transitive_tag_key or []
  )

  if args.external_id:
    opts["ExternalId"] = args.external_id

  role = Identity(**opts)

  if args.env_vars:
    print(role.credentials.env_vars)
  else:
    res = dumps(role.credentials, indent=2)
    print(res)


def whoami(_):
  res = DEFAULT_CLIENT.get_caller_identity()
  del res["ResponseMetadata"]
  print(dumps(res, indent=2))
