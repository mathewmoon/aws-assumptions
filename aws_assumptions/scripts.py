#!/usr/bin/env python3
from argparse import ArgumentParser, Namespace, REMAINDER
from json import dumps
from os import environ
from subprocess import run
from textwrap import dedent

from dotenv import dotenv_values

from .identity import Identity, PolicyArn, Tag, DEFAULT_CLIENT


def main(help=False):
    cmd_funcs = {"whoami": whoami, "assume": assume_role, "exec": executor}

    parser = ArgumentParser(
        epilog="Switch roles, or through a chain or roles, or print identity information from AWS STS"
    )

    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser(
        "whoami", epilog="Prints get-caller-identity info in JSON format"
    )

    assume = subparsers.add_parser(
        "assume",
        epilog=dedent(
            """
      Assume a role or a chain of roles with optional attributes, outputting the newly acquired credentials.
      Maintains parity with boto3's sts.assume_role except for MFA
    """
        ),
    )

    assume.add_argument(
        "-r",
        "--role-arn",
        help="""
      Role to assume. If declared multiple times each role will assume the next in the order given.
      All other options will be applied to all roles in the chain.
    """,
        action="append",
        required=True,
    )
    assume.add_argument(
        "-n",
        "--role-session-name",
        help="The session name to use with the role.",
        type=str,
        default="assumed-role",
    )
    assume.add_argument(
        "-p",
        "--policy-arn",
        help="Optional policy to attach to a session. Can be declared multiple times.",
        type=str,
        action="append",
    )
    assume.add_argument(
        "-t",
        "--tag",
        help="Optional tag to add to the session in the format of `mytagkey=myvalue`. Can be declared multiple times for multiple tags.",
        type=str,
        action="append",
    )
    assume.add_argument(
        "-T",
        "--transitive-tag-key",
        help="Transitive tag key. Can be declared multiple times.",
        type=str,
        action="append",
    )
    assume.add_argument(
        "-E",
        "--external-id",
        help="Optional External ID for the session. Required by some AssumeRole policies",
        type=str,
        default=None,
    )
    assume.add_argument(
        "-d",
        "--duration-seconds",
        help="Optional duration for the session.",
        type=int,
        default=3600,
    )

    # The order this comes in is imperative. It MUST come after all args in the parent
    # that we want but BEFORE those that we don't
    exec = subparsers.add_parser(
        "exec",
        epilog="Execute a command in a shell with newly created credentials.",
        parents=[assume],
        add_help=False
    )

    exec.add_argument(
       "-N",
       "--no-inherit-env",
       action="store_true",
       help="Don't allow the executed command to inherit the parent's env."
    )

    exec.add_argument(
       "-e",
       "--env-var",
       action="append",
       type=str,
       help="Env var in the format `MYVAR=foo` to pass to the executed command's environment. Can be declared multiple times."
    )

    exec.add_argument(
      "--env-file",
      type=str,
      help="Load env vars from a .env file."
    )

    assume.add_argument(
        "-e",
        "--env-vars",
        help="Output env vars usable from a terminal. If not set the output will match the output of aws-cli's `aws sts assume-role` JSON",
        action="store_true",
    )

    exec.add_argument(
        "exec_command",
        nargs=REMAINDER
    )

    if help:
      parser.print_help()
      return

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        exit()

    return cmd_funcs[args.command](args)


def assume_role(args: Namespace, print_vars: bool = True):
    opts = dict(
        RoleArn=args.role_arn,
        RoleSessionName=args.role_session_name,
        PolicyArns=[PolicyArn(arn) for arn in (args.policy_arn or [])],
        Tags=[Tag(*pair) for pair in [tag.split("=") for tag in (args.tag or [])]],
        TransitiveTagKeys=args.transitive_tag_key or [],
    )

    if args.external_id:
        opts["ExternalId"] = args.external_id

    role = Identity(**opts)

    if print_vars:
      if args.env_vars:
          print(role.credentials.env_vars)
      else:
          res = dumps(role.credentials, indent=2)
          print(res)

    return role


def whoami(_: Namespace):
    res = DEFAULT_CLIENT.get_caller_identity()
    del res["ResponseMetadata"]
    print(dumps(res, indent=2))


def executor(args: Namespace):
  if not args.exec_command:
    print("Must supply a command to run.")
    main(help=True)
    exit()

  role = assume_role(args, print_vars=False)

  env = environ if not args.no_inherit_env else {}

  if args.env_var:
    env.update({
      pair[0]: pair[1] for pair in [ env_var.split("=") for env_var in args.env_var]
    })

  env.update({
    "AWS_ACCESS_KEY_ID": role.credentials.AccessKeyId,
    "AWS_SECRET_ACCESS_KEY": role.credentials.SecretAccessKey,
    "AWS_SESSION_TOKEN": role.credentials.SessionToken
  })

  if args.env_file:
    env.update(dotenv_values(args.env_file))

  run(
    args.exec_command,
    env=env,
    shell=False
  )


if __name__ == "__main__":
  main()