#!/usr/bin/env python3
from argparse import ArgumentParser, Namespace, REMAINDER
from importlib.metadata import version
from json import dumps
from os import environ
from subprocess import run

from botocore.exceptions import ClientError
from dotenv import dotenv_values

from .identity import Identity, PolicyArn, Tag, DEFAULT_CLIENT


class _Scripts:
    def __init__(self):
        self.parser = ArgumentParser(
            epilog="Switch roles, or through a chain or roles, or print identity information from AWS STS"
        )

        self.subparsers = self.parser.add_subparsers(dest="command")

        # Args used in multiple subparsers
        self.common = self.subparsers.add_parser("common", add_help=False)

        self.common.add_argument(
            "-r",
            "--role-arn",
            help="""
                Role to assume. If declared multiple times each role will assume the next in the order given.
                All other options will be applied to all roles in the chain.
            """,
            action="append",
            required=True,
        )

        self.common.add_argument(
            "-n",
            "--role-session-name",
            help="The session name to use with the role.",
            type=str,
            default="assumed-role",
        )

        self.common.add_argument(
            "-p",
            "--policy-arn",
            help="Optional policy to attach to a session. Can be declared multiple times.",
            type=str,
            action="append",
        )

        self.common.add_argument(
            "-t",
            "--tag",
            help="Optional tag to add to the session in the format of `mytagkey=myvalue`. Can be declared multiple times for multiple tags.",
            type=str,
            action="append",
        )

        self.common.add_argument(
            "-T",
            "--transitive-tag-key",
            help="Transitive tag key. Can be declared multiple times.",
            type=str,
            action="append",
        )

        self.common.add_argument(
            "-E",
            "--external-id",
            help="Optional External ID for the session. Required by some AssumeRole policies",
            type=str,
            default=None,
        )

        self.common.add_argument(
            "-d",
            "--duration-seconds",
            help="Optional duration for the session.",
            type=int,
            default=3600,
        )

        self.subparsers.add_parser("version", epilog="Print version and exit")

        self.subparsers.add_parser(
            "whoami", epilog="Prints get-caller-identity info in JSON format"
        )

        self.exec = self.subparsers.add_parser(
            "exec",
            epilog="Execute a command in a shell with newly created credentials.",
            parents=[self.common],
        )

        self.exec.add_argument(
            "-N",
            "--no-inherit-env",
            action="store_true",
            help="Don't allow the executed command to inherit the parent's env.",
        )

        self.exec.add_argument(
            "-e",
            "--env-var",
            action="append",
            type=str,
            help="Env var in the format `MYVAR=foo` to pass to the executed command's environment. Can be declared multiple times.",
        )

        self.exec.add_argument(
            "--env-file", type=str, help="Load env vars from a .env file."
        )

        self.exec.add_argument(
            "exec_command",
            nargs=REMAINDER,
            help="The command to run",
        )

        self.assume = self.subparsers.add_parser(
            "assume",
            epilog="""
                Assume a role or a chain of roles with optional attributes, outputting the newly acquired credentials.
                Maintains parity with boto3's sts.assume_role except for MFA
            """,
            parents=[self.common],
        )

        self.assume.add_argument(
            "-e",
            "--env-vars",
            help="Output env vars usable from a terminal. If not set the output will match the output of aws-cli's `aws sts assume-role` JSON",
            action="store_true",
        )

        self.args = self.parser.parse_args()

        self.commands = {}

    def run_command(self) -> str:
        try:
            func = self.__getattribute__(f"cmd_{self.args.command}")
        except AttributeError:
            self.parser.print_help()
            print(f"Unknown command: {self.args.command}")
            return

        return func()

    def cmd_assume_role(self) -> str:
        opts = dict(
            RoleArn=self.args.role_arn,
            RoleSessionName=self.args.role_session_name,
            PolicyArns=[PolicyArn(arn) for arn in (self.args.policy_arn or [])],
            Tags=[
                Tag(*pair) for pair in [tag.split("=") for tag in (self.args.tag or [])]
            ],
            TransitiveTagKeys=self.args.transitive_tag_key or [],
        )

        if self.args.external_id:
            opts["ExternalId"] = self.args.external_id

        role = Identity(**opts)

        return (
            role.credentials.env_vars
            if self.args.env_vars
            else dumps(role.credentials, indent=2)
        )

    def cmd_whoami(self) -> str:
        res = DEFAULT_CLIENT.get_caller_identity()
        del res["ResponseMetadata"]
        return dumps(res, indent=2)

    def cmd_exec(self) -> None:
        if not self.args.exec_command:
            self.exec.print_help()
            return

        role = self.cmd_assume_role()

        env = environ if not self.args.no_inherit_env else {}

        if self.args.env_var:
            env.update(
                {
                    pair[0]: pair[1]
                    for pair in [env_var.split("=") for env_var in self.args.env_var]
                }
            )

        env.update(
            {
                "AWS_ACCESS_KEY_ID": role.credentials.AccessKeyId,
                "AWS_SECRET_ACCESS_KEY": role.credentials.SecretAccessKey,
                "AWS_SESSION_TOKEN": role.credentials.SessionToken,
            }
        )

        if self.args.env_file:
            env.update(dotenv_values(self.args.env_file))

        run(self.args.exec_command, env=env, shell=False)

    def cmd_version(self) -> None:
        pkg = Identity.__module__.split(".")[0]
        return f"{pkg.replace('_', '-')} {version(pkg)}"


def main() -> str:
    try:
        return _Scripts().run_command()
    except (Exception, ClientError) as e:
        return str(e)
