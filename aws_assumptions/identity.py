#!/usr/bin/env python3
from argparse import ArgumentParser
from copy import deepcopy
from textwrap import dedent
from typing import Any, Dict, List, Union

from boto3.session import Session


SESSION = Session()
DEFAULT_CLIENT = Session().client("sts")


"""
The slottiness of the classes below are really just here so I get smacked in the face
with an error for bad attribute access but don't have to add a separate methods
to access as a dict. Really more of a debugging thing than anything else.
"""


class PolicyArn(dict):
    __slots__ = ["arn"]

    def __init__(self, arn):
        self.arn = arn
        return super().__init__(arn=arn)


class Tag(dict):
    __slots__ = ["Key", "Value"]

    def __init__(self, Key, Value):
        self.Key = Key
        self.Value = Value
        return super().__init__(Key=Key, Value=Value)


class AWSCredentials(dict):
    __slots__ = [
        "AccessKeyId",
        "SecretAccessKey",
        "SessionToken",
        "Expiration",
    ]

    def __getattribute__(self, __name: str) -> Any:
        # So I like dots..... Get over it.....
        if __name in super().__getattribute__("__slots__"):
            return super().__getitem__(__name)
        else:
            return super().__getattribute__(__name)

    @property
    def session_args(self):
        # Formatting matches that of boto3.session.Session, boto3.client, and boto3.resource
        # signatures. So helpful for creating new clients or sessions from creds off your object
        return {
            "aws_access_key_id": self.AccessKeyId,
            "aws_secret_access_key": self.SecretAccessKey,
            "aws_session_token": self.SessionToken,
        }

    @property
    def env_vars(self):
        # Useful when running from cli. eg: $(assume-role -r arn:iam::123456577:role/foo)
        # will get you using your new role from a terminal
        return dedent(
            f"""
      AWS_ACCESS_KEY_ID={self.AccessKeyId}
      AWS_SECRET_ACCESS_KEY={self.SecretAccessKey}
      AWS_SESSION_TOKEN={self.SessionToken}
    """
        )


class Identity:
    # Being slotty here to prevent abusing attributes by callers.
    # Just use the damn thing as intended.
    __slots__ = [
        "RoleArn",
        "PolicyArns",
        "RoleSessionName",
        "ExternalId",
        "TransitiveTagKeys",
        "Tags",
        "DurationSeconds",
        "boto_session",
        "__sts_client",
        "__credentials",
        "__opts",
        "__client_cache",
    ]

    def __init__(
        self,
        *,
        RoleArn: Union[List[str], str],
        DurationSeconds: int = 3600,
        ExternalId: str = None,
        PolicyArns: List[PolicyArn] = [],
        RoleSessionName: str = "aws-assumptions-session",
        TransitiveTagKeys: List[str] = [],
        Tags: List[Tag] = [],
        sts_client: object = None,
    ):
        opts = dict(
            RoleArn=RoleArn,
            PolicyArns=PolicyArns,
            RoleSessionName=RoleSessionName,
            ExternalId=ExternalId,
            TransitiveTagKeys=TransitiveTagKeys,
            Tags=Tags,
            DurationSeconds=DurationSeconds,
        )

        self.boto_session = SESSION
        self.__sts_client = sts_client or self.boto_session.client("sts")
        self.__credentials = None
        self.__client_cache = {"resource": {}, "client": {}}

        # Get rid of Nones and empties
        self.__opts = {k: v for k, v in opts.items() if v}

        # Handle jumping through lists of roles
        if isinstance(RoleArn, list):
            if not RoleArn:
                raise ValueError("RoleArn cannot be empty list")

            role_list = deepcopy(RoleArn)

            # For each ARN that we get we'll assume that identity
            # by using an STS client created off the prior object
            for arn in role_list:
                opts["RoleArn"] = arn
                new_identity = Identity(**opts)
                opts["sts_client"] = new_identity.client("sts")

            # Patch our own attributes til we look and quack like
            # a duck that hatched from the last ARN in the list
            self.RoleArn = arn
            self.__sts_client = opts["sts_client"]
            self.__opts["RoleArn"] = arn
            self.__credentials = new_identity.credentials
        else:
            self.__load_credentials()

    @property
    def credentials(self):
        if self.__credentials is None:
            self.__load_credentials()
        return self.__credentials

    def __load_credentials(self):
        client = self.__sts_client or self.boto_session.client("sts")
        res = client.assume_role(**self.__opts)
        self.__credentials = AWSCredentials(**res["Credentials"])

    def client(self, service: str, **kwargs: Dict[str, Any]):
        # A little factory for making boto3.client(s)
        opts = {**kwargs, **self.credentials.session_args}

        # If we don't have a cached client then make one
        if (
            not (client := self.__client_cache["client"].get(service))
            or client["opts"] != opts
        ):
            self.__client_cache["client"][service] = {
                "opts": opts,
                "client_obj": self.boto_session.client(service, **opts),
            }

        # Return client from cache
        return self.__client_cache["client"][service]["client_obj"]

    def resource(self, service: str, **kwargs: Dict[str, Any]):
        # A little factory for making boto3.resource(s)
        opts = {**kwargs, **self.credentials.session_args}

        # If we don't have a cached resource then make one
        if (
            not (client := self.__client_cache["resource"].get(service))
            or client["opts"] != opts
        ):
            self.__client_cache["service"][service] = {
                "opts": opts,
                "client_obj": self.boto_session.resource(service, **opts),
            }

        # Return client from cache
        return self.__client_cache["resource"][service]["client_obj"]

    def whoami(self):
        res = self.client("sts").get_caller_identity()
        del res["ResponseMetadata"]
        return res

    def whomademe(self):
        res = self.__sts_client.get_caller_identity()
        del res["ResponseMetadata"]
        return res
