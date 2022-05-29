import json
import logging
import os
import sys
import boto3

from typing import Dict
from botocore.exceptions import ClientError

# configure logger defaults
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# start a boto3 session
session = boto3.session.Session()


def _is_authorized(context: Dict = None) -> Dict:
    return _authorization_response(True, context)


def _not_authorized(context: Dict = None) -> Dict:
    return _authorization_response(False, context)


def _authorization_response(is_authorized: bool, context: Dict = None) -> Dict:
    context = context if context else {}
    return {
        "isAuthorized": is_authorized,
        "context": context
    }


def _get_secrets(secret_name: str) -> Dict[str, str]:
    client = session.client(service_name='secretsmanager')

    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        logger.error(f"Error Fetching Secrets Manager Secret: {e.response['Error']['Code']}", exc_info=sys.exc_info())
        raise e
    else:
        secret_response = get_secret_value_response.get('SecretString', "{}")

    # decrypt the secret response, it *should* be in json format, but we'll see...
    try:
        return json.loads(secret_response)
    except json.decoder.JSONDecodeError:
        logger.warning(f"Error Decoding Secret Response as Json", exc_info=sys.exc_info())
        return {}


def _configure_logging(log_level: str) -> None:
    try:
        logger.setLevel(log_level)
    except (ValueError, TypeError):
        logger.warning(f"Unknown or Invalid Log Level: {log_level} - Using INFO")


def do(event, _):
    # set the logging level based on the environment variable
    log_level = os.environ.get('LOG_LEVEL', 'DEBUG')
    _configure_logging(log_level)

    request_context = event['requestContext']
    logging.info(
        f"Authentication Request for Domain {request_context['domainName']} from {request_context['http']['sourceIp']}"
    )

    # in api gateway identity source can be multi-valued (you provided multiple sources in the config),
    # we don't support that right now so just fetch the first one and remove any empty values
    identity_source = [c for c in event.get('identitySource', []) if c]
    if not identity_source:
        logging.error("Failed Authenticating Request: Empty Identity Source")
        return _not_authorized()

    # fetch off the first one and cast it as a string
    logger.debug(f"Fetching First Identity Source")
    identity_source = str(identity_source[0])

    # get the credentials that are valid for this invocation, make sure we don't have an oops with empty credentials
    logger.info(f"Fetching Valid Credentials from Secrets Manager for {request_context['domainName']}")
    valid_credentials = _get_secrets(f"{os.environ['SECRETS_MANAGER_PATH']}/{request_context['domainName']}")
    if not valid_credentials:
        logging.error("Failed Authenticating Request: Empty Credential Source")
        return _not_authorized()

    # brain-dead simple check
    matched_keys = {
        k for k, v in valid_credentials.items()
        if str(v) == identity_source
    }
    if not matched_keys:
        logging.error(f"Failed Authenticating Request: Credential Mismatch")
        return _not_authorized()

    # we've authenticated!
    logging.info(
        f"Authentication Success for Domain {request_context['domainName']} from {request_context['http']['sourceIp']} with Key(s): {', '.join(matched_keys)}"
    )
    return _is_authorized()
