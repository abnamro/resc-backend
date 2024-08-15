# Standard Library
import os
from unittest.mock import patch

# Third Party
import jwt
import pytest
from fastapi import Request
from fastapi.security import HTTPAuthorizationCredentials
from tenacity import RetryError, stop_after_attempt

# First Party
from resc_backend.resc_web_service.dependencies import (
    check_db_initialized,
    requires_auth,
    user_is_authorized,
)


# Test that JWT token verification works with audience claim
@pytest.mark.asyncio
@patch("jwt.PyJWKClient.get_signing_key_from_jwt")
@patch("jwt.api_jws.PyJWS._verify_signature")
async def test_jwt_validation_with_audience(_verify_signature, _get_signing_key):
    # Environment variables
    env_variables = {
        "SSO_ACCESS_TOKEN_ISSUER_URL": "https://fake-sso-url.com",
        "SSO_ACCESS_TOKEN_JWKS_URL": "https://fake-sso-url/ext/employeeoidc/jwks",
        "SSO_JWT_CLAIM_AUDIENCE": "fake-audience",
        "SSO_JWT_CLAIM_KEY_AUTHORIZATION": "roles",
        "SSO_JWT_CLAIM_VALUE_AUTHORIZATION": "OPERATOR",
        "SSO_JWT_CLAIM_KEY_USER_ID": "username",
        "SSO_JWT_REQUIRED_CLAIMS": "roles",
        "SSO_JWT_SIGN_ALGORITHM": "none",
    }
    # Access token
    payload = {"aud": "fake-audience", "iss": "https://fake-sso-url.com", "roles": "OPERATOR", "username": "fake-user"}
    access_token = jwt.encode(payload=payload, algorithm=None, key=None)
    # Function parameters
    request = Request({"user": "fake-user", "type": "http"})
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=access_token)

    with patch.dict(os.environ, env_variables):
        await requires_auth(request, credentials)


# Test that JWT token verification works without audience claim
@pytest.mark.asyncio
@patch("jwt.PyJWKClient.get_signing_key_from_jwt")
@patch("jwt.api_jws.PyJWS._verify_signature")
async def test_jwt_validation_without_audience(_verify_signature, _get_signing_key):
    # Environment variables
    env_variables = {
        "SSO_ACCESS_TOKEN_ISSUER_URL": "https://fake-sso-url.com",
        "SSO_ACCESS_TOKEN_JWKS_URL": "https://fake-sso-url/ext/employeeoidc/jwks",
        "SSO_JWT_CLAIM_KEY_AUTHORIZATION": "roles",
        "SSO_JWT_CLAIM_VALUE_AUTHORIZATION": "OPERATOR",
        "SSO_JWT_CLAIM_KEY_USER_ID": "username",
        "SSO_JWT_REQUIRED_CLAIMS": "roles",
        "SSO_JWT_SIGN_ALGORITHM": "none",
    }
    # Access token
    payload = {"iss": "https://fake-sso-url.com", "roles": "OPERATOR", "username": "fake-user"}
    access_token = jwt.encode(payload=payload, algorithm=None, key=None)
    # Function parameters
    request = Request({"user": "fake-user", "type": "http"})
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=access_token)

    with patch.dict(os.environ, env_variables):
        await requires_auth(request, credentials)


# Tests how the method responds to a person with the correct role; RESC_OPERATOR_ROLE
def test_correct_user_role():
    claims = {"roles": "OPERATOR"}
    env_variables = {
        "SSO_JWT_CLAIM_KEY_AUTHORIZATION": "roles",
        "SSO_JWT_CLAIM_VALUE_AUTHORIZATION": "OPERATOR",
    }
    assert user_is_authorized(claims, env_variables)


# Tests how the method responds to a person with the incorrect role; PCP_OPERATOR_ROLE
def test_incorrect_user_role():
    claims = {"roles": "Invalid role"}
    env_variables = {
        "SSO_JWT_CLAIM_KEY_AUTHORIZATION": "roles",
        "SSO_JWT_CLAIM_VALUE_AUTHORIZATION": "OPERATOR",
    }
    assert not user_is_authorized(claims, env_variables)


# Tests how the method responds to an empty role; " "
def test_empty_user_role():
    claims = {"roles": ""}
    env_variables = {
        "SSO_JWT_CLAIM_KEY_AUTHORIZATION": "roles",
        "SSO_JWT_CLAIM_VALUE_AUTHORIZATION": "OPERATOR",
    }
    assert not user_is_authorized(claims, env_variables)


def test_no_claims():
    claims = {}
    env_variables = {
        "SSO_JWT_CLAIM_KEY_AUTHORIZATION": "roles",
        "SSO_JWT_CLAIM_VALUE_AUTHORIZATION": "OPERATOR",
    }
    assert not user_is_authorized(claims, env_variables)


@patch("logging.Logger.error")
@patch("sqlalchemy.engine.reflection.Inspector.has_table")
def test_check_db_initialized_false(has_table, error_logger):
    check_db_initialized.retry.stop = stop_after_attempt(1)
    has_table.return_value = False

    with pytest.raises(RetryError):
        check_db_initialized()

    error_logger.assert_called_once_with(
        "Database is NOT connected or initialized | Unable to determine existence of "
        "required table(s) finding, repository, rules, scan, "
        "scan_finding | Retrying..."
    )


@patch("logging.Logger.error")
@patch("sqlalchemy.engine.reflection.Inspector.has_table")
def test_check_db_initialized_true(has_table, error_logger):
    has_table.return_value = True
    try:
        check_db_initialized()
    except SystemExit:
        pytest.fail("Unexpected SystemExit ..")
    error_logger.assert_not_called()
