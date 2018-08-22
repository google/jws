"""Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
"""JSON Web Token (JWT) in compact serialization format.

This package uses jws underneath. The difference between jws and jwt is that
jws only verifies the signature while jwt verifies both the signature and
claims as defined at https://tools.ietf.org/html/rfc7519#section-4.1.
"""

__author__ = "quannguyen@google.com (Quan Nguyen)"
import json
from jws import jws
from jws import jwsutil
import six
import datetime
import calendar


class JwtPublicKeyVerify(object):
  """JWT Public Key Verifier which verifies both the signature and claims."""

  def __init__(self, jwk_set, issuer=None, subject=None, audiences=None):
    """Constructor for JwtPublicKeyVerify.

    Args:
      jwk_set: a JwkSet.
      issuer: string, the issuer claim as defined at
        https://tools.ietf.org/html/rfc7519#section-4.1.1.
      subject: string, the subject claim as defined at
        https://tools.ietf.org/html/rfc7519#section-4.1.2.
      audiences: list of string, the audiences claim as defined at
        https://tools.ietf.org/html/rfc7519#section-4.1.3.

    Raises:
      UnsupportedAlgorithm: if the algorihtm is not defined at
      https://tools.ietf.org/html/rfc7518#section-3.1 or if jwk is not Rsa or
      Ecdsa key.
    """
    self.verifier = jws.JwsPublicKeyVerify(jwk_set)
    self.issuer = issuer
    self.subject = subject
    self.audiences = audiences

  def verify(self, token):
    """Verifies whether the token is signed with the corresponding private key and whether the payload's claims are valid.

    Args:
      token: string, the JWS compact serialization token as defined at
        https://tools.ietf.org/html/rfc7515#section-7.1.

    Returns:
      True if the token was verified, false if not.
    """
    if not self.verifier.verify(token):
      return False
    payload = json.loads(jwsutil.urlsafe_b64decode(token.split(".")[1]))
    return _verify_claims(payload, self.issuer, self.subject, self.audiences)


class JwtPublicKeySign(object):
  """Jwt public key signer that suppports both Ecdsa and Rsa signature schemes.
  """

  def __init__(self, jwk_set):
    """Constructor for JwtPublicKeySign.

    Args:
      jwk_set: a JwkSet.

    Raises:
      UnsupportedAlgorithm: if the algorihtm is not defined at
      https://tools.ietf.org/html/rfc7518#section-3.1 or if jwk is not Rsa or
      Ecdsa key.
    """
    self.signer = jws.JwsPublicKeySign(jwk_set)

  def sign(self, header, payload):
    """Computes the signed jwt as defined at rfc7515#section-7.1.

    Args:
      header: bytes, the header to be signed.
      payload: bytes, the payload to be signed.

    Returns:
      base64url(header) || '.' || base64url(payload) || '.' ||
      base64url(signature), where the signature is computed over
      base64url(utf8(header)) || '.' || base64url(payload).
    """
    return self.signer.sign(header, payload)


class JwtMacVerify(object):
  """Jwt Mac Verifier that verifies both message authentication code and claims."""

  def __init__(self, jwk_set, issuer=None, subject=None, audiences=None):
    """Constructor for JwtMacVerify.

    Args:
      jwk_set: a JwkSet.
      issuer: string, the issuer claim as defined at
        https://tools.ietf.org/html/rfc7519#section-4.1.1.
      subject: string, the subject claim as defined at
        https://tools.ietf.org/html/rfc7519#section-4.1.2.
      audiences: list of string, the audiences claim as defined at
        https://tools.ietf.org/html/rfc7519#section-4.1.3.

    Raises:
      UnsupportedAlgorithm: if the algorihtm is not defined at
      https://tools.ietf.org/html/rfc7518#section-3.1 or if jwk is not Rsa or
      Ecdsa key.
    """
    self.verifier = jws.JwsMacVerify(jwk_set)
    self.issuer = issuer
    self.subject = subject
    self.audiences = audiences

  def verify(self, token):
    """Verifies whether the token was authenticated with mac and whether the payload's claims are valid.

    Args:
      token: string, the JWS compact serialization token as defined at
        https://tools.ietf.org/html/rfc7515#section-7.1.

    Returns:
      True if the token was verified, false if not.
    """
    if not self.verifier.verify(token):
      return False
    payload = json.loads(jwsutil.urlsafe_b64decode(token.split(".")[1]))
    return _verify_claims(payload, self.issuer, self.subject, self.audiences)


class JwtMacAuthenticator(object):
  """Jws Mac Authenticator that authenticates jwt token."""

  def __init__(self, jwk_set):
    """Constructor for JwtMacAuthenticator.

    Args:
      jwk_set: a JwkSet.

    Raises:
      UnsupportedAlgorithm: if the key.algorihtm is not defined at
      https://tools.ietf.org/html/rfc7518#section-3.1 or if jwk is not symmetric
      Hmac key.
    """
    self.authenticator = jws.JwsMacAuthenticator(jwk_set)

  def authenticate(self, header, payload):
    """Computes the authenticated jwt as defined at rfc7515#section-7.1.

    Args:
      header: bytes, the header to be authenticated.
      payload: bytes, the payload to be authenticated.

    Returns:
      base64url(header) || '.' || base64url(payload) || '.' ||
      base64url(mac), where the mac is computed over
      base64url(utf8(header)) || '.' || base64url(payload).
    """
    return self.authenticator.authenticate(header, payload)


def _get_unix_timestamp():
  return calendar.timegm(datetime.datetime.utcnow().utctimetuple())


def _verify_claims(payload, issuer, subject, audiences):
  if issuer is not None:
    if payload.get("iss", None) is None:
      return False
    if not isinstance(payload["iss"],
                      six.string_types) or payload["iss"] != issuer:
      return False
  if subject is not None:
    if payload.get("sub", None) is None:
      return False
    if not isinstance(payload["sub"],
                      six.string_types) or payload["sub"] != subject:
      return False
  if audiences is not None:
    if payload.get("aud", None) is None:
      return False
    if not isinstance(payload["aud"], six.string_types) or not any(
        payload["aud"] == s for s in audiences):
      return False
  now = _get_unix_timestamp()
  if payload.get("exp", None) is not None and isinstance(
      payload["exp"], six.integer_types):
    if now > int(payload["exp"]):
      return False
  if payload.get("nbf", None) is not None and isinstance(
      payload["nbf"], six.integer_types):
    if now < int(payload["nbf"]):
      return False

  return True
