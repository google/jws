# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""JSON Web Token (JWT) in compact serialization format.

Jwt uses jws underneath. The difference between jws and jwt is that
jws only verifies the signature while jwt verifies both the signature and
claims as defined at https://tools.ietf.org/html/rfc7519#section-4.1. In
particular, in addition to signature verification, jwt does the following:

  1. Verify expected issuer, subjects and list of audiences. However, the
  verification is **optional** because one, jwt does not know what your expected
  issuer, subject and list of audiences are and second, RFCs do not mandate
  these claims. As a consequence, when you construct the verifier:
    + If you do not specify these fields, jwt does *not** know how to verify
    them, and hence does **not** verify them.
    + If you specify these fields, the verification is automatic and mandatory.

  2. When 'exp', 'nbf' are in the claims, jwt automatically verifies them.

  3. If you use your own claims that aren't defined at
  https://tools.ietf.org/html/rfc7519#section-4.1, jwt does not know how to
  verify them. You have to verify them yourselves after signature verification
  and RFC claims verification.
"""

__author__ = "quannguyen@google.com (Quan Nguyen)"
import json
import jws
from . import jwsutil
from .exceptions import SecurityException
import six
import datetime
import calendar


class JwtPublicKeyVerify(object):
  """JWT Public Key Verifier which verifies both the signature and claims."""

  def __init__(self,
               jwk_set,
               issuer=None,
               subject=None,
               audiences=None,
               clock_skew_tolerance=0):
    """Constructor for JwtPublicKeyVerify.

    Args:
      jwk_set: a JwkSet.
      issuer: string, the issuer claim as defined at
        https://tools.ietf.org/html/rfc7519#section-4.1.1.
      subject: string, the subject claim as defined at
        https://tools.ietf.org/html/rfc7519#section-4.1.2.
      audiences: list of string, the audiences claim as defined at
        https://tools.ietf.org/html/rfc7519#section-4.1.3.
      clock_skew_tolerance: integer, the clock skew that the verifier tolerates.

    Raises:
      UnsupportedAlgorithm: if the algorihtm is not defined at
      https://tools.ietf.org/html/rfc7518#section-3.1 or if jwk is not Rsa or
      Ecdsa key.
    """
    self.verifier = jws.JwsPublicKeyVerify(jwk_set)
    self.issuer = issuer
    self.subject = subject
    self.audiences = audiences
    self.clock_skew_tolerance = clock_skew_tolerance

  def verify(self, token):
    """Verifies whether the token is signed with the corresponding private key and whether the payload's claims are valid.

    Args:
      token: bytes, the JWS compact serialization token as defined at
        https://tools.ietf.org/html/rfc7515#section-7.1.

    Returns:
      dict, the deserialized JSON payload in the token.

    Raises:
      SecurityException: when the token is invalid
    """
    try:
      payload = json.loads(self.verifier.verify(token).decode("utf-8"))
      if _verify_claims(payload, self.issuer, self.subject, self.audiences,
                        self.clock_skew_tolerance):
        return payload
      else:
        raise SecurityException("Invalid token")
    except SecurityException as e:
      raise e
    except:
      raise SecurityException("Invalid token")


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
      header: dict, dictionary of header to convert to JSON and sign.
      payload: dict, dictionary of the payload to conert to JSON and sign.

    Returns:
      bytes, the signed token as defined at
      https://tools.ietf.org/html/rfc7515#section-7.1.

    Raises:
      SecurityException: if the header's algorithm or kid does not match the
      key's.
    """
    return self.signer.sign(header, payload)


class JwtMacVerify(object):
  """Jwt Mac Verifier that verifies both message authentication code and claims."""

  def __init__(self,
               jwk_set,
               issuer=None,
               subject=None,
               audiences=None,
               clock_skew_tolerance=0):
    """Constructor for JwtMacVerify.

    Args:
      jwk_set: a JwkSet.
      issuer: string, the issuer claim as defined at
        https://tools.ietf.org/html/rfc7519#section-4.1.1.
      subject: string, the subject claim as defined at
        https://tools.ietf.org/html/rfc7519#section-4.1.2.
      audiences: list of string, the audiences claim as defined at
        https://tools.ietf.org/html/rfc7519#section-4.1.3.
      clock_skew_tolerance: integer, the clock skew that the verifier tolerates.

    Raises:
      UnsupportedAlgorithm: if the algorihtm is not defined at
      https://tools.ietf.org/html/rfc7518#section-3.1 or if jwk is not Rsa or
      Ecdsa key.
    """
    self.verifier = jws.JwsMacVerify(jwk_set)
    self.issuer = issuer
    self.subject = subject
    self.audiences = audiences
    self.clock_skew_tolerance = clock_skew_tolerance

  def verify(self, token):
    """Verifies whether the token was authenticated with mac and whether the payload's claims are valid.

    Args:
      token: bytes, the JWS compact serialization token as defined at
        https://tools.ietf.org/html/rfc7515#section-7.1.

    Returns:
      dict, the deserialized JSON payload in the token.

    Raises:
      SecurityException: when the token is not valid.
    """
    try:
      payload = json.loads(self.verifier.verify(token).decode("utf-8"))
      if _verify_claims(payload, self.issuer, self.subject, self.audiences,
                        self.clock_skew_tolerance):
        return payload
      else:
        raise SecurityException("Invalid token")
    except SecurityException as e:
      raise e
    except:
      raise SecurityException("Invalid token")


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
      header: dict, dictionary of header to convert to JSON and sign.
      payload: dict, dictionary of payload to convert to JSON and sign.

    Returns:
      bytes, the authenticated token as defined at
      https://tools.ietf.org/html/rfc7515#section-7.1.

    Raises:
      SecurityException: if the header's algorithm or kid does not match the
      key's.
    """
    return self.authenticator.authenticate(header, payload)


def _get_unix_timestamp():
  return calendar.timegm(datetime.datetime.utcnow().utctimetuple())


def _verify_claims(payload, issuer, subject, audiences, clock_skew_tolerance):
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
    if now > int(payload["exp"]) + clock_skew_tolerance:
      return False
  if payload.get("nbf", None) is not None and isinstance(
      payload["nbf"], six.integer_types):
    if now < int(payload["nbf"]) - clock_skew_tolerance:
      return False

  return True
