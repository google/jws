"""
Copyright 2018 Google LLC

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

"""Json Web Signature (JWS) in compact serialization format.

Json Web Signature (Rfc7515) is a complicated standard with several dangerous
design options. Therefore, we will only implement a safe subset of it. JWS
Compact Serialization (https://tools.ietf.org/html/rfc7515#section-7.1) while
not ideal, is simple and safe if correctly implemented. We'll harden the API to
make it difficult to misuse.
"""

__author__ = "quannguyen@google.com (Quan Nguyen)"

import json

from cryptography import exceptions
from cryptography.hazmat.primitives.asymmetric import utils
import six

import jwsutil
from ecdsa_sign import EcdsaSign
from ecdsa_verify import EcdsaVerify
from hmac import Hmac
from rsa_sign import RsaSign
from rsa_verify import RsaVerify

class JwsPublicKeyVerify(object):
  """JWS Public Key Verifier which supports Rsa and Ecdsa signature schemes."""

  def __init__(self, jwk_set):
    """Constructor for JwsPublicKeyVerify.

    Args:
      jwk_set: a JwkSet.

    Raises:
      UnsupportedAlgorithm: if the algorihtm is not defined at
      https://tools.ietf.org/html/rfc7518#section-3.1 or if jwk is not Rsa or
      Ecdsa key.
    """
    self.verifiers = []
    for key in jwk_set.keys:
      if key.key_type == "RSA":
        self.verifiers.append((RsaVerify(key.pub_key, key.algorithm), key.kid))
      elif key.key_type == "EC":
        self.verifiers.append((EcdsaVerify(key.pub_key, key.algorithm),
                               key.kid))
      else:
        raise exceptions.UnsupportedAlgorithm(
            "Unsupported key type: %s" % (key.key_type))

  def verify(self, token):
    """Verifies whether the token is signed with the corresponding private key.

    Args:
      token: string, the JWS compact serialization token as defined at
        https://tools.ietf.org/html/rfc7515#section-7.1.

    Returns:
      True if the token was verified, false if not.
    """
    try:
      token_parts = token.split(".")
      if len(token_parts) != 3:
        return False
      [header, payload, sig] = [token_parts[0], token_parts[1], token_parts[2]]
      data = header + b"." + payload
      sig_bytes = jwsutil.urlsafe_b64decode(sig)
      header_json = json.loads(jwsutil.urlsafe_b64decode(header))
      if not header_json.get("alg", ""):
        return False
      header_kid = header_json.get("kid", "")
      # In practice, there is only 1 key that matches alg or kid.
      for (verifier, kid) in self.verifiers:
        found_candidate_verifier = False
        if header_kid:
          if header_kid == kid and header_json["alg"] == verifier.algorithm:
            found_candidate_verifier = True
        elif header_json["alg"] == verifier.algorithm:
          found_candidate_verifier = True
        if found_candidate_verifier:
          mod_sig_bytes = sig_bytes
          if header_json["alg"][:2] == "ES":
            # Jws's Ecdsa signature is a pair [r, s] while standard Ecdsa
            # signature is the DER encoding of [r, s].
            length = len(sig_bytes)
            if length % 2 != 0:
              return False
            [r, s] = [sig_bytes[0:length / 2], sig_bytes[length / 2:]]
            mod_sig_bytes = utils.encode_dss_signature(
                jwsutil.bytes_to_int(r), jwsutil.bytes_to_int(s))
          if verifier.verify(mod_sig_bytes, data):
            return True
      return False
    except:
      return False


class JwsPublicKeySign(object):
  """Jws public key signer that suppports both Ecdsa and Rsa signature schemes.
  """

  def __init__(self, jwk_set):
    """Constructor for JwsPublicKeySign.

    Args:
      jwk_set: a JwkSet.

    Raises:
      UnsupportedAlgorithm: if the algorihtm is not defined at
      https://tools.ietf.org/html/rfc7518#section-3.1 or if jwk is not Rsa or
      Ecdsa key.
    """
    if len(jwk_set.keys) != 1:
      raise exceptions.UnsupportedAlgorithm(
          "Do not support multiple keys in signer")
    key = jwk_set.keys[0]
    if key.key_type == "RSA":
      self.signer = RsaSign(key.priv_key, key.algorithm)
    elif key.key_type == "EC":
      self.signer = EcdsaSign(key.priv_key, key.algorithm)
    else:
      raise exceptions.UnsupportedAlgorithm(
          "Unknown key type: %s or algorithm: %s" % (key.key_type,
                                                     key.algorithm))
    if hasattr(key, "kid"):
      self.kid = key.kid
    self.algorithm = key.algorithm

  def sign(self, header, payload):
    """Computes the signed jws as defined at rfc7515#section-7.1.

    Args:
      header: bytes, the header to be signed.
      payload: bytes, the payload to be signed.

    Returns:
      base64url(header) || '.' || base64url(payload) || '.' ||
      base64url(signature), where the signature is computed over
      base64url(utf8(header)) || '.' || base64url(payload).
    """
    if not isinstance(header, six.binary_type) or not isinstance(
        payload, six.binary_type):
      raise TypeError("header and payload must be bytes.")
    signing_input = jwsutil.urlsafe_b64encode(
        header) + b"." + jwsutil.urlsafe_b64encode(payload)
    signature = self.signer.sign(signing_input)
    if self.algorithm[:2] == "ES":
      # Standard Ecdsa signature is the DER encoding of [r, s] while Jws's
      # singature is the concatenation of r and s.
      (r, s) = utils.decode_dss_signature(signature)
      curve_length = jwsutil.ecdsa_algorithm_to_curve_length(self.algorithm)
      signature = jwsutil.int_to_bytes(r, curve_length) + jwsutil.int_to_bytes(
          s, curve_length)
    return signing_input + b"." + jwsutil.urlsafe_b64encode(signature)


class JwsMacVerify(object):
  """Jws Mac Verifier that verifies message authentication code."""

  def __init__(self, jwk_set):
    """Constructor for JwsMacVerify.

    Args:
      jwk_set: a JwkSet.

    Raises:
      UnsupportedAlgorithm: if the algorihtm is not defined at
      https://tools.ietf.org/html/rfc7518#section-3.1 or if jwk is symmetric
      Hmac key.
    """
    self.verifiers = []
    for key in jwk_set.keys:
      if key.key_type == "oct":
        self.verifiers.append((Hmac(key.sym_key, key.algorithm), key.kid))
      else:
        raise exceptions.UnsupportedAlgorithm(
            "Unsupported key type: %s or unrecognized algorithm: %s" %
            (key.key_type, key.algorithm))

  def verify(self, token):
    """Verifies whether the token was authenticated with mac.

    Args:
      token: string, the JWS compact serialization token as defined at
        https://tools.ietf.org/html/rfc7515#section-7.1.

    Returns:
      True if the token was verified, false if not.
    """
    try:
      token_parts = token.split(".")
      if len(token_parts) != 3:
        return False
      [header, payload, mac] = [token_parts[0], token_parts[1], token_parts[2]]
      data = header + b"." + payload
      mac_bytes = jwsutil.urlsafe_b64decode(mac)
      header_json = json.loads(jwsutil.urlsafe_b64decode(header))
      if not header_json.get("alg", ""):
        return False
      header_kid = header_json.get("kid", "")
      # In practice, there is only 1 key that matches alg or kid.
      for (verifier, kid) in self.verifiers:
        found_candidate_verifier = False
        if header_kid:
          if header_kid == kid and header_json["alg"] == verifier.algorithm:
            found_candidate_verifier = True
        elif header_json["alg"] == verifier.algorithm:
          found_candidate_verifier = True
        if found_candidate_verifier:
          if verifier.verify_mac(mac_bytes, data):
            return True
      return False
    except:
      return False


class JwsMacAuthenticator(object):
  """Jws Mac Authenticator that authenticates jws token."""

  def __init__(self, jwk_set):
    """Constructor for JwsMacAuthenticator.

    Args:
      jwk_set: a JwkSet.

    Raises:
      UnsupportedAlgorithm: if the key.algorihtm is not defined at
      https://tools.ietf.org/html/rfc7518#section-3.1 or if jwk is not symmetric
      Hmac key.
    """
    if len(jwk_set.keys) != 1:
      raise exceptions.UnsupportedAlgorithm(
          "Do not support multiple keys in authenticator")
    key = jwk_set.keys[0]
    if key.key_type == "oct":
      self.mac = Hmac(key.sym_key, key.algorithm)
    else:
      raise exceptions.UnsupportedAlgorithm(
          "Unknown key type: %s or algorithm: %s" % (key.key_type,
                                                     key.algorithm))
    if hasattr(key, "kid"):
      self.kid = key.kid
    self.algorithm = key.algorithm

  def authenticate(self, header, payload):
    """Computes the authenticated jws as defined at rfc7515#section-7.1.

    Args:
      header: bytes, the header to be authenticated.
      payload: bytes, the payload to be authenticated.

    Returns:
      base64url(header) || '.' || base64url(payload) || '.' ||
      base64url(mac), where the mac is computed over
      base64url(utf8(header)) || '.' || base64url(payload).
    """
    if not isinstance(header, six.binary_type) or not isinstance(
        payload, six.binary_type):
      raise TypeError("header and payload must be bytes.")
    authenticating_input = jwsutil.urlsafe_b64encode(
        header) + b"." + jwsutil.urlsafe_b64encode(payload)
    mac_bytes = self.mac.compute_mac(authenticating_input)
    return authenticating_input + b"." + jwsutil.urlsafe_b64encode(mac_bytes)
