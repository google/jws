"""An implementation of PublicKeySign for RSA.

The implementation supports both PKCS1-v1_5 and PSS signatures.
"""

__author__ = "quannguyen@google.com (Quan Nguyen)"

from cryptography.hazmat.primitives.asymmetric import rsa
import six

from google3.experimental.users.quannguyen.jwslib import util as jwsutil
from google3.experimental.users.quannguyen.jwslib.public_key_sign import PublicKeySign


class RsaSign(PublicKeySign):
  """RSA signing with cryptography.io."""

  def __init__(self, priv_key, algorithm):
    """Constructor for RsaSign.

    Args:
      priv_key: rsa.RSAPrivateKey, the RSA private key.
      algorithm: string, RSA algorithm as defined at
        https://tools.ietf.org/html/rfc7518#section-3.1.

    Raises:
      TypeError: if the private key is not an instance of rsa.RSAPrivateKey.
      UnsupportedAlgorithm: if the algorithm is not supported.
    """
    if not isinstance(priv_key, rsa.RSAPrivateKey):
      raise TypeError(
          "The private key must be an instance of rsa.RSAPrivateKey")
    self.priv_key = priv_key
    self.algorithm = algorithm
    (self.hash, self.padding) = jwsutil.parse_rsa_algorithm(algorithm)

  def sign(self, data):
    """See base class."""
    if not isinstance(data, six.binary_type):
      raise TypeError("data must be bytes.")
    return self.priv_key.sign(data, self.padding, self.hash)
