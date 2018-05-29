"""An implementation of PublicKeyVerify for RSA.

The implementation supports both PKCS1-v1_5 and PSS signatures.
"""

__author__ = "quannguyen@google.com (Quan Nguyen)"

from cryptography.hazmat.primitives.asymmetric import rsa
import six

from google3.experimental.users.quannguyen.jwslib import util as jwsutil
from google3.experimental.users.quannguyen.jwslib.public_key_verify import PublicKeyVerify


class RsaVerify(PublicKeyVerify):
  """RSA verifying with cryptography.io."""

  def __init__(self, pub_key, algorithm):
    """Constructor for RsaVerify.

    Args:
      pub_key: rsa.RSAPublicKey
      algorithm: string, RSA algorithm as defined at
        https://tools.ietf.org/html/rfc7518#section-3.1.

    Raises:
      TypeError: if public key is not an instance of rsa.RSAPublicKey.
      UnsupportedAlgorithm: if the algorithm is not supported.
    """
    if not isinstance(pub_key, rsa.RSAPublicKey):
      raise TypeError("The public key must be an instance of RSAPublicKey")
    self.pub_key = pub_key
    self.algorithm = algorithm
    (self.hash, self.padding) = jwsutil.parse_rsa_algorithm(algorithm)

  def verify(self, signature, data):
    """See base class."""
    if not isinstance(data, six.binary_type) or not isinstance(
        data, six.binary_type):
      return False
    try:
      self.pub_key.verify(signature, data, self.padding, self.hash)
      return True
    except:
      return False
