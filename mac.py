"""Abstract base class for message authentication code (MAC).

Security guarantees:

Message Authentication Codes provide symmetric message authentication.
Instances implementing this abstract class are secure against existential
forgery under chosen plaintext attack, and can be deterministic or randomized.
This abstract class should be used for authentication only, and not for other
purposes like generation of pseudorandom bytes.

"""

__author__ = "quannguyen@google.com (Quan Nguyen)"

import abc


class Mac(object):
  """Abstract base class for message authentication code (MAC)."""
  __metaclass__ = abc.ABCMeta

  @abc.abstractmethod
  def compute_mac(self, data):
    """Computes message authentication code (MAC) for data.

    Args:
      data: bytes, the data.

    Returns:
      bytes, message authentication code (MAC) of the data.
    """

  @abc.abstractmethod
  def verify_mac(self, mac, data):
    """Verifies whether mac is the correct message authentication code of data.

    Args:
      mac: bytes, the message authentication code to verify against data.
      data: bytes, the data.
    Returns:
      True if the mac was valid, false if not.
    """
