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

__author__ = "quannguyen@google.com (Quan Nguyen)"
import json
from jws import jws
from jws import jwsutil


class JwtPublicKeyVerify(object):
  """JWT Public Key Verifier which verifies both the signature and claims."""

  def __init__(self, jwk_set, issuer=None, subject=None, audiences=None):
    self.verifier = jws.JwsPublicKeyVerify(jwk_set)
    self.issuer = issuer
    self.subject = subject
    self.audiences = audiences

  def verify(self, token):
    if not self.verifier.verify(token):
      return False
    payload = json.loads(jwsutil.urlsafe_b64decode(token.split(".")[1]))
    return _verify_claims(payload, self.issuer, self.subject, self.audiences)


def _verify_claims(payload, issuer, subject, audiences):
  if issuer is not None:
    if payload.get("iss", None) is None:
      return False
    if payload["iss"] != issuer:
      return False
  if subject is not None:
    if payload.get("sub", None) is None:
      return False
    if payload["sub"] != subject:
      return False
  if audiences is not None:
    if payload.get("aud", None) is None:
      return False
    if not any(payload["aud"] == s for s in audiences):
      return False
  return True
