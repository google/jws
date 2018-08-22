"""Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License."""
"""Test utilities."""

__author__ = 'quannguyen@google.com (Quan Nguyen)'

from jws import jwsutil


def modify_token(token):
  parts = token.split('.')
  assert (len(parts) == 3)
  for i in range(len(parts)):
    modified_parts = parts[:]
    decoded_part = jwsutil.urlsafe_b64decode(modified_parts[i])
    for s in modify_str(decoded_part):
      modified_parts[i] = jwsutil.urlsafe_b64encode(s)
      yield (modified_parts[0] + b'.' + modified_parts[1] + b'.' +
             modified_parts[2])


def modify_str(s):
  # Modify each bit of string.
  for i in range(len(s)):
    c = s[i]
    for j in range(8):
      yield (s[:i] + chr(ord(c) ^ (1 << j)) + s[i:])

  # Truncate string.
  for i in range(len(s)):
    yield s[:i]
