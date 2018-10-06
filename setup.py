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

from setuptools import setup
from setuptools import find_packages

with open('README.md') as f:
  long_description = f.read()

with open('LICENSE') as f:
  license = f.read()

setup(
    name='jws',
    version='0.1',
    description='JSON Web Signature (JWS).',
    long_description=long_description,
    author='Quan Nguyen',
    author_email='quannguyen@google.com',
    url='https://github.com/google/jws',
    packages=find_packages(exclude=['tests']),
    test_suite='tests',
    install_requires=[
        'cryptography'
    ]
)
