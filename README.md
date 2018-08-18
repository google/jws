# Json Web Signature (JWS)

Json Web Signature (RFC7515) is a complicated standard with several dangerous
design options, for instance, see [Practical Cryptanalysis of Json Web Token](https://rwc.iacr.org/2017/Slides/nguyen.quan.pdf) or [High risk vulnerability in RFC 7515](https://mailarchive.ietf.org/arch/msg/jose/gQU_C_QURVuwmy-Q2qyVwPLQlcg). Therefore, we will only implement a safe subset of it. JWS
Compact Serialization (https://tools.ietf.org/html/rfc7515#section-7.1) while
not ideal, is simple and safe if correctly implemented. We'll harden the API to
make it difficult to misuse.

(This is not an official Google project.)
