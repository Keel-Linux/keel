Real certificates made with openssl for the tls.acme tests, committed
without their keys (keel#35):

| File | Issued by | Names | Valid until |
| --- | --- | --- | --- |
| `acme-blog.pem` | Keel test ACME CA | blog.example.org, www.blog.example.org | 2039-01-01 |
| `acme-expired.pem` | Keel test ACME CA | blog.example.org | 2025-01-01 |
| `acme-other.pem` | Keel test ACME CA | shop.example.org | 2039-01-01 |
| `self-signed.pem` | itself | blog, blog.example.org | 2036-01-01 |

`tests/fixtures/inspect/turnkey/etc/ssl/private/cert.pem` is a copy of
`acme-blog.pem`. The tests that read it through `keel inspect` use the
real clock, so they start reporting `enabled: false` ("expired on
2039-01-01") on that date; the probe tests pin their own date.
