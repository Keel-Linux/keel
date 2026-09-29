# Copyright (c) 2026 KeelLinux maintainers
"""Reading the certificate in use, for tls.acme (keel#35)

The fixtures under tests/fixtures/certificates are real certificates made
with openssl, committed without their keys: one issued by a test CA for
blog.example.org and www.blog.example.org, the same CA's expired one, one
for another domain, and a self-signed one.
"""

import unittest
from datetime import datetime, timezone
from os.path import abspath, dirname, join
from unittest import mock

from helpers import spec  # noqa: F401

from keel.inspect import certificate
from keel.inspect.certificate import covers, read_certificate

CERTS = join(dirname(abspath(__file__)), "fixtures", "certificates")
NOW = datetime(2026, 9, 29, tzinfo=timezone.utc)
KEY = "-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----\n"


def pem(name: str) -> str:
    with open(join(CERTS, f"{name}.pem")) as fob:
        return fob.read()


class TestReadCertificate(unittest.TestCase):
    def test_an_issued_certificate(self):
        cert, problem = read_certificate(pem("acme-blog"))
        self.assertIsNone(problem)
        self.assertFalse(cert.self_signed)
        self.assertEqual(cert.names,
                         ("blog.example.org", "www.blog.example.org"))
        self.assertEqual(cert.not_after,
                         datetime(2039, 1, 1, tzinfo=timezone.utc))
        self.assertIn("Keel test ACME CA", cert.issuer)

    def test_a_self_signed_certificate(self):
        cert, _ = read_certificate(pem("self-signed"))
        self.assertTrue(cert.self_signed)
        self.assertEqual(cert.names, ("blog", "blog.example.org"))

    def test_the_combined_file_is_read_from_its_certificate(self):
        """cert.pem holds the certificate, the key and the DH parameters"""
        cert, problem = read_certificate(pem("acme-blog") + KEY)
        self.assertIsNone(problem)
        self.assertEqual(cert.names[0], "blog.example.org")

    def test_a_leaf_that_shares_its_ca_name_is_not_self_signed(self):
        """Same subject and issuer, but signed by another key (review of #38)"""
        cert, _ = read_certificate(pem("same-dn-leaf"))
        self.assertEqual(cert.subject, cert.issuer)
        self.assertFalse(cert.self_signed)

    def test_a_chain_with_the_ca_first_is_read_from_its_leaf(self):
        cert, problem = read_certificate(pem("chain-ca-first"))
        self.assertIsNone(problem)
        self.assertFalse(cert.self_signed)
        self.assertEqual(cert.names,
                         ("blog.example.org", "www.blog.example.org"))

    def test_a_lone_self_signed_ca_certificate_is_still_read(self):
        """openssl req -x509, as TurnKey makes its own, marks it CA:TRUE"""
        cert, _ = read_certificate(pem("self-signed"))
        self.assertTrue(cert.self_signed)

    def test_openssl_that_does_not_answer_is_a_problem(self):
        with mock.patch.object(
            certificate.subprocess, "run",
            side_effect=certificate.subprocess.TimeoutExpired("openssl", 10),
        ):
            cert, problem = read_certificate(pem("acme-blog"))
        self.assertIsNone(cert)
        self.assertIn("did not answer", problem)

    def test_text_without_a_certificate_is_a_problem(self):
        cert, problem = read_certificate(KEY)
        self.assertIsNone(cert)
        self.assertIn("no certificate", problem)
        cert, problem = read_certificate("")
        self.assertIsNone(cert)

    def test_a_truncated_file_is_no_certificate(self):
        cert, problem = read_certificate(pem("acme-blog").split("-----END")[0])
        self.assertIsNone(cert)
        self.assertIn("no certificate", problem)

    def test_a_certificate_openssl_cannot_parse_is_a_problem(self):
        broken = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
        cert, problem = read_certificate(broken)
        self.assertIsNone(cert)
        self.assertIn("openssl", problem)

    def test_openssl_missing_is_a_problem_and_not_a_guess(self):
        with mock.patch.object(certificate.subprocess, "run",
                               side_effect=FileNotFoundError(2, "No such file")):
            cert, problem = read_certificate(pem("acme-blog"))
        self.assertIsNone(cert)
        self.assertIn("openssl", problem)


class TestCovers(unittest.TestCase):
    def test_exact_names_and_case(self):
        cert, _ = read_certificate(pem("acme-blog"))
        self.assertTrue(covers(cert, "Blog.Example.org"))
        self.assertTrue(covers(cert, "blog.example.org."))
        self.assertFalse(covers(cert, "shop.example.org"))

    def test_a_wildcard_covers_one_label_only(self):
        cert = certificate.Certificate(
            subject="CN=*.example.org", issuer="CN=CA",
            names=("*.example.org",), not_after=NOW)
        self.assertTrue(covers(cert, "blog.example.org"))
        self.assertFalse(covers(cert, "a.blog.example.org"))
        self.assertFalse(covers(cert, "example.org"))


if __name__ == "__main__":
    unittest.main()
