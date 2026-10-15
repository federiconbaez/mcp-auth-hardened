import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest

from mcpauth import rsa

OPENSSL = shutil.which("openssl")


class RsaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_key(1024)

    def test_key_shape(self):
        k = self.key
        self.assertEqual(k["n"].bit_length(), 1024)
        self.assertEqual(k["e"], 65537)
        m = 123456789
        self.assertEqual(pow(pow(m, k["e"], k["n"]), k["d"], k["n"]), m)

    def test_sign_verify_roundtrip_and_tamper(self):
        k = self.key
        sig = rsa.sign(b"payload", k["n"], k["d"])
        self.assertEqual(len(sig), 128)
        self.assertTrue(rsa.verify(b"payload", sig, k["n"], k["e"]))
        self.assertFalse(rsa.verify(b"payloae", sig, k["n"], k["e"]))
        bad = bytearray(sig)
        bad[-1] ^= 1
        self.assertFalse(rsa.verify(b"payload", bytes(bad), k["n"], k["e"]))
        self.assertFalse(rsa.verify(b"payload", sig[:-1], k["n"], k["e"]), "wrong length")
        self.assertFalse(rsa.verify(b"payload", b"\x00" * 128, k["n"], k["e"]))
        self.assertFalse(rsa.verify(b"payload", (k["n"]).to_bytes(128, "big"), k["n"], k["e"]), "s >= n")
        other = rsa.generate_key(1024)
        self.assertFalse(rsa.verify(b"payload", sig, other["n"], other["e"]))

    def test_emsa_structure(self):
        em = rsa.emsa_pkcs1_v15(b"abc", 128)
        self.assertEqual(em[:2], b"\x00\x01")
        self.assertEqual(em[-32:], hashlib.sha256(b"abc").digest())
        self.assertEqual(em[-32 - len(rsa.SHA256_PREFIX) - 1], 0)
        self.assertTrue(set(em[2:128 - 32 - len(rsa.SHA256_PREFIX) - 1]) == {0xFF})

    def test_forged_signature_with_garbage_padding_rejected(self):
        """Bleichenbacher-style: build a block with short 0xFF padding + trailing garbage. A parser that does not compare the whole block would accept it."""
        k = self.key
        digest_info = rsa.SHA256_PREFIX + hashlib.sha256(b"payload").digest()
        em = b"\x00\x01" + b"\xff" * 8 + b"\x00" + digest_info
        em = em + b"\x42" * (128 - len(em))
        sig = pow(int.from_bytes(em, "big"), k["d"], k["n"]).to_bytes(128, "big")
        self.assertFalse(rsa.verify(b"payload", sig, k["n"], k["e"]))

    def test_primality(self):
        for p in (2, 3, 97, 7919, 2 ** 61 - 1, 2 ** 127 - 1):
            self.assertTrue(rsa._is_probable_prime(p), p)
        for c in (1, 4, 91, 561, 41041, 825265, 2 ** 61 + 1, (2 ** 31 - 1) * (2 ** 61 - 1)):  # incl. Carmichael numbers
            self.assertFalse(rsa._is_probable_prime(c), c)

    def test_bad_key_sizes_rejected(self):
        for bits in (256, 1000, 1023):
            with self.assertRaises(ValueError):
                rsa.generate_key(bits)

    def test_der_public_key_has_expected_header(self):
        pem = rsa.public_key_pem(self.key["n"], self.key["e"])
        self.assertTrue(pem.startswith("-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ"), pem[:80])


@unittest.skipUnless(OPENSSL, "openssl binary not available")
class OpenSslInterop(unittest.TestCase):
    """Independent cross-implementation checks: our verifier accepts openssl signatures and openssl accepts ours."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def sh(self, *args, **kw):
        return subprocess.run(args, capture_output=True, cwd=self.d, **kw)

    def test_our_verify_accepts_openssl_signature(self):
        self.assertEqual(self.sh(OPENSSL, "genrsa", "-out", "k.pem", "2048").returncode, 0)
        mod = self.sh(OPENSSL, "rsa", "-in", "k.pem", "-noout", "-modulus", text=True).stdout.strip().split("=")[1]
        n = int(mod, 16)
        with open(os.path.join(self.d, "m"), "wb") as fh:
            fh.write(b"signed by openssl")
        self.assertEqual(self.sh(OPENSSL, "dgst", "-sha256", "-sign", "k.pem", "-out", "s", "m").returncode, 0)
        with open(os.path.join(self.d, "s"), "rb") as fh:
            sig = fh.read()
        self.assertTrue(rsa.verify(b"signed by openssl", sig, n, 65537))
        self.assertFalse(rsa.verify(b"signed by openssl!", sig, n, 65537))

    def test_openssl_verifies_our_signature_with_our_pem(self):
        k = rsa.generate_key(2048)
        sig = rsa.sign(b"signed by mcpauth", k["n"], k["d"])
        with open(os.path.join(self.d, "pub.pem"), "w") as fh:
            fh.write(rsa.public_key_pem(k["n"], k["e"]))
        with open(os.path.join(self.d, "m"), "wb") as fh:
            fh.write(b"signed by mcpauth")
        with open(os.path.join(self.d, "s"), "wb") as fh:
            fh.write(sig)
        ok = self.sh(OPENSSL, "dgst", "-sha256", "-verify", "pub.pem", "-signature", "s", "m", text=True)
        self.assertEqual((ok.returncode, ok.stdout.strip()), (0, "Verified OK"))
        with open(os.path.join(self.d, "m"), "wb") as fh:
            fh.write(b"something else")
        bad = self.sh(OPENSSL, "dgst", "-sha256", "-verify", "pub.pem", "-signature", "s", "m")
        self.assertNotEqual(bad.returncode, 0)


if __name__ == "__main__":
    unittest.main()
