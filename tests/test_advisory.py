import jwt
import pytest
from jwt.exceptions import InvalidKeyError

# Test keys for CVE-2022-29217
ssh_priv_key_bytes = b"""-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOWc7RbaNswMtNtc+n6WZDlUblMr2FBPo79fcGXsJlGQoAoGCCqGSM49
AwEHoUQDQgAElcy2RSSSgn2RA/xCGko79N+7FwoLZr3Z0ij/ENjow2XpUDwwKEKk
Ak3TDXC9U8nipMlGcY7sDpXp2XyhHEM+Rw==
-----END EC PRIVATE KEY-----"""

ssh_key_bytes = b"""ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJXMtkUkkoJ9kQP8QhpKO/TfuxcKC2a92dIo/xDY6MNl6VA8MChCpAJN0w1wvVPJ4qTJRnGO7A6V6dl8oRxDPkc="""


class TestAdvisory:
    def test_cve_2022_29217_ecdsa_vulnerability(self):
        """
        Test for CVE-2022-29217: Ensure HMAC algorithm rejects ECDSA SSH public keys.

        The vulnerability allowed attackers to use asymmetric public keys
        (like ECDSA SSH keys) as HMAC secrets, potentially bypassing signature
        verification. The fix ensures HMAC rejects all SSH and PEM formatted keys.
        """
        # A valid JWT signed with the EC private key using ES256
        # This token is legitimately signed and should verify with the public key
        encoded_good = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoxMjM0fQ.NX42mS8cNqYoL3FOW9ZcKw8Nfq2mb6GqJVADeMA1-kyHAclilYo_edhdM_5eav9tBRQTlL0XMeu_WFE_mz3OXg"

        # A malicious JWT signed with HMAC using the SSH public key as the secret
        # This should be rejected because SSH public keys should not be HMAC secrets
        encoded_bad = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoxMjM0fQ.5eYfbrbeGYmWfypQ6rMWXNZ8bdHcqKng5GPr9MJZITU"

        # The good token should verify successfully with ES256
        jwt.decode(
            encoded_good,
            ssh_key_bytes,
            algorithms=jwt.get_default_algorithms()
        )

        # The bad token should be rejected - HMAC should not accept SSH keys
        with pytest.raises(InvalidKeyError):
            jwt.decode(
                encoded_bad,
                ssh_key_bytes,
                algorithms=jwt.get_default_algorithms()
            )
