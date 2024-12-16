# configuration for testing
import pytest


@pytest.fixture(scope='function')
def foo_dot_com_csr_str():
    test_csr = ("-----BEGIN CERTIFICATE REQUEST-----\n"  # foo.com, no sans
                "MIICczCCAVsCAQAwEjEQMA4GA1UEAwwHZm9vLmNvbTCCASIwDQYJKoZIhvcNAQEB\n"
                "BQADggEPADCCAQoCggEBAMf3BmnmNy4PK4UjZb4YnyMBf91QlMX4vm+dwG65ISkv\n"
                "i5YyWjmBhi+kvWxLZm0nut9/85ewE4STSg7CZhK0pj+lI3RRw7A9Rw6mVxsWzU8D\n"
                "40YV5DzpugSVnIKGQZsZJO9UVL/FXcOkOguI2gROjpoBuBXrwzKWaUNHUmp7SnD6\n"
                "f7/VAE2yfiBuykHUND0/F4t/TeUkOmThGx+HmUnVlHp8MIjnFzkOWtRaIA5qgGB0\n"
                "R+mwb17gvu8VAsWUsYZYCEk0N8xZm0AQN4CHVDlVJ19CS6B7oBBMdrf8OPu6gMGd\n"
                "do1hQ5tla6Xug5vWJGf/XBn5N+UWTCZI4IV3hZg5EUECAwEAAaAcMBoGCSqGSIb3\n"
                "DQEJDjENMAswCQYDVR0RBAIwADANBgkqhkiG9w0BAQsFAAOCAQEAdzhDwvuxNqAg\n"
                "5yWNvjmHGCJLLEGq9BSikBgOzaZim3J/2ArJQQpdv9XA0+6nyW+HI+fzkE61JMy9\n"
                "CEdJ5l6ttlnGOAILg2IpbNFhsq4PydwE2Ji9DBOD6AZjbtmHprx3qQyCCHGiCWpE\n"
                "OYmL6XQ0a1diSNpGc4I/ci7XQWUt8mOikn5DySe0Q4YxeCpVOmsnrtFjU1R3JFv/\n"
                "3Ui/rFhwUbyYTgju2WrwiKBAZXErVN1E8Vq/prFGKvZqzLnIIZ/zzmrGPy0A5rrI\n"
                "XTDc5iAda59tq9wibn2SF/cBHD9L7ESlq4GmaoAJoIJDFjpJ7ydFjKndNWOTv8rg\n"
                "C/EA2C/JWg==\n"
                "-----END CERTIFICATE REQUEST-----")
    return test_csr
