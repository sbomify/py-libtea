import pytest

from libtea.exceptions import (
    TeaAuthenticationError,
    TeaChecksumError,
    TeaConnectionError,
    TeaDiscoveryError,
    TeaError,
    TeaNotFoundError,
    TeaRequestError,
    TeaServerError,
    TeaValidationError,
)


def test_tea_error_inherits_exception():
    assert issubclass(TeaError, Exception)


def test_tea_error_is_base():
    assert issubclass(TeaConnectionError, TeaError)
    assert issubclass(TeaAuthenticationError, TeaError)
    assert issubclass(TeaNotFoundError, TeaError)
    assert issubclass(TeaRequestError, TeaError)
    assert issubclass(TeaServerError, TeaError)
    assert issubclass(TeaDiscoveryError, TeaError)
    assert issubclass(TeaChecksumError, TeaError)
    assert issubclass(TeaValidationError, TeaError)


def test_tea_error_message():
    err = TeaError("something went wrong")
    assert str(err) == "something went wrong"


def test_tea_not_found_with_error_type():
    err = TeaNotFoundError("not found", error_type="OBJECT_UNKNOWN")
    assert err.error_type == "OBJECT_UNKNOWN"
    assert "not found" in str(err)


def test_tea_not_found_default_error_type():
    err = TeaNotFoundError("not found")
    assert err.error_type is None


def test_tea_checksum_error_fields():
    err = TeaChecksumError("mismatch", algorithm="SHA-256", expected="abc", actual="def")
    assert err.algorithm == "SHA-256"
    assert err.expected == "abc"
    assert err.actual == "def"


def test_tea_checksum_error_default_fields():
    err = TeaChecksumError("mismatch")
    assert err.algorithm is None
    assert err.expected is None
    assert err.actual is None


@pytest.mark.parametrize(
    "exc_class",
    [
        TeaConnectionError,
        TeaAuthenticationError,
        TeaRequestError,
        TeaServerError,
        TeaDiscoveryError,
        TeaValidationError,
    ],
)
def test_simple_subclass_raise_and_catch(exc_class):
    with pytest.raises(TeaError) as exc_info:
        raise exc_class("test message")
    assert str(exc_info.value) == "test message"
