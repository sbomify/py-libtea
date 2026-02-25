import pytest

from libtea._http import TeaHttpClient

BASE_URL = "https://api.example.com/tea/v1"


@pytest.fixture
def base_url():
    return BASE_URL


@pytest.fixture
def http_client():
    c = TeaHttpClient(base_url=BASE_URL)
    yield c
    c.close()
