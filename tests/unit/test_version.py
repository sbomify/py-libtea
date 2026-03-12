import libtea
from libtea import TeaClient
from libtea.exceptions import TeaError
from libtea.models import Artifact, Collection, Product


def test_version():
    assert isinstance(libtea.__version__, str)


def test_public_api_exports():
    assert hasattr(libtea, "TeaClient")
    assert libtea.TeaClient is TeaClient


def test_exception_importable():
    assert issubclass(TeaError, Exception)


def test_model_importable():
    assert Product is not None
    assert Collection is not None
    assert Artifact is not None


def test_pagination_models_importable():
    from libtea.models import PaginatedComponentReleaseResponse, PaginatedComponentResponse

    assert PaginatedComponentResponse is not None
    assert PaginatedComponentReleaseResponse is not None


def test_lazy_import_pagination_models():
    import libtea

    assert libtea.PaginatedComponentResponse is not None
    assert libtea.PaginatedComponentReleaseResponse is not None
