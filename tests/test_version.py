import libtea


def test_version():
    assert isinstance(libtea.__version__, str)
