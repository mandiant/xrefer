from . import Backend


def sample_path() -> str:
    """Return a sample path for the backend."""
    return Backend().path
