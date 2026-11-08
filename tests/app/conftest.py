import pytest

from app.scheduler import providers


@pytest.fixture(autouse=True)
def _clear_lmstudio_model_cache():
    providers.clear_lmstudio_model_cache()
    yield
    providers.clear_lmstudio_model_cache()
