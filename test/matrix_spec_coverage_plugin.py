import _pytest
import pytest
from _pytest._pluggy import HookspecMarker
from matrix_spec_coverage import ApiGuide, RequestsMockWithApiGuide

hookspec = HookspecMarker("pytest")

# We use this to print api_guide coverage stats
# after pytest has finished running
def pytest_terminal_summary(terminalreporter, exitstatus):
    if pytest.responses_with_api_guide:
        guide = pytest.responses_with_api_guide.api_guide
        guide.print_summary()


def build_api_guide():
    import os
    from glob import glob
    DOC_FOLDER = "../matrix-doc/api/client-server/"
    api_files = glob(os.path.join(DOC_FOLDER, '*.yaml'))
    if not api_files:
        return
    guide = ApiGuide()
    guide.setup_from_files(API_FILES)
    return guide

# Load api_guide stats into the pytest namespace so
# that we can print a the stats on terminal summary
@hookspec(historic=True)
def pytest_namespace():
    guide = build_api_guide()
    return { 'responses_with_api_guide': RequestsMockWithApiGuide(guide) }
