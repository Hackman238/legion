import os
import time


def pin_local_timezone(testcase, tz_value):
    """Set the process-local timezone for one test and restore it afterwards.

    Some process timestamps are stored as naive local times, so tests whose fixture
    data assumes a particular UTC offset must pin it to be deterministic.
    """
    if not hasattr(time, "tzset"):
        testcase.skipTest("time.tzset is unavailable on this platform")
    original = os.environ.get("TZ")

    def _restore():
        if original is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = original
        time.tzset()

    testcase.addCleanup(_restore)
    os.environ["TZ"] = tz_value
    time.tzset()
