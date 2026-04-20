import logging
import unittest


class LoggingCompatibilityTest(unittest.TestCase):
    def test_legion_logging_disables_asyncio_task_capture(self):
        import app.logging.legionLog  # noqa: F401

        self.assertFalse(getattr(logging, "logAsyncioTasks", True))


if __name__ == "__main__":
    unittest.main()
