import os
import unittest


class LegionLogPathsTest(unittest.TestCase):
    """Every Legion log file lives under the one resolved log directory (LEGION_LOG_DIR or the fallback)."""

    def test_all_log_files_live_under_the_resolved_log_directory(self):
        from app.logging import legionLog

        seen_file_handlers = 0
        for getter in (legionLog.getStartupLogger, legionLog.getAppLogger, legionLog.getDbLogger):
            logger = getter()
            for handler in logger.handlers:
                base = getattr(handler, "baseFilename", None)
                if not base:
                    continue  # the startup logger is console-only (rich)
                seen_file_handlers += 1
                self.assertEqual(
                    os.path.realpath(legionLog.cache_path),
                    os.path.realpath(os.path.dirname(base)),
                    f"{logger.name} logs outside the resolved log directory",
                )
        self.assertGreaterEqual(seen_file_handlers, 2, "the application and database logs must be files")
        self.assertTrue(os.path.isdir(legionLog.cache_path))


if __name__ == "__main__":
    unittest.main()
