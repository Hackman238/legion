import unittest


class SettingsDefaultsTest(unittest.TestCase):
    def test_scheduler_on_import_has_default(self):
        from app.settings import Settings

        settings = Settings()

        self.assertTrue(hasattr(settings, "general_enable_scheduler_on_import"))
        self.assertEqual("False", settings.general_enable_scheduler_on_import)


if __name__ == "__main__":
    unittest.main()
