import unittest

import legion


class LegionLauncherTest(unittest.TestCase):
    def test_web_bind_all_flag_defaults_to_localhost(self):
        args = legion.build_arg_parser().parse_args(["--web"])
        self.assertFalse(args.web_bind_all)
        self.assertEqual("127.0.0.1", legion.resolve_web_bind_host(args))
        self.assertEqual("Localhost only", legion.describe_web_bind_host("127.0.0.1"))

    def test_web_bind_all_flag_uses_all_interfaces(self):
        args = legion.build_arg_parser().parse_args(["--web", "--web-bind-all", "--web-port", "5050"])
        self.assertTrue(args.web_bind_all)
        self.assertEqual(5050, args.web_port)
        self.assertEqual("0.0.0.0", legion.resolve_web_bind_host(args))
        self.assertEqual("All interfaces", legion.describe_web_bind_host("0.0.0.0"))

    def test_web_opaque_ui_flag_defaults_disabled(self):
        args = legion.build_arg_parser().parse_args(["--web"])
        self.assertFalse(args.web_opaque_ui)
        self.assertFalse(legion.resolve_web_opaque_ui(args))

    def test_web_opaque_ui_flag_enables_opaque_mode(self):
        args = legion.build_arg_parser().parse_args(["--web", "--web-opaque-ui"])
        self.assertTrue(args.web_opaque_ui)
        self.assertTrue(legion.resolve_web_opaque_ui(args))
