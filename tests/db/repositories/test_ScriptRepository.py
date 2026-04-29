import unittest
from unittest.mock import MagicMock

from tests.db.helpers.db_helpers import mockExecuteRows


class ScriptRepositoryTest(unittest.TestCase):
    def setUp(self) -> None:
        from db.repositories.ScriptRepository import ScriptRepository
        self.mockDbAdapter = MagicMock()
        self.mockDbSession = MagicMock()
        self.mockDbAdapter.session.return_value = self.mockDbSession
        self.scriptRepository = ScriptRepository(self.mockDbAdapter)

    def test_getScriptsByHostIP_WhenProvidedAHostIP_ReturnsAllScripts(self):
        expectedQuery = ("SELECT host.id, host.scriptId, port.portId, port.protocol FROM l1ScriptObj AS host "
                         "INNER JOIN hostObj AS hosts ON hosts.id = host.hostId "
                         "LEFT OUTER JOIN portObj AS port ON port.id = host.portId WHERE hosts.ip=:hostIP")
        self.mockDbSession.execute.return_value = mockExecuteRows(
            [(1, "some-script1"), (2, "some-script2")],
            ["id", "scriptId"],
        )
        scripts = self.scriptRepository.getScriptsByHostIP("some-host-ip")
        self.assertEqual([
            {"id": 1, "scriptId": "some-script1"},
            {"id": 2, "scriptId": "some-script2"},
        ], scripts)
        query, params = self.mockDbSession.execute.call_args.args
        self.assertEqual(expectedQuery, str(query))
        self.assertEqual({"hostIP": "some-host-ip"}, params)

    def test_getScriptOutputById_WhenProvidedAScriptId_ReturnsScriptOutput(self):
        expectedQuery = "SELECT script.output FROM l1ScriptObj as script WHERE script.id = :scriptDBId"
        self.mockDbSession.execute.return_value = mockExecuteRows(
            [("some-script-output1",), ("some-script-output2",)],
            ["output"],
        )

        scripts = self.scriptRepository.getScriptOutputById("some-id")
        self.assertEqual([
            {"output": "some-script-output1"},
            {"output": "some-script-output2"},
        ], scripts)
        query, params = self.mockDbSession.execute.call_args.args
        self.assertEqual(expectedQuery, str(query))
        self.assertEqual({"scriptDBId": "some-id"}, params)
