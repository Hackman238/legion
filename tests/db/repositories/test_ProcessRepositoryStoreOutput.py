import unittest
from unittest.mock import MagicMock


class ProcessRepositoryStoreOutputTest(unittest.TestCase):
    def setUp(self):
        from db.repositories.ProcessRepository import ProcessRepository

        self.session = MagicMock()
        self.db_adapter = MagicMock()
        self.db_adapter.session.return_value = self.session
        self.logger = MagicMock()
        self.repository = ProcessRepository(self.db_adapter, self.logger)

    def test_storeProcessOutput_looks_up_output_row_by_process_fk(self):
        mock_proc = MagicMock()
        mock_proc.status = "Running"

        proc_query = MagicMock()
        proc_query.filter_by.return_value.first.return_value = mock_proc

        mock_output = MagicMock()
        output_query = MagicMock()
        output_query.filter_by.return_value.first.return_value = mock_output

        self.session.query.side_effect = [proc_query, output_query]

        result = self.repository.storeProcessOutput("7", "tool output")

        self.assertTrue(result)
        output_query.filter_by.assert_called_once_with(processId="7")
        self.assertEqual("tool output", mock_output.output)
        self.assertEqual("Finished", mock_proc.status)
        self.assertEqual(0, mock_proc.estimatedRemaining)
        self.assertEqual("100", mock_proc.percent)
        self.session.commit.assert_called_once()

    def test_storeProcessOutput_creates_output_row_when_missing(self):
        from db.entities.processOutput import process_output

        mock_proc = MagicMock()
        mock_proc.status = "Killed"

        proc_query = MagicMock()
        proc_query.filter_by.return_value.first.return_value = mock_proc

        output_query = MagicMock()
        output_query.filter_by.return_value.first.return_value = None

        self.session.query.side_effect = [proc_query, output_query]

        result = self.repository.storeProcessOutput("11", "killed output")

        self.assertTrue(result)
        added_rows = [call.args[0] for call in self.session.add.call_args_list]
        created_output_rows = [row for row in added_rows if isinstance(row, process_output)]
        self.assertTrue(created_output_rows)
        self.assertEqual(11, created_output_rows[0].processId)
        self.assertEqual("Killed", mock_proc.status)
        self.assertEqual(0, mock_proc.estimatedRemaining)
        self.session.commit.assert_called_once()

    def test_storeProcessCrashStatus_sets_eta_to_zero(self):
        mock_proc = MagicMock()
        mock_proc.status = "Running"
        query = MagicMock()
        query.filter_by.return_value.first.return_value = mock_proc
        self.session.query.return_value = query

        self.repository.storeProcessCrashStatus("19")

        self.assertEqual("Crashed", mock_proc.status)
        self.assertEqual(0, mock_proc.estimatedRemaining)
        self.session.commit.assert_called_once()


if __name__ == "__main__":
    unittest.main()
