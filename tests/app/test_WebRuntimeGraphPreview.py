import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock


class GraphProcessOutputPreviewTest(unittest.TestCase):
    def _runtime(self, full_text):
        runtime = MagicMock()
        runtime.get_process_output_text.return_value = full_text
        runtime.get_process_output.side_effect = lambda process_id, offset=0, max_chars=12000: {
            "output_chunk": full_text[offset:offset + max_chars], "output_length": len(full_text),
        }
        return runtime

    def _node(self):
        return {"node_id": "n1", "type": "evidence_record", "label": "nmap",
                "properties": {"ref": "process_output:7"}}

    def test_preview_is_capped_and_download_is_complete(self):
        from app.web.runtime_graph import _resolve_graph_content_entry_locked

        full_text = "x" * 50000
        runtime = self._runtime(full_text)
        project = SimpleNamespace()

        preview = _resolve_graph_content_entry_locked(runtime, project, self._node(), max_chars=1000)
        download = _resolve_graph_content_entry_locked(
            runtime, project, self._node(), max_chars=1000, full_process_output=True,
        )

        self.assertEqual(1000, len(preview["preview_text"]))
        self.assertEqual(full_text, download["preview_text"])
        runtime.get_process_output_text.assert_called_once_with(7)

    def test_preview_of_a_deleted_process_is_empty_not_an_error(self):
        from app.web.runtime_graph import _resolve_graph_content_entry_locked

        runtime = MagicMock()
        runtime.get_process_output.side_effect = KeyError("Unknown process id: 7")
        entry = _resolve_graph_content_entry_locked(runtime, SimpleNamespace(), self._node(), max_chars=1000)
        self.assertFalse(entry["available"])


if __name__ == "__main__":
    unittest.main()
