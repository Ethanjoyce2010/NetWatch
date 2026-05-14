"""Tests for netwatch.scheduler"""

import textwrap

from netwatch.models import Severity
from netwatch.scheduler import TaskSchedulerScanner


class TestTaskSchedulerScanner:
    def test_parse_flags_lolbin_script_from_user_writable_path(self):
        text = textwrap.dedent("""\
            "TaskName","Task To Run","Author","Status"
            "\\Bad","powershell.exe -File C:\\Users\\Public\\bad.ps1","user","Ready"
        """)

        findings = TaskSchedulerScanner.parse_schtasks_csv(text)

        assert len(findings) == 1
        assert findings[0].task_name == "\\Bad"
        assert findings[0].severity == Severity.MEDIUM
        assert "launches a LOLBin or script host" in findings[0].reasons
        assert "runs from a user-writable path" in findings[0].reasons

    def test_parse_escalates_encoded_remote_lolbin_task(self):
        text = textwrap.dedent("""\
            "TaskName","Task To Run","Author","Status"
            "\\Encoded","powershell.exe -EncodedCommand AAAA http://example.invalid/a","user","Ready"
        """)

        findings = TaskSchedulerScanner.parse_schtasks_csv(text)

        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "contains encoded command content" in findings[0].reasons
        assert "references a remote path or URL" in findings[0].reasons

    def test_parse_ignores_plain_legitimate_task(self):
        text = textwrap.dedent("""\
            "TaskName","Task To Run","Author","Status"
            "\\Normal","C:\\Windows\\System32\\clean.exe","Microsoft","Ready"
        """)

        assert TaskSchedulerScanner.parse_schtasks_csv(text) == []
