import secure_message_cli as cli


def test_format_message_log_line_truncates_to_seconds():
    line = cli._format_message_log_line(
        "2026-04-15T21:32:00.864189+00:00",
        "ADMIN",
        "Rodrigo",
        "hi",
    )

    assert line == "2026-04-15 21:32:00 (ADMIN -> Rodrigo:) hi"


def test_conversation_rows_use_formatted_timestamp_and_sent_history_display():
    rows = cli._conversation_rows(
        [
            {
                "id": 7,
                "sender": "ADMIN",
                "recipient": "Rodrigo",
                "created_at": "2026-04-15 21:32:02.181834",
            }
        ],
        "ADMIN",
        None,
        {"7": {"display": "hello"}},
    )

    assert rows == [["7", "2026-04-15 21:32:02", "ADMIN", "Rodrigo", "hello"]]
