"""Unit tests for the SMTP submission transport (issue #322).

The mock boundary is ``smtplib`` — the SMTP equivalent of the connector's
``_run_applescript`` / ``IMAPClient`` boundaries. No test opens a real
socket or touches real credentials.
"""

from email import message_from_bytes
from email.policy import default as _default_policy
from unittest.mock import MagicMock, patch

import pytest

from apple_mail_fast_mcp.smtp_sender import SmtpSender


def _raw_with_bcc() -> bytes:
    return (
        b"From: Fred <fred@example.com>\r\n"
        b"To: alice@example.net\r\n"
        b"Cc: carol@example.org\r\n"
        b"Bcc: secret@example.com\r\n"
        b"Subject: Hi\r\n"
        b"\r\n"
        b"Body text.\r\n"
    )


class TestConstructor:
    def test_stores_credentials(self) -> None:
        sender = SmtpSender("smtp.example.com", 587, "u@example.com", "pw")
        assert sender._host == "smtp.example.com"
        assert sender._port == 587
        assert sender._email == "u@example.com"
        assert sender._password == "pw"

    def test_default_timeout(self) -> None:
        sender = SmtpSender("h", 587, "u", "p")
        assert sender._timeout == 30.0

    def test_custom_timeout(self) -> None:
        sender = SmtpSender("h", 587, "u", "p", timeout=5.0)
        assert sender._timeout == 5.0


class TestStartTls:
    @patch("apple_mail_fast_mcp.smtp_sender.smtplib.SMTP")
    def test_port_587_uses_starttls_then_login_and_send(
        self, mock_smtp: MagicMock
    ) -> None:
        client = mock_smtp.return_value.__enter__.return_value
        sender = SmtpSender("smtp.example.com", 587, "u@example.com", "pw")

        sender.send(_raw_with_bcc(), ["alice@example.net", "secret@example.com"])

        mock_smtp.assert_called_once()
        assert mock_smtp.call_args.args[0] == "smtp.example.com"
        client.starttls.assert_called_once()
        client.login.assert_called_once_with("u@example.com", "pw")
        client.send_message.assert_called_once()

    @patch("apple_mail_fast_mcp.smtp_sender.smtplib.SMTP")
    def test_envelope_uses_login_from_and_explicit_recipients(
        self, mock_smtp: MagicMock
    ) -> None:
        client = mock_smtp.return_value.__enter__.return_value
        sender = SmtpSender("smtp.example.com", 587, "u@example.com", "pw")
        recipients = ["alice@example.net", "carol@example.org", "secret@example.com"]

        sender.send(_raw_with_bcc(), recipients)

        _msg, kwargs = (
            client.send_message.call_args.args,
            client.send_message.call_args.kwargs,
        )
        assert kwargs["from_addr"] == "u@example.com"
        assert kwargs["to_addrs"] == recipients

    @patch("apple_mail_fast_mcp.smtp_sender.smtplib.SMTP")
    def test_bcc_header_stripped_from_wire_message(
        self, mock_smtp: MagicMock
    ) -> None:
        client = mock_smtp.return_value.__enter__.return_value
        sender = SmtpSender("smtp.example.com", 587, "u@example.com", "pw")

        sender.send(_raw_with_bcc(), ["alice@example.net", "secret@example.com"])

        sent_msg = client.send_message.call_args.args[0]
        assert sent_msg["Bcc"] is None
        # To/Cc must still be present on the wire message.
        assert sent_msg["To"] is not None


class TestSsl:
    @patch("apple_mail_fast_mcp.smtp_sender.smtplib.SMTP_SSL")
    @patch("apple_mail_fast_mcp.smtp_sender.smtplib.SMTP")
    def test_port_465_uses_ssl_no_starttls(
        self, mock_smtp: MagicMock, mock_ssl: MagicMock
    ) -> None:
        client = mock_ssl.return_value.__enter__.return_value
        sender = SmtpSender("smtp.example.com", 465, "u@example.com", "pw")

        sender.send(_raw_with_bcc(), ["alice@example.net"])

        mock_ssl.assert_called_once()
        mock_smtp.assert_not_called()
        client.starttls.assert_not_called()
        client.login.assert_called_once_with("u@example.com", "pw")
        client.send_message.assert_called_once()


class TestValidation:
    def test_empty_recipients_raises(self) -> None:
        sender = SmtpSender("h", 587, "u", "p")
        with pytest.raises(ValueError, match="recipient"):
            sender.send(b"From: a@example.com\r\n\r\nx", [])

    @patch("apple_mail_fast_mcp.smtp_sender.smtplib.SMTP")
    def test_wire_message_is_parseable(self, mock_smtp: MagicMock) -> None:
        """Regression guard: the object handed to send_message is a real
        parsed EmailMessage, not the raw bytes."""
        client = mock_smtp.return_value.__enter__.return_value
        sender = SmtpSender("h", 587, "u@example.com", "p")

        sender.send(_raw_with_bcc(), ["alice@example.net"])

        sent = client.send_message.call_args.args[0]
        # Re-serialize round-trips cleanly.
        reparsed = message_from_bytes(sent.as_bytes(), policy=_default_policy)
        assert reparsed["Subject"] == "Hi"
