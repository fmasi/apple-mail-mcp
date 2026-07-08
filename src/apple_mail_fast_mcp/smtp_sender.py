"""SMTP submission for wrapper-free immediate send (issue #322).

``create_draft(send_now=True)`` historically routed through Mail.app's
AppleScript ``tell theMessage to send``, whose ``content`` setter wraps the
body in an ``Apple-Mail-URLShareWrapper`` cite-blockquote that renders as a
quote on iOS (Mail.app bug FB11734014, #245). IMAP ``APPEND`` fixed the
draft case (#246/#292) but can only create drafts, never send. This module
submits a clean RFC 822 message (built by
:func:`apple_mail_fast_mcp.draft_builder.build_draft_mime`) over SMTP, so a
direct send never touches the AppleScript ``content`` setter.

Credential model: the account's IMAP app-password (see :mod:`keychain`) is
reused. For every provider we support (iCloud, Gmail, Yahoo, Outlook) the
same app-specific password authenticates both IMAP and SMTP submission, so
we deliberately reuse the existing Keychain entry rather than building a
parallel SMTP credential store (issue #322 "extend the keychain module").

``smtplib`` is the single point of external I/O for this module and the mock
boundary for unit tests, mirroring ``_run_applescript`` (AppleScript) and
``IMAPClient`` (IMAP).
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from email import message_from_bytes
from email.message import Message
from email.policy import default as _default_policy

logger = logging.getLogger(__name__)

# Implicit-TLS submission port (RFC 8314). Anything else (587 submission,
# 25) is treated as explicit-TLS: connect cleartext, then STARTTLS.
_SMTP_SSL_PORT = 465

_DEFAULT_TIMEOUT_S = 30.0


class SmtpSender:
    """Submit a pre-built RFC 822 message over authenticated SMTP.

    One instance targets one account's outgoing server. The message bytes
    come from ``build_draft_mime`` (the same builder the clean IMAP draft
    path uses), so message construction is already correct and tested — this
    class only adds the send transport.
    """

    def __init__(
        self,
        host: str,
        port: int,
        email: str,
        password: str,
        *,
        timeout: float = _DEFAULT_TIMEOUT_S,
    ) -> None:
        """Store connection parameters.

        Args:
            host: SMTP server hostname (e.g. ``smtp.mail.me.com``).
            port: SMTP submission port. ``465`` uses implicit TLS
                (``SMTP_SSL``); any other value connects cleartext then
                issues ``STARTTLS``.
            email: SMTP AUTH username / envelope ``MAIL FROM`` address.
            password: App-specific password (shared with IMAP; see module
                docstring).
            timeout: Socket timeout in seconds.
        """
        self._host = host
        self._port = port
        self._email = email
        self._password = password
        self._timeout = timeout

    def send(self, raw_message: bytes, recipients: list[str]) -> None:
        """Authenticate and submit ``raw_message`` to ``recipients``.

        The ``Bcc`` header is stripped from the transmitted message — blind
        recipients are carried only in the envelope ``RCPT TO`` list, never
        on the wire — while the caller-supplied ``recipients`` list is used
        verbatim as the envelope recipients (it already includes any Bcc).

        Args:
            raw_message: A serialized RFC 822 message from
                ``build_draft_mime``.
            recipients: The full envelope recipient list (to + cc + bcc).
                Must be non-empty.

        Raises:
            ValueError: ``recipients`` is empty.
            smtplib.SMTPException: Any SMTP-level failure (auth, refused
                recipient, protocol error). Callers that want graceful
                AppleScript fallback catch this plus ``OSError``.
            OSError: Connection failure (host unreachable, TLS error,
                timeout).
        """
        if not recipients:
            raise ValueError("SMTP send requires at least one recipient")

        msg = message_from_bytes(raw_message, policy=_default_policy)
        # A Bcc header must never travel on the wire; the envelope RCPT list
        # (passed explicitly below) is what actually delivers to blind
        # recipients. ``del`` is a no-op when no Bcc header is present.
        del msg["Bcc"]

        context = ssl.create_default_context()
        if self._port == _SMTP_SSL_PORT:
            with smtplib.SMTP_SSL(
                self._host, self._port, timeout=self._timeout, context=context
            ) as client:
                self._authenticate_and_send(client, msg, recipients)
        else:
            with smtplib.SMTP(
                self._host, self._port, timeout=self._timeout
            ) as client:
                client.ehlo()
                client.starttls(context=context)
                client.ehlo()
                self._authenticate_and_send(client, msg, recipients)

    def _authenticate_and_send(
        self,
        client: smtplib.SMTP,
        msg: Message,
        recipients: list[str],
    ) -> None:
        """Log in and hand the message to ``send_message`` with an explicit
        envelope (``MAIL FROM`` = the login address, ``RCPT TO`` = the
        caller-supplied recipient list)."""
        client.login(self._email, self._password)
        client.send_message(msg, from_addr=self._email, to_addrs=recipients)
        logger.debug(
            "SMTP send via %s:%d to %d recipient(s)",
            self._host,
            self._port,
            len(recipients),
        )
