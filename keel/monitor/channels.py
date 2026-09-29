# Copyright (c) 2026 KeelLinux maintainers
"""Send one message to one channel: mail, Telegram, ntfy, a webhook

Standard library only, HTTPS with the system's certificate verification,
a timeout on every call, and nothing written to disk on the way.

A token is a secret, and the Telegram token is part of the request path
(`/bot<token>/sendMessage`), so no URL is ever put in a message this
module raises: an HTTP error says its status, a connection error says
its reason, and the exception is raised `from None`, so a traceback does
not carry urllib's own exception, which holds the request.
"""

import http.client
import json
import ssl
import subprocess
import urllib.error
import urllib.request
from email.message import EmailMessage

TELEGRAM_API = "https://api.telegram.org"
SENDMAIL = "/usr/sbin/sendmail"
TIMEOUT = 10
MAIL_TIMEOUT = 30
# Telegram refuses a text longer than 4096 characters
TELEGRAM_LIMIT = 4096
# what is read of an answer, which nothing uses beyond its status
ANSWER_BYTES = 65536
NTFY_PRIORITY = {"critical": "high", "warn": "default",
                 "recovery": "default"}


class ChannelError(Exception):
    """A channel did not take the message; the text never holds a URL"""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is an answer, never followed

    urllib would carry the Authorization header to whatever host the
    Location names, over plain http if it says so, so a moved topic
    would hand its token to somebody else. The 3xx is reported instead.
    """

    def redirect_request(self, *args, **kwargs):
        return None


def post(url: str, body: bytes, headers: dict[str, str],
         context: ssl.SSLContext | None) -> None:
    """POST, verifying the server with `context` or the system's CAs

    The default context is made here for each call rather than left to
    urlopen, whose shared opener keeps the first one it made for the
    life of the process.
    """
    request = urllib.request.Request(url, data=body, headers=headers,
                                     method="POST")
    opener = urllib.request.build_opener(
        NoRedirect(),
        urllib.request.HTTPSHandler(
            context=context or ssl.create_default_context()),
    )
    try:
        with opener.open(request, timeout=TIMEOUT) as answer:
            answer.read(ANSWER_BYTES)
    except urllib.error.HTTPError as e:
        raise ChannelError(f"answered HTTP {e.code}") from None
    except urllib.error.URLError as e:
        raise ChannelError(f"not reached: {reason(e.reason)}") from None
    except (OSError, http.client.HTTPException, ValueError) as e:
        raise ChannelError(f"not reached: {reason(e)}") from None


def reason(error: object) -> str:
    """Why a connection failed, from the error's own words or its kind

    An OSError's strerror and an SSL error's reason name no URL; any
    other exception is named by its class, since its text might.
    """
    if isinstance(error, ssl.SSLError):
        return f"TLS: {error.reason or error.__class__.__name__}"
    if isinstance(error, OSError) and error.strerror:
        return error.strerror
    if isinstance(error, str):
        return error
    return error.__class__.__name__


def telegram(chat_id: str, token: str, text: str,
             context: ssl.SSLContext | None = None,
             api: str = TELEGRAM_API) -> None:
    body = json.dumps({"chat_id": chat_id,
                       "text": text[:TELEGRAM_LIMIT]}).encode()
    post(f"{api}/bot{token}/sendMessage", body,
         {"Content-Type": "application/json"}, context)


def ntfy(url: str, token: str | None, title: str, level: str, text: str,
         context: ssl.SSLContext | None = None) -> None:
    headers = {
        "Title": ascii_header(title),
        "Priority": NTFY_PRIORITY.get(level, "default"),
        "Tags": level,
        "Content-Type": "text/plain; charset=utf-8",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    post(url, text.encode(), headers, context)


def webhook(url: str, payload: dict,
            context: ssl.SSLContext | None = None) -> None:
    """Slack compatible: `text`, which Slack and Mattermost show, plus the
    structured fields for a program that reads them"""
    post(url, json.dumps(payload).encode(),
         {"Content-Type": "application/json"}, context)


def email(address: str, subject: str, text: str,
          sendmail: str = SENDMAIL) -> None:
    """Hand the message to the local MTA, best effort

    postfix needs disk to queue, so on a full disk this is the channel
    that fails; the HTTPS ones are why the others exist.
    """
    message = EmailMessage()
    message["To"] = address
    message["Subject"] = subject
    message.set_content(text)
    try:
        out = subprocess.run(
            [sendmail, "-t", "-oi"], input=message.as_string(),
            capture_output=True, text=True, timeout=MAIL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise ChannelError(f"{sendmail} took longer than {MAIL_TIMEOUT} s")
    except OSError as e:
        raise ChannelError(f"cannot run {sendmail}: {e.strerror}")
    if out.returncode != 0:
        detail = out.stderr.strip() or out.stdout.strip()
        raise ChannelError(f"{sendmail} exited {out.returncode}: {detail}")


def ascii_header(text: str) -> str:
    """An HTTP header value, which http.client sends as latin-1"""
    return text.encode("ascii", "replace").decode()
