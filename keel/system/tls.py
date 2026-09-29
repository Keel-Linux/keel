# Copyright (c) 2026 KeelLinux maintainers
"""Plan the tls section: an ACME certificate for the declared domains

Nothing applied tls.acme before this, not even at first boot: apply
warned and pointed at confconsole. The request itself goes through the
client the operator already uses, confconsole's dehydrated-wrapper, which
answers the challenge, installs the certificate where every service reads
it, backs up the previous one and installs the renewal job; this module
decides whether to call it.

It is called only when the machine needs it, decided from the certificate
in use read as inspect reads it (keel.inspect.certificate): not issued
by a CA, not covering every declared domain, or within RENEW_WITHIN of
its end. A second run after a successful request finds the certificate
and asks Let's Encrypt nothing, which its rate limits require.

Three refusals, each with its reason, where a request would be wrong:
- no Let's Encrypt account on the machine and no `agree_tos: true` in
  the spec: registering accepts the terms of service, and confconsole
  asks the operator on screen; a declarative run accepts them only when
  the spec says so;
- dns-01: it needs a DNS provider and its credentials, which the spec has
  no field for yet;
- enabled with no domains.

`enabled: false`, stated, over a certificate that a CA issued goes back
to the self-signed certificate the machine makes for itself, disables the
renewal job and restarts the services that read it. Absent is not false:
a spec that says nothing about tls.acme leaves it as it is.
"""

from datetime import timedelta

from keel.inspect.certificate import Certificate, covers, read_certificate
from keel.system.actions import Action, Note, Refuse, Run, Step, WriteFile
from keel.system.state import SystemState

FIELD = "tls.acme"
DOMAINS = "etc/dehydrated/confconsole.domains.txt"
CRON = "etc/cron.daily/confconsole-dehydrated"
WRAPPER = "/usr/lib/confconsole/plugins.d/Lets_Encrypt/dehydrated-wrapper"
ETC_MODE = 0o644
RENEW_WITHIN = timedelta(days=30)
HEADER = "# written by keel apply --system"
# the services 15regen-sslcert restarts, and webmin, which reads the same pair
SERVICES = ("nginx.service", "apache2.service", "lighttpd.service",
            "tomcat10.service", "tomcat11.service", "webmin.service")


def plan_tls(tls: dict, state: SystemState) -> list[Step]:
    acme = tls.get("acme") or {}
    enabled = acme.get("enabled")
    if enabled is True:
        return [request_step(acme, state)]
    if enabled is False:
        return [off_step(state)]
    return []


def in_use(state: SystemState) -> Certificate | None:
    cert = state.tls_cert
    if cert is None or not cert.readable:
        return None
    found, _ = read_certificate(cert.text or "")
    return found


def request_step(acme: dict, state: SystemState) -> Step:
    domains = [str(d) for d in acme.get("domains") or []]
    if not domains:
        return Step(FIELD, (Refuse(
            "enabled with no domains: there is nothing to request"),))
    challenge = str(acme.get("challenge") or "http-01")
    cert = in_use(state)
    if cert is not None and carries(cert, domains, state):
        return Step(FIELD, (Note(
            f"unchanged ({', '.join(domains)}, valid until"
            f" {cert.not_after.date().isoformat()})"),))

    actions: list[Action] = []
    wanted = f"{HEADER}\n{' '.join(domains)}\n"
    current = state.acme_domains
    if current is None or not current.readable or \
            current.lines() != [" ".join(domains)]:
        actions.append(WriteFile(DOMAINS, wanted, ETC_MODE, None,
                                 f"write /{DOMAINS} with {', '.join(domains)}"))
    # a scratch tree is never asked for a certificate, so how one would be
    # asked for is moot there, and refusing it would fail the run for nothing
    if not state.live:
        return Step(FIELD, (*actions, Note(
            "certificate not requested: not the live system")))
    refusal = why_not(acme, challenge, state)
    if refusal is not None:
        return Step(FIELD, (*actions, Refuse(refusal)))
    argv = ("/bin/bash", WRAPPER, "--log-info", "--challenge", challenge)
    if not state.acme_account:
        argv += ("--register",)
    actions.append(Run(argv, f"request a certificate for {', '.join(domains)}"))
    return Step(FIELD, tuple(actions))


def carries(cert: Certificate, domains: list[str], state: SystemState) -> bool:
    """Issued by a CA, covering every domain, and not due for renewal"""
    if cert.self_signed or state.now is None:
        return False
    if cert.not_after - state.now <= RENEW_WITHIN:
        return False
    return all(covers(cert, domain) for domain in domains)


def why_not(acme: dict, challenge: str, state: SystemState) -> str | None:
    if challenge == "dns-01":
        return ("dns-01 needs a DNS provider and its credentials, which the"
                " spec has no field for yet; request it through confconsole")
    if not state.acme_wrapper:
        return (f"{WRAPPER} is not installed: confconsole's Let's Encrypt"
                " client is what requests the certificate")
    if not state.acme_account and acme.get("agree_tos") is not True:
        return ("no Let's Encrypt account on this machine, and registering"
                " one accepts the terms of service: set tls.acme.agree_tos"
                " to true to accept them, or register through confconsole")
    return None


def off_step(state: SystemState) -> Step:
    cert = in_use(state)
    if cert is None or cert.self_signed:
        return Step(FIELD, (Note("unchanged (off)"),))
    if not state.live:
        return Step(FIELD, (Note(
            "a CA issued certificate is in use; not replaced: not the live"
            " system"),))
    return Step(FIELD, (
        Run(("chmod", "a-x", f"/{CRON}"), "disable the renewal job"),
        Run(("turnkey-make-ssl-cert", "--default", "--force"),
            "make a self-signed certificate for this machine"),
        Run(("systemctl", "try-restart", *SERVICES),
            "restart the services that read it, where they run"),
    ))
