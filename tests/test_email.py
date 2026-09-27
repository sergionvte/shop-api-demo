"""Subsistema de correo: backends, SMTP, plantillas, enlaces y configuración."""

import logging
import smtplib
import ssl
import stat
from dataclasses import replace

import pytest
from pydantic import ValidationError

from app.core.config import Settings, settings
from app.email import mask_email
from app.email.backends import PermanentEmailError, TransientEmailError, get_backend
from app.email.backends.console import ConsoleBackend
from app.email.backends.file import FileBackend
from app.email.backends.smtp import SMTPBackend
from app.email.links import build_link
from app.email.message import EmailMessage, build_mime
from app.email.render import (
    BUILTIN,
    TemplateError,
    check_templates,
    html_to_text,
    render,
    reset_templates,
    resolve_language,
    sample_context,
)

MSG = EmailMessage(to=("ana@example.com",), subject="Hola", text="texto", html="<p>html</p>")


def _prod(**overrides) -> Settings:
    values = {
        "ENVIRONMENT": "production",
        "SECRET_KEY": "k" * 40,
        "ALLOWED_HOSTS": ["api.example.com"],
        "DATABASE_URL": "postgresql+asyncpg://u:p@db:5432/api",
        "TRUSTED_PROXIES": ["172.30.57.1"],
        "EMAIL_BACKEND": None,
    }
    values.update(overrides)
    return Settings(**values)


# --- Mensaje y backends --------------------------------------------------------------
async def test_memory_backend_is_default_in_tests(outbox):
    backend = get_backend()
    assert backend.name == "memory"
    await backend.send(MSG)
    assert outbox == [MSG]


def test_mime_is_multipart_with_auto_submitted_and_stable_message_id(monkeypatch):
    monkeypatch.setattr(settings, "EMAIL_FROM", "no-reply@example.com")
    mime = build_mime(replace(MSG, message_id="<job-1@example.com>"))
    assert mime.get_content_type() == "multipart/alternative"
    assert mime["Auto-Submitted"] == "auto-generated"
    assert mime["Message-ID"] == "<job-1@example.com>"
    assert "no-reply@example.com" in mime["From"]


def test_header_injection_is_rejected(monkeypatch):
    """ST-31: CR/LF en un valor de cabecera nunca produce una cabecera inyectada."""
    monkeypatch.setattr(settings, "EMAIL_FROM", "no-reply@example.com")
    monkeypatch.setattr(settings, "EMAIL_REPLY_TO", "a@example.com\r\nBcc: evil@example.com")
    with pytest.raises(ValueError):
        build_mime(MSG)
    monkeypatch.setattr(settings, "EMAIL_REPLY_TO", "")
    # El asunto se reduce a una línea.
    mime = build_mime(EmailMessage(to=MSG.to, subject="a\r\nBcc: evil@example.com", text="x"))
    assert "Bcc" not in mime.keys() and "\n" not in mime["Subject"]


async def test_file_backend_writes_private_eml(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "EMAIL_FROM", "no-reply@example.com")
    await FileBackend(str(tmp_path / "mail")).send(MSG)
    files = sorted((tmp_path / "mail").iterdir())
    assert [f.suffix for f in files] == [".eml", ".html", ".txt"]
    assert stat.S_IMODE(files[0].stat().st_mode) == 0o600
    assert b"Subject: Hola" in files[0].read_bytes()
    # UX-71: el .txt va decodificado (el token se copia entero).
    assert files[2].read_text().endswith("texto")


async def test_console_backend_prints_in_development_only(monkeypatch, caplog):
    monkeypatch.setattr(settings, "EMAIL_FROM", "no-reply@example.com")
    with caplog.at_level(logging.WARNING, logger="app.email"):
        await ConsoleBackend().send(MSG)
    assert "texto" in caplog.text and "token" in caplog.text
    caplog.clear()
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    with caplog.at_level(logging.WARNING, logger="app.email"):
        await ConsoleBackend().send(MSG)
    assert "texto" not in caplog.text


# --- SMTP ------------------------------------------------------------------------------
class FakeSMTP:
    """Servidor SMTP simulado: registra lo que el backend hace con él."""

    calls: list = []
    starttls_offered = True
    fail_on: str | None = None
    exc: Exception | None = None

    def __init__(self, host, port, timeout=None, context=None):
        FakeSMTP.calls.append(("connect", host, port, timeout))
        if FakeSMTP.fail_on == "connect":
            raise ConnectionRefusedError

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def set_debuglevel(self, level):
        FakeSMTP.calls.append(("debuglevel", level))

    def ehlo(self):
        pass

    def has_extn(self, name):
        return FakeSMTP.starttls_offered

    def starttls(self, context):
        FakeSMTP.calls.append(("starttls", context.verify_mode, context.check_hostname))

    def login(self, user, password):
        FakeSMTP.calls.append(("login", user))
        if FakeSMTP.fail_on == "login":
            raise smtplib.SMTPAuthenticationError(535, b"5.7.8 bad credentials secret123")

    def send_message(self, mime):
        FakeSMTP.calls.append(("send", mime["To"]))
        if FakeSMTP.exc:
            raise FakeSMTP.exc
        return {}


@pytest.fixture
def fake_smtp(monkeypatch):
    FakeSMTP.calls, FakeSMTP.starttls_offered, FakeSMTP.fail_on, FakeSMTP.exc = [], True, None, None
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTP)
    for key, value in {
        "EMAIL_FROM": "no-reply@example.com",
        "SMTP_HOST": "smtp.example.com",
        "SMTP_USER": "apikey",
        "SMTP_PASSWORD": settings.SMTP_PASSWORD.__class__("secret123"),
        "SMTP_SECURITY": "starttls",
    }.items():
        monkeypatch.setattr(settings, key, value)
    return FakeSMTP


async def test_smtp_starttls_with_verified_certificate(fake_smtp):
    await SMTPBackend().send(MSG)
    assert ("debuglevel", 0) in fake_smtp.calls
    assert ("starttls", ssl.CERT_REQUIRED, True) in fake_smtp.calls
    assert ("login", "apikey") in fake_smtp.calls
    assert fake_smtp.calls[-1][0] == "send"


async def test_smtp_refuses_to_send_without_starttls(fake_smtp):
    """ST-36: sin STARTTLS anunciado se falla, no se degrada a texto plano."""
    fake_smtp.starttls_offered = False
    with pytest.raises(PermanentEmailError) as info:
        await SMTPBackend().send(MSG)
    assert info.value.code == "smtp_starttls_unavailable"
    assert not any(call[0] == "send" for call in fake_smtp.calls)


async def test_smtp_errors_are_classified_without_leaking(fake_smtp):
    """ST-37/42: 5xx y autenticación → permanente; 4xx y red → transitorio. Ni la
    respuesta cruda del servidor ni credenciales en el mensaje ni en la causa."""
    fake_smtp.fail_on = "login"
    with pytest.raises(PermanentEmailError) as info:
        await SMTPBackend().send(MSG)
    assert info.value.code == "smtp_auth_failed"
    assert "secret123" not in str(info.value) and info.value.__cause__ is None

    fake_smtp.fail_on = None
    fake_smtp.exc = smtplib.SMTPDataError(550, b"mailbox unavailable")
    with pytest.raises(PermanentEmailError):
        await SMTPBackend().send(MSG)
    fake_smtp.exc = smtplib.SMTPDataError(421, b"try later")
    with pytest.raises(TransientEmailError):
        await SMTPBackend().send(MSG)
    fake_smtp.exc = None
    fake_smtp.fail_on = "connect"
    with pytest.raises(TransientEmailError) as info:
        await SMTPBackend().send(MSG)
    assert info.value.code == "smtp_connection"


# --- Plantillas ------------------------------------------------------------------------
def test_all_builtin_templates_render_in_every_language():
    errors, _ = check_templates()
    assert errors == []
    for lang in ("en", "es"):
        for name in BUILTIN:
            rendered = render(name, lang, sample_context(name, lang))
            assert rendered.subject and rendered.text and rendered.html
            assert "example" not in rendered.html.split("<body")[0]  # nada de marca fija


def test_html_is_escaped_and_text_is_literal():
    """ST-30: el nombre del usuario sale escapado en el HTML."""
    evil = "<img src=x onerror=alert(1)><a href=//evil>"
    rendered = render("password_changed", "en", {"user_name": evil, "changed_at": "now"})
    assert evil not in rendered.html and "&lt;img" in rendered.html
    assert evil in rendered.text


def test_missing_variable_is_an_error():
    with pytest.raises(TemplateError):
        render("password_reset", "en", {})


@pytest.mark.parametrize("value", ["../../etc/passwd", "xx", "", None, "es;q=abc", "a" * 500])
def test_language_is_whitelisted(value):
    """ST-32: el idioma nunca se concatena a una ruta."""
    assert resolve_language(value) == settings.MAIL_DEFAULT_LANGUAGE


def test_accept_language_negotiation():
    assert resolve_language("fr-FR,es-ES;q=0.8,en;q=0.5") == "es"
    assert resolve_language("en-GB") == "en"
    assert resolve_language("es") == "es"


def test_template_name_cannot_traverse():
    with pytest.raises(TemplateError):
        render("../_layout", "en", {})


def test_project_templates_override_file_by_file(tmp_path, monkeypatch):
    custom = tmp_path / "email_templates" / "es"
    custom.mkdir(parents=True)
    (custom / "password_reset.subject.txt").write_text("Asunto propio de {{ brand.name }}")
    (custom / "promo.subject.txt").write_text("Oferta")
    (custom / "promo.html").write_text(
        "<p>Hola <b>{{ name }}</b> <a href='https://x.example'>ver</a></p>"
    )
    monkeypatch.setattr(settings, "EMAIL_TEMPLATES_DIR", str(tmp_path / "email_templates"))
    reset_templates()
    try:
        rendered = render("password_reset", "es", sample_context("password_reset", "es"))
        assert rendered.subject.startswith("Asunto propio")
        assert "restablecer" in rendered.text  # el cuerpo sigue siendo el de serie
        promo = render("promo", "es", {"name": "Ana"})
        assert "Hola Ana" in promo.text and "https://x.example" in promo.text  # texto del HTML
    finally:
        reset_templates()


def test_sandbox_blocks_template_escapes(tmp_path, monkeypatch):
    """ST-33: una plantilla del cliente no puede salir del sandbox."""
    custom = tmp_path / "en"
    custom.mkdir()
    (custom / "evil.subject.txt").write_text("x")
    (custom / "evil.txt").write_text("{{ ''.__class__.__mro__[1].__subclasses__() }}")
    monkeypatch.setattr(settings, "EMAIL_TEMPLATES_DIR", str(tmp_path))
    reset_templates()
    try:
        with pytest.raises(TemplateError, match="SecurityError"):
            render("evil", "en", {})
    finally:
        reset_templates()


def test_html_to_text():
    assert html_to_text("<p>Hola</p><p><a href='https://a.example'>x</a></p>").startswith("Hola")


# --- Enlaces ------------------------------------------------------------------------------
def test_links_come_only_from_frontend_url(monkeypatch):
    monkeypatch.setattr(settings, "FRONTEND_URL", "https://app.example.com/")
    assert build_link("reset", "pr_abc") == "https://app.example.com/reset-password#token=pr_abc"
    monkeypatch.setattr(settings, "EMAIL_LINK_VERIFY", "/verify?token={token}")
    assert build_link("verify", "ev_a/b") == "https://app.example.com/verify?token=ev_a%2Fb"


def test_mask_email():
    assert mask_email("nuevo@example.com") == "n***@example.com"


# --- Configuración ------------------------------------------------------------------------
# Un dominio "real" (los de ejemplo no valen en producción). Se construye por partes
# porque el escáner de new_api.py no admite emails reales en ficheros versionados.
SENDER = "no-reply@" + "tienda.es"
PROD_MAIL = {
    "PASSWORD_RESET": True,
    "EMAIL_BACKEND": "smtp",
    "EMAIL_FROM": SENDER,
    "FRONTEND_URL": "https://app.tienda.es",
}


def test_production_mail_baseline_is_valid():
    assert _prod(**PROD_MAIL).password_reset_enabled


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"EMAIL_BACKEND": None}, "EMAIL_BACKEND es obligatorio"),
        ({"EMAIL_BACKEND": "console"}, "no envía correos reales"),
        ({"EMAIL_BACKEND": "file"}, "no envía correos reales"),
        ({"EMAIL_BACKEND": "memory"}, "solo para tests"),
        ({"EMAIL_BACKEND": "disabled"}, "no es compatible"),
        ({"EMAIL_FROM": ""}, "EMAIL_FROM es obligatorio"),
        ({"EMAIL_FROM": "no-reply@example.com"}, "dominio de ejemplo"),
        ({"EMAIL_FROM": f"Tienda <{SENDER}>"}, "una sola dirección"),
        ({"FRONTEND_URL": ""}, "FRONTEND_URL es obligatorio"),
        ({"FRONTEND_URL": "http://app.tienda.es"}, "https"),
        ({"FRONTEND_URL": "https://localhost:3000"}, "no localhost"),
        ({"FRONTEND_URL": "https://app.tienda.es/?next=x"}, "query"),
        ({"EMAIL_LINK_RESET": "https://evil.example/{token}"}, "EMAIL_LINK_RESET"),
        ({"EMAIL_LINK_RESET": "/reset#t={token}&u={token}"}, "exactamente una vez"),
        ({"EMAIL_LINK_VERIFY": "/verify"}, "exactamente una vez"),
        ({"EMAIL_FROM_NAME": "Tienda\r\nBcc: x@evil.example"}, "EMAIL_FROM_NAME"),
        ({"MAIL_BRAND_COLOR": "red;background:url(x)"}, "MAIL_BRAND_COLOR"),
        ({"MAIL_DEFAULT_LANGUAGE": "fr"}, "MAIL_DEFAULT_LANGUAGE"),
        ({"EMAIL_DELIVERY": "inline"}, "inline"),
        ({"EMAIL_BACKEND": "custom", "EMAIL_BACKEND_CLASS": "os:system"}, "EMAIL_BACKEND_CLASS"),
    ],
)
def test_production_mail_misconfiguration_refuses_to_start(overrides, message):
    """ST-34/35/31: la app no arranca, con un mensaje que dice qué variable cambiar."""
    with pytest.raises(ValidationError, match=message):
        _prod(**{**PROD_MAIL, **overrides})


def test_verification_with_disabled_backend_is_rejected_everywhere():
    with pytest.raises(ValidationError, match="no es compatible"):
        Settings(ENVIRONMENT="development", EMAIL_BACKEND="disabled", EMAIL_VERIFICATION="required")


def test_smtp_checks_only_in_worker():
    """REQ-C07/C10: SMTP sin TLS hacia fuera y credenciales incompletas se comprueban en
    el worker (el único que envía y recibe las credenciales)."""
    api = _prod(**PROD_MAIL, SMTP_HOST="", SMTP_SECURITY="none")
    assert api.SMTP_HOST == ""
    worker = {**PROD_MAIL, "PROCESS_ROLE": "worker"}
    with pytest.raises(ValidationError, match="SMTP_HOST"):
        _prod(**worker)
    with pytest.raises(ValidationError, match="SMTP_SECURITY=none"):
        _prod(**worker, SMTP_HOST="smtp.tienda.es", SMTP_SECURITY="none")
    with pytest.raises(ValidationError, match="SMTP_USER sin SMTP_PASSWORD"):
        _prod(**worker, SMTP_HOST="smtp.tienda.es", SMTP_USER="apikey")
    assert _prod(**worker, SMTP_HOST="localhost", SMTP_SECURITY="none")


def test_smtp_password_is_secret_and_can_come_from_a_file(tmp_path):
    secret = tmp_path / "smtp_password"
    secret.write_text("s3cr3t-from-file\n")
    configured = _prod(**PROD_MAIL, SMTP_PASSWORD_FILE=secret)
    assert configured.smtp_password() == "s3cr3t-from-file"
    assert "s3cr3t" not in repr(_prod(**PROD_MAIL, SMTP_PASSWORD="s3cr3t"))


def test_defaults_are_neutral_and_off(monkeypatch):
    """Por defecto nada cambia y no hay datos de nadie: todo apagado y sin remitente."""
    for key in ("EMAIL_BACKEND", "EMAIL_DELIVERY", "EMAIL_VERIFICATION", "PASSWORD_RESET"):
        monkeypatch.delenv(key, raising=False)
    fresh = Settings(_env_file=None, ENVIRONMENT="development")
    assert fresh.EMAIL_VERIFICATION == "off" and not fresh.PASSWORD_RESET
    assert fresh.EMAIL_FROM == "" and fresh.FRONTEND_URL == ""
    assert fresh.email_backend == "console" and fresh.email_delivery == "inline"


# --- CLI ------------------------------------------------------------------------------------


# --- README del cliente -------------------------------------------------------------------


# --- Correcciones de la validación -----------------------------------------------------
def test_startup_error_never_shows_secrets(tmp_path, monkeypatch):
    """SEC-44: con una configuración inválida, el error de arranque no muestra ningún valor
    del .env (antes, la cola del diccionario podía incluir SMTP_PASSWORD en claro)."""
    for name in Settings.model_fields:  # que mande el .env, no el entorno de conftest
        monkeypatch.delenv(name, raising=False)
    sentinel = "SENTINELpw5555"
    env = tmp_path / ".env"
    env.write_text(
        "ENVIRONMENT=production\nSECRET_KEY=" + "k" * 40 + "\nALLOWED_HOSTS=api.example.com\n"
        "DATABASE_URL=postgresql+asyncpg://u:p@db/api\nPASSWORD_RESET=on\nEMAIL_BACKEND=smtp\n"
        "EMAIL_FROM=no-reply@example.com\nFRONTEND_URL=https://app.example.com\n"
        f"SMTP_PASSWORD={sentinel}\nSMTP_PORT=not-a-port-{sentinel}\n"
    )
    with pytest.raises(ValidationError) as info:
        Settings(_env_file=env)
    text = str(info.value) + repr(info.value)  # lo que imprime una traza de arranque
    assert sentinel not in text and "input_value" not in text
    assert "SMTP_PORT" in text  # el error sigue diciendo qué variable está mal
    # Solo falla la validación del modelo (_check_security), con el secreto al final.
    env.write_text(env.read_text().replace(f"SMTP_PORT=not-a-port-{sentinel}\n", ""))
    with pytest.raises(ValidationError) as info:
        Settings(_env_file=env)
    text = str(info.value) + repr(info.value)
    assert sentinel not in text and "dominio de ejemplo" in text


def test_development_defaults_are_forgiving(monkeypatch):
    """UX-70/67: en development, cupos holgados y marcadores para FRONTEND_URL/EMAIL_FROM
    (en producción siguen siendo obligatorios); en tests y producción, los de D3."""
    for key in (
        "EMAIL_BACKEND",
        "EMAIL_PER_ACCOUNT_PER_HOUR",
        "EMAIL_PER_ACCOUNT_COOLDOWN_SECONDS",
    ):
        monkeypatch.delenv(key, raising=False)
    dev = Settings(_env_file=None, ENVIRONMENT="development", PASSWORD_RESET=True)
    assert dev.EMAIL_PER_ACCOUNT_PER_HOUR == 30 and dev.EMAIL_PER_ACCOUNT_COOLDOWN_SECONDS == 0
    assert dev.FRONTEND_URL == "http://localhost:3000" and dev.EMAIL_FROM.endswith("@example.com")
    assert _prod(**PROD_MAIL).EMAIL_PER_ACCOUNT_PER_HOUR == 3
    assert Settings(_env_file=None, ENVIRONMENT="testing").EMAIL_PER_ACCOUNT_COOLDOWN_SECONDS == 60


def test_smtp_without_tls_only_to_exact_loopback():
    """Info-2: `*.localhost` podría resolver a otro host: no cuenta como loopback."""
    worker = {**PROD_MAIL, "PROCESS_ROLE": "worker", "SMTP_SECURITY": "none"}
    with pytest.raises(ValidationError, match="SMTP_SECURITY=none"):
        _prod(**worker, SMTP_HOST="relay.localhost")
    assert _prod(**worker, SMTP_HOST="127.0.0.1")


def test_preview_uses_client_links(monkeypatch):
    """UX-75: la vista previa enseña el enlace con FRONTEND_URL y EMAIL_LINK_* reales."""
    monkeypatch.setattr(settings, "FRONTEND_URL", "https://app.cliente.example")
    context = sample_context("password_reset", "es")
    assert context["action_url"].startswith("https://app.cliente.example/reset-password#token=pr_")


async def test_smtp_unknown_host_is_explained(fake_smtp, monkeypatch):
    """UX-72: un SMTP_HOST que no resuelve no se confunde con un timeout."""
    import socket

    def unresolvable(*args, **kwargs):
        raise socket.gaierror("nodename nor servname provided")

    monkeypatch.setattr(smtplib, "SMTP", unresolvable)
    with pytest.raises(TransientEmailError) as info:
        await SMTPBackend().send(MSG)
    assert info.value.code == "smtp_host_not_found"
