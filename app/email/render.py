"""Plantillas de correo (Jinja2 en sandbox, autoescape en HTML, modo estricto).

Cada plantilla son hasta tres ficheros por idioma: `<lang>/<nombre>.subject.txt`,
`<lang>/<nombre>.txt` y `<lang>/<nombre>.html`. Se buscan primero en la carpeta del
proyecto (EMAIL_TEMPLATES_DIR, que apigen nunca toca) y después en las de serie,
fichero a fichero: se puede cambiar solo el asunto sin copiar el HTML.

- Idioma: validado contra MAIL_LANGUAGES (nunca se concatena lo recibido a una ruta);
  si falta un fichero en ese idioma se usa MAIL_DEFAULT_LANGUAGE y, al final, `en`.
- `SandboxedEnvironment`: una plantilla del cliente no puede salir del sandbox (REQ-M02).
- `StrictUndefined`: una variable que falta es un error en tests/`apigen check`, no un
  hueco en el correo del primer usuario.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from jinja2 import FileSystemLoader, StrictUndefined, TemplateNotFound, select_autoescape
from jinja2.sandbox import SandboxedEnvironment

from app.core.config import settings
from app.db.types import utcnow
from app.email.message import clean_subject

BUILTIN_DIR = Path(__file__).parent / "templates"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
# Plantillas de serie (los flujos de cuenta usan solo estas; REQ-M02).
BUILTIN = (
    "password_reset",
    "verify_email",
    "email_change_confirm",
    "email_change_requested",
    "email_changed",
    "password_changed",
    "account_exists",
    "test",
)
TEMPLATE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,50}$")
_LANG = re.compile(r"^[a-z]{2}(-[A-Z]{2})?$")

# Textos del layout común (el resto está en las plantillas de cada idioma).
_LABELS = {
    "en": {"support": "Need help? Write to", "button_hint": "Or copy this link:"},
    "es": {"support": "¿Necesitas ayuda? Escribe a", "button_hint": "O copia este enlace:"},
}


class TemplateError(Exception):
    """Plantilla inexistente o con errores (sintaxis, variable indefinida, sandbox)."""


@dataclass(frozen=True, slots=True)
class Rendered:
    subject: str
    text: str
    html: str | None
    language: str


def templates_dir() -> Path:
    path = Path(settings.EMAIL_TEMPLATES_DIR)
    return path if path.is_absolute() else PROJECT_ROOT / path


@lru_cache
def _environment(override: str) -> SandboxedEnvironment:
    search = [override] if Path(override).is_dir() else []
    return SandboxedEnvironment(
        loader=FileSystemLoader([*search, str(BUILTIN_DIR)]),
        autoescape=select_autoescape(
            enabled_extensions=("html",), default_for_string=False, default=False
        ),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=False,
    )


def environment() -> SandboxedEnvironment:
    return _environment(str(templates_dir()))


def reset_templates() -> None:
    """Olvida la caché (tests o tras añadir la carpeta de plantillas propias)."""
    _environment.cache_clear()


def resolve_language(value: str | None) -> str:
    """Idioma a usar: un código o una cabecera Accept-Language, SIEMPRE dentro de
    MAIL_LANGUAGES (REQ-M03). Si no hay coincidencia, MAIL_DEFAULT_LANGUAGE."""
    allowed = settings.MAIL_LANGUAGES
    candidates: list[tuple[float, int, str]] = []
    for index, part in enumerate((value or "")[:200].split(",")[:10]):
        code, _, params = part.strip().partition(";")
        quality = 1.0
        if params.strip().startswith("q="):
            try:
                quality = float(params.strip()[2:])
            except ValueError:
                continue
        candidates.append((-quality, index, code.strip()))
    for _, _, code in sorted(candidates):
        if not code or len(code) > 20:
            continue
        # Normaliza es-es -> es-ES; prueba el código completo y después el primario.
        primary, _, region = code.partition("-")
        normalized = primary.lower() + (f"-{region.upper()}" if region else "")
        for option in (normalized, primary.lower()):
            if _LANG.match(option) and option in allowed:
                return option
    return settings.MAIL_DEFAULT_LANGUAGE


def format_duration(minutes: int, language: str) -> str:
    """ "30 minutes" / "30 minutos" / "48 hours" / "48 horas"."""
    spanish = language.split("-")[0] == "es"
    if minutes % 60 == 0 and minutes >= 60:
        value = minutes // 60
        unit = (
            ("hora" if value == 1 else "horas") if spanish else ("hour" if value == 1 else "hours")
        )
    else:
        value = minutes
        unit = (
            ("minuto" if value == 1 else "minutos")
            if spanish
            else ("minute" if value == 1 else "minutes")
        )
    return f"{value} {unit}"


def base_context(language: str) -> dict[str, Any]:
    labels = _LABELS.get(language.split("-")[0], _LABELS["en"])
    return {
        "brand": {
            "name": settings.mail_brand_name,
            "url": settings.MAIL_BRAND_URL or settings.FRONTEND_URL,
            "logo_url": settings.MAIL_BRAND_LOGO_URL,
            "color": settings.MAIL_BRAND_COLOR,
            "support_email": settings.MAIL_SUPPORT_EMAIL,
            "footer": settings.MAIL_FOOTER,
        },
        "labels": labels,
        "language": language,
        "year": utcnow().year,
    }


def _find(name: str, suffix: str, language: str) -> str | None:
    """Primer fichero existente en el orden idioma → por defecto → en."""
    env = environment()
    chain = dict.fromkeys([language, settings.MAIL_DEFAULT_LANGUAGE, "en"])
    for lang in chain:
        candidate = f"{lang}/{name}.{suffix}"
        try:
            env.loader.get_source(env, candidate)  # type: ignore[union-attr]
        except TemplateNotFound:
            continue
        return candidate
    return None


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"style", "script", "head"}:
            self._skip += 1
        elif tag in {"br", "p", "div", "tr", "h1", "h2", "h3", "li"}:
            self.parts.append("\n")
        elif tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.parts.append(f" {href} ")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"style", "script", "head"} and self._skip:
            self._skip -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self.parts.append(data)


def html_to_text(html: str) -> str:
    """Texto plano a partir del HTML (si una plantilla propia no trae el .txt)."""
    parser = _TextExtractor()
    parser.feed(html)
    lines = [" ".join(line.split()) for line in "".join(parser.parts).splitlines()]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def render(name: str, language: str | None, context: dict[str, Any] | None = None) -> Rendered:
    """Renderiza asunto, texto y HTML. Lanza TemplateError si algo falla."""
    if not TEMPLATE_NAME.match(name):
        raise TemplateError(f"invalid template name {name!r}")
    lang = resolve_language(language)
    values = {**base_context(lang), **(context or {})}
    env = environment()
    try:
        subject_file = _find(name, "subject.txt", lang)
        text_file = _find(name, "txt", lang)
        html_file = _find(name, "html", lang)
        if subject_file is None or (text_file is None and html_file is None):
            raise TemplateError(f"template {name!r} not found (subject and txt/html needed)")
        subject = clean_subject(env.get_template(subject_file).render(values))
        html = env.get_template(html_file).render(values) if html_file else None
        text = env.get_template(text_file).render(values) if text_file else html_to_text(html or "")
    except TemplateError:
        raise
    except Exception as exc:  # sintaxis, variable indefinida, SecurityError del sandbox...
        raise TemplateError(f"template {name!r} ({lang}): {type(exc).__name__}: {exc}") from None
    if not subject:
        raise TemplateError(f"template {name!r} ({lang}): empty subject")
    return Rendered(subject=subject, text=text.strip() + "\n", html=html, language=lang)


# Datos de ejemplo para `apigen email preview` y `apigen check`.
SAMPLE_CONTEXT: dict[str, dict[str, Any]] = {
    "password_reset": {"action_url": "https://app.example.com/reset-password#token=pr_example"},
    "verify_email": {"action_url": "https://app.example.com/verify-email#token=ev_example"},
    "email_change_confirm": {"action_url": "https://app.example.com/verify-email#token=ec_example"},
    "email_change_requested": {"new_email": "n***@example.com", "user_name": "Ada"},
    "email_changed": {"new_email": "n***@example.com", "user_name": "Ada"},
    "password_changed": {"changed_at": "2026-01-01 10:00 UTC", "user_name": "Ada"},
    "account_exists": {"password_reset": True, "reset_hint_url": "https://app.example.com"},
    "test": {},
}


def sample_context(name: str, language: str) -> dict[str, Any]:
    context = dict(SAMPLE_CONTEXT.get(name, {}))
    if "action_url" in context and settings.FRONTEND_URL:
        # La vista previa enseña el enlace real del cliente (su dominio y rutas; UX-75).
        from app.email.links import build_link

        kind, prefix = ("reset", "pr_") if name == "password_reset" else ("verify", "ev_")
        context["action_url"] = build_link(kind, prefix + "EXAMPLE_TOKEN_1234567890")  # type: ignore[arg-type]
    if "action_url" in context:
        minutes = {
            "password_reset": settings.TOKEN_TTL_RESET_MINUTES,
            "verify_email": settings.TOKEN_TTL_VERIFY_HOURS * 60,
            "email_change_confirm": settings.TOKEN_TTL_EMAIL_CHANGE_MINUTES,
        }[name]
        context["expires_in"] = format_duration(minutes, language)
    return context


def check_templates() -> tuple[list[str], list[str]]:
    """Renderiza todas las plantillas de serie en todos los idiomas configurados.

    Devuelve (errores, avisos): un error de sintaxis o una variable inexistente en una
    plantilla propia sale aquí (apigen check / tests) y no con el primer usuario."""
    errors: list[str] = []
    warnings: list[str] = []
    override = templates_dir()
    for lang in settings.MAIL_LANGUAGES:
        for name in BUILTIN:
            try:
                render(name, lang, sample_context(name, lang))
            except TemplateError as exc:
                errors.append(str(exc))
            if _find(name, "subject.txt", lang) and not _find_exact(name, lang):
                warnings.append(
                    f"sin plantilla {name!r} en {lang!r}: se usa la de "
                    f"{settings.MAIL_DEFAULT_LANGUAGE!r} o la de serie en inglés"
                )
        if override.is_dir():
            for path in sorted((override / lang).glob("*.subject.txt")):
                custom = path.name.removesuffix(".subject.txt")
                if custom not in BUILTIN and TEMPLATE_NAME.match(custom):
                    try:
                        render(custom, lang, None)
                    except TemplateError as exc:
                        # Las propias pueden necesitar variables: solo avisamos.
                        warnings.append(str(exc))
    return errors, warnings


def _find_exact(name: str, language: str) -> bool:
    env = environment()
    try:
        env.loader.get_source(env, f"{language}/{name}.subject.txt")  # type: ignore[union-attr]
    except TemplateNotFound:
        return False
    return True
