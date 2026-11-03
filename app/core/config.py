"""Configuración central de la aplicación.

Todo se lee de variables de entorno (o de `.env`). En producción la configuración
se valida de forma estricta y la aplicación se niega a arrancar si detecta
valores inseguros.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import logging
import os
import re
import secrets
from email.utils import parseaddr
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from limits import parse_many
from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

logger = logging.getLogger(__name__)

_INSECURE_SECRETS = {
    "",
    "secret",
    "changeme",
    "change-me",
    "change_me",
    "please-change-me",
    "supersecret",
    "your-secret-key",
}
_SYMMETRIC_ALGORITHMS = {"HS256", "HS384", "HS512"}

CommaList = Annotated[list[str], NoDecode]


class Environment(StrEnum):
    development = "development"
    testing = "testing"
    production = "production"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        # APP_ENV_FILE permite otro fichero (los tests apuntan a uno inexistente para no
        # depender del .env local del proyecto).
        env_file=os.environ.get("APP_ENV_FILE") or ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
        # `DOCS_ENABLED=` (vacío) en .env significa "valor por defecto", no un error
        # de validación: así el .env que genera `apigen init-env` arranca tal cual.
        env_ignore_empty=True,
        # Un error de validación nunca muestra los valores recibidos: podría volcar el
        # final del .env (SMTP_PASSWORD, SECRET_KEY...) en los logs de arranque (SEC-44).
        hide_input_in_errors=True,
    )

    # --- General -----------------------------------------------------------
    PROJECT_NAME: str = "Tienda Demo API"
    PROJECT_VERSION: str = "0.1.0"
    # Texto que aparece en la portada de /docs (OpenAPI `info.description`).
    PROJECT_DESCRIPTION: str = ""
    ENVIRONMENT: Environment = Environment.development
    DEBUG: bool = False
    # None = activado salvo en producción.
    DOCS_ENABLED: bool | None = None
    API_PREFIX: str = "/api"

    # --- JWT -----------------------------------------------------------------
    SECRET_KEY: SecretStr = SecretStr("")
    JWT_ALGORITHM: Literal[
        "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "EdDSA"
    ] = "HS256"
    # Solo para algoritmos asimétricos (RS*/ES*/EdDSA).
    JWT_PRIVATE_KEY_FILE: Path | None = None
    JWT_PUBLIC_KEY_FILE: Path | None = None
    # Claves HS antiguas que se siguen aceptando para verificar durante una rotación.
    JWT_PREVIOUS_SECRET_KEYS: CommaList = []
    JWT_ISSUER: str = "tienda-demo-api"
    JWT_AUDIENCE: str = "tienda-demo-api-clients"
    JWT_LEEWAY_SECONDS: int = Field(default=10, ge=0, le=120)
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=15, ge=1, le=1440)
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7, ge=1, le=90)

    # --- Política de autenticación -----------------------------------------
    ALLOW_REGISTRATION: bool = True
    PASSWORD_MIN_LENGTH: int = Field(default=12, ge=8, le=64)
    PASSWORD_MAX_LENGTH: int = Field(default=128, ge=64, le=1024)
    LOGIN_MAX_ATTEMPTS: int = Field(default=5, ge=1)
    LOGIN_LOCKOUT_MINUTES: int = Field(default=15, ge=1)
    # Cada bloqueo consecutivo dobla la duración hasta este tope.
    LOGIN_LOCKOUT_MAX_MINUTES: int = Field(default=240, ge=1)
    # Durante un bloqueo, un cliente (IP o /64) desde el que el usuario ya inició
    # sesión en estos días puede seguir entrando ("smart lockout"): un tercero no
    # puede dejar fuera al titular solo por conocer su email.
    LOGIN_FAMILIAR_DAYS: int = Field(default=30, ge=0, le=365)
    # Reutilizar un refresh token ya rotado revoca la sesión (robo). Excepción:
    # si ocurre en estos segundos, desde la misma IP y la sesión sigue viva, se
    # trata como una carrera legítima (dos pestañas) y se responde 409 sin revocar.
    # 0 = sin periodo de gracia.
    REFRESH_REUSE_GRACE_SECONDS: int = Field(default=10, ge=0, le=60)
    # Coste de Argon2id (por defecto: RFC 9106, 64 MiB / 3 pasadas). Bajarlo acelera
    # el login pero abarata los ataques offline si se filtra la BD. Mínimo OWASP:
    # 19 MiB (19456 KiB), 2 pasadas, 1 hilo.
    ARGON2_TIME_COST: int = Field(default=3, ge=2, le=20)
    ARGON2_MEMORY_COST_KIB: int = Field(default=65_536, ge=19_456, le=1_048_576)
    ARGON2_PARALLELISM: int = Field(default=4, ge=1, le=16)
    # Hashes Argon2 calculándose a la vez (cada uno usa ARGON2_MEMORY_COST_KIB de RAM).
    PASSWORD_HASH_CONCURRENCY: int = Field(default=8, ge=1, le=256)
    # Sesiones de refresh activas por usuario; las más antiguas se revocan.
    MAX_SESSIONS_PER_USER: int = Field(default=10, ge=1, le=1000)

    # --- Base de datos -------------------------------------------------------
    DATABASE_URL: str = "sqlite+aiosqlite:///./app.db"
    # En producción SQLite es un error salvo que se confirme expresamente (p. ej.
    # laboratorios o demos de un solo proceso).
    ALLOW_SQLITE_IN_PRODUCTION: bool = False
    DB_ECHO: bool = False
    DB_POOL_SIZE: int = Field(default=10, ge=1)
    DB_MAX_OVERFLOW: int = Field(default=20, ge=0)
    DB_POOL_TIMEOUT: int = Field(default=30, ge=1)
    DB_POOL_RECYCLE: int = Field(default=1800, ge=-1)
    # Solo PostgreSQL: corta consultas que tarden demasiado (0 = sin límite).
    DB_STATEMENT_TIMEOUT_MS: int = Field(default=15000, ge=0)

    # --- Rate limiting (SlowAPI) --------------------------------------------
    RATE_LIMIT_ENABLED: bool = True
    # memory:// (una instancia) o redis://host:6379/0 (varias instancias/workers).
    RATE_LIMIT_STORAGE_URI: str = "memory://"
    RATE_LIMIT_STRATEGY: Literal["fixed-window", "moving-window", "sliding-window-counter"] = (
        "sliding-window-counter"
    )
    RATE_LIMIT_DEFAULT: str = "120/minute"
    RATE_LIMIT_GLOBAL: str = "1000/minute"
    RATE_LIMIT_LOGIN: str = "10/minute;50/hour"
    # None = 5/hour en producción y 50/hour fuera de ella (en desarrollo creas
    # muchas cuentas de prueba seguidas).
    RATE_LIMIT_REGISTER: str | None = None
    RATE_LIMIT_REFRESH: str = "30/minute"
    RATE_LIMIT_HEADERS: bool = True

    # --- HTTP -------------------------------------------------------------
    CORS_ORIGINS: CommaList = []
    CORS_ALLOW_CREDENTIALS: bool = False
    ALLOWED_HOSTS: CommaList = ["*"]
    # IPs/CIDR de proxies de confianza cuyos X-Forwarded-For se aceptan.
    TRUSTED_PROXIES: CommaList = []
    MAX_BODY_SIZE: int = Field(default=1_048_576, ge=1024)
    GZIP_MIN_SIZE: int = Field(default=1024, ge=0)  # 0 = desactivado
    HSTS_SECONDS: int = Field(default=63_072_000, ge=0)

    # --- Tareas en segundo plano (apigen worker) -----------------------------
    JOBS_CONCURRENCY: int = Field(default=4, ge=1, le=256)  # trabajos a la vez por worker
    JOBS_POLL_INTERVAL: float = Field(default=1.0, ge=0.05, le=60)  # s entre consultas
    JOBS_PROCESS_WORKERS: int = Field(default=2, ge=1, le=64)  # procesos para executor=process
    JOBS_DEFAULT_TIMEOUT: int = Field(default=300, ge=1, le=86_400)
    JOBS_LEASE_GRACE: int = Field(default=60, ge=5, le=3600)  # margen sobre el timeout
    JOBS_RECLAIM_INTERVAL: int = Field(default=30, ge=5, le=3600)
    JOBS_SHUTDOWN_GRACE: int = Field(default=30, ge=0, le=3600)
    JOBS_MAX_PENDING_PER_USER: int = Field(default=20, ge=0)  # 0 = sin límite
    JOBS_MAX_PAYLOAD_BYTES: int = Field(default=65_536, ge=256)
    JOBS_MAX_RESULT_BYTES: int = Field(default=262_144, ge=256)
    JOBS_RETENTION_DAYS: int = Field(default=7, ge=0, le=3650)
    # Latido del worker para el healthcheck. Vacío = <tmp>/apigen-worker.heartbeat. Fuera
    # de Docker, con /tmp compartido, mejor un directorio propio (SEC-36).
    JOBS_HEARTBEAT_FILE: str = ""
    # Qué proceso carga la configuración. El worker no firma ni valida tokens: no
    # necesita SECRET_KEY (docker compose no se la pasa; SEC-38).
    PROCESS_ROLE: Literal["api", "worker"] = "api"

    # --- Flujos de cuenta (verificación de email y recuperación) --------------
    # off = sin verificación (como hasta ahora) | optional = se envía el correo y
    # `email_verified` informa | required = sin verificar no se puede iniciar sesión.
    EMAIL_VERIFICATION: Literal["off", "optional", "required"] = "off"
    # Recuperación de contraseña por correo (on/off).
    PASSWORD_RESET: bool = False
    # URL del frontend del cliente: los enlaces de los correos salen SOLO de aquí
    # (nunca de la cabecera Host). Las rutas llevan `{token}` exactamente una vez;
    # por defecto en el fragmento (#), que el navegador no envía a ningún servidor.
    FRONTEND_URL: str = ""
    EMAIL_LINK_RESET: str = "/reset-password#token={token}"
    EMAIL_LINK_VERIFY: str = "/verify-email#token={token}"
    # Vida de los tokens de un solo uso.
    TOKEN_TTL_RESET_MINUTES: int = Field(default=30, ge=10, le=60)
    TOKEN_TTL_VERIFY_HOURS: int = Field(default=48, ge=1, le=168)
    TOKEN_TTL_EMAIL_CHANGE_MINUTES: int = Field(default=60, ge=10, le=1440)
    # Cupo por cuenta (lo aplica el worker con datos de la BD, sea cual sea la IP).
    # Vacío = 60 s / 3 por hora / 10 al día (producción y tests) y más holgado en
    # development (0 s / 30 / 200), para no quedarse sin correos probando (UX-70).
    EMAIL_PER_ACCOUNT_COOLDOWN_SECONDS: int | None = Field(default=None, ge=0, le=3600)
    EMAIL_PER_ACCOUNT_PER_HOUR: int | None = Field(default=None, ge=1, le=1000)
    EMAIL_PER_ACCOUNT_PER_DAY: int | None = Field(default=None, ge=1, le=10000)
    # Avisos de seguridad (contraseña o email cambiados) por cuenta y hora (SEC-40).
    EMAIL_NOTICES_PER_ACCOUNT_PER_HOUR: int = Field(default=5, ge=1, le=100)
    # Enlaces de cambio de email a una misma dirección de destino por hora (SEC-40).
    EMAIL_PER_ADDRESS_PER_HOUR: int = Field(default=3, ge=1, le=100)
    # Cortacircuitos global (0 = sin límite), en dos presupuestos separados para que
    # quien provoca correos masivos (altas, "ya tienes cuenta", cambios de email,
    # correos propios) no agote el de los de seguridad (reset y avisos) (SEC-40).
    EMAIL_MAX_PER_HOUR: int = Field(default=200, ge=0)
    EMAIL_MAX_PER_DAY: int = Field(default=1000, ge=0)
    EMAIL_MAX_SECURITY_PER_HOUR: int = Field(default=300, ge=0)
    EMAIL_MAX_SECURITY_PER_DAY: int = Field(default=2000, ge=0)
    # Por IP. None = 5/minute;20/hour en producción y 30/minute;300/hour fuera.
    RATE_LIMIT_EMAIL_REQUEST: str | None = None
    RATE_LIMIT_TOKEN_CONFIRM: str = "10/minute;50/hour"  # noqa: S105

    # --- Correo -------------------------------------------------------------
    # console (log) | file (.eml en EMAIL_FILE_DIR) | memory (tests) | smtp |
    # disabled | custom (EMAIL_BACKEND_CLASS). Vacío = console en development,
    # memory en testing y OBLIGATORIO en producción.
    EMAIL_BACKEND: Literal["console", "file", "memory", "smtp", "disabled", "custom"] | None = None
    EMAIL_BACKEND_CLASS: str = ""  # p. ej. app.mail_backends.acme:AcmeBackend
    # queue = lo envía `apigen worker` | inline = la propia API tras responder (solo
    # fuera de producción). Vacío = inline en development y queue en el resto.
    EMAIL_DELIVERY: Literal["queue", "inline"] | None = None
    EMAIL_FROM: str = ""  # dirección del dominio del CLIENTE (con SPF/DKIM/DMARC)
    EMAIL_FROM_NAME: str = ""  # vacío = MAIL_BRAND_NAME
    EMAIL_REPLY_TO: str = ""
    EMAIL_FILE_DIR: str = "var/mail"
    # Plantillas propias del proyecto: ganan a las de serie, fichero a fichero.
    EMAIL_TEMPLATES_DIR: str = "email_templates"
    SMTP_HOST: str = ""
    SMTP_PORT: int = Field(default=587, ge=1, le=65535)
    SMTP_USER: str = ""
    SMTP_PASSWORD: SecretStr = SecretStr("")
    SMTP_PASSWORD_FILE: Path | None = None  # alternativa para Docker secrets
    SMTP_SECURITY: Literal["starttls", "ssl", "none"] = "starttls"
    # Menor que el timeout de la tarea (60 s), y este menor que el arrendamiento.
    SMTP_TIMEOUT: int = Field(default=20, ge=1, le=45)
    # Marca de los correos (vacío = PROJECT_NAME / FRONTEND_URL / sin logo).
    MAIL_BRAND_NAME: str = ""
    MAIL_BRAND_URL: str = ""
    MAIL_BRAND_LOGO_URL: str = ""
    MAIL_BRAND_COLOR: str = "#2563eb"
    MAIL_SUPPORT_EMAIL: str = ""
    MAIL_FOOTER: str = Field(default="", max_length=500)
    MAIL_DEFAULT_LANGUAGE: str = "en"
    # Idiomas con plantilla; se elige por Accept-Language dentro de esta lista.
    MAIL_LANGUAGES: CommaList = ["en", "es"]

    # --- Paginación ---------------------------------------------------------
    PAGE_SIZE_DEFAULT: int = Field(default=20, ge=1)
    PAGE_SIZE_MAX: int = Field(default=100, ge=1, le=1000)
    MAX_OFFSET: int = Field(default=10_000, ge=0)

    # --- Logging --------------------------------------------------------------
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    # None = JSON en producción, texto legible en desarrollo.
    LOG_JSON: bool | None = None
    # IP del cliente en el log de acceso: full | truncated (/24 en IPv4, /48 en IPv6) |
    # off. Minimización (ISO 27701 7.4.5): los eventos de auditoría sí guardan la IP
    # completa, porque su finalidad es la seguridad.
    ACCESS_LOG_IP: Literal["full", "truncated", "off"] = "truncated"

    # --- Auditoría (SOC 2 CC7.2 / ISO 27701 6.9.4) --------------------------------
    # Clave HMAC que encadena los eventos de auditoría de cada proceso: con ella, quien
    # pueda escribir en los logs no puede alterar ni borrar eventos sin que lo detecte
    # `apigen audit verify`. Distinta de SECRET_KEY (el worker también audita y no
    # recibe la clave de los JWT). Vacía = cadena SHA-256 sin clave (solo detecta
    # errores accidentales).
    AUDIT_HMAC_KEY: SecretStr = SecretStr("")
    # Cifrado en reposo de los campos `sensitive` (AES-256-GCM): 32 bytes en base64
    # (`apigen secret --data-key`). Obligatoria en producción si algún recurso los
    # tiene. Para rotar: la nueva aquí y la anterior en PREVIOUS (solo descifra).
    DATA_ENCRYPTION_KEY: SecretStr = SecretStr("")
    DATA_ENCRYPTION_PREVIOUS_KEYS: CommaList = []

    # --- Privacidad y retención (ISO 27701 7.3 / 7.4, SOC 2 P4-P5 y C1.2) ---------
    # Derechos del interesado: GET /users/me/export (copia de sus datos) y
    # DELETE /users/me (supresión de su cuenta y de todo lo que le pertenece).
    ALLOW_SELF_DELETION: bool = True
    RATE_LIMIT_PRIVACY: str = "5/hour"
    # Filas por tabla en la exportación (si hay más, se marca `truncated`).
    PRIVACY_EXPORT_MAX_ROWS: int = Field(default=10_000, ge=100, le=1_000_000)
    # `apigen db prune` (0 = no se borra nada):
    # - cuentas nunca verificadas, solo con EMAIL_VERIFICATION=required (no pueden
    #   iniciar sesión, así que no tiene sentido guardar su email indefinidamente);
    UNVERIFIED_ACCOUNT_RETENTION_DAYS: int = Field(default=30, ge=0, le=3650)
    # - filas borradas lógicamente (soft delete): pasado este plazo se borran de verdad.
    SOFT_DELETE_RETENTION_DAYS: int = Field(default=30, ge=0, le=3650)

    @field_validator(
        "CORS_ORIGINS",
        "ALLOWED_HOSTS",
        "TRUSTED_PROXIES",
        "JWT_PREVIOUS_SECRET_KEYS",
        "MAIL_LANGUAGES",
        "DATA_ENCRYPTION_PREVIOUS_KEYS",
        mode="before",
    )
    @classmethod
    def _split_commas(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("API_PREFIX")
    @classmethod
    def _normalize_prefix(cls, value: str) -> str:
        value = "/" + value.strip("/")
        return "" if value == "/" else value

    @field_validator(
        "RATE_LIMIT_DEFAULT",
        "RATE_LIMIT_GLOBAL",
        "RATE_LIMIT_LOGIN",
        "RATE_LIMIT_REGISTER",
        "RATE_LIMIT_REFRESH",
        "RATE_LIMIT_EMAIL_REQUEST",
        "RATE_LIMIT_TOKEN_CONFIRM",
        "RATE_LIMIT_PRIVACY",
    )
    @classmethod
    def _valid_limit(cls, value: str | None) -> str | None:
        if value is not None:
            parse_many(value)  # lanza ValueError si el formato no es válido
        return value

    @field_validator("TRUSTED_PROXIES")
    @classmethod
    def _valid_proxies(cls, value: list[str]) -> list[str]:
        for item in value:
            if item == "*":
                continue  # se rechaza en producción (_check_security)
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError as exc:
                raise ValueError(f"TRUSTED_PROXIES: {item!r} no es una IP ni un CIDR") from exc
        return value

    @model_validator(mode="after")
    def _check_security(self) -> Settings:
        if self.RATE_LIMIT_REGISTER is None:
            self.RATE_LIMIT_REGISTER = "5/hour" if self.is_production else "50/hour"
        development = self.ENVIRONMENT == Environment.development
        for name, prod_value, dev_value in (
            ("EMAIL_PER_ACCOUNT_COOLDOWN_SECONDS", 60, 0),
            ("EMAIL_PER_ACCOUNT_PER_HOUR", 3, 30),
            ("EMAIL_PER_ACCOUNT_PER_DAY", 10, 200),
        ):
            if getattr(self, name) is None:
                setattr(self, name, dev_value if development else prod_value)
        if self.RATE_LIMIT_EMAIL_REQUEST is None:
            self.RATE_LIMIT_EMAIL_REQUEST = (
                "5/minute;20/hour" if self.is_production else "30/minute;300/hour"
            )
        problems: list[str] = _email_problems(self)
        symmetric = self.JWT_ALGORITHM in _SYMMETRIC_ALGORITHMS
        secret = self.SECRET_KEY.get_secret_value()

        if self.PASSWORD_MIN_LENGTH > self.PASSWORD_MAX_LENGTH:
            problems.append("PASSWORD_MIN_LENGTH no puede ser mayor que PASSWORD_MAX_LENGTH")

        if self.PROCESS_ROLE == "worker":
            # El worker no emite ni valida JWT: una clave efímera basta (y si alguien lo
            # compromete no se lleva la clave que firma los tokens).
            if symmetric and (secret.lower() in _INSECURE_SECRETS or len(secret) < 32):
                self.SECRET_KEY = SecretStr(secrets.token_urlsafe(64))
        elif symmetric:
            weak = secret.lower() in _INSECURE_SECRETS or len(secret) < 32
            if weak and self.is_production:
                problems.append("SECRET_KEY debe tener al menos 32 caracteres aleatorios")
            elif weak:
                # En desarrollo/testing generamos una clave efímera para no bloquear.
                self.SECRET_KEY = SecretStr(secrets.token_urlsafe(64))
                logger.warning(
                    "SECRET_KEY no configurada o débil: usando una clave efímera "
                    "(los tokens dejarán de valer al reiniciar). Ejecuta `apigen init-env`."
                )
        else:
            if not self.JWT_PRIVATE_KEY_FILE or not self.JWT_PUBLIC_KEY_FILE:
                problems.append(
                    f"{self.JWT_ALGORITHM} requiere JWT_PRIVATE_KEY_FILE y JWT_PUBLIC_KEY_FILE"
                )

        if self.CORS_ALLOW_CREDENTIALS and "*" in self.CORS_ORIGINS:
            problems.append("CORS_ORIGINS='*' no se puede combinar con CORS_ALLOW_CREDENTIALS")

        audit_key = self.AUDIT_HMAC_KEY.get_secret_value()
        if audit_key and (len(audit_key) < 32 or audit_key == secret):
            problems.append(
                "AUDIT_HMAC_KEY necesita 32+ caracteres aleatorios y distinta de SECRET_KEY"
            )

        problems += _data_key_problems(self)

        if self.is_production:
            if not audit_key:
                logger.warning(
                    "AUDIT_HMAC_KEY vacía: la cadena de auditoría no resiste manipulaciones "
                    "deliberadas. Genera una con `apigen secret`."
                )
            if self.LOG_JSON is False:
                logger.warning(
                    "LOG_JSON=false en producción: `apigen audit verify` solo lee logs JSON."
                )
            if self.DEBUG:
                problems.append("DEBUG debe ser false en producción")
            if self.DATABASE_URL.startswith("sqlite"):
                if self.ALLOW_SQLITE_IN_PRODUCTION:
                    logger.warning("Usando SQLite en producción: recomendado PostgreSQL.")
                else:
                    # Un DATABASE_URL ausente o vacío acabaría aquí en silencio.
                    problems.append(
                        "DATABASE_URL apunta a SQLite: usa PostgreSQL en producción "
                        "(o ALLOW_SQLITE_IN_PRODUCTION=true si es intencionado)"
                    )
            if self.PROCESS_ROLE == "api":
                problems += self._api_production_problems(symmetric)

        if problems:
            raise ValueError("Configuración insegura:\n  - " + "\n  - ".join(problems))
        return self

    def _api_production_problems(self, symmetric: bool) -> list[str]:
        """Comprobaciones de producción que solo afectan a la API HTTP (no al worker)."""
        problems: list[str] = []
        if "*" in self.CORS_ORIGINS:
            problems.append("CORS_ORIGINS no puede ser '*' en producción")
        if "*" in self.ALLOWED_HOSTS:
            problems.append("ALLOWED_HOSTS debe enumerar los dominios reales en producción")
        if self.RATE_LIMIT_ENABLED and self.RATE_LIMIT_STORAGE_URI.startswith("memory"):
            logger.warning(
                "Rate limit en memoria: con varios workers/instancias cada uno "
                "cuenta por separado. Usa Redis (RATE_LIMIT_STORAGE_URI)."
            )
        problems += _proxy_problems(self.TRUSTED_PROXIES)
        if not self.TRUSTED_PROXIES:
            logger.warning(
                "TRUSTED_PROXIES vacío: si la API está detrás de un proxy inverso, "
                "todos los clientes compartirán la IP del proxy (rate limit y bloqueo "
                "de login globales) y no se enviará HSTS. Ver README, sección Despliegue."
            )
        if self.FRONTEND_URL and self.account_emails_enabled:
            front = urlsplit(self.FRONTEND_URL)
            if f"{front.scheme}://{front.netloc}" not in self.CORS_ORIGINS:
                logger.warning(
                    "El origen de FRONTEND_URL no está en CORS_ORIGINS: el frontend no "
                    "podrá llamar a /auth/password/reset ni a /auth/email/verify."
                )
        weak_old = [k for k in self.JWT_PREVIOUS_SECRET_KEYS if len(k) < 32]
        if symmetric and weak_old:
            problems.append("JWT_PREVIOUS_SECRET_KEYS: cada clave necesita 32+ caracteres")
        return problems

    # --- Propiedades derivadas ----------------------------------------------
    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == Environment.production

    @property
    def is_testing(self) -> bool:
        return self.ENVIRONMENT == Environment.testing

    @property
    def docs_enabled(self) -> bool:
        return (not self.is_production) if self.DOCS_ENABLED is None else self.DOCS_ENABLED

    @property
    def log_json(self) -> bool:
        return self.is_production if self.LOG_JSON is None else self.LOG_JSON

    @property
    def is_sqlite(self) -> bool:
        return self.DATABASE_URL.startswith("sqlite")

    @property
    def is_postgres(self) -> bool:
        return self.DATABASE_URL.startswith("postgresql")

    # --- Correo y flujos de cuenta --------------------------------------------
    @property
    def email_backend(self) -> str | None:
        """Backend efectivo: el configurado o el de por defecto del entorno."""
        if self.EMAIL_BACKEND:
            return self.EMAIL_BACKEND
        if self.is_testing:
            return "memory"
        if self.ENVIRONMENT == Environment.development:
            return "console"
        return None  # producción: hay que elegirlo

    @property
    def email_enabled(self) -> bool:
        return self.email_backend not in (None, "disabled")

    @property
    def password_reset_enabled(self) -> bool:
        return self.PASSWORD_RESET and self.email_enabled

    @property
    def email_verification(self) -> str:
        return self.EMAIL_VERIFICATION if self.email_enabled else "off"

    @property
    def account_emails_enabled(self) -> bool:
        """¿Hay algún flujo de cuenta por correo? (habilita el cambio de email)."""
        return self.email_verification != "off" or self.password_reset_enabled

    @property
    def email_delivery(self) -> str:
        if self.EMAIL_DELIVERY:
            return self.EMAIL_DELIVERY
        return "inline" if self.ENVIRONMENT == Environment.development else "queue"

    @property
    def mail_brand_name(self) -> str:
        return self.MAIL_BRAND_NAME or self.PROJECT_NAME

    def smtp_password(self) -> str:
        """Contraseña SMTP (de la variable o de SMTP_PASSWORD_FILE, p. ej. Docker secrets)."""
        if self.SMTP_PASSWORD_FILE:
            return self.SMTP_PASSWORD_FILE.read_text(encoding="utf-8").strip()
        return self.SMTP_PASSWORD.get_secret_value()


# ---------------------------------------------------------------------------
# Validación de la configuración de correo
# ---------------------------------------------------------------------------
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}
# Dominios de ejemplo o reservados: en producción el remitente no puede usarlos.
_PLACEHOLDER_DOMAIN = re.compile(
    r"(^|\.)(example(\.(com|org|net))?|localhost|test|invalid|local)$", re.IGNORECASE
)
_LANG = re.compile(r"^[a-z]{2}(-[A-Z]{2})?$")
_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")
_CUSTOM_BACKEND = re.compile(r"^app(\.[a-z_][a-z0-9_]*)+:[A-Za-z_][A-Za-z0-9_]*$")
# Ruta relativa sin espacios ni barras invertidas; `{token}` exactamente una vez.
_LINK = re.compile(r"^/(?!/)[A-Za-z0-9\-._~!$&'()*+,;=:@/?#%]*$")


def _has_control(value: str, allow_newline: bool = False) -> bool:
    return any(
        (ord(ch) < 32 and not (allow_newline and ch == "\n")) or ord(ch) == 127 for ch in value
    )


def _is_local_host(host: str) -> bool:
    host = host.lower().strip("[]")
    try:
        if ipaddress.ip_address(host).is_loopback:  # 127.0.0.0/8 y ::1
            return True
    except ValueError:
        pass
    return host in _LOOPBACK or host.endswith(".localhost")


def _address_problem(value: str, production: bool) -> str | None:
    """Una sola dirección válida, sin nombre ni CR/LF (REQ-C06)."""
    if _has_control(value):
        return "no puede contener saltos de línea ni caracteres de control"
    name, addr = parseaddr(value)
    if name or addr != value.strip() or "," in value:
        return "debe ser una sola dirección, sin nombre (el nombre va en EMAIL_FROM_NAME)"
    local, _, domain = addr.rpartition("@")
    if not local or "." not in domain:
        return f"{value!r} no es una dirección de correo válida"
    if production and _PLACEHOLDER_DOMAIN.search(domain):
        return f"{value!r} usa un dominio de ejemplo o reservado: pon uno real del cliente"
    return None


def _url_problem(value: str, production: bool, *, base: bool = False) -> str | None:
    """URL absoluta: https (http solo hacia localhost fuera de producción)."""
    if _has_control(value) or " " in value:
        return "no puede contener espacios ni caracteres de control"
    parts = urlsplit(value)
    host = parts.hostname or ""
    if parts.scheme not in {"https", "http"} or not host:
        return f"{value!r} debe ser una URL absoluta https://..."
    if parts.username or parts.password:
        return "no puede llevar usuario ni contraseña"
    if base and (parts.query or parts.fragment):
        return "no puede llevar query (?) ni fragmento (#): van en EMAIL_LINK_*"
    if production and (parts.scheme != "https" or _is_local_host(host)):
        return f"{value!r} debe ser https y no localhost en producción"
    if parts.scheme == "http" and not _is_local_host(host):
        return f"{value!r}: http solo se admite hacia localhost (usa https)"
    return None


def _link_problem(value: str) -> str | None:
    """REQ-L02: ruta relativa a FRONTEND_URL con `{token}` exactamente una vez."""
    if value.count("{token}") != 1:
        return "debe contener {token} exactamente una vez"
    rest = value.replace("{token}", "")
    if "{" in rest or "}" in rest or not _LINK.match(rest):
        return "debe ser una ruta que empiece por / (p. ej. /reset-password#token={token})"
    return None


def _email_problems(s: Settings) -> list[str]:
    """Correo y flujos de cuenta (REQ-C03..C07). Devuelve los problemas bloqueantes."""
    problems: list[str] = []
    prod = s.is_production
    backend = s.email_backend
    features = s.EMAIL_VERIFICATION != "off" or s.PASSWORD_RESET

    for name in ("EMAIL_FROM", "EMAIL_REPLY_TO", "MAIL_SUPPORT_EMAIL"):
        value = getattr(s, name)
        if value and (error := _address_problem(value, prod)):
            problems.append(f"{name}: {error}")
    for name in ("EMAIL_FROM_NAME", "MAIL_BRAND_NAME"):
        value = getattr(s, name)
        if _has_control(value) or len(value) > 100:
            problems.append(f"{name}: sin saltos de línea y como mucho 100 caracteres")
    if _has_control(s.MAIL_FOOTER, allow_newline=True):
        problems.append("MAIL_FOOTER no puede contener caracteres de control")
    for name in ("MAIL_BRAND_URL", "MAIL_BRAND_LOGO_URL"):
        value = getattr(s, name)
        if value and (error := _url_problem(value, prod)):
            problems.append(f"{name}: {error}")
    if not _COLOR.match(s.MAIL_BRAND_COLOR):
        problems.append("MAIL_BRAND_COLOR debe ser un color #rrggbb")
    bad_langs = [lang for lang in s.MAIL_LANGUAGES if not _LANG.match(lang)]
    if bad_langs or not s.MAIL_LANGUAGES:
        problems.append(f"MAIL_LANGUAGES: códigos no válidos {bad_langs} (usa p. ej. en,es)")
    elif s.MAIL_DEFAULT_LANGUAGE not in s.MAIL_LANGUAGES:
        problems.append("MAIL_DEFAULT_LANGUAGE debe estar en MAIL_LANGUAGES")
    if s.EMAIL_BACKEND == "custom" and not _CUSTOM_BACKEND.match(s.EMAIL_BACKEND_CLASS):
        problems.append(
            "EMAIL_BACKEND=custom requiere EMAIL_BACKEND_CLASS=app.<módulo>:<Clase> "
            "(una clase de tu proyecto)"
        )
    if s.SMTP_PASSWORD_FILE and s.SMTP_PASSWORD.get_secret_value():
        problems.append("Usa SMTP_PASSWORD o SMTP_PASSWORD_FILE, no los dos")
    if prod and s.EMAIL_BACKEND == "memory":
        problems.append("EMAIL_BACKEND=memory es solo para tests")
    if prod and s.EMAIL_DELIVERY == "inline":
        problems.append("EMAIL_DELIVERY=inline es solo para desarrollo: usa el worker")
    if s.FRONTEND_URL and (error := _url_problem(s.FRONTEND_URL, prod, base=True)):
        problems.append(f"FRONTEND_URL: {error}")
    for name in ("EMAIL_LINK_RESET", "EMAIL_LINK_VERIFY"):
        if error := _link_problem(getattr(s, name)):
            problems.append(f"{name}: {error}")

    if features:
        active = ", ".join(
            [f"EMAIL_VERIFICATION={s.EMAIL_VERIFICATION}"] * (s.EMAIL_VERIFICATION != "off")
            + ["PASSWORD_RESET=on"] * s.PASSWORD_RESET
        )
        if backend is None:
            problems.append(f"EMAIL_BACKEND es obligatorio en producción con {active}")
        elif backend == "disabled":
            problems.append(f"EMAIL_BACKEND=disabled no es compatible con {active}")
        elif prod and backend in {"console", "file", "memory"}:
            problems.append(
                f"EMAIL_BACKEND={backend} no envía correos reales: usa smtp en producción"
            )
        if not s.EMAIL_FROM and prod:
            problems.append(f"EMAIL_FROM es obligatorio con {active}")
        elif not s.EMAIL_FROM:
            # Fuera de producción, un marcador (en producción es obligatorio).
            s.EMAIL_FROM = "no-reply@example.com"
        if not s.FRONTEND_URL and prod:
            problems.append(f"FRONTEND_URL es obligatorio con {active} (los enlaces van ahí)")
        elif not s.FRONTEND_URL:
            s.FRONTEND_URL = "http://localhost:3000"
            logger.warning(
                "FRONTEND_URL vacío: los enlaces de los correos irán a %s", s.FRONTEND_URL
            )
        for name in ("EMAIL_LINK_RESET", "EMAIL_LINK_VERIFY"):
            if "#" not in getattr(s, name):
                logger.warning(
                    "%s lleva el token en la query: el frontend debe usar "
                    "Referrer-Policy: no-referrer y retirarlo con history.replaceState.",
                    name,
                )

    if prod and s.PROCESS_ROLE == "worker" and backend == "smtp":
        # Solo el worker envía (y solo él recibe las credenciales; REQ-C10).
        if not s.SMTP_HOST:
            problems.append("EMAIL_BACKEND=smtp requiere SMTP_HOST")
        elif s.SMTP_SECURITY == "none" and s.SMTP_HOST.lower() not in _LOOPBACK:
            # Solo loopback exacto: `*.localhost` podría resolver a otro host (Info-2).
            problems.append("SMTP_SECURITY=none solo se admite hacia localhost: usa starttls o ssl")
        has_password = bool(s.SMTP_PASSWORD_FILE or s.SMTP_PASSWORD.get_secret_value())
        if s.SMTP_USER and not has_password:
            problems.append("SMTP_USER sin SMTP_PASSWORD (o SMTP_PASSWORD_FILE)")
    if prod and backend == "console":
        logger.warning("EMAIL_BACKEND=console en producción: los correos solo van al log.")
    return problems


def _data_key_problems(s: Settings) -> list[str]:
    """Formato de las claves de cifrado de datos (32 bytes en base64)."""
    problems: list[str] = []
    current = s.DATA_ENCRYPTION_KEY.get_secret_value()
    for name, value in [("DATA_ENCRYPTION_KEY", current)] + [
        ("DATA_ENCRYPTION_PREVIOUS_KEYS", k) for k in s.DATA_ENCRYPTION_PREVIOUS_KEYS
    ]:
        if not value:
            continue
        try:
            raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        except (binascii.Error, ValueError):
            raw = b""
        if len(raw) != 32:
            problems.append(
                f"{name}: 32 bytes en base64 (genera una con `apigen secret --data-key`)"
            )
    if s.DATA_ENCRYPTION_PREVIOUS_KEYS and not current:
        problems.append("DATA_ENCRYPTION_PREVIOUS_KEYS sin DATA_ENCRYPTION_KEY")
    return problems


def _proxy_problems(proxies: list[str]) -> list[str]:
    """SEC-21: la IP del cliente decide rate limits, bloqueo de login y gracia del
    refresh. Confiar en X-Forwarded-For de cualquiera permite falsificarla."""
    problems: list[str] = []
    for item in proxies:
        if item == "*":
            problems.append("TRUSTED_PROXIES='*' permite falsificar la IP del cliente")
            continue
        net = ipaddress.ip_network(item, strict=False)
        # Más amplio que /8 (IPv4) o /32 (IPv6) no puede ser "la red del proxy".
        if net.prefixlen < (8 if net.version == 4 else 32):
            problems.append(f"TRUSTED_PROXIES={item} es demasiado amplio: pon la IP del proxy")
        elif net.prefixlen < (16 if net.version == 4 else 48):
            logger.warning(
                "TRUSTED_PROXIES=%s es muy amplio: confía solo en la IP/subred del proxy.", item
            )
    return problems


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
