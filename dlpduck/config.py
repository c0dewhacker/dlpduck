"""Validated startup configuration. Every regex is compiled and every path
is checked before the watcher starts — a bad rule fails the process at
boot, not on document 4,000.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, model_validator

from dlpduck.rules import Rule, RuleConfigError, load_ruleset


class SourceConfig(BaseModel):
    name: str
    path: Path
    pdf_suffix: str = ".pdf"
    metadata_format: Literal["xml", "json", "text", "none"] = "none"
    metadata_suffix: str = ".xml"
    metadata_fields: list[str] = Field(default_factory=list)  # allowlist only
    poll_seconds: float = Field(default=5.0, gt=0)
    stability_polls: int = Field(default=2, ge=1)  # size must hold across N polls before claim
    # Even with a metadata_format configured, a companion file is a
    # convenience, not a requirement — a bare PDF dropped with no XML/JSON
    # alongside it must still get processed, not wait forever. This
    # many EXTRA stable-size polls are given to let a companion that's
    # genuinely en route catch up before claiming without one.
    metadata_grace_polls: int = Field(default=3, ge=0)


class LimitsConfig(BaseModel):
    max_bytes: int = Field(default=200 * 1024 * 1024, gt=0)
    max_pages: int = Field(default=500, gt=0)
    rule_budget_ms: int = Field(default=2000, gt=0)  # per document, per rule
    # A companion file arrives from the same semi-trusted drop folder as
    # the PDF and was previously read whole with no ceiling at all — so a
    # one-line PDF with a multi-gigabyte .xml beside it could exhaust the
    # daemon. Scanner metadata is a few KB; 1 MB is already generous.
    max_metadata_bytes: int = Field(default=1024 * 1024, gt=0)


class ExtractionConfig(BaseModel):
    dpi: int = Field(default=150, ge=36, le=600)
    timeout_seconds: float = Field(default=120, gt=0)
    isolate_worker: bool = True
    native_min_chars: int = Field(default=20, ge=0)  # evaluated per page


class DlpConfig(BaseModel):
    quarantine_on_degraded: bool = True  # fail closed
    hmac_key_env: str = "DLPDUCK_HMAC_KEY"
    rules: list[dict] = Field(default_factory=list)


class DestinationConfig(BaseModel):
    archive: Path
    quarantine: Path  # use a separate mount/ACL from `archive` in production
    work_dir: Path


class AuditConfig(BaseModel):
    integrity: Literal["chained", "none"] = "chained"
    path: Path | None = None


class ConsoleUserConfig(BaseModel):
    username: str
    password_hash: str  # argon2id — never a plaintext password; see `dlpduck console hash-password`
    roles: list[str] = Field(default_factory=list)
    role: str | None = None  # convenience for a single-role account

    @model_validator(mode="after")
    def _merge_singular_role(self) -> ConsoleUserConfig:
        if self.role and self.role not in self.roles:
            self.roles = [*self.roles, self.role]
        return self

    @model_validator(mode="after")
    def _password_hash_is_actually_a_hash(self) -> ConsoleUserConfig:
        # The commonest way to get this wrong is pasting the password
        # itself into password_hash. Left alone that isn't just a broken
        # login — it means an account's credential is sitting in cleartext
        # in a config file, and argon2 raises InvalidHashError deep inside
        # the login handler. Caught here it fails at boot, and in
        # `dlpduck validate-config`, so in CI.
        if not str(self.password_hash).startswith("$argon2"):
            raise ValueError(
                f"console.auth.users[{self.username!r}].password_hash is not an argon2 hash "
                "— generate one with `dlpduck console hash-password`, and never put a "
                "plaintext password in config"
            )
        return self


class OidcConfig(BaseModel):
    issuer: str  # e.g. https://idp.example/realms/dlpduck — discovery is read from here
    client_id: str
    client_secret_env: str = "DLPDUCK_OIDC_CLIENT_SECRET"  # noqa: S105 — an env var name, not a secret
    roles_claim: str = "roles"  # ID token claim holding the user's external roles/groups
    # External role/group name -> internal role (viewer|investigator|dlp_admin|auditor).
    # A claim value not present here is tried as-is — set this only where the names differ.
    role_map: dict[str, str] = Field(default_factory=dict)

    def client_secret(self) -> str:
        raw = os.environ.get(self.client_secret_env)
        if not raw:
            raise ConfigError(
                f"environment variable {self.client_secret_env} is not set — "
                "the OIDC client needs its secret to exchange an authorization code"
            )
        return raw


class ConsoleAuthConfig(BaseModel):
    # Both may be configured at once — OIDC as the primary path,
    # local accounts as the fallback for when the IdP is unreachable, an
    # air-gapped install, or a break-glass admin account. Neither is
    # required; an install with just `users` behaves exactly as before.
    users: list[ConsoleUserConfig] = Field(default_factory=list)
    oidc: OidcConfig | None = None
    # Failed local logins before that username, or that client address, is
    # refused for `lockout_seconds`. This bounds password guessing, but the
    # sharper reason is availability: verifying a password is deliberately
    # expensive (argon2id, ~64MB and tens of milliseconds each), and the
    # equal-time path for an unknown username costs the same. Without a
    # ceiling, a few hundred concurrent POSTs to /login — no valid username
    # needed — exhaust memory and CPU and take the console down for the
    # people who are supposed to be using it.
    max_failed_logins: int = Field(default=10, ge=1)
    lockout_seconds: int = Field(default=300, ge=1)


class ConsoleConfig(BaseModel):
    bind: str = "127.0.0.1:8080"
    session_secret_env: str = "DLPDUCK_SESSION_SECRET"  # noqa: S105 — an env var name, not a secret
    # Starlette's own default is a 14-day cookie, which is a long time to
    # hold a session that can read masked hits and (for an admin) reveal
    # cleartext. 8 hours is one working day: long enough not to interrupt
    # an investigation, short enough that a forgotten browser doesn't stay
    # authenticated for a fortnight. The operational store can revoke a
    # session sooner; this remains its hard upper lifetime.
    session_max_age_seconds: int = Field(default=8 * 60 * 60, gt=0)
    # Mark the session cookie Secure, so a browser will never send it over
    # plain HTTP. Defaults to False only because the console also has to
    # come up on http://127.0.0.1 for local/dev use; ANY deployment reached
    # over a network should set this true and terminate TLS in front.
    session_cookie_secure: bool = False
    # How a search is recorded in the audit trail.
    #
    # "hashed" (default) logs only a keyed digest. The audit trail is hash-chained
    # and has no purge path by design, so anything written there is
    # permanent — and a DLP investigation routinely means searching for
    # the sensitive value itself ("did this SSN appear anywhere else?").
    # That would put the value in a store that outlives the documents and
    # is readable by Auditors, who are deliberately denied document text.
    # Repeated searches for the same term still correlate. "plain" is an
    # explicit policy choice for deployments that must retain exact queries.
    audit_search_terms: Literal["plain", "hashed"] = "hashed"
    auth: ConsoleAuthConfig = Field(default_factory=ConsoleAuthConfig)

    def host_port(self) -> tuple[str, int]:
        """Split `bind` into a host and a port.

        A bare `partition(":")` is wrong for IPv6 and crashed the console
        at startup with a raw ValueError: `[::1]:8080` split at the first
        colon, leaving `int(":1]:8080")`. Binding a console to an IPv6
        address is ordinary, and a config that validates clean and then
        refuses to start is the worst way to find out.

        Accepts `host`, `host:port`, `[v6]`, `[v6]:port`, and a bare IPv6
        literal with no port. The port defaults to 8080.
        """
        raw = self.bind.strip()
        if raw.startswith("["):
            host, closed, rest = raw[1:].partition("]")
            if not closed:
                raise ConfigError(f"console.bind has an unclosed '[' : {self.bind!r}")
            port = rest[1:] if rest.startswith(":") else rest
            if rest and not rest.startswith(":"):
                raise ConfigError(f"console.bind is malformed after ']': {self.bind!r}")
        elif raw.count(":") > 1:
            host, port = raw, ""  # a bare IPv6 literal, no port given
        else:
            host, _, port = raw.partition(":")
        if not host:
            raise ConfigError(f"console.bind has no host: {self.bind!r}")
        if not port:
            return host, 8080
        try:
            number = int(port)
        except ValueError:
            raise ConfigError(f"console.bind port is not a number: {self.bind!r}") from None
        if not 1 <= number <= 65535:
            raise ConfigError(f"console.bind port is out of range: {self.bind!r}")
        return host, number

    def session_secret(self) -> str:
        raw = os.environ.get(self.session_secret_env)
        if not raw:
            raise ConfigError(
                f"environment variable {self.session_secret_env} is not set — "
                "the console needs a secret to sign session cookies"
            )
        return raw


class RetentionConfig(BaseModel):
    # None means "keep forever" — retention is opt-in per store, not a
    # surprise default that starts silently deleting data.
    documents_days: int | None = Field(default=None, ge=0)  # PDFs (archive + quarantine) + the content store
    index_days: int | None = Field(default=None, ge=0)
    audit_days: int | None = Field(default=None, ge=0)


# The config format this release understands. It is declared in the file so
# that a format change can be detected rather than guessed at — a key
# renamed between versions would otherwise be silently ignored by pydantic
# and take its default, which for something like quarantine_on_degraded
# means a policy quietly flipping on upgrade.
SUPPORTED_CONFIG_VERSION = 2


class Config(BaseModel):
    version: int = SUPPORTED_CONFIG_VERSION
    # Everything this process writes — archived PDFs, quarantined PDFs, the
    # content store, the audit log — is sensitive by definition, and all of
    # it inherits the process umask. Setting it once at startup is both
    # more reliable and more auditable than chmod'ing at each of the dozen
    # places that create a file. "0077" is owner-only; widen it (e.g.
    # "0027", owner + group) only if a reviewer group genuinely needs
    # filesystem access. Set to null to inherit the invoking shell's.
    umask: str | None = "0077"
    source: SourceConfig
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    extraction: ExtractionConfig = Field(default_factory=ExtractionConfig)
    dlp: DlpConfig = Field(default_factory=DlpConfig)
    destination: DestinationConfig
    audit: AuditConfig = Field(default_factory=AuditConfig)
    retention: RetentionConfig = Field(default_factory=RetentionConfig)
    console: ConsoleConfig = Field(default_factory=ConsoleConfig)
    plugins: list[dict] = Field(default_factory=list)  # enrich and emit phases

    _config_dir: Path = Path(".")

    @property
    def rule_budget_seconds(self) -> float:
        return self.limits.rule_budget_ms / 1000

    @property
    def audit_dir(self) -> Path:
        """Configured audit store, defaulting to the work directory."""
        return self.audit.path or self.destination.work_dir / "audit"

    def load_rules(self) -> list[Rule]:
        return load_ruleset(self.dlp.rules, self._config_dir)

    def load_plugins(self):
        from dlpduck.plugins.loader import load_plugins

        return load_plugins(self.plugins, spool_root=self.destination.work_dir / "spool")

    def apply_umask(self) -> int | None:
        """Set the process umask from config. Call once, at startup, before
        anything is written. Returns the previous value, or None if the
        config opted out."""
        if self.umask is None:
            return None
        try:
            mask = int(self.umask, 8)
        except (TypeError, ValueError):
            raise ConfigError(
                f"umask must be an octal string like '0077', got {self.umask!r}"
            ) from None
        if not 0 <= mask <= 0o777:
            raise ConfigError(f"umask {self.umask!r} is out of range")
        return os.umask(mask)

    def hmac_key(self) -> bytes:
        raw = os.environ.get(self.dlp.hmac_key_env)
        if not raw:
            raise ConfigError(
                f"environment variable {self.dlp.hmac_key_env} is not set — "
                "the DLP engine needs an HMAC key to correlate matches without "
                "storing them"
            )
        return raw.encode("utf-8")


class ConfigError(ValueError):
    pass


def load_config(path: str | Path) -> Config:
    path = Path(path)
    if not path.is_file():
        raise ConfigError(f"config file not found: {path}")
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    declared = raw.get("version", SUPPORTED_CONFIG_VERSION)
    if declared != SUPPORTED_CONFIG_VERSION:
        raise ConfigError(
            f"config declares version {declared!r}, but this DLPDuck understands "
            f"version {SUPPORTED_CONFIG_VERSION}. Refusing to guess at a format it "
            "was not written for — a key that moved between versions would "
            "otherwise be ignored and silently take its default."
        )
    try:
        config = Config.model_validate(raw)
    except Exception as exc:  # pydantic.ValidationError, re-raised as ours
        raise ConfigError(f"invalid config: {exc}") from exc
    config._config_dir = path.parent
    return config


def validate_config(path: str | Path) -> Config:
    """Load config, compile every rule regex, and check every path exists
    or is creatable. Raises ConfigError on the first problem. Intended for
    `dlpduck validate-config` and for CI.
    """
    config = load_config(path)

    try:
        rules = config.load_rules()
    except RuleConfigError as exc:
        raise ConfigError(f"rule configuration error: {exc}") from exc
    if not rules:
        raise ConfigError("ruleset is empty after loading — check dlp.rules")

    config.hmac_key()  # raises ConfigError if unset
    # Parsed here so a bind the console cannot actually listen on fails
    # validation rather than the daemon's first second of life.
    config.console.host_port()

    if not config.source.path.is_dir():
        raise ConfigError(f"source.path does not exist: {config.source.path}")

    for dest in (
        config.destination.archive,
        config.destination.quarantine,
        config.destination.work_dir,
        config.audit_dir,
    ):
        dest.mkdir(parents=True, exist_ok=True)

    from dlpduck.plugins.loader import PluginConfigError

    try:
        config.load_plugins()
    except PluginConfigError as exc:
        raise ConfigError(f"plugin configuration error: {exc}") from exc

    return config


def config_warnings(config: Config) -> list[str]:
    """Settings that are legal, load fine, and are probably not what the
    operator meant.

    Separate from `validate_config`, which raises: none of these should
    stop a daemon starting, and an install may have chosen every one of
    them deliberately. But each is a property this system otherwise
    claims, quietly switched off in a way nothing else would report.
    """
    warnings: list[str] = []
    r = config.retention

    if (
        r.audit_days is not None
        and r.documents_days is not None
        and r.audit_days < r.documents_days
    ):
        # The audit trail is the only record of what was purged, and
        # `dlpduck reindex` reads it to avoid re-extracting erased content
        # back out of a surviving PDF. Age the trail out first and a
        # later rebuild has no way to know the erasure ever happened.
        warnings.append(
            f"retention.audit_days ({r.audit_days}) is shorter than "
            f"retention.documents_days ({r.documents_days}) — a purge record can age out "
            "while its PDF survives, and a later `reindex` would restore content that "
            "was erased on purpose. Keep the audit window at least as long."
        )

    host, _port = config.console.host_port()
    if not config.console.session_cookie_secure and host not in ("127.0.0.1", "::1", "localhost"):
        warnings.append(
            f"console.bind is {config.console.bind} but session_cookie_secure is false — "
            "the session cookie will cross plain HTTP. Set it true and terminate TLS in front."
        )

    if config.audit.integrity == "none":
        warnings.append(
            "audit.integrity is 'none' — events are still recorded, but nothing detects "
            "one being edited or removed afterwards, and `verify-audit` cannot help."
        )

    return warnings
