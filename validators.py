import re
from pathlib import Path

# -------- Чёрный список --------
BLACKLIST_FILE = Path(__file__).parent / "blacklist.txt"

DEFAULT_BLACKLIST = [
    "admin", "root", "administrator", "user", "test",
    "guest", "manager", "support", "moderator", "superuser",
    "qwerty", "system", "operator",
]


def load_blacklist() -> set[str]:
    """Загружает чёрный список логинов из файла. Если файла нет — создаёт его."""
    if not BLACKLIST_FILE.exists():
        BLACKLIST_FILE.write_text("\n".join(DEFAULT_BLACKLIST), encoding="utf-8")

    lines = BLACKLIST_FILE.read_text(encoding="utf-8").splitlines()
    return {line.strip().lower() for line in lines if line.strip()}


# -------- Регулярные выражения --------
# Формат телефона: +x-xxx-xxx-xxxx
PHONE_RE = re.compile(r"^\+\d-\d{3}-\d{3}-\d{4}$")

# Формат email (стандартная маска)
EMAIL_RE = re.compile(
    r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$"
)

# Формат обычной строки: минимум 5 символов, только латиница, цифры, _
PLAIN_LOGIN_RE = re.compile(r"^[A-Za-z0-9_]{5,}$")

# Пароль: минимум 7 символов, только кириллица/цифры/спецсимволы
# (буквы латиницы не допускаются)
PASSWORD_ALLOWED_RE = re.compile(r"^[А-Яа-яЁё0-9!@#$%^&*()_\-+=<>?/\\|.,:;{}\[\]~`\"']+$")


# -------- Валидация --------

class ValidationError(Exception):
    """Исключение с текстовым описанием причины отказа."""
    pass


def validate_login(login: str) -> None:
    """Проверяет логин. Бросает ValidationError при нарушении правил."""
    if login is None or login == "":
        raise ValidationError("Логин не может быть пустым")

    # Определяем тип логина
    if PHONE_RE.match(login):
        # телефон валиден
        pass
    elif EMAIL_RE.match(login):
        # email валиден
        pass
    else:
        # Не телефон и не email — трактуем как обычную строку
        if len(login) < 5:
            raise ValidationError(
                "Логин-строка должен содержать минимум 5 символов"
            )
        if not PLAIN_LOGIN_RE.match(login):
            raise ValidationError(
                "Логин-строка может содержать только латиницу, цифры и символ '_'"
            )

    # Проверка чёрного списка (без учёта регистра)
    blacklist = load_blacklist()
    if login.lower() in blacklist:
        raise ValidationError(
            f"Логин '{login}' находится в чёрном списке запрещённых"
        )


def validate_password(password: str) -> None:
    """Проверяет пароль по всем правилам."""
    if password is None or password == "":
        raise ValidationError("Пароль не может быть пустым")

    if len(password) < 7:
        raise ValidationError("Пароль должен содержать минимум 7 символов")

    if not PASSWORD_ALLOWED_RE.match(password):
        raise ValidationError(
            "Пароль может содержать только кириллицу, цифры и спецсимволы"
        )

    if not re.search(r"[А-ЯЁ]", password):
        raise ValidationError("Пароль должен содержать хотя бы одну заглавную букву")

    if not re.search(r"[а-яё]", password):
        raise ValidationError("Пароль должен содержать хотя бы одну строчную букву")

    if not re.search(r"\d", password):
        raise ValidationError("Пароль должен содержать хотя бы одну цифру")

    if not re.search(r"[!@#$%^&*()_\-+=<>?/\\|.,:;{}\[\]~`\"']", password):
        raise ValidationError("Пароль должен содержать хотя бы один спецсимвол")


def validate_passwords_match(password: str, confirm: str) -> None:
    """Проверяет совпадение пароля и подтверждения."""
    if password != confirm:
        raise ValidationError("Пароль и подтверждение пароля не совпадают")


def validate_registration(login: str, password: str, confirm: str) -> None:
    """Комплексная валидация. Бросает ValidationError при первой ошибке."""
    validate_login(login)
    validate_password(password)
    validate_passwords_match(password, confirm)