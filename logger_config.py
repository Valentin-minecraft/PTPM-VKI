import logging
import hashlib
from pathlib import Path

LOG_FILE = Path(__file__).parent / "app.log"


def mask_password(password: str) -> str:
    """
    Безопасное маскирование пароля.

    Требования:
    - Одинаковые пароли -> одинаковый результат (детерминированность).
    - Разные пароли -> разный результат (устойчивость к коллизиям).

    Реализация: SHA-256 + фиксированный префикс для наглядности.
    Плюс короткий "отпечаток" для удобства чтения в логах.
    """
    if password is None:
        return "<None>"
    digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return f"masked:{digest}"


def get_logger(name: str = "registration") -> logging.Logger:
    """
    Возвращает логгер, который пишет СКВОЗНО в файл и в консоль.
    """
    logger = logging.getLogger(name)

    # Чтобы не добавлять хендлеры повторно при повторных вызовах
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Хендлер в файл
    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(fmt)

    # Хендлер в консоль
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(fmt)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    logger.propagate = False

    return logger