import sys
import traceback
from datetime import datetime

from logger_config import get_logger, mask_password
from validators import ValidationError, validate_registration

logger = get_logger()


def register_user(login: str, password: str, confirm: str) -> tuple[bool, str]:
    """
    Основной метод валидации учётных данных.

    Возвращает:
        (True, "")              — при успехе
        (False, "<сообщение>")  — при ошибке
    """
    # Для логирования маскируем пароли
    safe_params = {
        "login": login,
        "password": mask_password(password),
        "confirm": mask_password(confirm),
    }

    try:
        validate_registration(login, password, confirm)
    except ValidationError as e:
        # Неуспешный запрос — дата/время, параметры, текст ошибки
        logger.warning(
            "ОТКАЗ | параметры=%s | причина=%s",
            safe_params, str(e),
        )
        return False, str(e)
    except Exception as e:
        # Непредвиденная ошибка — логируем с traceback
        logger.error(
            "СБОЙ | параметры=%s | ошибка=%s\n%s",
            safe_params, str(e), traceback.format_exc(),
        )
        return False, f"Внутренняя ошибка: {e}"

    # Успешный запрос
    logger.info(
        "УСПЕХ | параметры=%s | результат=пользователь зарегистрирован",
        safe_params,
    )
    return True, ""


def main() -> None:
    # Чтение трёх строк из stdin
    try:
        login = input().strip()
        password = input()          # пароль без strip — пробелы могут быть значимыми
        confirm = input()
    except EOFError:
        print("False")
        print("Недостаточно входных данных")
        return

    ok, message = register_user(login, password, confirm)

    # Выходные данные строго по ТЗ
    print(ok)
    print(message)


if __name__ == "__main__":
    main()