import os
import sys
import getpass
import json
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ITERATIONS = 480000
HASH_ALGORITHM = hashes.SHA256()
SALT_SIZE = 16

CONFIG_FILE = "master_config.json"
DATA_FILE = "password_data.bin"

MASTER_CONFIG = {"salt": None, "hashed_password": None}

PASSWORD_GROUPS = {}

ENCRYPTION_KEY = None


def derive_encryption_key(password, salt):
    """
    Генерирует 32-байтный ключ, пригодный для Fernet, из мастер-пароля и соли.
    Мы используем HKDF (Key Derivation Function) для этого. Так как обычный пароль слишком короткий используем
    алгоритм HKDF и им потом шифруем базу
    """
    info = b"password_manager_key_derivation"

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
        backend=default_backend(),
    )

    raw_key = hkdf.derive(password.encode("utf-8"))

    # Fernet требует, чтобы ключ был в Base64, вот и конвертируем
    encoded_key = base64.urlsafe_b64encode(raw_key)

    return encoded_key


def encrypt_data(data):
    """Шифрует данные перед записью в файл с помощью Fernet."""
    global ENCRYPTION_KEY
    if ENCRYPTION_KEY is None:
        raise ValueError("Ключ шифрования не установлен. Это ошибка!")

    data_json = json.dumps(data).encode("utf-8")

    f = Fernet(ENCRYPTION_KEY)
    encrypted_data = f.encrypt(data_json)

    return encrypted_data


def decrypt_data(encrypted_data):
    """Расшифровывает данные из файла с помощью Fernet."""
    global ENCRYPTION_KEY
    if ENCRYPTION_KEY is None:
        raise ValueError("Ключ шифрования не установлен. Не могу расшифровать!")

    f = Fernet(ENCRYPTION_KEY)

    try:
        decrypted_json_bytes = f.decrypt(encrypted_data)
        decrypted_data = json.loads(decrypted_json_bytes.decode("utf-8"))

        return decrypted_data
    except Exception as e:
        print(
            f"Ошибка дешифрования. Возможно, неверный мастер-пароль или повреждение файла: {e}"
        )
        return None


def hash_password(password, salt=None):
    """
    Делает хэш мастер-пароля с использованием PBKDF2HMAC.
    Это специальный алгоритм, замедляющий перебор паролей.
    """
    if salt is None:
        salt = os.urandom(SALT_SIZE)

    kdf = PBKDF2HMAC(
        algorithm=HASH_ALGORITHM,
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend(),
    )
    key = kdf.derive(password.encode("utf-8"))
    return key, salt


def check_password(stored_hash, salt, entered_password):
    """Проверяет, совпадает ли введенный пароль с сохраненным хэшем."""
    try:
        kdf = PBKDF2HMAC(
            algorithm=HASH_ALGORITHM,
            length=32,
            salt=salt,
            iterations=ITERATIONS,
            backend=default_backend(),
        )
        # Если пароль совпадает, функция verify завершится без исключения.
        kdf.verify(entered_password.encode("utf-8"), stored_hash)
        return True
    except Exception:
        # Иначе, это неверный пароль.
        return False


def save_master_config(config):
    try:
        config_to_save = {
            "salt": config["salt"].hex() if config["salt"] else None,
            "hashed_password": (
                config["hashed_password"].hex() if config["hashed_password"] else None
            ),
        }

        with open(CONFIG_FILE, "w") as f:
            json.dump(config_to_save, f, indent=4)
    except Exception as e:
        print(f"Что-то пошло не так при сохранении файла конфигурации: {e}")


def load_master_config():
    global MASTER_CONFIG

    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                config_loaded = json.load(f)

            MASTER_CONFIG["salt"] = (
                bytes.fromhex(config_loaded["salt"]) if config_loaded["salt"] else None
            )
            MASTER_CONFIG["hashed_password"] = (
                bytes.fromhex(config_loaded["hashed_password"])
                if config_loaded["hashed_password"]
                else None
            )
            return True

        except Exception as e:
            print(
                f"Ошибка при загрузке или чтении файла {CONFIG_FILE}. Может, он сломался? Запустите снова."
            )
            return False

    return False


def authenticate_user():
    global MASTER_CONFIG

    if MASTER_CONFIG["hashed_password"] is None:
        print("\n--- ПЕРВЫЙ ЗАПУСК: УСТАНОВКА МАСТЕР-ПАРОЛЯ ---")

        while True:
            password = getpass.getpass(
                "Придумай мастер-пароль (минимум 8 символов): "
            ).strip()
            confirm = getpass.getpass("Повтори пароль: ").strip()

            if password == confirm and len(password) >= 8:
                hashed_pw, salt = hash_password(password)

                MASTER_CONFIG["hashed_password"] = hashed_pw
                MASTER_CONFIG["salt"] = salt

                save_master_config(MASTER_CONFIG)

                print("Мастер-пароль установлен. Добро пожаловать!")
                return True, password
            elif password != confirm:
                print("Пароли не совпадают. Попробуй еще раз.")
            else:
                print("Пароль должен быть не менее 8 символов.")

    else:
        attempts = 3
        print("\n--- ВХОД В СИСТЕМУ ---")
        for attempt in range(attempts):
            password = getpass.getpass("Введи мастер-пароль: ").strip()

            if check_password(
                MASTER_CONFIG["hashed_password"], MASTER_CONFIG["salt"], password
            ):
                print("Вход успешен. Добро пожаловать!")
                return True, password
            else:
                remaining = attempts - (attempt + 1)
                if remaining > 0:
                    print(f"Неверный пароль. Осталось попыток: {remaining}.")
                else:
                    print("Неверный пароль. Все, попытки кончились.")
                    break

        return False, None


def load_and_decrypt_database(password):
    global PASSWORD_GROUPS, ENCRYPTION_KEY

    salt = MASTER_CONFIG.get("salt")
    if salt is None:
        print("Ошибка: Соль для шифрования не найдена.")
        return False

    ENCRYPTION_KEY = derive_encryption_key(password, salt)

    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "rb") as f:
                encrypted_data = f.read()

            decrypted_data = decrypt_data(encrypted_data)

            if decrypted_data is not None:
                PASSWORD_GROUPS = decrypted_data
                print("База данных успешно загружена и расшифрована.")
                return True
            else:
                return False

        except Exception as e:
            print(f"Ошибка при чтении или дешифровании базы данных: {e}")
            return False
    else:
        PASSWORD_GROUPS = {}
        print("Файл базы данных не найден. Создана новая пустая база.")
        return True


def save_and_encrypt_database():
    global PASSWORD_GROUPS, ENCRYPTION_KEY
    if ENCRYPTION_KEY is None:
        print("Внимание: База данных не сохранена, ключ шифрования отсутствует.")
        return

    try:
        encrypted_data = encrypt_data(PASSWORD_GROUPS)

        with open(DATA_FILE, "wb") as f:
            f.write(encrypted_data)

        print(f"База данных успешно зашифрована и сохранена в {DATA_FILE}")

    except Exception as e:
        print(f"Критическая ошибка при шифровании/сохранении: {e}")


def diplay_groups():
    print("Существующие группы:")
    if not PASSWORD_GROUPS:
        print("Группы пока не созданы.")
        return 0
    for index, (group_name, entries_list) in enumerate(PASSWORD_GROUPS.items(), 1):
        count = len(entries_list)

        print(f"{index} - {group_name} ({count} записей)")

    return len(PASSWORD_GROUPS)


def get_group_by_index(index):
    group_names = list(PASSWORD_GROUPS.keys())
    if 1 <= index <= len(group_names):
        return group_names[index - 1]
    return None


def add_group():
    global PASSWORD_GROUPS
    print("\n--- СОЗДАНИЕ ГРУППЫ ---")
    new_group_name = input("Введите название новой группы: ").strip()

    if not new_group_name:
        print("Название не может быть пустым.")
        return

    if new_group_name in PASSWORD_GROUPS:
        print(f"Группа '{new_group_name}' уже существует.")
    else:
        PASSWORD_GROUPS[new_group_name] = []
        print(f"Группа '{new_group_name}' успешно создана.")


def del_group():
    global PASSWORD_GROUPS

    print("\n--- УДАЛЕНИЕ ГРУППЫ ---")
    num_groups = diplay_groups()

    if num_groups == 0:
        return

    try:
        choice = input("Введите номер группы для удаления (0 - отмена): ").strip()
        if choice == "0":
            return
        group_index = int(choice)
        group_to_delete = get_group_by_index(group_index)
        if group_to_delete:
            del PASSWORD_GROUPS[group_to_delete]
            print(f"Группа '{group_to_delete}' и все ее пароли удалены.")
        else:
            print("Неверный номер группы.")
    except ValueError:
        print("Ошибка: Введите числовой номер.")
    except Exception as e:
        print(f"Произошла ошибка при удалении: {e}")


def password_management_menu(group_name):
    current_group_data = PASSWORD_GROUPS.get(group_name, [])

    while True:
        print(f"\n=== ГРУППА: {group_name} ===")
        print("--- ЗАПИСИ ---")

        if not current_group_data:
            print("В этой группе пока нет записей.")
        else:
            print(f"{'№':<3} | {'Сервис':<15} | {'Логин':<15} | Пароль (зашифрован)")
            print("-------------------------------------------------------")

            for index, entry in enumerate(current_group_data, 1):
                service = entry["service"]
                login = entry["login"]
                password = entry["encrypted_pw"]

                print(f"{index:<3} | {service:<15} | {login:<15} | {password}")

        print("\n--- ДЕЙСТВИЯ ---")
        print("д - Добавить новую запись")
        print("у - Удалить запись")
        print("н - Назад в Главное меню")

        choice = input("Ваш выбор: ").strip()

        if choice == "н":
            return
        elif choice == "д":
            add_password_entry(group_name)
        elif choice == "у":
            del_password_entry(group_name)
        else:
            print("Неизвестная команда.")


def add_password_entry(group_name):
    global PASSWORD_GROUPS
    print(f"\n--- ДОБАВЛЕНИЕ ЗАПИСИ В ГРУППУ: {group_name} ---")
    service = input("Введите название сервиса: ").strip()
    login = input("Введите логин/имя пользователя: ").strip()
    password = getpass.getpass("Введите пароль: ").strip()

    if not (service and login and password):
        print("Все поля (сервис, логин, пароль) должны быть заполнены.")
        return
    new_entry = {"service": service, "login": login, "encrypted_pw": password}
    PASSWORD_GROUPS[group_name].append(new_entry)
    print(f"Запись для '{service}' успешно добавлена в группу '{group_name}'.")


def del_password_entry(group_name):
    current_entries = PASSWORD_GROUPS.get(group_name, [])
    if not current_entries:
        print("В этой группе нет записей для удаления.")
        return

    print("\n--- УДАЛЕНИЕ ЗАПИСИ ---")

    for index, entry in enumerate(current_entries, 1):
        print(f"{index} - {entry['service']} (Логин: {entry['login']})")

    try:
        choice = input(
            f"Введите номер записи для удаления (1-{len(current_entries)}, 0 - отмена): "
        ).strip()
        if choice == "0":
            return

        entry_index = int(choice)

        if 1 <= entry_index <= len(current_entries):
            deleted_entry = current_entries.pop(entry_index - 1)
            print(f"Запись для сервиса '{deleted_entry['service']}' успешно удалена.")
        else:
            print("Неверный номер записи.")

    except ValueError:
        print("Ошибка: Введите числовой номер.")


def main_menu():
    while True:
        print("_________________")
        print("Главное меню:")
        num_groups = diplay_groups()
        print("Введите номер группы чтобы перейти к паролям")
        print("с - Создать группу ")
        print("у - Удалить группу")
        print("в - Выход из программы")
        choice = input("Ваш выбор:").strip()
        if choice == "в":
            save_and_encrypt_database()
            sys.exit()
        elif choice == "с":
            add_group()
        elif choice == "у":
            del_group()
        elif choice.isdigit():
            try:
                group_index = int(choice)
                group_name = get_group_by_index(group_index)

                if group_name:
                    password_management_menu(group_name)
                else:
                    print("Неверный номер группы. Попробуйте снова.")
            except ValueError:
                print("Ошибка: Введите числовой номер или команду (с, у, в).")
        else:
            print("Неизвестная команда. Попробуйте снова.")


if __name__ == "__main__":
    print("__Менеджер Паролей__")

    load_master_config()

    auth_success, master_password = authenticate_user()

    if auth_success:
        if load_and_decrypt_database(master_password):
            main_menu()
        else:
            print("Критическая ошибка: Не удалось дешифровать базу данных. Выход.")
            sys.exit()
    else:
        sys.exit()
