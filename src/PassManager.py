import os
import sys
import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import json

ITERATIONS = 480000 
HASH_ALGORITHM = hashes.SHA256()
SALT_SIZE = 16 

CONFIG_FILE = 'master_config.json'

MASTER_CONFIG = {
    "salt": None, 
    "hashed_password": None 
}

PASSWORD_GROUPS = {
    "Социальные сети": [
        {
            "service": "VK",
            "login": "my_vk_login",
            "encrypted_pw": "124dfv3"
        },
        {
            "service": "Reddit",
            "login": "my_redditor",
            "encrypted_pw": "gfgdgsdf"
        }
    ],
    "Работа": [
        {
            "service": "Рабочий комп",
            "login": "admin_user",
            "encrypted_pw": "124fd3f3"
        }
    ],
    "Личное": []
}

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(SALT_SIZE) 
        
    kdf = PBKDF2HMAC(
        algorithm=HASH_ALGORITHM,
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    return key, salt

def save_master_config(config):
    """Сохраняет словарь MASTER_CONFIG в файл в формате JSON."""
    try:
        config_to_save = {
            "salt": config["salt"].hex() if config["salt"] else None,
            "hashed_password": config["hashed_password"].hex() if config["hashed_password"] else None
        }

        with open(CONFIG_FILE, 'w') as f:
            json.dump(config_to_save, f, indent=4)
    except Exception as e:
        print(f"Ошибка сохранения файла конфигурации: {e}")

def check_password(stored_hash, salt, entered_password):
    """Проверяет введенный пароль, сравнивая его хэш с сохраненным."""
    try:
        kdf = PBKDF2HMAC(
            algorithm=HASH_ALGORITHM,
            length=32,
            salt=salt,
            iterations=ITERATIONS,
            backend=default_backend()
        )
        kdf.verify(entered_password.encode('utf-8'), stored_hash)
        return True
    except Exception:
        return False

def load_master_config():
    """Загружает словарь MASTER_CONFIG из файла."""
    global MASTER_CONFIG
    
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                config_loaded = json.load(f)
            
            MASTER_CONFIG["salt"] = bytes.fromhex(config_loaded["salt"]) if config_loaded["salt"] else None
            MASTER_CONFIG["hashed_password"] = bytes.fromhex(config_loaded["hashed_password"]) if config_loaded["hashed_password"] else None
            return True
        
        except Exception as e:
            print(f"Ошибка при загрузке или чтении файла {CONFIG_FILE}. Запустите снова.")
            return False
    
    return False 

def authenticate_user():
    global MASTER_CONFIG
    
    if MASTER_CONFIG["hashed_password"] is None:
        print("\n--- ПЕРВЫЙ ЗАПУСК: УСТАНОВКА МАСТЕР-ПАРОЛЯ ---")
        
        while True:
            password = getpass.getpass("Введите новый мастер-пароль (минимум 8 символов): ").strip()
            confirm = getpass.getpass("Повторите пароль: ").strip()
            
            if password == confirm and len(password) >= 8:
                hashed_pw, salt = hash_password(password)
                
                MASTER_CONFIG["hashed_password"] = hashed_pw
                MASTER_CONFIG["salt"] = salt
                
                save_master_config(MASTER_CONFIG)
                
                print("Мастер-пароль успешно установлен. Добро пожаловать!")
                return True
            elif password != confirm:
                print("Пароли не совпадают. Попробуйте снова.")
            else:
                print("Пароль должен быть не менее 8 символов.")
                
    else:
        attempts = 3
        print("\n--- ВХОД В СИСТЕМУ ---")
        for attempt in range(attempts):
            password = getpass.getpass("\n---Введите мастер-пароль: ").strip()
            
            if check_password(MASTER_CONFIG["hashed_password"], MASTER_CONFIG["salt"], password):
                print("Вход успешен. Добро пожаловать!")
                return True
            else:
                remaining = attempts - (attempt + 1)
                if remaining > 0:
                    print(f"Неверный пароль. Осталось попыток: {remaining}.")
                else:
                    print("Неверный пароль. Все попытки исчерпаны.")
                    break

        return False

def diplay_groups():
    print("Сущестующие группы:")
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
        if choice == '0':
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
            print(f"{'№':<3} | {'Сервис':<15} | {'Логин':<15} | Пароль")
            print("-------------------------------------------------------")
            
            for index, entry in enumerate(current_group_data, 1):
                service = entry['service']
                login = entry['login']
                password = entry['encrypted_pw'] 
                
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
    password = input("Введите пароль: ").strip() 
    if not (service and login and password):
        print("Все поля (сервис, логин, пароль) должны быть заполнены.")
        return
    new_entry = {
        "service": service,
        "login": login,
        "encrypted_pw": password 
    }
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
        choice = input(f"Введите номер записи для удаления (1-{len(current_entries)}, 0 - отмена): ").strip()
        if choice == '0':
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
    if authenticate_user():
        main_menu()
    else:
        sys.exit()