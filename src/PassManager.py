import os
import json
import getpass
import hashlib
import base64
from cryptography.fernet import Fernet, InvalidToken

DATA_FILE = 'passwords.enc'
SALT_FILE = 'salt.bin'
HASH_FILE = 'master_hash.bin'
ITERATIONS = 100000
KEY_LENGTH = 32

def derive_key(password, salt):
    return base64.urlsafe_b64encode(hashlib.pbkdf2_hmac('sha256', password.encode(), salt, ITERATIONS, KEY_LENGTH))

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, ITERATIONS)

def setup_master_password():
    print("Это первый запуск. Установите мастер-пароль.")
    password = getpass.getpass("Введите мастер-пароль: ")
    confirm = getpass.getpass("Подтвердите мастер-пароль: ")
    if password != confirm:
        print("Пароли не совпадают.")
        return setup_master_password()
    
    salt = os.urandom(16)
    master_hash = hash_password(password, salt)
    key = derive_key(password, salt)
    
    with open(SALT_FILE, 'wb') as f:
        f.write(salt)
    with open(HASH_FILE, 'wb') as f:
        f.write(master_hash)
    
    passwords = {}
    encrypt_data(passwords, key)
    
    print("Мастер-пароль установлен.")
    return key

def load_salt_and_hash():
    if not os.path.exists(SALT_FILE) or not os.path.exists(HASH_FILE):
        return None, None
    with open(SALT_FILE, 'rb') as f:
        salt = f.read()
    with open(HASH_FILE, 'rb') as f:
        master_hash = f.read()
    return salt, master_hash

def authenticate():
    salt, stored_hash = load_salt_and_hash()
    if salt is None:
        return setup_master_password()
    
    attempts = 3
    while attempts > 0:
        password = getpass.getpass("Введите мастер-пароль: ")
        computed_hash = hash_password(password, salt)
        if computed_hash == stored_hash:
            return derive_key(password, salt)
        else:
            attempts -= 1
            print(f"Неверный пароль. Осталось попыток: {attempts}")
    print("Превышено количество попыток.")
    exit(1)

def encrypt_data(data, key):
    fernet = Fernet(key)
    encrypted = fernet.encrypt(json.dumps(data).encode())
    with open(DATA_FILE, 'wb') as f:
        f.write(encrypted)

def decrypt_data(key):
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, 'rb') as f:
        encrypted = f.read()
    fernet = Fernet(key)
    try:
        decrypted = fernet.decrypt(encrypted).decode()
        return json.loads(decrypted)
    except InvalidToken:
        print("Ошибка расшифровки.")
        exit(1)

def main_menu(passwords, key):
    while True:
        print("\nМеню групп:")
        groups = list(passwords.keys())
        num_groups = len(groups)
        for i, group in enumerate(groups, 1):
            print(f"{i}. {group}")
        print(f"{num_groups + 1}. Создать группу")
        if num_groups > 0:
            print(f"{num_groups + 2}. Удалить группу")
            exit_option = num_groups + 3
        else:
            exit_option = num_groups + 2
        print(f"{exit_option}. Выход")
        
        try:
            choice = int(input("Выберите опцию: ").strip())
        except ValueError:
            print("Неверный выбор.")
            continue
        
        if choice == exit_option:
            break
        elif choice == num_groups + 1:
            group_name = input("Введите имя группы: ").strip()
            if group_name in passwords:
                print("Группа уже существует.")
            else:
                passwords[group_name] = {}
                print("Группа создана.")
                encrypt_data(passwords, key)
        elif num_groups > 0 and choice == num_groups + 2:
            try:
                del_index = int(input("Введите номер группы для удаления: ")) - 1
                if 0 <= del_index < num_groups:
                    group = groups[del_index]
                    del passwords[group]
                    print("Группа удалена.")
                    encrypt_data(passwords, key)
                else:
                    print("Неверный номер.")
            except ValueError:
                print("Неверный выбор.")
        elif 1 <= choice <= num_groups:
            group = groups[choice - 1]
            group_menu(passwords, group, key)
        else:
            print("Неверный выбор.")

def group_menu(passwords, group, key):
    while True:
        print(f"\nМеню паролей в группе '{group}':")
        services = list(passwords[group].keys())
        num_services = len(services)
        for i, service in enumerate(services, 1):
            print(f"{i}. {service}")
        print(f"{num_services + 1}. Добавить пароль")
        if num_services > 0:
            print(f"{num_services + 2}. Удалить пароль")
            back_option = num_services + 3
        else:
            back_option = num_services + 2
        print(f"{back_option}. Назад")
        
        try:
            choice = int(input("Выберите опцию: ").strip())
        except ValueError:
            print("Неверный выбор.")
            continue
        
        if choice == back_option:
            break
        elif choice == num_services + 1:
            service = input("Введите название сервиса: ").strip()
            if service in passwords[group]:
                print("Сервис уже существует.")
            else:
                login = input("Введите логин: ").strip()
                password = getpass.getpass("Введите пароль: ")
                passwords[group][service] = {'login': login, 'password': password}
                print("Пароль добавлен.")
                encrypt_data(passwords, key)
        elif num_services > 0 and choice == num_services + 2:
            try:
                del_index = int(input("Введите номер сервиса для удаления: ")) - 1
                if 0 <= del_index < num_services:
                    service = services[del_index]
                    del passwords[group][service]
                    print("Пароль удален.")
                    encrypt_data(passwords, key)
                else:
                    print("Неверный номер.")
            except ValueError:
                print("Неверный выбор.")
        elif 1 <= choice <= num_services:
            service = services[choice - 1]
            entry = passwords[group][service]
            print(f"Сервис: {service}")
            print(f"Логин: {entry['login']}")
            print(f"Пароль: {entry['password']}")
        else:
            print("Неверный выбор.")

if __name__ == "__main__":
    key = authenticate()
    passwords = decrypt_data(key)
    main_menu(passwords, key)
    print("Выход из программы.")