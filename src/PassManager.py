import os
import sys

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
    """Удаляет группу из глобального словаря PASSWORD_GROUPS."""
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

def main_menu():
    while True:
        print("_________________")
        print("Главное меню:")
        diplay_groups()
        print("Введите номер группы чтобы перейти к паролям")
        print("с - Создать группу ")
        print("у - Удалить группу")
        print("в - Выход из программы")
        choice = input("Ваш выбор:")
        if choice == "в":
            sys.exit()
        elif choice == "с":
            add_group()
        elif choice == "у":
            del_group()


if __name__ == "__main__":
    print("__Менеджер Паролей__")
    main_menu()