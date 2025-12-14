Менеджер Паролей 🔑
Простое консольное приложение для безопасного хранения паролей. Использует сильное шифрование (cryptography.fernet и PBKDF2HKDF) для защиты данных.

✨ Возможности
Безопасность: Использование надежных криптографических примитивов для защиты хранимых данных.

Консольный интерфейс: Легкий и быстрый доступ к паролям.

🚀 Как запустить
1. Требования
Для работы программы нужен Python 3.x.

2. Установка зависимостей
Проект использует внешнюю библиотеку cryptography. Ее нужно установить с помощью pip.

Bash

pip install -r requirements.txt
3. Запуск приложения
После установки зависимостей вы можете запустить менеджер паролей.

Bash

# Пример команды запуска
python main.py
🔒 Безопасность
Данные хранятся в зашифрованном виде. Для шифрования используются следующие технологии:

Генерация ключа: PBKDF2HKDF (Key Derivation Function)

Шифрование данных: cryptography.fernet (реализует аутентифицированное шифрование)

🇬🇧 English
Password Manager 🔑
A simple console application for securely storing passwords. It uses strong encryption (cryptography.fernet and PBKDF2HKDF) to protect your data.

✨ Features
Security: Utilizes robust cryptographic primitives to protect stored data.

Console Interface: Provides fast and easy access to your passwords.

🚀 Getting Started
1. Requirements
The program requires Python 3.x to run.

2. Installation of Dependencies
The project uses the external cryptography library. You need to install it using pip.

Bash

pip install -r requirements.txt
3. Running the Application
After installing the dependencies, you can launch the password manager.

Bash

# Example launch command
python main.py
🔒 Security
Data is stored in an encrypted format. The following technologies are used for encryption:

Key Generation: PBKDF2HKDF (Key Derivation Function)

Data Encryption: cryptography.fernet (implements authenticated encryption)