# Syberno Password Manager

SybernoPass is an open source password management application that allows users to securely generate, store, and manage passwords. It features password generation, encryption, and decryption capabilities, and uses RSA encryption for secure password storage.

## Features

- **Generate Secure Passwords**: Create strong passwords based on keywords and dates.
- **Encrypt and Decrypt Passwords**: Use RSA encryption to keep passwords secure.
- **Password Management**: Store, view, and delete saved passwords.
- **User Authentication**: Protect access with a master passphrase.

## Technical Stack

- **Python**: Main programming language.
- **Cryptography**: For encryption and decryption (`cryptography` library).
- **Tkinter**: For the graphical user interface (GUI).

## Installation

1. **Clone the Repository**:

    ```bash
    git clone https://github.com/h3x0crypt/SybernoPass.git
    cd SybernoPass
    ```

2. **Create and Activate a Virtual Environment** (recommended):

    ```bash
    python -m venv .venv
    source .venv/bin/activate  # On Windows use `.venv\Scripts\activate`
    ```

3. **Install Dependencies**:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. **Run the Application**:

    ```bash
    python main.py
    ```

2. **Login**:
    - Enter the username and password (default: `admin` / `password`).

3. **Generate Password**:
    - Enter keywords and a date to generate a password.
    - Set a master passphrase if it's your first time running the app.

4. **View Saved Passwords**:
    - Use the "View Saved Passwords" button to see a list of saved passwords.
    - Select a password to view or delete it.

5. **Copy Password to Clipboard**:
    - Use the "Copy" button in the password details window to copy the password to the clipboard.


## License

This project is licensed under the MIT License

## Contributing

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/YourFeature`).
3. Commit your changes (`git commit -am 'Add some feature'`).
4. Push to the branch (`git push origin feature/YourFeature`).
5. Create a new Pull Request.

## Acknowledgements

- The `cryptography` library for providing robust encryption.
- The `Tkinter` library for creating the GUI.

