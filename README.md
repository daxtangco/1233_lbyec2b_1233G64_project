# API (Archers Password Inventory)

A MATLAB-based password manager application that securely stores and manages user credentials using AES-256 encryption for passwords and SHA-256 hashing for user authentication.

## Features

- User Registration with password hashing and reset key encryption
- User Login with password verification
- Password Manager interface for storing and managing credentials
- AES-256 encryption for stored passwords
- SHA-256 hashing for user passwords
- Reset password functionality with secure key verification

## Requirements

- MATLAB (R2019b or later)
- SQLite

## Installation

1. **Clone the repository:**
    ```bash
    git clone https://github.com/daxtangco/1233_lbyec2b_1233G64_project.git
    cd 1233_lbyec2b_1233G64_project
    ```

2. **Ensure you have the required dependencies installed:**
    - MATLAB
    - SQLite

## Usage

1. **Run the password manager:**
    ```matlab
    API
    ```

2. **User Registration:**
    - Click on the 'Register' button.
    - Fill in the username, password, and confirm the password.
    - A message box will display the reset key. Copy this key for password recovery purposes.

3. **User Login:**
    - Enter your registered username and password.
    - Click on the 'Login' button to access the password manager interface.

4. **Forgot Password:**
    - Click on the 'Forgot Password' button.
    - Enter your username, reset key, new password, and confirm the new password.
    - Click on the 'Confirm' button to reset your password.

5. **Password Manager Interface:**
    - Add new credentials by entering the alias, platform, username, and password, then click 'Add'.
    - View stored credentials by selecting an entry and clicking 'Show'.
    - Edit credentials by selecting an entry, making changes, and clicking 'Edit'.
    - Delete credentials by selecting an entry and clicking 'Delete'.
    - Log out by clicking the 'Log Out' button.

## Security

- **Password Hashing:** User passwords are hashed using SHA-256 before storing in the database.
- **Encryption:** Stored passwords are encrypted using AES-256 to ensure security.
- **Reset Key:** A reset key is generated and encrypted using AES-256 for secure password recovery.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributors
Yuan Miguel Obias
Dax Axis Tangco
Aron Chaz Zuñiga

