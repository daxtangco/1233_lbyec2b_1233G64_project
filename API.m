function passwordManager()
    % Define the SQLite database file
    dbfile = 'API.db';
    
    % Create or connect to the SQLite database and user table if not exist
    if ~isfile(dbfile)
        conn = sqlite(dbfile, 'create');
        exec(conn, 'CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, reset_key TEXT)');
        exec(conn, 'CREATE TABLE IF NOT EXISTS vault (id INTEGER PRIMARY KEY, alias TEXT, platform TEXT, username TEXT, encrypted_password TEXT, user_username TEXT)');
        close(conn);
    else
        conn = sqlite(dbfile, 'connect');
        exec(conn, 'CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, reset_key TEXT)');
        exec(conn, 'CREATE TABLE IF NOT EXISTS vault (id INTEGER PRIMARY KEY, alias TEXT, platform TEXT, username TEXT, encrypted_password TEXT, user_username TEXT)');
        close(conn);
    end

    % Create main figure without toolbar and menu, set name to 'Login'
    hFig = figure('Position', centerFigure(300, 250), 'Name', 'Login', ...
                  'MenuBar', 'none', 'ToolBar', 'none', 'NumberTitle', 'off', 'CloseRequestFcn', @closeGUI);

    % Username label and field
    uicontrol('Style', 'text', 'Position', [50, 180, 60, 20], 'String', 'Username:');
    hUser = uicontrol('Style', 'edit', 'Position', [120, 180, 100, 20]);

    % Password label and field
    uicontrol('Style', 'text', 'Position', [50, 140, 60, 20], 'String', 'Password:');
    hPass = uicontrol('Style', 'edit', 'Position', [120, 140, 100, 20]);

    % Login button
    uicontrol('Style', 'pushbutton', 'Position', [120, 100, 100, 30], 'String', 'Login', ...
              'Callback', @loginCallback);

    % Register button
    uicontrol('Style', 'pushbutton', 'Position', [120, 60, 100, 30], 'String', 'Register', ...
              'Callback', @registerCallback);

    % Forgot password button
    uicontrol('Style', 'pushbutton', 'Position', [120, 20, 100, 30], 'String', 'Forgot Password', ...
              'Callback', @forgotPasswordCallback);

    % Login button callback function
    function loginCallback(~, ~)
        username = get(hUser, 'String');
        password = get(hPass, 'String');
        passwordHash = sha256hash(password);  % Hash the password
        
        % Check credentials in SQLite database
        conn = sqlite(dbfile, 'connect');
        result = fetch(conn, ['SELECT password FROM users WHERE username = ''' username '''']);
        close(conn);

        if isempty(result)
            msgboxHandle = msgbox('No such user found.', 'Error', 'error');
            uiwait(msgboxHandle);
        else
            storedPassword = result.password{1};  % Accessing the password correctly from the table
            
            if strcmp(storedPassword, passwordHash)
                msgboxHandle = msgbox('Login successful.', 'Success');
                uiwait(msgboxHandle);
                
                close(hFig);
                createPasswordManagerGUI(dbfile, username);
            else
                msgboxHandle = msgbox('Invalid username or password.', 'Error', 'error');
                uiwait(msgboxHandle);
            end
        end
    end

    % Register button callback function
    function registerCallback(~, ~)
        close(hFig); % Close the login window
        createRegisterGUI(dbfile); % Open the register window with dbfile argument
    end

    % Forgot password button callback function
    function forgotPasswordCallback(~, ~)
        close(hFig); % Close the login window
        createForgotPasswordGUI(dbfile); % Open the forgot password window with dbfile argument
    end

    % Close function to clean up
    function closeGUI(~, ~)
        delete(hFig);
    end
end

function createRegisterGUI(dbfile)
    % Create register figure without toolbar and menu, set name to 'Register'
    hFig = figure('Position', centerFigure(300, 250), 'Name', 'Register', ...
                  'MenuBar', 'none', 'ToolBar', 'none', 'NumberTitle', 'off', 'CloseRequestFcn', @closeGUI);

    % Username label and field
    uicontrol('Style', 'text', 'Position', [50, 180, 100, 20], 'String', 'Username:');
    hUser = uicontrol('Style', 'edit', 'Position', [150, 180, 100, 20]);

    % Password label and field
    uicontrol('Style', 'text', 'Position', [50, 140, 100, 20], 'String', 'Password:');
    hPass = uicontrol('Style', 'edit', 'Position', [150, 140, 100, 20]);

    % Confirm password label and field
    uicontrol('Style', 'text', 'Position', [50, 100, 100, 20], 'String', 'Confirm Password:');
    hConfirmPass = uicontrol('Style', 'edit', 'Position', [150, 100, 100, 20]);

    % Confirm button
    uicontrol('Style', 'pushbutton', 'Position', [100, 50, 100, 30], 'String', 'Confirm', ...
              'Callback', @confirmCallback);

    % Back to Login button
    uicontrol('Style', 'pushbutton', 'Position', [100, 10, 100, 30], 'String', 'Back to Login', ...
              'Callback', @backToLoginCallback);

    % Confirm button callback function
    function confirmCallback(~, ~)
        username = get(hUser, 'String');
        password = get(hPass, 'String');
        confirmPassword = get(hConfirmPass, 'String');

        if strcmp(password, confirmPassword) && ~isempty(username) && ~isempty(password)
            key = generateKey();
            keyEncrypted = aesEncrypt(key);  % Encrypt the reset key
            passwordHash = sha256hash(password);  % Hash the password

            createCopyableMsgBox({['Account created for username: ', username], ...
                                  ['Password: ', password], ...
                                  ['Your key for password reset is: ', key]}, 'Success', key);
            
            % Insert user data into SQLite database
            conn = sqlite(dbfile, 'connect');
            exec(conn, ['INSERT INTO users (username, password, reset_key) VALUES (''' username ''', ''' passwordHash ''', ''' keyEncrypted ''')']);
            close(conn);

            close(hFig); % Close the register window
            passwordManager(); % Reopen the login window
        else
            if isempty(username)
                msgboxHandle = msgbox('Username cannot be empty.', 'Error', 'error');
                uiwait(msgboxHandle);
            elseif isempty(password)
                msgboxHandle = msgbox('Password cannot be empty.', 'Error', 'error');
                uiwait(msgboxHandle);
            else
                msgboxHandle = msgbox('Passwords do not match!', 'Error', 'error');
                uiwait(msgboxHandle);
            end
        end
    end

    % Back to Login button callback function
    function backToLoginCallback(~, ~)
        close(hFig); % Close the register window
        passwordManager(); % Reopen the login window
    end

    % Close function to clean up
    function closeGUI(~, ~)
        delete(hFig);
    end
end

function createForgotPasswordGUI(dbfile)
    % Create forgot password figure without toolbar and menu, set name to 'Forgot Password'
    hFig = figure('Position', centerFigure(300, 250), 'Name', 'Forgot Password', ...
                  'MenuBar', 'none', 'ToolBar', 'none', 'NumberTitle', 'off', 'CloseRequestFcn', @closeGUI);

    % Username label and field
    uicontrol('Style', 'text', 'Position', [50, 200, 100, 20], 'String', 'Username:');
    hUser = uicontrol('Style', 'edit', 'Position', [150, 200, 100, 20]);

    % Reset key label and field
    uicontrol('Style', 'text', 'Position', [50, 160, 100, 20], 'String', 'Reset Key:');
    hResetKey = uicontrol('Style', 'edit', 'Position', [150, 160, 100, 20]);

    % New password label and field
    uicontrol('Style', 'text', 'Position', [50, 120, 100, 20], 'String', 'New Password:');
    hNewPass = uicontrol('Style', 'edit', 'Position', [150, 120, 100, 20]);

    % Confirm new password label and field
    uicontrol('Style', 'text', 'Position', [50, 80, 100, 20], 'String', 'Confirm New Password:');
    hConfirmNewPass = uicontrol('Style', 'edit', 'Position', [150, 80, 100, 20]);

    % Confirm button
    uicontrol('Style', 'pushbutton', 'Position', [50, 40, 100, 30], 'String', 'Confirm', ...
              'Callback', @confirmCallback);

    % Back to Login button
    uicontrol('Style', 'pushbutton', 'Position', [160, 40, 100, 30], 'String', 'Back to Login', ...
              'Callback', @backToLoginCallback);

    % Confirm button callback function
    function confirmCallback(~, ~)
        username = get(hUser, 'String');
        resetKey = get(hResetKey, 'String');
        newPassword = get(hNewPass, 'String');
        confirmNewPassword = get(hConfirmNewPass, 'String');

        if ~isempty(username) && ~isempty(resetKey) && ~isempty(newPassword) && strcmp(newPassword, confirmNewPassword)
            % Check reset key and old password in SQLite database
            conn = sqlite(dbfile, 'connect');
            result = fetch(conn, ['SELECT password, reset_key FROM users WHERE username = ''' username '''']);
            
            if isempty(result)
                msgboxHandle = msgbox('No such user found.', 'Error', 'error');
                uiwait(msgboxHandle);
                close(conn);
                return;
            end

            storedPassword = result.password{1};
            storedResetKeyEncrypted = result.reset_key{1};
            storedResetKey = aesDecrypt(storedResetKeyEncrypted);  % Decrypt the reset key

            if ~strcmp(resetKey, storedResetKey)
                msgboxHandle = msgbox('Invalid reset key.', 'Error', 'error');
                uiwait(msgboxHandle);
                close(conn);
                return;
            end

            if strcmp(newPassword, storedPassword)
                msgboxHandle = msgbox('New password cannot be the same as the old password.', 'Error', 'error');
                uiwait(msgboxHandle);
                close(conn);
                return;
            end

            % Update the password in the database
            newPasswordHash = sha256hash(newPassword);  % Hash the new password
            exec(conn, ['UPDATE users SET password = ''' newPasswordHash ''' WHERE username = ''' username '''']);
            close(conn);
            msgboxHandle = msgbox('Password reset successful.', 'Success');
            uiwait(msgboxHandle);

            close(hFig); % Close the forgot password window
            passwordManager(); % Reopen the login window
        else
            if isempty(username)
                msgboxHandle = msgbox('Username cannot be empty.', 'Error', 'error');
                uiwait(msgboxHandle);
            elseif isempty(resetKey)
                msgboxHandle = msgbox('Reset key cannot be empty.', 'Error', 'error');
                uiwait(msgboxHandle);
            elseif isempty(newPassword)
                msgboxHandle = msgbox('New password cannot be empty.', 'Error', 'error');
                uiwait(msgboxHandle);
            else
                msgboxHandle = msgbox('Passwords do not match!', 'Error', 'error');
                uiwait(msgboxHandle);
            end
        end
    end

    % Back to Login button callback function
    function backToLoginCallback(~, ~)
        close(hFig); % Close the forgot password window
        passwordManager(); % Reopen the login window
    end

    % Close function to clean up
    function closeGUI(~, ~)
        delete(hFig);
    end
end

function key = generateKey()
    % Generate a random key for password reset
    symbols = ['A':'Z', 'a':'z', '0':'9'];
    nums = randi(numel(symbols), [1, 8]);
    key = symbols(nums);
end

function createPasswordManagerGUI(dbfile, username)
    % Create main figure for password manager
    hFig = figure('Position', centerFigure(500, 400), 'Name', 'Password Manager', ...
                  'MenuBar', 'none', 'ToolBar', 'none', 'NumberTitle', 'off', 'CloseRequestFcn', @closeGUI);

    % Alias label and field
    uicontrol('Style', 'text', 'Position', [50, 330, 60, 20], 'String', 'Alias:');
    hAlias = uicontrol('Style', 'edit', 'Position', [120, 330, 100, 20]);

    % Platform label and field
    uicontrol('Style', 'text', 'Position', [50, 300, 60, 20], 'String', 'Platform:');
    hPlatform = uicontrol('Style', 'edit', 'Position', [120, 300, 100, 20]);

    % Username label and field
    uicontrol('Style', 'text', 'Position', [50, 270, 60, 20], 'String', 'Username:');
    hUsername = uicontrol('Style', 'edit', 'Position', [120, 270, 100, 20]);

    % Password label and field
    uicontrol('Style', 'text', 'Position', [50, 240, 60, 20], 'String', 'Password:');
    hPassword = uicontrol('Style', 'edit', 'Position', [120, 240, 100, 20]);

    % Generate button
    uicontrol('Style', 'pushbutton', 'Position', [230, 240, 80, 20], 'String', 'Generate', ...
              'Callback', @generateCallback);

    % Display area for password entries
    hDisplay = uicontrol('Style', 'listbox', 'Position', [50, 50, 400, 180], 'Max', 1, 'Min', 0, 'Value', 1);

    % Add button
    uicontrol('Style', 'pushbutton', 'Position', [50, 20, 50, 20], 'String', 'Add', ...
              'Callback', @addCallback);

    % Show button
    uicontrol('Style', 'pushbutton', 'Position', [110, 20, 50, 20], 'String', 'Show', ...
              'Callback', @showCallback);

    % Edit button
    uicontrol('Style', 'pushbutton', 'Position', [170, 20, 50, 20], 'String', 'Edit', ...
              'Callback', @editCallback);

    % Delete button
    uicontrol('Style', 'pushbutton', 'Position', [230, 20, 50, 20], 'String', 'Delete', ...
              'Callback', @deleteCallback);

    % Log out button
    uicontrol('Style', 'pushbutton', 'Position', [290, 20, 50, 20], 'String', 'Log Out', ...
              'Callback', @logoutCallback);

    % Variable to track the selected alias for editing
    selectedAlias = '';

    % Callback functions
    function generateCallback(~, ~)
        password = generatePassword();
        set(hPassword, 'String', password);
    end

    function addCallback(~, ~)
        alias = get(hAlias, 'String');
        platform = get(hPlatform, 'String');
        user = get(hUsername, 'String');
        pass = get(hPassword, 'String');
        
        if ~isempty(alias) && ~isempty(platform) && ~isempty(user) && ~isempty(pass)
            passEncrypted = aesEncrypt(pass);  % Encrypt the password
            conn = sqlite(dbfile, 'connect');
            if isempty(selectedAlias)
                % Add new entry
                exec(conn, ['INSERT INTO vault (alias, platform, username, encrypted_password, user_username) VALUES (''' alias ''', ''' platform ''', ''' user ''', ''' passEncrypted ''', ''' username ''')']);
            else
                % Update existing entry
                exec(conn, ['UPDATE vault SET alias = ''' alias ''', platform = ''' platform ''', username = ''' user ''', encrypted_password = ''' passEncrypted ''' WHERE alias = ''' selectedAlias ''' AND user_username = ''' username '''']);
                selectedAlias = '';
            end
            close(conn);
            updateDisplay();
            % Clear the input fields
            set(hAlias, 'String', '');
            set(hPlatform, 'String', '');
            set(hUsername, 'String', '');
            set(hPassword, 'String', '');
        else
            msgboxHandle = msgbox('All fields are required.', 'Error', 'error');
            uiwait(msgboxHandle);
        end
    end

    function showCallback(~, ~)
        selected = get(hDisplay, 'Value');
        data = get(hDisplay, 'String');
        if ischar(data)
            data = cellstr(data); % Convert to cell array of strings if it's a character array
        end
        if selected > 0 && ~isempty(data)
            alias = strtrim(data{selected});
            conn = sqlite(dbfile, 'connect');
            result = fetch(conn, sprintf('SELECT * FROM vault WHERE alias = ''%s'' AND user_username = ''%s''', alias, username));
            close(conn);
            if ~isempty(result)
                platform = result.platform{1};
                user = result.username{1};
                passEncrypted = result.encrypted_password{1};
                pass = aesDecrypt(passEncrypted);  % Decrypt the password
                createCopyableMsgBox({['Alias: ', alias], ...
                                      ['Platform: ', platform], ...
                                      ['Username: ', user], ...
                                      ['Password: ', pass]}, 'Password Details', pass);
            end
        end
    end

    function editCallback(~, ~)
        selected = get(hDisplay, 'Value');
        data = get(hDisplay, 'String');
        if ischar(data)
            data = cellstr(data); % Convert to cell array of strings if it's a character array
        end
        if selected > 0 && ~isempty(data)
            selectedAlias = strtrim(data{selected});
            conn = sqlite(dbfile, 'connect');
            result = fetch(conn, sprintf('SELECT * FROM vault WHERE alias = ''%s'' AND user_username = ''%s''', selectedAlias, username));
            close(conn);
            if ~isempty(result)
                set(hAlias, 'String', result.alias{1});
                set(hPlatform, 'String', result.platform{1});
                set(hUsername, 'String', result.username{1});
                set(hPassword, 'String', aesDecrypt(result.encrypted_password{1}));
            end
        end
    end

    function deleteCallback(~, ~)
        selected = get(hDisplay, 'Value');
        data = get(hDisplay, 'String');
        if ischar(data)
            data = cellstr(data); % Convert to cell array of strings if it's a character array
        end
        if selected > 0 && ~isempty(data)
            alias = strtrim(data{selected});
            conn = sqlite(dbfile, 'connect');
            exec(conn, sprintf('DELETE FROM vault WHERE alias = ''%s'' AND user_username = ''%s''', alias, username));
            close(conn);
            updateDisplay();
        end
    end

    function logoutCallback(~, ~)
        close(hFig);
        passwordManager();
    end

    function closeGUI(~, ~)
        delete(hFig);
    end

    function updateDisplay()
        conn = sqlite(dbfile, 'connect');
        data = fetch(conn, sprintf('SELECT alias FROM vault WHERE user_username = ''%s''', username));
        close(conn);
        if isempty(data)
            set(hDisplay, 'String', {}, 'Value', 1);
        else
            set(hDisplay, 'String', data.alias, 'Value', 1);
        end
    end

    function password = generatePassword()
        symbols = ['A':'Z', 'a':'z', '0':'9', '!@#$%^&*()'];
        nums = randi(numel(symbols), [1, 12]);
        password = symbols(nums);
    end

    % Initial update
    updateDisplay();
end

function createCopyableMsgBox(msg, title, key)
    % Create custom message box
    hFig = figure('Name', title, 'NumberTitle', 'off', 'MenuBar', 'none', 'ToolBar', 'none', ...
                  'Position', centerFigure(300, 150));

    % Message text (non-selectable)
    uicontrol('Style', 'text', 'Position', [20, 60, 260, 60], 'String', msg, 'HorizontalAlignment', 'left', 'Enable', 'inactive');

    % Copy button
    uicontrol('Style', 'pushbutton', 'Position', [20, 20, 100, 30], 'String', 'Copy Password', ...
              'Callback', @(~,~) copyToClipboard(key));

    % OK button
    uicontrol('Style', 'pushbutton', 'Position', [180, 20, 100, 30], 'String', 'OK', ...
              'Callback', @(~,~) close(hFig));

    uiwait(hFig);
end

function copyToClipboard(key)
    clipboard('copy', key);
    msgboxHandle = msgbox('Password copied to clipboard.', 'Success');
    uiwait(msgboxHandle);
end

function pos = centerFigure(width, height)
    screenSize = get(0, 'ScreenSize');
    x = (screenSize(3) - width) / 2;
    y = (screenSize(4) - height) / 2;
    pos = [x, y, width, height];
end

function hash = sha256hash(input)
    import java.security.*;
    md = MessageDigest.getInstance('SHA-256');
    md.update(uint8(input));
    hash = typecast(md.digest, 'uint8');
    hash = dec2hex(hash)';
    hash = lower(hash(:)');
end

function encrypted = aesEncrypt(plaintext)
    key = '12345678901234567890123456789012';  % 32-byte key for AES-256
    iv = '1234567890123456';  % 16-byte IV for AES-256

    % Convert plaintext to byte array
    plaintextBytes = uint8(plaintext);
    
    % Initialize cipher
    cipher = javax.crypto.Cipher.getInstance('AES/CBC/PKCS5Padding');
    skeySpec = javax.crypto.spec.SecretKeySpec(uint8(key), 'AES');
    ivSpec = javax.crypto.spec.IvParameterSpec(uint8(iv));
    cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, skeySpec, ivSpec);
    
    % Perform encryption
    encryptedBytes = cipher.doFinal(plaintextBytes);
    encrypted = dec2hex(typecast(encryptedBytes, 'uint8'))';
    encrypted = lower(encrypted(:)');
end

function decrypted = aesDecrypt(encrypted)
    key = '12345678901234567890123456789012';  % 32-byte key for AES-256
    iv = '1234567890123456';  % 16-byte IV for AES-256

    % Convert hex string to byte array
    encryptedBytes = uint8(hex2dec(reshape(encrypted, 2, [])'));

    % Initialize cipher
    cipher = javax.crypto.Cipher.getInstance('AES/CBC/PKCS5Padding');
    skeySpec = javax.crypto.spec.SecretKeySpec(uint8(key), 'AES');
    ivSpec = javax.crypto.spec.IvParameterSpec(uint8(iv));
    cipher.init(javax.crypto.Cipher.DECRYPT_MODE, skeySpec, ivSpec);
    
    % Perform decryption
    decryptedBytes = cipher.doFinal(encryptedBytes);
    decrypted = char(decryptedBytes');
end
