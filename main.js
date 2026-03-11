const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');

const DATA_DIR = path.join(app.getPath('appData'), 'PassSafer', 'PassSaferData');
const MASTER_HASH_FILE = path.join(DATA_DIR, '.mh');
const PIN_HASH_FILE = path.join(DATA_DIR, '.ph');
const PASSWORDS_FILE = path.join(DATA_DIR, '.pw');

let mainWindow;

// Erstelle App-Fenster
function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1000,
        height: 700,
        minWidth: 900,
        minHeight: 650,
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true,
            preload: path.join(__dirname, 'preload.js')
        },
        frame: true,
        backgroundColor: '#2d2d2d',
        icon: path.join(__dirname, '..', 'logos', 'locked.png')
    });

    mainWindow.loadFile('index.html');
    mainWindow.removeMenu(); // Menüleiste entfernen
    // Dev Tools nur in Entwicklung
    // mainWindow.webContents.openDevTools();

    // Content Security Policy
    mainWindow.webContents.session.webRequest.onHeadersReceived((details, callback) => {
        callback({
            responseHeaders: {
                ...details.responseHeaders,
                'Content-Security-Policy': ["default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';"]
            }
        });
    });
}

app.whenReady().then(async () => {
    await ensureDataDir();
    createWindow();

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) {
            createWindow();
        }
    });
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

// Stelle sicher dass Daten-Verzeichnis existiert
async function ensureDataDir() {
    try {
        await fs.mkdir(DATA_DIR, { recursive: true });
    } catch (err) {
        console.error('Error creating data directory:', err);
    }
}

// Login Attempt Tracker
class LoginAttemptTracker {
    constructor() {
        this.attempts = {}; // { username: { count, lastAttempt } }
        this.lockouts = {}; // { username: lockoutUntil }
        this.MAX_ATTEMPTS = 5;
        this.LOCKOUT_DURATION = 5 * 60 * 1000; // 5 Minutes
    }

    recordAttempt(username) {
        const now = Date.now();

        // Check if locked out
        if (this.lockouts[username]) {
            if (now < this.lockouts[username]) {
                return false; // Still locked
            } else {
                delete this.lockouts[username]; // Lockout expired
                delete this.attempts[username]; // Reset attempts after lockout
            }
        }

        if (!this.attempts[username]) {
            this.attempts[username] = { count: 0, lastAttempt: 0 };
        }

        this.attempts[username].count++;
        this.attempts[username].lastAttempt = now;

        if (this.attempts[username].count >= this.MAX_ATTEMPTS) {
            this.lockouts[username] = now + this.LOCKOUT_DURATION;
            return false;
        }

        return true;
    }

    resetAttempts(username) {
        delete this.attempts[username];
        delete this.lockouts[username];
    }

    getRemainingLockoutTime(username) {
        if (!this.lockouts[username]) return 0;
        const remaining = this.lockouts[username] - Date.now();
        return remaining > 0 ? remaining : 0;
    }
}

const loginTracker = new LoginAttemptTracker();

// Hash-Funktionen mit bcrypt-ähnlicher Sicherheit (PBKDF2)
function hashPassword(password, salt) {
    return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}

function verifyPassword(password, hash, salt) {
    const passwordHash = hashPassword(password, salt);
    // Timing-safe comparison to prevent timing attacks
    const hashBuffer = Buffer.from(hash, 'hex');
    const inputBuffer = Buffer.from(passwordHash, 'hex');
    if (hashBuffer.length !== inputBuffer.length) return false;
    return crypto.timingSafeEqual(hashBuffer, inputBuffer);
}

// Verschlüsselungs-Funktionen
function deriveKey(password, salt) {
    return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
}

function deriveExportKey(password, salt) {
    // Gleiche Parameter wie Python-Version
    return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
}

function encrypt(text, password, salt) {
    const key = deriveKey(password, salt);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decrypt(encryptedData, password, salt) {
    const key = deriveKey(password, salt);
    const parts = encryptedData.split(':');
    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

function encryptExport(text, password) {
    // Festes Salt für Export (kompatibel mit Python implementation plan)
    const exportSalt = Buffer.from('export_salt_for_passsafer_app_12345');
    const key = deriveExportKey(password, exportSalt);

    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decryptExport(encryptedData, password) {
    const exportSalt = Buffer.from('export_salt_for_passsafer_app_12345');
    const key = deriveExportKey(password, exportSalt);

    const parts = encryptedData.split(':');
    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];

    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

async function setSecurePermissions(filePath) {
    try {
        await fs.chmod(filePath, 0o600); // Read/Write for owner only
    } catch (err) {
        // Ignore errors on Windows if not supported perfectly
    }
}


// Prüfe ob erste Nutzung
ipcMain.handle('check-first-run', async () => {
    try {
        await fs.access(MASTER_HASH_FILE);
        return false; // Nicht erste Nutzung
    } catch {
        return true; // Erste Nutzung
    }
});

// Registrierung
ipcMain.handle('register', async (event, { username, password, pin }) => {
    try {
        await ensureDataDir(); // Ensure directory exists (important if account was just deleted)

        const masterSalt = crypto.randomBytes(16).toString('hex');
        const pinSalt = crypto.randomBytes(16).toString('hex');

        const masterHash = hashPassword(password, masterSalt);
        const pinHash = hashPassword(pin, pinSalt);

        await fs.writeFile(MASTER_HASH_FILE, JSON.stringify({ hash: masterHash, salt: masterSalt }));
        await setSecurePermissions(MASTER_HASH_FILE);

        await fs.writeFile(PIN_HASH_FILE, JSON.stringify({ hash: pinHash, salt: pinSalt }));
        await setSecurePermissions(PIN_HASH_FILE);

        // Initialisiere leere Passwort-Datei
        const storageSalt = crypto.randomBytes(16).toString('hex');
        const initialData = { folders: [], passwords: [] };
        const encrypted = encrypt(JSON.stringify(initialData), password, storageSalt);

        await fs.writeFile(PASSWORDS_FILE, JSON.stringify({ salt: storageSalt, data: encrypted }));
        await setSecurePermissions(PASSWORDS_FILE);

        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

// Login
ipcMain.handle('login', async (event, { username, password, pin }) => {
    try {
        // Brute Force Schutz
        if (!loginTracker.recordAttempt(username)) {
            const remaining = Math.ceil(loginTracker.getRemainingLockoutTime(username) / 1000);
            const minutes = Math.floor(remaining / 60);
            const seconds = remaining % 60;
            return { success: false, error: `Zu viele Versuche. Bitte warte ${minutes}m ${seconds}s.` };
        }

        const masterData = JSON.parse(await fs.readFile(MASTER_HASH_FILE, 'utf8'));
        const pinData = JSON.parse(await fs.readFile(PIN_HASH_FILE, 'utf8'));

        const masterValid = verifyPassword(password, masterData.hash, masterData.salt);
        const pinValid = verifyPassword(pin, pinData.hash, pinData.salt);

        if (masterValid && pinValid) {
            loginTracker.resetAttempts(username);
            return { success: true };
        } else {
            return { success: false, error: 'Ungültige Zugangsdaten' };
        }
    } catch (error) {
        return { success: false, error: error.message };
    }
});

// Lade Passwörter
ipcMain.handle('load-passwords', async (event, { password }) => {
    try {
        const fileData = JSON.parse(await fs.readFile(PASSWORDS_FILE, 'utf8'));
        const decryptedData = decrypt(fileData.data, password, fileData.salt);
        const parsedData = JSON.parse(decryptedData);

        return {
            success: true,
            data: parsedData.passwords || parsedData.data || [],
            folders: parsedData.folders || []
        };
    } catch (error) {
        return { success: false, error: error.message, data: [], folders: [] };
    }
});

// Speichere Passwörter
ipcMain.handle('save-passwords', async (event, { password, passwords, folders }) => {
    try {
        const fileData = JSON.parse(await fs.readFile(PASSWORDS_FILE, 'utf8'));
        const salt = fileData.salt;

        const dataToSave = { passwords, folders };
        const encrypted = encrypt(JSON.stringify(dataToSave), password, salt);

        await fs.writeFile(PASSWORDS_FILE, JSON.stringify({ salt, data: encrypted }));
        await setSecurePermissions(PASSWORDS_FILE);

        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

// PIN ändern
ipcMain.handle('change-pin', async (event, { currentPassword, currentPin, newPin }) => {
    try {
        // Verifiziere aktuelle Credentials
        const masterData = JSON.parse(await fs.readFile(MASTER_HASH_FILE, 'utf8'));
        const pinData = JSON.parse(await fs.readFile(PIN_HASH_FILE, 'utf8'));

        const masterValid = verifyPassword(currentPassword, masterData.hash, masterData.salt);
        const pinValid = verifyPassword(currentPin, pinData.hash, pinData.salt);

        if (!masterValid || !pinValid) {
            return { success: false, error: 'Ungültige Zugangsdaten' };
        }

        // Speichere neuen PIN
        const newPinSalt = crypto.randomBytes(16).toString('hex');
        const newPinHash = hashPassword(newPin, newPinSalt);

        await fs.writeFile(PIN_HASH_FILE, JSON.stringify({ hash: newPinHash, salt: newPinSalt }));
        await setSecurePermissions(PIN_HASH_FILE);

        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

// Master-Passwort ändern
ipcMain.handle('change-password', async (event, { currentPassword, currentPin, newPassword }) => {
    try {
        // Verifiziere aktuelle Credentials
        const masterData = JSON.parse(await fs.readFile(MASTER_HASH_FILE, 'utf8'));
        const pinData = JSON.parse(await fs.readFile(PIN_HASH_FILE, 'utf8'));

        const masterValid = verifyPassword(currentPassword, masterData.hash, masterData.salt);
        const pinValid = verifyPassword(currentPin, pinData.hash, pinData.salt);

        if (!masterValid || !pinValid) {
            return { success: false, error: 'Ungültige Zugangsdaten' };
        }

        // Lade und entschlüssele Daten mit altem Passwort
        const fileData = JSON.parse(await fs.readFile(PASSWORDS_FILE, 'utf8'));
        const decryptedData = decrypt(fileData.data, currentPassword, fileData.salt);

        // Speichere neues Master-Passwort Hash
        const newMasterSalt = crypto.randomBytes(16).toString('hex');
        const newMasterHash = hashPassword(newPassword, newMasterSalt);
        await fs.writeFile(MASTER_HASH_FILE, JSON.stringify({ hash: newMasterHash, salt: newMasterSalt }));
        await setSecurePermissions(MASTER_HASH_FILE);

        // Re-verschlüssele Daten mit neuem Passwort
        const newStorageSalt = crypto.randomBytes(16).toString('hex');
        const encrypted = encrypt(decryptedData, newPassword, newStorageSalt);
        await fs.writeFile(PASSWORDS_FILE, JSON.stringify({ salt: newStorageSalt, data: encrypted }));
        await setSecurePermissions(PASSWORDS_FILE);

        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

// Export Passwords
ipcMain.handle('export-passwords', async (event, { password, filePath, data }) => {
    try {
        // Validate file extension
        if (!filePath.toLowerCase().endsWith('.pass')) {
            return { success: false, error: 'Invalid file type. Only .pass files are allowed.' };
        }
        // Verschlüssele Daten mit Export-Passwort und festem Salt
        const encrypted = encryptExport(JSON.stringify(data), password);
        await fs.writeFile(filePath, encrypted);
        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

// Import Passwords
ipcMain.handle('import-passwords', async (event, { password, filePath }) => {
    try {
        // Validate file extension
        if (!filePath.toLowerCase().endsWith('.pass')) {
            return { success: false, error: 'Invalid file type. Only .pass files are allowed.' };
        }
        const fileContent = await fs.readFile(filePath, 'utf8');
        const decrypted = decryptExport(fileContent, password);
        const data = JSON.parse(decrypted);
        return { success: true, data };
    } catch (error) {
        return { success: false, error: 'Import failed: Incorrect password or corrupted file' };
    }
});

// Account löschen
ipcMain.handle('delete-account', async (event, { password }) => {
    try {
        // Verifiziere Passwort vor dem Löschen
        const masterData = JSON.parse(await fs.readFile(MASTER_HASH_FILE, 'utf8'));
        const masterValid = verifyPassword(password, masterData.hash, masterData.salt);

        if (!masterValid) {
            return { success: false, error: 'Invalid password' };
        }

        // Lösche alle Daten
        await fs.unlink(MASTER_HASH_FILE);
        await fs.unlink(PIN_HASH_FILE);
        await fs.unlink(PASSWORDS_FILE);

        // Optional: Lösche Data Directory wenn leer
        try {
            await fs.rmdir(DATA_DIR);
        } catch (e) {
            // Ignorieren wenn nicht leer
        }

        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

// Path safety check - prevent access to critical system directories
function isPathSafe(filePath) {
    const resolved = path.resolve(filePath);
    const dangerous = [
        path.join(process.env.SystemRoot || 'C:\\Windows'),
        path.join(process.env.ProgramFiles || 'C:\\Program Files'),
        path.join(process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)'),
        DATA_DIR // Protect own data directory
    ].map(p => p.toLowerCase());
    const resolvedLower = resolved.toLowerCase();
    return !dangerous.some(d => resolvedLower.startsWith(d));
}

// Read File (for file attachment upload)
ipcMain.handle('read-file', async (event, filePath) => {
    try {
        if (!isPathSafe(filePath)) {
            return { success: false, error: 'Access to this location is not allowed.' };
        }
        const stats = await fs.stat(filePath);
        const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100 MB
        if (stats.size > MAX_FILE_SIZE) {
            return { success: false, error: `File too large. Maximum size is 100 MB.` };
        }
        const buffer = await fs.readFile(filePath);
        const base64 = buffer.toString('base64');
        const fileName = path.basename(filePath);
        return { success: true, data: base64, fileName };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

// Write File (for file attachment download)
ipcMain.handle('write-file', async (event, { filePath, data }) => {
    try {
        if (!isPathSafe(filePath)) {
            return { success: false, error: 'Access to this location is not allowed.' };
        }
        const buffer = Buffer.from(data, 'base64');
        await fs.writeFile(filePath, buffer);
        return { success: true };
    } catch (error) {
        return { success: false, error: error.message };
    }
});

// Show Save Dialog
ipcMain.handle('show-save-dialog', async (event, options) => {
    const result = await dialog.showSaveDialog(mainWindow, options);
    return result;
});

// Show Open Dialog
ipcMain.handle('show-open-dialog', async (event, options) => {
    const result = await dialog.showOpenDialog(mainWindow, options);
    return result;
});
