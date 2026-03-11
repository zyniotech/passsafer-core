const { contextBridge, ipcRenderer } = require('electron');

// Expose geschützte IPC-Methoden an Renderer
contextBridge.exposeInMainWorld('api', {
    checkFirstRun: () => ipcRenderer.invoke('check-first-run'),
    register: (data) => ipcRenderer.invoke('register', data),
    login: (data) => ipcRenderer.invoke('login', data),
    loadPasswords: (data) => ipcRenderer.invoke('load-passwords', data),
    savePasswords: (data) => ipcRenderer.invoke('save-passwords', data),
    changePin: (data) => ipcRenderer.invoke('change-pin', data),
    changePassword: (data) => ipcRenderer.invoke('change-password', data),
    exportPasswords: (data) => ipcRenderer.invoke('export-passwords', data),
    importPasswords: (data) => ipcRenderer.invoke('import-passwords', data),
    deleteAccount: (data) => ipcRenderer.invoke('delete-account', data),
    readFile: (filePath) => ipcRenderer.invoke('read-file', filePath),
    writeFile: (data) => ipcRenderer.invoke('write-file', data),
    showSaveDialog: (options) => ipcRenderer.invoke('show-save-dialog', options),
    showOpenDialog: (options) => ipcRenderer.invoke('show-open-dialog', options)
});
