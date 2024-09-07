const bcrypt = require('bcrypt');
const saltRounds = 10;

async function hashPassword(password) {
    return await bcrypt.hash(password, saltRounds);
}

async function isPasswordValid(storedHash, inputPassword) {
    return await bcrypt.compare(inputPassword, storedHash);
}

// Test del codice
(async () => {
    const myPassword = 'Dev';
    const hashedPassword = await hashPassword(myPassword);
    console.log('Hashed Password:', hashedPassword);

    const isValid = await isPasswordValid(hashedPassword, myPassword);
    console.log('Password is valid:', isValid);
})();
const crypto = require('crypto');
const fs = require('fs');

// Funzione per decodificare la password
function unmaskPassword(maskedPassword) {
    const decipher = crypto.createDecipher('aes-256-cbc', 'a secret key');
    let password = decipher.update(maskedPassword, 'hex', 'utf8');
    password += decipher.final('utf8');
    return password;
}

// Leggi e verifica le credenziali
async function verifyCredentials(username, inputPassword) {
    const data = fs.readFileSync('users.txt', 'utf8');
    const users = data.trim().split('\n').map(line => {
        const [user, password] = line.split(' ');
        return { username: user, password };
    });

    for (const user of users) {
        if (user.username === username && unmaskPassword(user.password) === inputPassword) {
            return true;
        }
    }
    return false;
}

// Esempio di utilizzo
verifyCredentials('username', 'inputPassword').then(isValid => {
    if (isValid) {
        console.log('Credenziali valide');
    } else {
        console.log('Credenziali non valide');
    }
});

