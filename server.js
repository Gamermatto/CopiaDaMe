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
