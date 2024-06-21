// vim: ts=4:sw=4

'use strict';

const sodium = require('libsodium-wrappers')
const assert = require('assert');

function assertBuffer(value) {
    if (!(value instanceof Buffer)) {
        throw TypeError(`Expected Buffer instead of: ${value.constructor.name}`);
    }
    return value;
}

function encrypt(key, data, iv) {
    const cipherText = sodium.crypto_secretbox_easy(data, iv, key);
    return Buffer.from(cipherText);
}

function decrypt(key, cipherText, iv) {
    const decryptedData = sodium.crypto_secretbox_open_easy(cipherText, iv, key);
    return Buffer.from(decryptedData);
}


function calculateMAC(key, data) {
    if (key.length !== sodium.crypto_auth_KEYBYTES) {
        throw new Error('Chave incorreta');
    }

    const mac = sodium.crypto_auth(data, key);
    return Buffer.from(mac);
}


function hash(data) {
    const hash = sodium.crypto_generichash(data);
    return Buffer.from(hash);
}


// Salts always end up being 32 bytes
function deriveSecrets(input, salt, info, chunks) {
    if (salt.length !== sodium.crypto_generichash_BYTES) {
        throw new Error('Salt incorreto');
    }

    chunks = chunks || 3;
    if (chunks < 1 || chunks > 3) {
        throw new Error('Chunks deve ser um número entre 1 e 3');
    }

    const PRK = sodium.crypto_generichash(sodium.crypto_generichash_BYTES, input, salt);
    const derivedSecrets = [];

    for (let i = 1; i <= chunks; i++) {
        const infoArray = Buffer.concat([info, Buffer.from([i])]);
        const derivedSecret = sodium.crypto_generichash(sodium.crypto_generichash_BYTES, infoArray, PRK);

        derivedSecrets.push(Buffer.from(derivedSecret));
    }

    return derivedSecrets;
}

function verifyMAC(data, key, mac, length) {
    const calculatedMac = calculateMAC(key, data).slice(0, length);
    if (mac.length !== length || calculatedMac.length !== length) {
        throw new Error("Bad MAC length");
    }
    if (!mac.equals(calculatedMac)) {
        throw new Error("Bad MAC");
    }
}

module.exports = {
    deriveSecrets,
    decrypt,
    encrypt,
    hash,
    calculateMAC,
    verifyMAC
};