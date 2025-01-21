const crypto = require('../build/Release/signal_crypto');
const basepoint = new Uint8Array(32);
basepoint[0] = 9;

exports.keyPair = function(privKey) {
    return new Promise((resolve, reject) => {
        const priv = new Uint8Array(privKey);
        priv[0]  &= 248;
        priv[31] &= 127;
        priv[31] |= 64;

        crypto.curve25519_donna(priv, basepoint, (err, pubKey) => {
            if (err) reject(err);
            else resolve({
                pubKey: pubKey.buffer,
                privKey: priv.buffer
            });
        });
    });
};

exports.sharedSecret = function(pubKey, privKey) {
    return new Promise((resolve, reject) => {
        privKey[0]  &= 248;
        privKey[31] &= 127;
        privKey[31] |= 64;

        crypto.curve25519_donna(new Uint8Array(privKey), new Uint8Array(pubKey), (err, result) => {
            if (err) reject(err);
            else resolve(result.buffer);
        });
    });
};

exports.sign = function(privKey, message) {
    return new Promise((resolve, reject) => {
        crypto.curve25519_sign(new Uint8Array(privKey), new Uint8Array(message), (err, signature) => {
            if (err) reject(err);
            else resolve(signature.buffer);
        });
    });
};

exports.verify = function(pubKey, message, sig) {
    return new Promise((resolve, reject) => {
        crypto.curve25519_verify(new Uint8Array(sig), new Uint8Array(pubKey), new Uint8Array(message), (err, isValid) => {
            if (err) reject(err);
            else resolve(isValid);
        });
    });
};
