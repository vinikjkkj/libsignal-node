const assert = require('assert');
const curve = require('./src/curve25519_wrapper');
const nodeCrypto = require('crypto');

const PUBLIC_KEY_DER_PREFIX = Buffer.from([
    48, 42, 48, 5, 6, 3, 43, 101, 110, 3, 33, 0
]);
  
const PRIVATE_KEY_DER_PREFIX = Buffer.from([
    48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32
]);

const generateKeyPairCrypto = function() {
    const {publicKey: publicDerBytes, privateKey: privateDerBytes} = nodeCrypto.generateKeyPairSync(
        'x25519',
        {
            publicKeyEncoding: { format: 'der', type: 'spki' },
            privateKeyEncoding: { format: 'der', type: 'pkcs8' }
        }
    );
    const pubKey = publicDerBytes.slice(PUBLIC_KEY_DER_PREFIX.length, PUBLIC_KEY_DER_PREFIX.length + 32);

    const privKey = privateDerBytes.slice(PRIVATE_KEY_DER_PREFIX.length, PRIVATE_KEY_DER_PREFIX.length + 32);

    return {
        pubKey,
        privKey
    };
};

console.log('Running tests...\n');

// Test 1: Key Generation
console.log('Test 1: Key Generation');
try {
    const privateKey = new Uint8Array(32);
    for(let i = 0; i < 32; i++) privateKey[i] = i;
    
    const keyPair = curve.keyPair(privateKey);
    assert(keyPair.pubKey instanceof ArrayBuffer, 'Public key should be ArrayBuffer');
    assert(keyPair.pubKey.byteLength === 32, 'Public key should be 32 bytes');
    assert(keyPair.privKey instanceof ArrayBuffer, 'Private key should be ArrayBuffer');
    assert(keyPair.privKey.byteLength === 32, 'Private key should be 32 bytes');
    console.log('✓ Key generation works\n');
} catch (err) {
    console.error('✗ Key generation failed:', err, '\n');
}

// Test 2: Shared Secret
console.log('Test 2: Shared Secret');
try {    
    const aliceKeyPair = generateKeyPairCrypto();
    const bobKeyPair = generateKeyPairCrypto();
    
    const aliceShared = curve.sharedSecret(bobKeyPair.pubKey, aliceKeyPair.privKey);
    const bobShared = curve.sharedSecret(aliceKeyPair.pubKey, bobKeyPair.privKey);
    
    assert(aliceShared instanceof ArrayBuffer, 'Shared secret should be ArrayBuffer');
    assert(aliceShared.byteLength === 32, 'Shared secret should be 32 bytes');
    
    // Convert ArrayBuffers to arrays for comparison
    const aliceSharedArray = Array.from(new Uint8Array(aliceShared));
    const bobSharedArray = Array.from(new Uint8Array(bobShared));
    
    assert.deepStrictEqual(aliceSharedArray, bobSharedArray, 'Shared secrets should match');
    console.log('✓ Shared secret generation works\n');
} catch (err) {
    console.error('✗ Shared secret generation failed:', err, '\n');
}

// Test 2: Shared Secret And Crypto
console.log('Test 2: Shared Secret and Crypto');
try {
    const aliceKeyPair = generateKeyPairCrypto();
    const bobKeyPair = generateKeyPairCrypto();

    const aliceSharedCurve = curve.sharedSecret(bobKeyPair.pubKey, aliceKeyPair.privKey);
    const nodePrivateKey = nodeCrypto.createPrivateKey({
        key: Buffer.concat([PRIVATE_KEY_DER_PREFIX, Buffer.from(aliceKeyPair.privKey)]),
        format: 'der',
        type: 'pkcs8'
    });
    const nodePublicKey = nodeCrypto.createPublicKey({
        key: Buffer.concat([PUBLIC_KEY_DER_PREFIX, Buffer.from(bobKeyPair.pubKey)]),
        format: 'der',
        type: 'spki'
    });
    
    const aliceSharedCrypto =nodeCrypto.diffieHellman({
        privateKey: nodePrivateKey,
        publicKey: nodePublicKey,
    });
    // Convert ArrayBuffers to arrays for comparison
    const aliceSharedArrayCurve = Array.from(new Uint8Array(aliceSharedCurve));
    const aliceSharedArrayCrypto = Array.from(new Uint8Array(aliceSharedCrypto));
    
    console.log('curveResult is:', typeof aliceSharedCurve);
    assert.deepStrictEqual(aliceSharedArrayCurve, aliceSharedArrayCrypto, 'Shared secrets should match');
    console.log('✓ Shared secret generation works\n');
} catch (err) {
    console.error('✗ Shared secret generation failed:', err, '\n');
}

// Test 3: Signing and Verification
console.log('Test 3: Signing and Verification');
try {
    const privateKey = new Uint8Array(32);
    for(let i = 0; i < 32; i++) privateKey[i] = i;
    
    const keyPair = curve.keyPair(privateKey);
    const message = new Uint8Array([1, 2, 3, 4, 5]);
    
    const signature = curve.sign(keyPair.privKey, message);
    assert(signature instanceof ArrayBuffer, 'Signature should be ArrayBuffer');
    assert(signature.byteLength === 64, 'Signature should be 64 bytes');
    
    const isValid = curve.verify(keyPair.pubKey, message, signature);
    assert(isValid === true, 'Signature verification should succeed');
    
    // Test invalid signature
    const invalidMessage = new Uint8Array([5, 4, 3, 2, 1]);
    const isInvalid = curve.verify(keyPair.pubKey, invalidMessage, signature);
    assert(isInvalid === false, 'Invalid signature verification should fail');
    
    console.log('✓ Signing and verification work\n');
} catch (err) {
    console.error('✗ Signing and verification failed:', err, '\n');
}

console.log('All tests completed!');
