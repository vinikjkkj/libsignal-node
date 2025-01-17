const assert = require('assert');
const curve = require('./src/curve25519_wrapper');

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
    const alicePrivate = new Uint8Array(32);
    const bobPrivate = new Uint8Array(32);
    for(let i = 0; i < 32; i++) {
        alicePrivate[i] = i;
        bobPrivate[i] = 31 - i;
    }
    
    const aliceKeyPair = curve.keyPair(alicePrivate);
    const bobKeyPair = curve.keyPair(bobPrivate);
    
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

// Test 3: Signing and Verification
console.log('Test 3: Signing and Verification');
try {
    const privateKey = new Uint8Array(32);
    for(let i = 0; i < 32; i++) privateKey[i] = i;
    
    const keyPair = curve.keyPair(privateKey);
    console.log(keyPair);
    const message = new Uint8Array([1, 2, 3, 4, 5]);
    
    const signature = curve.sign(keyPair.privKey, message);
    console.log(signature);
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
