import * as kdbxweb from 'kdbxweb';

const Version = 1;
const Iterations = 200000;
const SaltLength = 32;
const IvLength = 12;
const Context = 'KeeWeb key file cache v1';

const subtle = () => global.crypto.subtle;

function contextBytes() {
    return kdbxweb.ByteUtils.stringToBytes(Context);
}

async function deriveKey(password, salt) {
    const passwordBytes = password.getBinary();
    try {
        const baseKey = await subtle().importKey('raw', passwordBytes, 'PBKDF2', false, [
            'deriveKey'
        ]);
        return await subtle().deriveKey(
            {
                name: 'PBKDF2',
                hash: 'SHA-256',
                salt,
                iterations: Iterations
            },
            baseKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    } finally {
        kdbxweb.ByteUtils.zeroBuffer(passwordBytes);
    }
}

async function encryptKeyFileHash(keyFileHash, password) {
    const salt = kdbxweb.CryptoEngine.random(SaltLength);
    const iv = kdbxweb.CryptoEngine.random(IvLength);
    const key = await deriveKey(password, salt);
    const data = kdbxweb.ByteUtils.stringToBytes(keyFileHash);
    try {
        const encrypted = await subtle().encrypt(
            { name: 'AES-GCM', iv, additionalData: contextBytes() },
            key,
            data
        );
        return {
            v: Version,
            alg: 'AES-GCM',
            kdf: 'PBKDF2-SHA256',
            iter: Iterations,
            salt: kdbxweb.ByteUtils.bytesToBase64(salt),
            iv: kdbxweb.ByteUtils.bytesToBase64(iv),
            data: kdbxweb.ByteUtils.bytesToBase64(encrypted)
        };
    } finally {
        kdbxweb.ByteUtils.zeroBuffer(data);
    }
}

async function decryptKeyFileHash(encryptedKeyFileHash, password) {
    if (!encryptedKeyFileHash || encryptedKeyFileHash.v !== Version) {
        throw new Error('Unsupported encrypted key file cache');
    }
    const salt = kdbxweb.ByteUtils.base64ToBytes(encryptedKeyFileHash.salt);
    const iv = kdbxweb.ByteUtils.base64ToBytes(encryptedKeyFileHash.iv);
    const data = kdbxweb.ByteUtils.base64ToBytes(encryptedKeyFileHash.data);
    const key = await deriveKey(password, salt);
    const decrypted = await subtle().decrypt(
        { name: 'AES-GCM', iv, additionalData: contextBytes() },
        key,
        data
    );
    const decryptedBytes = new Uint8Array(decrypted);
    try {
        return kdbxweb.ByteUtils.bytesToString(decryptedBytes);
    } finally {
        kdbxweb.ByteUtils.zeroBuffer(decryptedBytes);
    }
}

export { encryptKeyFileHash, decryptKeyFileHash };
