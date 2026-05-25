import * as kdbxweb from 'kdbxweb';

const Version = 1;
const PrfSaltLength = 32;
const HkdfSaltLength = 32;
const IvLength = 12;
const ChallengeLength = 32;
const Context = 'KeeWeb WebAuthn PRF quick unlock v1';

const subtle = () => global.crypto?.subtle;
const credentials = () => global.navigator?.credentials;

function bytesToBase64(bytes) {
    return kdbxweb.ByteUtils.bytesToBase64(bytes);
}

function base64ToBytes(base64) {
    return kdbxweb.ByteUtils.base64ToBytes(base64);
}

function bytesToBase64Url(bytes) {
    return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlToBytes(base64Url) {
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    return base64ToBytes(base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '='));
}

function stringToBytes(str) {
    return kdbxweb.ByteUtils.stringToBytes(str);
}

function aadFor(blob) {
    return stringToBytes([Context, blob.origin, blob.fileId, blob.credentialId].join('|'));
}

function randomBytes(length) {
    return new Uint8Array(kdbxweb.CryptoEngine.random(length));
}

function getOrigin() {
    return global.location?.origin || 'app://keeweb';
}

async function isSupported() {
    if (!subtle() || !credentials() || !global.PublicKeyCredential) {
        return false;
    }
    if (global.PublicKeyCredential.getClientCapabilities) {
        try {
            const capabilities = await global.PublicKeyCredential.getClientCapabilities();
            return capabilities['extension:prf'] === true;
        } catch (e) {}
    }
    return false;
}

async function deriveWrappingKey(prfOutput, salt, blob) {
    const baseKey = await subtle().importKey('raw', prfOutput, 'HKDF', false, ['deriveKey']);
    return subtle().deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt,
            info: stringToBytes([Context, blob.origin, blob.fileId, 'wrap'].join('|'))
        },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function createCredential(file, params) {
    const prfSalt = randomBytes(PrfSaltLength);
    const userId = randomBytes(32);
    const publicKey = {
        challenge: randomBytes(ChallengeLength),
        rp: { name: 'KeeWeb' },
        user: {
            id: userId,
            name: file.name || 'KeeWeb database',
            displayName: file.name || 'KeeWeb database'
        },
        pubKeyCredParams: [
            { type: 'public-key', alg: -7 },
            { type: 'public-key', alg: -257 }
        ],
        authenticatorSelection: {
            residentKey: 'required',
            requireResidentKey: true,
            userVerification: 'required'
        },
        attestation: 'none',
        extensions: {
            credProps: true,
            prf: { eval: { first: prfSalt } }
        }
    };

    const credential = await credentials().create({ publicKey });
    const extensionResults = credential.getClientExtensionResults();
    const prfOutput = extensionResults.prf?.results?.first;
    if (!extensionResults.prf?.enabled || !prfOutput) {
        throw new Error('WebAuthn PRF is not supported by this credential');
    }

    return encryptUnlockBlob(file, params, credential, prfSalt, prfOutput);
}

async function encryptUnlockBlob(file, params, credential, prfSalt, prfOutput) {
    const credentialsHash = await file.db.credentials.getCompositeHash();
    const payload = stringToBytes(
        JSON.stringify({
            credentialsHash
        })
    );
    const blob = {
        v: Version,
        type: 'webauthn-prf-quick-unlock',
        origin: getOrigin(),
        fileId: file.id,
        credentialId: credential.id || bytesToBase64Url(new Uint8Array(credential.rawId)),
        prfSalt: bytesToBase64(prfSalt),
        hkdfSalt: bytesToBase64(randomBytes(HkdfSaltLength)),
        alg: 'AES-GCM-256',
        kdf: 'HKDF-SHA256',
        iv: bytesToBase64(randomBytes(IvLength))
    };
    const key = await deriveWrappingKey(prfOutput, base64ToBytes(blob.hkdfSalt), blob);
    try {
        const encrypted = await subtle().encrypt(
            { name: 'AES-GCM', iv: base64ToBytes(blob.iv), additionalData: aadFor(blob) },
            key,
            payload
        );
        blob.data = bytesToBase64(encrypted);
        return blob;
    } finally {
        kdbxweb.ByteUtils.zeroBuffer(payload);
    }
}

async function unlock(blob) {
    if (!blob || blob.v !== Version || blob.type !== 'webauthn-prf-quick-unlock') {
        throw new Error('Unsupported quick unlock blob');
    }
    if (blob.origin !== getOrigin()) {
        throw new Error('Quick unlock origin mismatch');
    }
    const credentialIdBytes = base64UrlToBytes(blob.credentialId);
    const publicKey = {
        challenge: randomBytes(ChallengeLength),
        allowCredentials: [{ type: 'public-key', id: credentialIdBytes }],
        userVerification: 'required',
        extensions: {
            prf: {
                evalByCredential: {
                    [blob.credentialId]: { first: base64ToBytes(blob.prfSalt) }
                }
            }
        }
    };
    const credential = await credentials().get({ publicKey });
    const extensionResults = credential.getClientExtensionResults();
    const prfOutput = extensionResults.prf?.results?.first;
    if (!prfOutput || credential.id !== blob.credentialId) {
        throw new Error('Quick unlock credential mismatch');
    }

    const key = await deriveWrappingKey(prfOutput, base64ToBytes(blob.hkdfSalt), blob);
    const decrypted = await subtle().decrypt(
        { name: 'AES-GCM', iv: base64ToBytes(blob.iv), additionalData: aadFor(blob) },
        key,
        base64ToBytes(blob.data)
    );
    const decryptedBytes = new Uint8Array(decrypted);
    try {
        return JSON.parse(kdbxweb.ByteUtils.bytesToString(decryptedBytes));
    } finally {
        kdbxweb.ByteUtils.zeroBuffer(decryptedBytes);
    }
}

export const QuickUnlockCrypto = { isSupported, createCredential, unlock };
