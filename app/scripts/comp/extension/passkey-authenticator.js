import * as kdbxweb from 'kdbxweb';
import { parse as parsePublicSuffix } from 'psl';

const PasskeyFields = {
    credentialId: 'KPEX_PASSKEY_CREDENTIAL_ID',
    be: 'KPEX_PASSKEY_FLAG_BE',
    bs: 'KPEX_PASSKEY_FLAG_BS',
    privateKeyPem: 'KPEX_PASSKEY_PRIVATE_KEY_PEM',
    relyingParty: 'KPEX_PASSKEY_RELYING_PARTY',
    username: 'KPEX_PASSKEY_USERNAME',
    userHandle: 'KPEX_PASSKEY_USER_HANDLE'
};

const PasskeyErrors = {
    noMatches: '15',
    attestationNotSupported: '20',
    credentialExcluded: '21',
    invalidUrl: '25',
    originNotAllowed: '26',
    rpIdMismatch: '28',
    noSupportedAlgorithms: '29',
    unknown: '31',
    invalidChallenge: '32'
};

function findMatchingPasskeys(files, publicKey, origin) {
    const rpId = resolveRpId(publicKey, origin);
    const allowedCredentialIds = new Set(
        (publicKey.allowCredentials || [])
            .filter(isAllowedCredential)
            .map((cred) => normalizeBase64Url(cred.id))
    );

    const passkeys = [];
    for (const file of files) {
        file.forEachEntry({ includeDisabled: true }, (entry) => {
            const passkey = entryToPasskey(entry);
            if (!passkey || passkey.rpId !== rpId) {
                return;
            }
            if (
                allowedCredentialIds.size &&
                !allowedCredentialIds.has(normalizeBase64Url(passkey.credentialId))
            ) {
                return;
            }
            passkeys.push(passkey);
        });
    }
    return passkeys;
}

function findExcludedPasskeys(files, publicKey, origin) {
    const excludedCredentialIds = new Set(
        (publicKey.excludeCredentials || [])
            .filter(isAllowedCredential)
            .map((cred) => normalizeBase64Url(cred.id))
    );

    if (!excludedCredentialIds.size) {
        return [];
    }

    const rpId = resolveRpId(publicKey, origin);
    const passkeys = [];
    for (const file of files) {
        file.forEachEntry({ includeDisabled: true }, (entry) => {
            const passkey = entryToPasskey(entry);
            if (!passkey || passkey.rpId !== rpId) {
                return;
            }
            if (!excludedCredentialIds.has(normalizeBase64Url(passkey.credentialId))) {
                return;
            }
            passkeys.push(passkey);
        });
    }
    return passkeys;
}

async function createAssertionResponse(passkey, publicKey, origin) {
    if (!isValidChallenge(publicKey?.challenge)) {
        throw makePasskeyError(PasskeyErrors.invalidChallenge);
    }

    const rpId = resolveRpId(publicKey, origin);

    const clientDataJSON = JSON.stringify({
        type: 'webauthn.get',
        challenge: publicKey.challenge,
        origin,
        crossOrigin: false
    });

    const authenticatorData = await buildAuthenticatorData(rpId, passkey);
    const clientDataHash = await sha256(new TextEncoder().encode(clientDataJSON));
    const signedData = concatBytes(authenticatorData, clientDataHash);
    const signature = await signWithPrivateKey(passkey.privateKeyPem, signedData);

    return {
        id: passkey.credentialId,
        rawId: passkey.credentialId,
        type: 'public-key',
        authenticatorAttachment: 'platform',
        response: {
            authenticatorData: bytesToBase64Url(authenticatorData),
            clientDataJSON: bytesToBase64Url(new TextEncoder().encode(clientDataJSON)),
            signature: bytesToBase64Url(signature),
            userHandle: passkey.userHandle
        }
    };
}

async function createRegistrationResponse(publicKey, origin) {
    if (!isValidChallenge(publicKey?.challenge)) {
        throw makePasskeyError(PasskeyErrors.invalidChallenge);
    }
    if (!publicKey?.user?.id) {
        throw makePasskeyError(PasskeyErrors.invalidChallenge);
    }
    // if (publicKey.attestation && publicKey.attestation !== 'none') {
    //     throw makePasskeyError(PasskeyErrors.attestationNotSupported);
    // }

    const rpId = resolveRpId(
        { rpId: publicKey.rp?.id, relatedOrigins: publicKey.relatedOrigins },
        origin
    );
    const alg = selectAlgorithm(publicKey);
    const credentialId = randomBase64Url(32);
    const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
        'sign'
    ]);
    const publicKeyRaw = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
    const privateKeyPem = arrayBufferToPem(
        await crypto.subtle.exportKey('pkcs8', keyPair.privateKey)
    );

    const passkey = {
        backupEligible: true,
        backupState: true
    };
    const clientDataJSON = JSON.stringify({
        type: 'webauthn.create',
        challenge: publicKey.challenge,
        origin,
        crossOrigin: false
    });
    const authenticatorData = await buildAttestationAuthenticatorData(
        rpId,
        passkey,
        base64UrlToBytes(credentialId),
        publicKeyRaw
    );
    const attestationObject = cborEncodeMap([
        ['fmt', 'none'],
        ['attStmt', cborRaw(new Uint8Array([0xa0]))],
        ['authData', authenticatorData]
    ]);

    return {
        credential: {
            credentialId,
            privateKeyPem,
            rpId,
            username: publicKey.user.name || publicKey.user.displayName || '',
            userHandle: normalizeBase64Url(publicKey.user.id),
            backupEligible: true,
            backupState: true
        },
        response: {
            id: credentialId,
            rawId: credentialId,
            type: 'public-key',
            authenticatorAttachment: 'platform',
            response: {
                attestationObject: bytesToBase64Url(attestationObject),
                authenticatorData: bytesToBase64Url(authenticatorData),
                clientDataJSON: bytesToBase64Url(new TextEncoder().encode(clientDataJSON)),
                publicKey: bytesToBase64Url(publicKeyRaw),
                publicKeyAlgorithm: alg,
                transports: ['internal']
            }
        }
    };
}

function resolveRpId(publicKey, origin) {
    const originInfo = getOriginInfo(origin);
    const rpId = canonicalizeDomain(publicKey?.rpId || originInfo.hostname);
    validateRpId(rpId, originInfo, publicKey?.relatedOrigins || []);
    return rpId;
}

function validateOrigin(origin, rpId, relatedOrigins = []) {
    const originInfo = getOriginInfo(origin);
    validateRpId(canonicalizeDomain(rpId), originInfo, relatedOrigins);
}

function getOriginInfo(origin) {
    let url;
    try {
        url = new URL(origin);
    } catch {
        throw makePasskeyError(PasskeyErrors.invalidUrl);
    }

    if (url.protocol !== 'https:') {
        throw makePasskeyError(PasskeyErrors.originNotAllowed);
    }

    if (url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
        throw makePasskeyError(PasskeyErrors.invalidUrl);
    }

    const hostname = canonicalizeDomain(url.hostname);
    if (!hostname) {
        throw makePasskeyError(PasskeyErrors.invalidUrl);
    }
    return { origin: url.origin, hostname };
}

function validateRpId(rpId, originInfo, relatedOrigins) {
    if (!rpId) {
        throw makePasskeyError(PasskeyErrors.rpIdMismatch);
    }

    if (rpId === originInfo.hostname) {
        return;
    }

    if (isRelatedOriginAllowed(originInfo.origin, relatedOrigins) && !isPublicSuffix(rpId)) {
        return;
    }

    if (!isRegistrableDomainSuffix(rpId, originInfo.hostname)) {
        throw makePasskeyError(PasskeyErrors.rpIdMismatch);
    }
}

function isRegistrableDomainSuffix(rpId, effectiveDomain) {
    if (!effectiveDomain.endsWith(`.${rpId}`)) {
        return false;
    }
    return !isPublicSuffix(rpId);
}

function isRelatedOriginAllowed(origin, relatedOrigins) {
    return relatedOrigins.some((relatedOrigin) => {
        try {
            return getOriginInfo(relatedOrigin).origin === origin;
        } catch {
            return false;
        }
    });
}

function canonicalizeDomain(host) {
    if (!host) {
        return '';
    }
    let url;
    try {
        url = new URL(`https://${host}`);
    } catch {
        return '';
    }
    if (
        url.username ||
        url.password ||
        url.pathname !== '/' ||
        url.search ||
        url.hash ||
        url.port
    ) {
        return '';
    }
    const hostname = url.hostname.toLowerCase();
    if (!isDomain(hostname)) {
        return '';
    }
    return hostname;
}

function isDomain(hostname) {
    return (
        /^[a-z0-9.-]+$/i.test(hostname) &&
        !hostname.endsWith('.') &&
        hostname.includes('.') &&
        !isIpAddress(hostname) &&
        hostname
            .split('.')
            .every((label) => label && !label.startsWith('-') && !label.endsWith('-'))
    );
}

function isIpAddress(hostname) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.includes(':');
}

function isPublicSuffix(hostname) {
    const parsed = parsePublicSuffix(hostname);
    return Boolean(parsed.error || !parsed.domain);
}

function isAllowedCredential(cred) {
    if (!cred?.id || cred.type !== 'public-key') {
        return false;
    }
    const transports = cred.transports || [];
    return (
        !transports.length ||
        transports.includes('internal') ||
        transports.includes('usb') ||
        transports.includes('nfc')
    );
}

function isValidChallenge(challenge) {
    if (!challenge) {
        return false;
    }
    try {
        return base64UrlToBytes(challenge).length >= 16;
    } catch {
        return false;
    }
}

async function buildAuthenticatorData(rpId, passkey) {
    const rpIdHash = await sha256(new TextEncoder().encode(rpId));
    const flags =
        0x01 | 0x04 | (passkey.backupEligible ? 0x08 : 0) | (passkey.backupState ? 0x10 : 0);
    const signCount = new Uint8Array([0x00, 0x00, 0x00, 0x00]);
    return concatBytes(rpIdHash, new Uint8Array([flags]), signCount);
}

async function buildAttestationAuthenticatorData(rpId, passkey, credentialId, publicKeyRaw) {
    const rpIdHash = await sha256(new TextEncoder().encode(rpId));
    const flags =
        0x01 | 0x04 | 0x40 | (passkey.backupEligible ? 0x08 : 0) | (passkey.backupState ? 0x10 : 0);
    const signCount = new Uint8Array([0x00, 0x00, 0x00, 0x00]);
    const aaguid = new Uint8Array(16);
    const credentialIdLength = new Uint8Array([
        (credentialId.length >> 8) & 0xff,
        credentialId.length & 0xff
    ]);
    const coseKey = encodeCosePublicKey(publicKeyRaw);
    return concatBytes(
        rpIdHash,
        new Uint8Array([flags]),
        signCount,
        aaguid,
        credentialIdLength,
        credentialId,
        coseKey
    );
}

function selectAlgorithm(publicKey) {
    const hasEs256 = (publicKey.pubKeyCredParams || []).some(
        (param) => param.type === 'public-key' && Number(param.alg) === -7
    );
    if (!hasEs256) {
        throw makePasskeyError(PasskeyErrors.noSupportedAlgorithms);
    }
    return -7;
}

async function signWithPrivateKey(privateKeyPem, data) {
    const key = await crypto.subtle.importKey(
        'pkcs8',
        pemToArrayBuffer(privateKeyPem),
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign']
    );
    const signature = new Uint8Array(
        await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, data)
    );
    return signature[0] === 0x30 ? signature : ecdsaRawSignatureToDer(signature);
}

function entryToPasskey(entry) {
    const fields = entry.getAllFields();
    const credentialId = getFieldText(fields[PasskeyFields.credentialId]);
    const privateKeyPem = getFieldText(fields[PasskeyFields.privateKeyPem]);
    const rpId = getFieldText(fields[PasskeyFields.relyingParty]);
    const userHandle = getFieldText(fields[PasskeyFields.userHandle]);

    if (!credentialId || !privateKeyPem || !rpId || !userHandle) {
        return undefined;
    }

    return {
        entry,
        credentialId: normalizeBase64Url(credentialId),
        privateKeyPem,
        rpId,
        userHandle: normalizeBase64Url(userHandle),
        username: getFieldText(fields[PasskeyFields.username]) || entry.user || entry.title || '',
        backupEligible: fieldToBool(fields[PasskeyFields.be]),
        backupState: fieldToBool(fields[PasskeyFields.bs])
    };
}

function getFieldText(value) {
    if (!value) {
        return '';
    }
    return value.isProtected ? value.getText() : String(value);
}

function fieldToBool(value) {
    const text = getFieldText(value).toLowerCase();
    return text === '1' || text === 'true' || text === 'yes';
}

function passkeyToEntryFields(passkey, publicKey, { includeEntryFields = true } = {}) {
    const passkeyFields = {
        [PasskeyFields.credentialId]: kdbxweb.ProtectedValue.fromString(passkey.credentialId),
        [PasskeyFields.be]: passkey.backupEligible ? '1' : '0',
        [PasskeyFields.bs]: passkey.backupState ? '1' : '0',
        [PasskeyFields.privateKeyPem]: kdbxweb.ProtectedValue.fromString(passkey.privateKeyPem),
        [PasskeyFields.relyingParty]: passkey.rpId,
        [PasskeyFields.username]: passkey.username,
        [PasskeyFields.userHandle]: kdbxweb.ProtectedValue.fromString(passkey.userHandle)
    };

    if (!includeEntryFields) {
        return passkeyFields;
    }

    return {
        Title: publicKey.rp?.name || publicKey.rp?.id || passkey.rpId,
        UserName: passkey.username,
        Password: kdbxweb.ProtectedValue.fromString(''),
        URL: `https://${passkey.rpId}`,
        ...passkeyFields
    };
}

async function sha256(data) {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

function pemToArrayBuffer(pem) {
    const base64 = pem
        .replace(/-+BEGIN PRIVATE KEY-+/g, '')
        .replace(/-+END PRIVATE KEY-+/g, '')
        .replace(/\s+/g, '');
    return kdbxweb.ByteUtils.arrayToBuffer(kdbxweb.ByteUtils.base64ToBytes(base64));
}

function normalizeBase64Url(value) {
    return value.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function randomBase64Url(length) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytesToBase64Url(bytes);
}

function arrayBufferToPem(buffer) {
    const base64 = kdbxweb.ByteUtils.bytesToBase64(new Uint8Array(buffer));
    const lines = base64.match(/.{1,64}/g).join('\n');
    return `-----BEGIN PRIVATE KEY-----\n${lines}\n-----END PRIVATE KEY-----`;
}

function base64UrlToBytes(value) {
    const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
    return kdbxweb.ByteUtils.base64ToBytes(padded);
}

function bytesToBase64Url(bytes) {
    return kdbxweb.ByteUtils.bytesToBase64(bytes)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/g, '');
}

function concatBytes(...arrays) {
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}

function encodeCosePublicKey(publicKeyRaw) {
    return cborEncodeMap([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, publicKeyRaw.slice(1, 33)],
        [-3, publicKeyRaw.slice(33, 65)]
    ]);
}

function cborEncodeMap(entries) {
    const chunks = [cborEncodeTypeAndLength(5, entries.length)];
    for (const [key, value] of entries) {
        chunks.push(cborEncode(key));
        if (value?.cborRaw) {
            chunks.push(value.data);
        } else {
            chunks.push(cborEncode(value));
        }
    }
    return concatBytes(...chunks);
}

function cborEncode(value) {
    if (typeof value === 'number') {
        if (value >= 0) {
            return cborEncodeTypeAndLength(0, value);
        }
        return cborEncodeTypeAndLength(1, -1 - value);
    }
    if (typeof value === 'string') {
        const bytes = new TextEncoder().encode(value);
        return concatBytes(cborEncodeTypeAndLength(3, bytes.length), bytes);
    }
    if (value instanceof Uint8Array) {
        return concatBytes(cborEncodeTypeAndLength(2, value.length), value);
    }
    throw new Error('Unsupported CBOR value');
}

function cborEncodeTypeAndLength(type, length) {
    const major = type << 5;
    if (length < 24) {
        return new Uint8Array([major | length]);
    }
    if (length < 0x100) {
        return new Uint8Array([major | 24, length]);
    }
    if (length < 0x10000) {
        return new Uint8Array([major | 25, (length >> 8) & 0xff, length & 0xff]);
    }
    return new Uint8Array([
        major | 26,
        (length >> 24) & 0xff,
        (length >> 16) & 0xff,
        (length >> 8) & 0xff,
        length & 0xff
    ]);
}

function cborRaw(data) {
    return { cborRaw: true, data };
}

function ecdsaRawSignatureToDer(signature) {
    const len = signature.length / 2;
    const r = derInteger(signature.slice(0, len));
    const s = derInteger(signature.slice(len));
    return concatBytes(new Uint8Array([0x30, r.length + s.length]), r, s);
}

function derInteger(bytes) {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) {
        start++;
    }
    let value = bytes.slice(start);
    if (value[0] & 0x80) {
        value = concatBytes(new Uint8Array([0]), value);
    }
    return concatBytes(new Uint8Array([0x02, value.length]), value);
}

function makePasskeyError(code) {
    const err = new Error(`Passkeys error ${code}`);
    err.passkeyErrorCode = code;
    return err;
}

export {
    PasskeyErrors,
    createAssertionResponse,
    createRegistrationResponse,
    findExcludedPasskeys,
    findMatchingPasskeys,
    makePasskeyError,
    passkeyToEntryFields,
    validateOrigin
};
