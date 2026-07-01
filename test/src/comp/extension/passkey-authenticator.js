import { expect } from 'chai';
import { findExcludedPasskeys, findMatchingPasskeys } from 'comp/extension/passkey-authenticator';

const PasskeyFields = {
    credentialId: 'KPEX_PASSKEY_CREDENTIAL_ID',
    be: 'KPEX_PASSKEY_FLAG_BE',
    bs: 'KPEX_PASSKEY_FLAG_BS',
    privateKeyPem: 'KPEX_PASSKEY_PRIVATE_KEY_PEM',
    relyingParty: 'KPEX_PASSKEY_RELYING_PARTY',
    username: 'KPEX_PASSKEY_USERNAME',
    userHandle: 'KPEX_PASSKEY_USER_HANDLE'
};

function makePasskeyEntry({ credentialId, rpId = 'example.com', username = 'user' }) {
    return {
        id: credentialId,
        user: username,
        title: username,
        getAllFields() {
            return {
                [PasskeyFields.credentialId]: credentialId,
                [PasskeyFields.be]: '1',
                [PasskeyFields.bs]: '1',
                [PasskeyFields.privateKeyPem]: 'private-key',
                [PasskeyFields.relyingParty]: rpId,
                [PasskeyFields.username]: username,
                [PasskeyFields.userHandle]: `${username}-handle`
            };
        }
    };
}

function makeFile(entries) {
    return {
        forEachEntry(options, callback) {
            entries.forEach(callback);
        }
    };
}

describe('PasskeyAuthenticator', () => {
    const origin = 'https://example.com';
    const files = [
        makeFile([
            makePasskeyEntry({ credentialId: 'credential-one', username: 'one' }),
            makePasskeyEntry({ credentialId: 'credential-two', username: 'two' })
        ])
    ];

    it('keeps empty allowCredentials matching all passkeys for assertion', () => {
        const passkeys = findMatchingPasskeys(files, { rpId: 'example.com' }, origin);

        expect(passkeys.map((passkey) => passkey.credentialId)).to.eql([
            'credential-one',
            'credential-two'
        ]);
    });

    it('does not exclude same-rp passkeys when excludeCredentials is empty', () => {
        const passkeys = findExcludedPasskeys(files, { rpId: 'example.com' }, origin);

        expect(passkeys).to.eql([]);
    });

    it('excludes only passkeys listed in excludeCredentials', () => {
        const passkeys = findExcludedPasskeys(
            files,
            {
                rpId: 'example.com',
                excludeCredentials: [{ id: 'credential-two', type: 'public-key' }]
            },
            origin
        );

        expect(passkeys.map((passkey) => passkey.credentialId)).to.eql(['credential-two']);
    });
});
