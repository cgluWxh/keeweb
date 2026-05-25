import * as kdbxweb from 'kdbxweb';
import { expect } from 'chai';
import 'util/kdbxweb/protected-value-ex';

describe('ProtectedValueEx', () => {
    it('should return a reusable composite hash', async () => {
        const hash = kdbxweb.CryptoEngine.random(32);
        const hashBase64 = kdbxweb.ByteUtils.bytesToBase64(hash);
        const credentials = kdbxweb.Credentials.fromCompositeHash(hashBase64);

        const firstHash = await credentials.getHash();
        kdbxweb.ByteUtils.zeroBuffer(firstHash);

        const secondHash = await credentials.getHash();
        expect(kdbxweb.ByteUtils.bytesToBase64(secondHash)).to.eql(hashBase64);
    });
});
