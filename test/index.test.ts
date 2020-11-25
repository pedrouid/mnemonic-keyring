import Store from '@pedrouid/iso-store';

import MnemonicKeyring from '../src';

const TEST_DERIVATION_PATH = "m/44'/60'/0'/0";
const TEST_MNEMMONIC =
  'journey mango dad alert garlic arrange twist van unlock anger erode agent';
const TEST_PRIVATE_KEY =
  '7aa5106365e135cf235a256c31d7a61c3fbd1dc1000a5ef85a831e218d7ff2eb';
const TEST_PUBLIC_KEY = {
  secp256k1:
    '0269399482c45f2a286efe1892a7f2b4d3ea37dc65bb24532bc7f4f1c08a882658',
  ed25519: '9305925ba7f481dc73faf5d35e127d7d36b6ab0db68c7a77dafa0a543602f1e8',
};

describe('MnemonicKeyring', () => {
  let keyring: MnemonicKeyring;
  beforeAll(async () => {
    const store = new Store();
    await store.init();
    keyring = await MnemonicKeyring.init({
      mnemonic: TEST_MNEMMONIC,
      store,
    });
  });
  it('init', async () => {
    expect(keyring).toBeTruthy();
  });
  it('default keyPair', async () => {
    const keyPair = keyring.getKeyPair(TEST_DERIVATION_PATH);
    expect(keyPair.privateKey).toEqual(TEST_PRIVATE_KEY);
    expect(keyPair.publicKey).toEqual(TEST_PUBLIC_KEY['secp256k1']);
  });
  it('secp256k1 keyPair', async () => {
    const keyPair = keyring.getKeyPair(TEST_DERIVATION_PATH, 'secp256k1');
    expect(keyPair.privateKey).toEqual(TEST_PRIVATE_KEY);
    expect(keyPair.publicKey).toEqual(TEST_PUBLIC_KEY['secp256k1']);
  });
  it('ed25519 keyPair', async () => {
    const keyPair = keyring.getKeyPair(TEST_DERIVATION_PATH, 'ed25519');
    expect(keyPair.privateKey).toEqual(TEST_PRIVATE_KEY);
    expect(keyPair.publicKey).toEqual(TEST_PUBLIC_KEY['ed25519']);
  });
});
