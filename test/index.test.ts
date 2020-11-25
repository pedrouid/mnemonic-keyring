import Store from '@pedrouid/iso-store';
import MnemonicKeyring from '../src';

const TEST_DERIVATION_PATH = "m/44'/60'/0'/0";
const TEST_MNEMMONIC =
  'rate table empower climb pretty pioneer reward exotic kid sugar knock dilemma';
const TEST_PRIVATE_KEY =
  '529faf0565e7d08a0cde2d8483414888ebb2b30d7bbb34aeecd305217265bd56';
const TEST_PUBLIC_KEY = {
  secp256k1:
    '03f71b9a7cae7c46bcd3af9da52b3f944efbfd7425f2d7732645b1a9739b66f746',
  ed25519: '0e5f32968c4a1babe2d96efd7e74212a166c955cd2676f409802eccfb2f5c943',
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
  it('default keypair', async () => {
    const keyPair = keyring.getKeyPair(TEST_DERIVATION_PATH);
    expect(keyPair.privateKey).toEqual(TEST_PRIVATE_KEY);
    expect(keyPair.publicKey).toEqual(TEST_PUBLIC_KEY['secp256k1']);
  });
  it('secp256k1 keypair', async () => {
    const keyPair = keyring.getKeyPair(TEST_DERIVATION_PATH, 'secp256k1');
    expect(keyPair.privateKey).toEqual(TEST_PRIVATE_KEY);
    expect(keyPair.publicKey).toEqual(TEST_PUBLIC_KEY['secp256k1']);
  });
  it('ed25519 keypair', async () => {
    const keyPair = keyring.getKeyPair(TEST_DERIVATION_PATH, 'ed25519');
    expect(keyPair.privateKey).toEqual(TEST_PRIVATE_KEY);
    expect(keyPair.publicKey).toEqual(TEST_PUBLIC_KEY['ed25519']);
  });
});
