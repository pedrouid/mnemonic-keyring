// @ts-ignore
import ed25519 from 'bcrypto/lib/ed25519';
// @ts-ignore
import secp256k1 from 'bcrypto/lib/secp256k1';
import * as bip39 from 'bip39';
import * as bip32 from 'bip32';
import Store from '@pedrouid/iso-store';
import * as isoCrypto from '@pedrouid/iso-crypto';
import * as encUtils from 'enc-utils';

import { KeyPair, KeyringOptions, MasterKey } from './types';
import {
  DEFAULT_ELLIPTIC_CURVE,
  DEFAULT_ENTROPY_LENGTH,
  DEFAULT_STORE_KEY,
} from './constants';

export class MnemonicKeyring {
  public static generateMnemonic(length = DEFAULT_ENTROPY_LENGTH): string {
    const entropy = isoCrypto.randomBytes(length);
    return bip39.entropyToMnemonic(encUtils.arrayToBuffer(entropy));
  }

  public static async deriveMasterKey(mnemonic: string): Promise<MasterKey> {
    if (!bip39.validateMnemonic(mnemonic)) {
      throw new Error('Invalid mnemonic provided!');
    }
    const seed = await bip39.mnemonicToSeed(mnemonic);
    return bip32.fromSeed(seed);
  }

  public static async init(opts: KeyringOptions): Promise<MnemonicKeyring> {
    const storeKey = opts.storeKey || DEFAULT_STORE_KEY;
    const entropyLength = opts.entropyLength || DEFAULT_ENTROPY_LENGTH;
    let mnemonic: string;
    if (typeof opts.mnemonic !== 'undefined') {
      mnemonic = opts.mnemonic;
    } else {
      mnemonic =
        opts.mnemonic ||
        (await opts.store.get(storeKey)) ||
        this.generateMnemonic(entropyLength);
    }
    await opts.store.set(storeKey, mnemonic);
    const masterKey = await this.deriveMasterKey(mnemonic);
    return new MnemonicKeyring(opts.store, mnemonic, masterKey);
  }

  constructor(
    public store: Store,
    public mnemonic: string,
    public masterKey: MasterKey
  ) {
    this.store = store;
    this.mnemonic = mnemonic;
    this.masterKey = masterKey;
  }

  public getPrivateKey(derivationPath: string): string {
    return this.derivePrivateKey(this.masterKey, derivationPath);
  }

  public getPublicKey(
    derivationPath: string,
    ellipticCurve = DEFAULT_ELLIPTIC_CURVE
  ): string {
    const privateKey = this.derivePrivateKey(this.masterKey, derivationPath);
    return this.derivePublicKey(privateKey, ellipticCurve);
  }

  public getKeyPair(
    derivationPath: string,
    ellipticCurve = DEFAULT_ELLIPTIC_CURVE
  ): KeyPair {
    const privateKey = this.derivePrivateKey(this.masterKey, derivationPath);
    const publicKey = this.derivePublicKey(privateKey, ellipticCurve);
    return { privateKey, publicKey };
  }

  // ---------- Private ----------------------------------------------- //

  private derivePrivateKey(
    masterKey: MasterKey,
    derivationPath: string
  ): string {
    const hdnode = masterKey.derivePath(derivationPath);
    return encUtils.bufferToHex(hdnode.privateKey || Buffer.from([]));
  }
  private derivePublicKey(
    privateKey: string,
    ellipticCurve = DEFAULT_ELLIPTIC_CURVE
  ): string {
    let publicKey: Buffer;
    switch (ellipticCurve) {
      case 'ed25519':
        publicKey = ed25519.publicKeyCreate(
          encUtils.hexToBuffer(privateKey),
          true
        );
        break;
      case 'secp256k1':
        publicKey = secp256k1.publicKeyCreate(
          encUtils.hexToBuffer(privateKey),
          true
        );
        break;
      default:
        throw new Error(`Elliptic curve not supported: ${ellipticCurve}`);
    }
    return encUtils.bufferToHex(publicKey);
  }
}