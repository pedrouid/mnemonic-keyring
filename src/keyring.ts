// @ts-ignore
import ed25519 from 'bcrypto/lib/ed25519';
// @ts-ignore
import secp256k1 from 'bcrypto/lib/secp256k1';
// @ts-ignore
import random from 'bcrypto/lib/random';
// @ts-ignore
import base16 from 'bcrypto/lib/encoding/base16';

import * as bip39 from 'bip39';
import * as bip32 from 'bip32';

import { KeyPair, KeyringOptions, MasterKey } from './types';
import {
  DEFAULT_ELLIPTIC_CURVE,
  DEFAULT_ENTROPY_LENGTH,
  DEFAULT_STORAGE_KEY,
} from './constants';

export class MnemonicKeyring {
  public static generateMnemonic(length = DEFAULT_ENTROPY_LENGTH): string {
    return bip39.entropyToMnemonic(random.randomBytes(length));
  }

  public static async deriveMasterKey(mnemonic: string): Promise<MasterKey> {
    if (!bip39.validateMnemonic(mnemonic)) {
      throw new Error('Invalid mnemonic provided!');
    }
    const seed = await bip39.mnemonicToSeed(mnemonic);
    return bip32.fromSeed(seed);
  }

  public static async init(opts: KeyringOptions): Promise<MnemonicKeyring> {
    const storageKey = opts.storageKey || DEFAULT_STORAGE_KEY;
    const entropyLength = opts.entropyLength || DEFAULT_ENTROPY_LENGTH;
    let mnemonic: string;
    if (typeof opts.mnemonic !== 'undefined') {
      mnemonic = opts.mnemonic;
    } else {
      mnemonic =
        opts.mnemonic ||
        (typeof opts.storage !== 'undefined'
          ? await opts.storage.getItem(storageKey)
          : undefined) ||
        this.generateMnemonic(entropyLength);
    }
    if (typeof opts.storage !== 'undefined') {
      await opts.storage.setItem(storageKey, mnemonic);
    }
    const masterKey = await this.deriveMasterKey(mnemonic);
    return new MnemonicKeyring(mnemonic, masterKey);
  }

  constructor(public mnemonic: string, public masterKey: MasterKey) {
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
    return base16.encode(hdnode.privateKey || Buffer.from([]));
  }
  private derivePublicKey(
    privateKey: string,
    ellipticCurve = DEFAULT_ELLIPTIC_CURVE
  ): string {
    let publicKey: Buffer;
    switch (ellipticCurve) {
      case 'ed25519':
        publicKey = ed25519.publicKeyCreate(base16.decode(privateKey), true);
        break;
      case 'secp256k1':
        publicKey = secp256k1.publicKeyCreate(base16.decode(privateKey), true);
        break;
      default:
        throw new Error(`Elliptic curve not supported: ${ellipticCurve}`);
    }
    return base16.encode(publicKey);
  }
}
