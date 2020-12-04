import Store from '@pedrouid/iso-store';
import * as bip32 from 'bip32';

export interface KeyringOptions {
  store?: Store;
  storeKey?: string;
  mnemonic?: string;
  entropyLength?: number;
}

export type MasterKey = bip32.BIP32Interface;

export interface KeyPair {
  privateKey: string;
  publicKey: string;
}
