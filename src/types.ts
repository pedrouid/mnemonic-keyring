import { IKeyValueStorage } from 'keyvaluestorage';
import * as bip32 from 'bip32';

export interface KeyringOptions {
  storage?: IKeyValueStorage;
  storageKey?: string;
  mnemonic?: string;
  entropyLength?: number;
}

export type MasterKey = bip32.BIP32Interface;

export interface KeyPair {
  privateKey: string;
  publicKey: string;
}
