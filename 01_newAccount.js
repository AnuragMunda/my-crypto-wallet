import { generateMnemonic, mnemonicToEntropy } from "ethereum-cryptography/bip39";
import { wordlist } from "ethereum-cryptography/bip39/wordlists/english";
import { HDKey } from "ethereum-cryptography/hdkey";
import { secp256k1 } from "ethereum-cryptography/secp256k1";
import { keccak256 } from "ethereum-cryptography/keccak";
import { bytesToHex } from "ethereum-cryptography/utils";
import { writeFileSync } from "fs";

function _generateMnemonic() {
    const strength = 256; // 256 bit, 24 words; default is 128 bits, 12 words
    const mnemonic = generateMnemonic(wordlist, strength);
    const entropy = mnemonicToEntropy(mnemonic, wordlist);
    return { mnemonic, entropy };
}

function _getHdRootKey(_mnemonic) {
    return HDKey.fromMasterSeed(_mnemonic);
}

function _generatePrivateKey(_hdRootKey, _accountIndex) {
    return _hdRootKey.deriveChild(_accountIndex).privateKey;
}

function _getPublicKey(_privateKey) {
    return secp256k1.getPublicKey(_privateKey);
}

function _getEthAddress(_publicKey) {
    return keccak256(_publicKey).slice(-20);
}

async function main() {
    const { mnemonic, entropy } = _generateMnemonic();
    console.log(`WARNING! Never disclose your Seed Phrase:\n ${mnemonic}`);

    const hdRootKey = _getHdRootKey(entropy);
    const accountOneIndex = 0;
    const accountOnePrivateKey = _generatePrivateKey(hdRootKey, accountOneIndex);
    const accountOnePublicKey = _getPublicKey(accountOnePrivateKey);
    const accountOneEthAddress = _getEthAddress(accountOnePublicKey);
    console.log(`Account One Wallet Address: 0x${bytesToHex(accountOneEthAddress)}`);
}

function _store(_privateKey, _publicKey, _address) {
    const accountOne = {
        privateKey: _privateKey,
        publicKey: _publicKey,
        address: _address,
    };

    const accountOneData = JSON.stringify(accountOne);
    writeFileSync("account 1.json", accountOneData);
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.log(error);
        process.exit(1);
    });