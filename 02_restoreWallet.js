import { mnemonicToEntropy } from "ethereum-cryptography/bip39";
import { wordlist } from "ethereum-cryptography/bip39/wordlists/english";
import { HDKey } from "ethereum-cryptography/hdkey";
import { secp256k1 } from "ethereum-cryptography/secp256k1";
import { keccak256 } from "ethereum-cryptography/keccak";
import { bytesToHex } from "ethereum-cryptography/utils";
import { writeFileSync } from "fs";

async function main(_mnemonic) {
    const entropy = mnemonicToEntropy(_mnemonic, wordlist);
    const hdRootKey = HDKey.fromMasterSeed(entropy);
    const privateKey = hdRootKey.deriveChild(0).privateKey;
    const publicKey = secp256k1.getPublicKey(privateKey);
    const address = keccak256(publicKey).slice(-20);

    console.log(`Account One Wallet Address: 0x${bytesToHex(address)}`);
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

main(process.argv[2])
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    })