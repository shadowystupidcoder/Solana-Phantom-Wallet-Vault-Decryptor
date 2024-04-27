import { pbkdf2 } from 'crypto';
import nacl from "tweetnacl"
import * as b39 from "bip39"
import { derivePath } from "ed25519-hd-key"
import * as bip32 from "bip32"
import { Keypair, Account } from "@solana/web3.js"
import bs58 from 'bs58';

//add every vault you can find to this list and hit run, it will handle decrypting the private keys and mnemonic(s) for both old and new vault versions.
//doesnt matter how long the "encrypted" string is, it will just try every combo and one will work probably


const datas = [
{
  "encrypted": "9K5j1E36kS...",
  "iterations": 10000,
  "kdf": "pbkdf2",
  "nonce": "ANmAvaghvjbc2P29nbbQBiG51aJUjQfdV",
  "salt": "8gKXzUD5TpgsUrC8Q6ngbP"
},
{
  "encrypted": "52NGCM7....",
  "iterations": 10000,
  "kdf": "pbkdf2",
  "nonce": "MoCz38t18wQEomFvjs273SDs42t9FM8nZ",
  "salt": "BP6umCZwT6NPxnwFEjMkMY"
},
{
  "encrypted": "4DvKmf29xBnz6kS399rry74MrrYMcCak9......",
  "iterations": 10000,
  "kdf": "pbkdf2",
  "nonce": "8EhKBz4WSr8RRNEKyrqkTEXYevBvMucpq",
  "salt": "V6BUQtkRC9pwnert3k5gNP"
},
{
  "encrypted": "332G5eBwiLKPfub2....",
  "iterations": 10000,
  "kdf": "pbkdf2",
  "nonce": "kNFw5SDgFEpCDv7MAdb6WaoDuECB6Ws9",
  "salt": "WoyDUK7DTdyaBKsGd8ojGu"
},
{
  "encrypted": "3KWYcPD5Pp8H.....",
  "iterations": 10000,
  "kdf": "pbkdf2",
  "nonce": "4PKAAkwy3Q4mbq74Mh325q2ukiL1UVf5n",
  "salt": "RMY3KKguZ2u4dhV2TqW7xo"
}]


for (const each of datas) {
for (const eac of datas) {
try {
const salt = bs58.decode(each.salt);
const nonce = bs58.decode(each.nonce);
const encrypted = bs58.decode(each.encrypted);
const key = await deriveEncryptionKey(Buffer.from("aaaaaaaa"), salt);
const decryptedKey = nacl.secretbox.open(encrypted, nonce, key);
const salt2 = bs58.decode(eac.salt);
const nonce2 = bs58.decode(eac.nonce);
const encrypted2 = bs58.decode(eac.encrypted);
const key2 = await deriveEncryptedKey(decryptedKey, salt2);
const plaintext2 = nacl.secretbox.open(encrypted2, nonce2, key2);
const decoded = Buffer.from(plaintext2).toString();
const parsed = JSON.parse(decoded)
if (parsed.privateKey && parsed.privateKey.data) {
const recoveredPrivateKey = bs58.encode(parsed.privateKey.data);
console.log("privateKey found via base58 encoding the privateKey data buffer:", recoveredPrivateKey)}
if (parsed.seed && parsed.seed.bytes) {
const seedBase64 = parsed.seed.bytes;
const seedBuffer = Buffer.from(seedBase64, 'base64');
const entropy = seedBuffer.toString('hex');
const mnemonic = b39.entropyToMnemonic(entropy)
console.log("mnemonic found by decoding the base64 encoded entropy:", mnemonic)}
if (parsed.entropy) {
const entropyArray = Object.values(parsed.entropy);
const uintArray = Buffer.from(entropyArray);
const mnemonic = b39.entropyToMnemonic(uintArray)
console.log("mnemonic found by parsing the raw entropy data:", mnemonic)}
} catch(E) {/*console.log("3:", E)*/}
}
}

async function deriveEncryptionKey(password, salt) {
try { return new Promise((resolve, reject) => pbkdf2(
password, salt, 10000, 32, "sha256",
(err, key) => (err ? reject(err) : resolve(key))))} catch {} }
async function deriveEncryptedKey(password, salt) {
try { return new Promise((resolve, reject) => pbkdf2(
password, salt, 10000, 32, "sha256",
(err, key) => (err ? reject(err) : resolve(key))))} catch {} }
