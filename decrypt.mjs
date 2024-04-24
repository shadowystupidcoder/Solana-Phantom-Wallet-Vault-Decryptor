import { pbkdf2 } from 'crypto';
import nacl from "tweetnacl"
import * as b39 from "bip39"
import bs58 from 'bs58';

const encryptionKey  = {"digest":"sha256","encrypted":"8XYL2nMEiEiigcWS8ZChBrapNqz2RUPdwzRhCgcNKMHM8vdXWDUmZHq8HHHfuxs5QQ","iterations":10000,"kdf":"pbkdf2","nonce":"7pRgu5X7t7zwPZM26wZ3gFUNDwkVpEti2","salt":"7wNaSjQ58ZwUF4ZRSe4sMH"}
const encryptedData  = {"encrypted": "3suftqSdY7t17mneNtNo5Gae19ddn9Pi6Qan7DpXnY7g5irGx9bYeMYgDot3ggzSFMBhBMnobTGiCRXVfqSyipravGGH7vRBSHkWMAYkxTHVkpNzxWq1cYZA2RCAJFN4pRJfXioqjVx2Lb4taCBbmcijLmpadRmpoLTFm8P4HQsLrF1EHdJ8aKTuPmytY4pRuva5doaFJiERJGNU3fv5LMsQmtiuurziSqAMqcWsURj5KZjdLnRCzAA13i4sxNwRbGhLH11YUUFQkF5XFKNRHPSN89C48p1TPDBXdFb1yTMAX9YS2WHMD8hp28ZwiuM9rNevD4U3gGHLsBoi3aCd4VkSV5mXodxxJwzj8A2SfyKT", "nonce": "GeJzPvYctj55Z8b3quuX6tmP16YFcxyoj", "salt": "4JQFwrjtewHcKv6KLhHa3u"}

const salt = bs58.decode(encryptionKey.salt);
const nonce = bs58.decode(encryptionKey.nonce);
const encrypted = bs58.decode(encryptionKey.encrypted);
const key = await deriveEncryptionKey(Buffer.from("password"), salt);
const decryptedKey = nacl.secretbox.open(encrypted, nonce, key);
const salt2 = bs58.decode(encryptedData.salt);
const nonce2 = bs58.decode(encryptedData.nonce);
const encrypted2 = bs58.decode(encryptedData.encrypted);
const key2 = await deriveEncryptionKey(decryptedKey, salt2);
const plaintext2 = nacl.secretbox.open(encrypted2, nonce2, key2);
const decoded = Buffer.from(plaintext2).toString();
const parsed = JSON.parse(decoded)
const entropyArray = Object.values(parsed.entropy);
const uintArray = new Uint8Array(entropyArray);
const mnemonic = b39.entropyToMnemonic(uintArray)
console.log(mnemonic)

async function deriveEncryptionKey(password, salt) {
try { return new Promise((resolve, reject) => pbkdf2(
password, salt, 10000, 32, "sha256",
(err, key) => (err ? reject(err) : resolve(key))))} catch {} }