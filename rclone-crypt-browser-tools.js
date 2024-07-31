(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
(function (global){(function (){
"use strict";var _rcloneCrypt=require("@fyears/rclone-crypt");global.window.rcloneCrypt={encrypt:async function(e,t="",n=""){const a=new _rcloneCrypt.Cipher("base32");await a.key(t,n);const r=await fetch(e),i=await r.arrayBuffer();return await a.encryptData(new Uint8Array(i))},encryptPath:async function(e,t="",n=""){const a=new _rcloneCrypt.Cipher("base32");return await a.key(t,n),await a.encryptFileName(e)},decrypt:async function(e,t="",n=""){const a=new _rcloneCrypt.Cipher("base32");await a.key(t,n);const r=await fetch(e),i=await r.arrayBuffer();return await a.decryptData(new Uint8Array(i))},decryptPath:async function(e,t="",n=""){const a=new _rcloneCrypt.Cipher("base32");return await a.key(t,n),await a.decryptFileName(e)},type:function(e){let t=e.split(".").pop(),n={pdf:"application/pdf",jpg:"image/jpg",jpeg:"image/jpeg",png:"image/png",gif:"image/gif",mp4:"video/mp4",webm:"video/webm"};return n[t]?n[t]:"application/octect-stream"},render:function(e,t="",n=!1,a=!1){let r=new Blob([e],{type:window.rcloneCrypt.type(t)}),i=t.split("/").pop();if(window.navigator.msSaveOrOpenBlob)window.navigator.msSaveOrOpenBlob(r,i);else{const e=document.createElement("a");document.body.appendChild(e);const t=window.URL.createObjectURL(r);if(!a)return t;e.href=t,n&&(e.download=i),e.click(),setTimeout(()=>{window.URL.revokeObjectURL(t),document.body.removeChild(e)},0)}}};

}).call(this)}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"@fyears/rclone-crypt":3}],2:[function(require,module,exports){
"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AESCipherBlock = exports.EMECipher = void 0;
const aes_1 = require("@noble/ciphers/aes");
function multByTwo(output, input) {
    if (input.length !== 16) {
        throw Error("len must be 16");
    }
    const tmp = new Uint8Array(16);
    tmp[0] = 2 * input[0];
    if (input[15] >= 128) {
        tmp[0] = tmp[0] ^ 135;
    }
    for (let j = 1; j < 16; j++) {
        tmp[j] = 2 * input[j];
        if (input[j - 1] >= 128) {
            tmp[j] = tmp[j] + 1;
        }
    }
    output.set(tmp);
}
function xorBlocks(output, input1, input2) {
    if (input1.length !== input2.length) {
        throw Error(`input1.length=${input1.length} is not equal to input2.length=${input2.length}`);
    }
    for (let i = 0; i < input1.length; ++i) {
        output[i] = input1[i] ^ input2[i];
    }
}
// aesTransform - encrypt or decrypt (according to "isEncrypt") using block
// cipher "bc" (typically AES)
function aesTransform(dst, src, isEncrypt, bc) {
    return __awaiter(this, void 0, void 0, function* () {
        if (isEncrypt) {
            yield bc.encrypt(dst, src);
        }
        else {
            yield bc.decrypt(dst, src);
        }
    });
}
// tabulateL - calculate L_i for messages up to a length of m cipher blocks
function tabulateL(bc, m) {
    return __awaiter(this, void 0, void 0, function* () {
        /* set L0 = 2*AESenc(K; 0) */
        const eZero = new Uint8Array(16);
        const Li = new Uint8Array(16);
        yield bc.encrypt(Li, eZero);
        const LTable = new Array(m);
        for (let i = 0; i < m; i++) {
            multByTwo(Li, Li);
            LTable[i] = new Uint8Array(Li);
        }
        return LTable;
    });
}
// Transform - EME-encrypt or EME-decrypt, according to "isEncrypt"
// (defined in the constants isEncryptEncrypt and isEncryptDecrypt).
// The data in "inputData" is en- or decrypted with the block ciper "bc" under
// "tweak" (also known as IV).
//
// The tweak is used to randomize the encryption in the same way as an
// IV.  A use of this encryption mode envisioned by the authors of the
// algorithm was to encrypt each sector of a disk, with the tweak
// being the sector number.  If you encipher the same data with the
// same tweak you will get the same ciphertext.
//
// The result is returned in a freshly allocated subarray of the same
// size as inputData.
//
// Limitations:
// * The block cipher must have block size 16 (usually AES).
// * The size of "tweak" must be 16
// * "inputData" must be a multiple of 16 bytes long
// If any of these pre-conditions are not met, the function will panic.
//
// Note that you probably don't want to call this function directly and instead
// use eme.New(), which provides conventient wrappers.
function transform(bc, tweak, inputData, isEncrypt) {
    return __awaiter(this, void 0, void 0, function* () {
        // In the paper, the tweak is just called "T". Call it the same here to
        // make following the paper easy.
        const T = tweak;
        // In the paper, the plaintext data is called "P" and the ciphertext is
        // called "C". Because encryption and decryption are virtually identical,
        // we share the code and always call the input data "P" and the output data
        // "C", regardless of the isEncrypt.
        const P = inputData;
        if (bc.blockSize() !== 16) {
            throw Error("Using a block size other than 16 is not implemented");
        }
        if (T.length !== 16) {
            throw Error(`Tweak must be 16 bytes long, is ${T.length}`);
        }
        if (P.length % 16 !== 0) {
            throw Error(`Data P must be a multiple of 16 long, is ${P.length}`);
        }
        const m = P.length / 16;
        if (m === 0 || m > 16 * 8) {
            throw Error(`EME operates on 1 to ${16 * 8} block-cipher blocks, you passed ${m}`);
        }
        const C = new Uint8Array(P.length);
        const LTable = yield tabulateL(bc, m);
        const PPj = new Uint8Array(16);
        for (let j = 0; j < m; j++) {
            const Pj = P.subarray(j * 16, (j + 1) * 16);
            /* PPj = 2**(j-1)*L xor Pj */
            xorBlocks(PPj, Pj, LTable[j]);
            /* PPPj = AESenc(K; PPj) */
            yield aesTransform(C.subarray(j * 16, (j + 1) * 16), PPj, isEncrypt, bc);
        }
        /* MP =(xorSum PPPj) xor T */
        const MP = new Uint8Array(16);
        xorBlocks(MP, C.subarray(0, 16), T);
        for (let j = 1; j < m; j++) {
            xorBlocks(MP, MP, C.subarray(j * 16, (j + 1) * 16));
        }
        /* MC = AESenc(K; MP) */
        const MC = new Uint8Array(16);
        yield aesTransform(MC, MP, isEncrypt, bc);
        /* M = MP xor MC */
        const M = new Uint8Array(16);
        xorBlocks(M, MP, MC);
        const CCCj = new Uint8Array(16);
        for (let j = 1; j < m; j++) {
            multByTwo(M, M);
            /* CCCj = 2**(j-1)*M xor PPPj */
            xorBlocks(CCCj, C.subarray(j * 16, (j + 1) * 16), M);
            C.subarray(j * 16, (j + 1) * 16).set(CCCj);
        }
        /* CCC1 = (xorSum CCCj) xor T xor MC */
        const CCC1 = new Uint8Array(16);
        xorBlocks(CCC1, MC, T);
        for (let j = 1; j < m; j++) {
            xorBlocks(CCC1, CCC1, C.subarray(j * 16, (j + 1) * 16));
        }
        C.subarray(0, 16).set(CCC1);
        for (let j = 0; j < m; j++) {
            /* CCj = AES-enc(K; CCCj) */
            yield aesTransform(C.subarray(j * 16, (j + 1) * 16), C.subarray(j * 16, (j + 1) * 16), isEncrypt, bc);
            /* Cj = 2**(j-1)*L xor CCj */
            xorBlocks(C.subarray(j * 16, (j + 1) * 16), C.subarray(j * 16, (j + 1) * 16), LTable[j]);
        }
        return C;
    });
}
class EMECipher {
    constructor(bc) {
        this.bc = bc;
    }
    encrypt(tweak, inputData) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield transform(this.bc, tweak, inputData, true);
        });
    }
    decrypt(tweak, inputData) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield transform(this.bc, tweak, inputData, false);
        });
    }
}
exports.EMECipher = EMECipher;
class AESCipherBlock {
    constructor(keyRaw) {
        this.keyRaw = keyRaw;
        this.iv = new Uint8Array(16);
        if (keyRaw.length === 16) {
            this.algo = 'aes128';
        }
        else if (keyRaw.length === 24) {
            this.algo = 'aes192';
        }
        else if (keyRaw.length === 32) {
            this.algo = 'aes256';
        }
        else {
            throw Error(`invalid key length = ${keyRaw.length}`);
        }
    }
    encrypt(dst, src) {
        return __awaiter(this, void 0, void 0, function* () {
            const stream = (0, aes_1.ecb)(this.keyRaw, { disablePadding: true });
            dst.set([...stream.encrypt(src)]);
        });
    }
    decrypt(dst, src) {
        return __awaiter(this, void 0, void 0, function* () {
            const stream = (0, aes_1.ecb)(this.keyRaw, { disablePadding: true });
            dst.set([...stream.decrypt(src)]);
        });
    }
    blockSize() {
        return 16;
    }
}
exports.AESCipherBlock = AESCipherBlock;

},{"@noble/ciphers/aes":8}],3:[function(require,module,exports){
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.decryptedSize = exports.encryptedSize = exports.add = exports.increment = exports.carry = exports.Cipher = exports.msgErrorSuffixMissingDot = exports.msgErrorBadSeek = exports.msgErrorNotAnEncryptedFile = exports.msgErrorFileClosed = exports.msgErrorBadBase32Encoding = exports.msgErrorEncryptedBadBlock = exports.msgErrorEncryptedBadMagic = exports.msgErrorEncryptedFileBadHeader = exports.msgErrorEncryptedFileTooShort = exports.msgErrorBadDecryptControlChar = exports.msgErrorBadDecryptUTF8 = void 0;
const scrypt_1 = require("@noble/hashes/scrypt");
const salsa_1 = require("@noble/ciphers/salsa");
const webcrypto_1 = require("@noble/ciphers/webcrypto");
const pkcs7_padding_1 = require("pkcs7-padding");
const eme_1 = require("@fyears/eme");
const rfc4648_1 = require("rfc4648");
const base32768 = __importStar(require("base32768"));
const newNonce = () => (0, webcrypto_1.randomBytes)(salsa_1.xsalsa20poly1305.nonceLength); // 24
const nameCipherBlockSize = 16; // aes block size
const fileMagic = "RCLONE\x00\x00";
const fileMagicBytes = new TextEncoder().encode(fileMagic);
const fileMagicSize = fileMagic.length;
const fileNonceSize = 24;
const fileHeaderSize = fileMagicSize + fileNonceSize;
const blockHeaderSize = salsa_1.xsalsa20poly1305.tagLength; // 16
const blockDataSize = 64 * 1024;
const blockSize = blockHeaderSize + blockDataSize;
const defaultSalt = new Uint8Array([
    0xa8, 0x0d, 0xf4, 0x3a, 0x8f, 0xbd, 0x03, 0x08, 0xa7, 0xca, 0xb8, 0x3e, 0x58,
    0x1f, 0x86, 0xb1,
]);
exports.msgErrorBadDecryptUTF8 = "bad decryption - utf-8 invalid";
exports.msgErrorBadDecryptControlChar = "bad decryption - contains control chars";
exports.msgErrorEncryptedFileTooShort = "file is too short to be encrypted";
exports.msgErrorEncryptedFileBadHeader = "file has truncated block header";
exports.msgErrorEncryptedBadMagic = "not an encrypted file - bad magic string";
exports.msgErrorEncryptedBadBlock = "failed to authenticate decrypted block - bad password?";
exports.msgErrorBadBase32Encoding = "bad base32 filename encoding";
exports.msgErrorFileClosed = "file already closed";
exports.msgErrorNotAnEncryptedFile = "not an encrypted file - does not match suffix";
exports.msgErrorBadSeek = "Seek beyond end of file";
exports.msgErrorSuffixMissingDot = "suffix config setting should include a '.'";
// Cipher defines an encoding and decoding cipher for the crypt backend
class Cipher {
    constructor(fileNameEnc) {
        this.dataKey = new Uint8Array(32);
        this.nameKey = new Uint8Array(32);
        this.nameTweak = new Uint8Array(nameCipherBlockSize);
        this.dirNameEncrypt = true;
        this.fileNameEnc = fileNameEnc;
    }
    toString() {
        return `
dataKey=${this.dataKey} 
nameKey=${this.nameKey}
nameTweak=${this.nameTweak}
dirNameEncrypt=${this.dirNameEncrypt}
fileNameEnc=${this.fileNameEnc}
`;
    }
    encodeToString(ciphertext) {
        if (this.fileNameEnc === "base32") {
            return rfc4648_1.base32hex.stringify(ciphertext, { pad: false }).toLowerCase();
        }
        else if (this.fileNameEnc === "base64") {
            return rfc4648_1.base64url.stringify(ciphertext, { pad: false });
        }
        else if (this.fileNameEnc === "base32768") {
            return base32768.encode(ciphertext);
        }
        else {
            throw Error(`unknown fileNameEnc=${this.fileNameEnc}`);
        }
    }
    decodeString(ciphertext) {
        if (this.fileNameEnc === "base32") {
            if (ciphertext.endsWith("=")) {
                // should not have ending = in our seting
                throw new Error(exports.msgErrorBadBase32Encoding);
            }
            return rfc4648_1.base32hex.parse(ciphertext.toUpperCase(), {
                loose: true,
            });
        }
        else if (this.fileNameEnc === "base64") {
            return rfc4648_1.base64url.parse(ciphertext, {
                loose: true,
            });
        }
        else if (this.fileNameEnc === "base32768") {
            return base32768.decode(ciphertext);
        }
        else {
            throw Error(`unknown fileNameEnc=${this.fileNameEnc}`);
        }
    }
    key(password, salt) {
        return __awaiter(this, void 0, void 0, function* () {
            const keySize = this.dataKey.length + this.nameKey.length + this.nameTweak.length;
            // console.log(`keySize=${keySize}`)
            let saltBytes = defaultSalt;
            if (salt !== "") {
                saltBytes = new TextEncoder().encode(salt);
            }
            let key;
            if (password === "") {
                key = new Uint8Array(keySize);
            }
            else {
                key = yield (0, scrypt_1.scryptAsync)(new TextEncoder().encode(password), saltBytes, {
                    N: 2 ** 14,
                    r: 8,
                    p: 1,
                    dkLen: keySize,
                });
            }
            // console.log(`key=${key}`)
            this.dataKey.set(key.slice(0, this.dataKey.length));
            this.nameKey.set(key.slice(this.dataKey.length, this.dataKey.length + this.nameKey.length));
            this.nameTweak.set(key.slice(this.dataKey.length + this.nameKey.length));
            return this;
        });
    }
    updateInternalKey(dataKey, nameKey, nameTweak) {
        this.dataKey = dataKey;
        this.nameKey = nameKey;
        this.nameTweak = nameTweak;
        return this;
    }
    getInternalKey() {
        return {
            dataKey: this.dataKey,
            nameKey: this.nameKey,
            nameTweak: this.nameTweak
        };
    }
    // encryptSegment encrypts a path segment
    //
    // This uses EME with AES.
    //
    // EME (ECB-Mix-ECB) is a wide-block encryption mode presented in the
    // 2003 paper "A Parallelizable Enciphering Mode" by Halevi and
    // Rogaway.
    //
    // This makes for deterministic encryption which is what we want - the
    // same filename must encrypt to the same thing.
    //
    // This means that
    //   - filenames with the same name will encrypt the same
    //   - filenames which start the same won't have a common prefix
    encryptSegment(plaintext) {
        return __awaiter(this, void 0, void 0, function* () {
            if (plaintext === "") {
                return "";
            }
            const paddedPlaintext = (0, pkcs7_padding_1.pad)(new TextEncoder().encode(plaintext), nameCipherBlockSize);
            // console.log(`paddedPlaintext=${paddedPlaintext}`)
            const bc = new eme_1.AESCipherBlock(this.nameKey);
            const eme = new eme_1.EMECipher(bc);
            const ciphertext = yield eme.encrypt(this.nameTweak, paddedPlaintext);
            // console.log(`ciphertext=${ciphertext}`)
            return this.encodeToString(ciphertext);
        });
    }
    encryptFileName(input) {
        return __awaiter(this, void 0, void 0, function* () {
            const segments = input.split("/");
            for (let i = 0; i < segments.length; ++i) {
                // Skip directory name encryption if the user chose to
                // leave them intact
                if (!this.dirNameEncrypt && i !== segments.length - 1) {
                    continue;
                }
                segments[i] = yield this.encryptSegment(segments[i]);
            }
            return segments.join("/");
        });
    }
    decryptSegment(ciphertext) {
        return __awaiter(this, void 0, void 0, function* () {
            if (ciphertext === "") {
                return "";
            }
            const rawCiphertext = this.decodeString(ciphertext);
            const bc = new eme_1.AESCipherBlock(this.nameKey);
            const eme = new eme_1.EMECipher(bc);
            const paddedPlaintext = yield eme.decrypt(this.nameTweak, rawCiphertext);
            const plaintext = (0, pkcs7_padding_1.unpad)(paddedPlaintext);
            return new TextDecoder().decode(plaintext);
        });
    }
    decryptFileName(input) {
        return __awaiter(this, void 0, void 0, function* () {
            const segments = input.split("/");
            for (let i = 0; i < segments.length; ++i) {
                // Skip directory name encryption if the user chose to
                // leave them intact
                if (!this.dirNameEncrypt && i !== segments.length - 1) {
                    continue;
                }
                segments[i] = yield this.decryptSegment(segments[i]);
            }
            return segments.join("/");
        });
    }
    encryptData(input, nonceInput) {
        return __awaiter(this, void 0, void 0, function* () {
            let nonce;
            if (nonceInput !== undefined) {
                nonce = nonceInput;
            }
            else {
                nonce = newNonce();
            }
            const res = new Uint8Array(encryptedSize(input.byteLength));
            // console.log(`size=${encryptedSize(input.byteLength)}`)
            res.set(fileMagicBytes);
            res.set(nonce, fileMagicSize);
            // console.log(`res=${res}`)
            for (let offset = 0, i = 0; offset < input.byteLength; offset += blockDataSize, i += 1) {
                // console.log(`i=${i}`)
                const readBuf = input.slice(offset, offset + blockDataSize);
                // console.log(`readBuf=${readBuf}`)
                const buf = (0, salsa_1.xsalsa20poly1305)(this.dataKey, nonce).encrypt(readBuf);
                // console.log(`buf=${buf}`)
                increment(nonce);
                res.set(buf, fileMagicSize + fileNonceSize + offset + i * blockHeaderSize);
                // console.log(`res=${res}`)
            }
            // console.log(`final res=${res}`)
            return res;
        });
    }
    decryptData(input) {
        return __awaiter(this, void 0, void 0, function* () {
            // console.log(`input=${input}`)
            if (input.byteLength < fileHeaderSize) {
                throw Error(exports.msgErrorEncryptedFileTooShort);
            }
            if (!compArr(input.slice(0, fileMagicSize), fileMagicBytes)) {
                throw Error(exports.msgErrorEncryptedBadMagic);
            }
            const nonce = input.slice(fileMagicSize, fileHeaderSize);
            // console.log(`nonce=${nonce}`)
            // console.log(`dec size=${decryptedSize(input.byteLength)}`);
            const res = new Uint8Array(decryptedSize(input.byteLength));
            for (let offsetInput = fileHeaderSize, offsetOutput = 0, i = 0; offsetInput < input.byteLength; offsetInput += blockSize, offsetOutput += blockDataSize, i += 1) {
                // console.log(`i=${i}`);
                // console.log(`offsetInput = ${offsetInput}`);
                const readBuf = input.slice(offsetInput, offsetInput + blockSize);
                // console.log(`readBuf length = ${readBuf.length}`);
                // console.log(`readBuf=${readBuf}`)
                const buf = (0, salsa_1.xsalsa20poly1305)(this.dataKey, nonce).decrypt(readBuf);
                if (buf === null) {
                    throw Error(exports.msgErrorEncryptedBadBlock);
                }
                // console.log(`buf length = ${buf.length}`);
                // console.log(`buf=${buf}`)
                increment(nonce);
                // console.log(`offsetOutput = ${offsetOutput}`);
                res.set(buf, offsetOutput);
                // console.log(`res=${res}`)
            }
            return res;
        });
    }
}
exports.Cipher = Cipher;
// func (n *nonce) carry(i int)
function carry(i, n) {
    for (; i < n.length; i++) {
        const digit = n[i];
        const newDigit = (digit + 1) & 0xff; // mask a bit
        n[i] = newDigit;
        if (newDigit >= digit) {
            // exit if no carry
            break;
        }
    }
}
exports.carry = carry;
// increment to add 1 to the nonce
// func (n *nonce) increment()
function increment(n) {
    return carry(0, n);
}
exports.increment = increment;
// add a uint64 to the nonce
// func (n *nonce) add(x uint64)
function add(x, n) {
    let y = BigInt(0);
    if (typeof x === "bigint") {
        y = BigInt.asUintN(64, x);
    }
    else if (typeof x === "number") {
        y = BigInt.asUintN(64, BigInt(x));
    }
    let carryNum = BigInt.asUintN(16, BigInt(0));
    for (let i = 0; i < 8; i++) {
        const digit = n[i];
        const xDigit = y & BigInt(0xff);
        y >>= BigInt(8);
        carryNum = carryNum + BigInt(digit) + BigInt(xDigit);
        n[i] = Number(carryNum);
        carryNum >>= BigInt(8);
    }
    if (carryNum !== BigInt(0)) {
        carry(8, n);
    }
}
exports.add = add;
function compArr(x, y) {
    if (x.length !== y.length) {
        return false;
    }
    for (let i = 0; i < x.length; ++i) {
        if (x[i] !== y[i]) {
            return false;
        }
    }
    return true;
}
function encryptedSize(size) {
    const blocks = Math.floor(size / blockDataSize);
    const residue = size % blockDataSize;
    let encryptedSize = fileHeaderSize + blocks * (blockHeaderSize + blockDataSize);
    if (residue !== 0) {
        encryptedSize += blockHeaderSize + residue;
    }
    return encryptedSize;
}
exports.encryptedSize = encryptedSize;
function decryptedSize(size) {
    let size2 = size;
    size2 -= fileHeaderSize;
    if (size2 < 0) {
        throw new Error(exports.msgErrorEncryptedFileTooShort);
    }
    const blocks = Math.floor(size2 / blockSize);
    let residue = size2 % blockSize;
    let decryptedSize = blocks * blockDataSize;
    if (residue !== 0) {
        residue -= blockHeaderSize;
        if (residue <= 0) {
            throw new Error(exports.msgErrorEncryptedFileBadHeader);
        }
    }
    decryptedSize += residue;
    return decryptedSize;
}
exports.decryptedSize = decryptedSize;

},{"@fyears/eme":2,"@noble/ciphers/salsa":10,"@noble/ciphers/webcrypto":12,"@noble/hashes/scrypt":18,"base32768":21,"pkcs7-padding":22,"rfc4648":23}],4:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createCipher = exports.rotl = exports.sigma = void 0;
// Basic utils for ARX (add-rotate-xor) salsa and chacha ciphers.
const _assert_js_1 = require("./_assert.js");
const utils_js_1 = require("./utils.js");
/*
RFC8439 requires multi-step cipher stream, where
authKey starts with counter: 0, actual msg with counter: 1.

For this, we need a way to re-use nonce / counter:

    const counter = new Uint8Array(4);
    chacha(..., counter, ...); // counter is now 1
    chacha(..., counter, ...); // counter is now 2

This is complicated:

- 32-bit counters are enough, no need for 64-bit: max ArrayBuffer size in JS is 4GB
- Original papers don't allow mutating counters
- Counter overflow is undefined [^1]
- Idea A: allow providing (nonce | counter) instead of just nonce, re-use it
- Caveat: Cannot be re-used through all cases:
- * chacha has (counter | nonce)
- * xchacha has (nonce16 | counter | nonce16)
- Idea B: separate nonce / counter and provide separate API for counter re-use
- Caveat: there are different counter sizes depending on an algorithm.
- salsa & chacha also differ in structures of key & sigma:
  salsa20:      s[0] | k(4) | s[1] | nonce(2) | ctr(2) | s[2] | k(4) | s[3]
  chacha:       s(4) | k(8) | ctr(1) | nonce(3)
  chacha20orig: s(4) | k(8) | ctr(2) | nonce(2)
- Idea C: helper method such as `setSalsaState(key, nonce, sigma, data)`
- Caveat: we can't re-use counter array

xchacha [^2] uses the subkey and remaining 8 byte nonce with ChaCha20 as normal
(prefixed by 4 NUL bytes, since [RFC8439] specifies a 12-byte nonce).

[^1]: https://mailarchive.ietf.org/arch/msg/cfrg/gsOnTJzcbgG6OqD8Sc0GO5aR_tU/
[^2]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha#appendix-A.2
*/
// We can't make top-level var depend on utils.utf8ToBytes
// because it's not present in all envs. Creating a similar fn here
const _utf8ToBytes = (str) => Uint8Array.from(str.split('').map((c) => c.charCodeAt(0)));
const sigma16 = _utf8ToBytes('expand 16-byte k');
const sigma32 = _utf8ToBytes('expand 32-byte k');
const sigma16_32 = (0, utils_js_1.u32)(sigma16);
const sigma32_32 = (0, utils_js_1.u32)(sigma32);
exports.sigma = sigma32_32.slice();
function rotl(a, b) {
    return (a << b) | (a >>> (32 - b));
}
exports.rotl = rotl;
// Is byte array aligned to 4 byte offset (u32)?
function isAligned32(b) {
    return b.byteOffset % 4 === 0;
}
// Salsa and Chacha block length is always 512-bit
const BLOCK_LEN = 64;
const BLOCK_LEN32 = 16;
// new Uint32Array([2**32])   // => Uint32Array(1) [ 0 ]
// new Uint32Array([2**32-1]) // => Uint32Array(1) [ 4294967295 ]
const MAX_COUNTER = 2 ** 32 - 1;
const U32_EMPTY = new Uint32Array();
function runCipher(core, sigma, key, nonce, data, output, counter, rounds) {
    const len = data.length;
    const block = new Uint8Array(BLOCK_LEN);
    const b32 = (0, utils_js_1.u32)(block);
    // Make sure that buffers aligned to 4 bytes
    const isAligned = isAligned32(data) && isAligned32(output);
    const d32 = isAligned ? (0, utils_js_1.u32)(data) : U32_EMPTY;
    const o32 = isAligned ? (0, utils_js_1.u32)(output) : U32_EMPTY;
    for (let pos = 0; pos < len; counter++) {
        core(sigma, key, nonce, b32, counter, rounds);
        if (counter >= MAX_COUNTER)
            throw new Error('arx: counter overflow');
        const take = Math.min(BLOCK_LEN, len - pos);
        // aligned to 4 bytes
        if (isAligned && take === BLOCK_LEN) {
            const pos32 = pos / 4;
            if (pos % 4 !== 0)
                throw new Error('arx: invalid block position');
            for (let j = 0, posj; j < BLOCK_LEN32; j++) {
                posj = pos32 + j;
                o32[posj] = d32[posj] ^ b32[j];
            }
            pos += BLOCK_LEN;
            continue;
        }
        for (let j = 0, posj; j < take; j++) {
            posj = pos + j;
            output[posj] = data[posj] ^ block[j];
        }
        pos += take;
    }
}
function createCipher(core, opts) {
    const { allowShortKeys, extendNonceFn, counterLength, counterRight, rounds } = (0, utils_js_1.checkOpts)({ allowShortKeys: false, counterLength: 8, counterRight: false, rounds: 20 }, opts);
    if (typeof core !== 'function')
        throw new Error('core must be a function');
    (0, _assert_js_1.number)(counterLength);
    (0, _assert_js_1.number)(rounds);
    (0, _assert_js_1.bool)(counterRight);
    (0, _assert_js_1.bool)(allowShortKeys);
    return (key, nonce, data, output, counter = 0) => {
        (0, _assert_js_1.bytes)(key);
        (0, _assert_js_1.bytes)(nonce);
        (0, _assert_js_1.bytes)(data);
        const len = data.length;
        if (!output)
            output = new Uint8Array(len);
        (0, _assert_js_1.bytes)(output);
        (0, _assert_js_1.number)(counter);
        if (counter < 0 || counter >= MAX_COUNTER)
            throw new Error('arx: counter overflow');
        if (output.length < len)
            throw new Error(`arx: output (${output.length}) is shorter than data (${len})`);
        const toClean = [];
        // Key & sigma
        // key=16 -> sigma16, k=key|key
        // key=32 -> sigma32, k=key
        let l = key.length, k, sigma;
        if (l === 32) {
            k = key.slice();
            toClean.push(k);
            sigma = sigma32_32;
        }
        else if (l === 16 && allowShortKeys) {
            k = new Uint8Array(32);
            k.set(key);
            k.set(key, 16);
            sigma = sigma16_32;
            toClean.push(k);
        }
        else {
            throw new Error(`arx: invalid 32-byte key, got length=${l}`);
        }
        // Nonce
        // salsa20:      8   (8-byte counter)
        // chacha20orig: 8   (8-byte counter)
        // chacha20:     12  (4-byte counter)
        // xsalsa20:     24  (16 -> hsalsa,  8 -> old nonce)
        // xchacha20:    24  (16 -> hchacha, 8 -> old nonce)
        // Align nonce to 4 bytes
        if (!isAligned32(nonce)) {
            nonce = nonce.slice();
            toClean.push(nonce);
        }
        const k32 = (0, utils_js_1.u32)(k);
        // hsalsa & hchacha: handle extended nonce
        if (extendNonceFn) {
            if (nonce.length !== 24)
                throw new Error(`arx: extended nonce must be 24 bytes`);
            extendNonceFn(sigma, k32, (0, utils_js_1.u32)(nonce.subarray(0, 16)), k32);
            nonce = nonce.subarray(16);
        }
        // Handle nonce counter
        const nonceNcLen = 16 - counterLength;
        if (nonceNcLen !== nonce.length)
            throw new Error(`arx: nonce must be ${nonceNcLen} or 16 bytes`);
        // Pad counter when nonce is 64 bit
        if (nonceNcLen !== 12) {
            const nc = new Uint8Array(12);
            nc.set(nonce, counterRight ? 0 : 12 - nonce.length);
            nonce = nc;
            toClean.push(nonce);
        }
        const n32 = (0, utils_js_1.u32)(nonce);
        runCipher(core, sigma, k32, n32, data, output, counter, rounds);
        while (toClean.length > 0)
            toClean.pop().fill(0);
        return output;
    };
}
exports.createCipher = createCipher;

},{"./_assert.js":5,"./utils.js":11}],5:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.output = exports.exists = exports.hash = exports.bytes = exports.bool = exports.number = exports.isBytes = void 0;
function number(n) {
    if (!Number.isSafeInteger(n) || n < 0)
        throw new Error(`positive integer expected, not ${n}`);
}
exports.number = number;
function bool(b) {
    if (typeof b !== 'boolean')
        throw new Error(`boolean expected, not ${b}`);
}
exports.bool = bool;
function isBytes(a) {
    return (a instanceof Uint8Array ||
        (a != null && typeof a === 'object' && a.constructor.name === 'Uint8Array'));
}
exports.isBytes = isBytes;
function bytes(b, ...lengths) {
    if (!isBytes(b))
        throw new Error('Uint8Array expected');
    if (lengths.length > 0 && !lengths.includes(b.length))
        throw new Error(`Uint8Array expected of length ${lengths}, not of length=${b.length}`);
}
exports.bytes = bytes;
function hash(hash) {
    if (typeof hash !== 'function' || typeof hash.create !== 'function')
        throw new Error('hash must be wrapped by utils.wrapConstructor');
    number(hash.outputLen);
    number(hash.blockLen);
}
exports.hash = hash;
function exists(instance, checkFinished = true) {
    if (instance.destroyed)
        throw new Error('Hash instance has been destroyed');
    if (checkFinished && instance.finished)
        throw new Error('Hash#digest() has already been called');
}
exports.exists = exists;
function output(out, instance) {
    bytes(out);
    const min = instance.outputLen;
    if (out.length < min) {
        throw new Error(`digestInto() expects output buffer of length at least ${min}`);
    }
}
exports.output = output;
const assert = { number, bool, bytes, hash, exists, output };
exports.default = assert;

},{}],6:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.poly1305 = exports.wrapConstructorWithKey = void 0;
const _assert_js_1 = require("./_assert.js");
const utils_js_1 = require("./utils.js");
// Poly1305 is a fast and parallel secret-key message-authentication code.
// https://cr.yp.to/mac.html, https://cr.yp.to/mac/poly1305-20050329.pdf
// https://datatracker.ietf.org/doc/html/rfc8439
// Based on Public Domain poly1305-donna https://github.com/floodyberry/poly1305-donna
const u8to16 = (a, i) => (a[i++] & 0xff) | ((a[i++] & 0xff) << 8);
class Poly1305 {
    constructor(key) {
        this.blockLen = 16;
        this.outputLen = 16;
        this.buffer = new Uint8Array(16);
        this.r = new Uint16Array(10);
        this.h = new Uint16Array(10);
        this.pad = new Uint16Array(8);
        this.pos = 0;
        this.finished = false;
        key = (0, utils_js_1.toBytes)(key);
        (0, _assert_js_1.bytes)(key, 32);
        const t0 = u8to16(key, 0);
        const t1 = u8to16(key, 2);
        const t2 = u8to16(key, 4);
        const t3 = u8to16(key, 6);
        const t4 = u8to16(key, 8);
        const t5 = u8to16(key, 10);
        const t6 = u8to16(key, 12);
        const t7 = u8to16(key, 14);
        // https://github.com/floodyberry/poly1305-donna/blob/e6ad6e091d30d7f4ec2d4f978be1fcfcbce72781/poly1305-donna-16.h#L47
        this.r[0] = t0 & 0x1fff;
        this.r[1] = ((t0 >>> 13) | (t1 << 3)) & 0x1fff;
        this.r[2] = ((t1 >>> 10) | (t2 << 6)) & 0x1f03;
        this.r[3] = ((t2 >>> 7) | (t3 << 9)) & 0x1fff;
        this.r[4] = ((t3 >>> 4) | (t4 << 12)) & 0x00ff;
        this.r[5] = (t4 >>> 1) & 0x1ffe;
        this.r[6] = ((t4 >>> 14) | (t5 << 2)) & 0x1fff;
        this.r[7] = ((t5 >>> 11) | (t6 << 5)) & 0x1f81;
        this.r[8] = ((t6 >>> 8) | (t7 << 8)) & 0x1fff;
        this.r[9] = (t7 >>> 5) & 0x007f;
        for (let i = 0; i < 8; i++)
            this.pad[i] = u8to16(key, 16 + 2 * i);
    }
    process(data, offset, isLast = false) {
        const hibit = isLast ? 0 : 1 << 11;
        const { h, r } = this;
        const r0 = r[0];
        const r1 = r[1];
        const r2 = r[2];
        const r3 = r[3];
        const r4 = r[4];
        const r5 = r[5];
        const r6 = r[6];
        const r7 = r[7];
        const r8 = r[8];
        const r9 = r[9];
        const t0 = u8to16(data, offset + 0);
        const t1 = u8to16(data, offset + 2);
        const t2 = u8to16(data, offset + 4);
        const t3 = u8to16(data, offset + 6);
        const t4 = u8to16(data, offset + 8);
        const t5 = u8to16(data, offset + 10);
        const t6 = u8to16(data, offset + 12);
        const t7 = u8to16(data, offset + 14);
        let h0 = h[0] + (t0 & 0x1fff);
        let h1 = h[1] + (((t0 >>> 13) | (t1 << 3)) & 0x1fff);
        let h2 = h[2] + (((t1 >>> 10) | (t2 << 6)) & 0x1fff);
        let h3 = h[3] + (((t2 >>> 7) | (t3 << 9)) & 0x1fff);
        let h4 = h[4] + (((t3 >>> 4) | (t4 << 12)) & 0x1fff);
        let h5 = h[5] + ((t4 >>> 1) & 0x1fff);
        let h6 = h[6] + (((t4 >>> 14) | (t5 << 2)) & 0x1fff);
        let h7 = h[7] + (((t5 >>> 11) | (t6 << 5)) & 0x1fff);
        let h8 = h[8] + (((t6 >>> 8) | (t7 << 8)) & 0x1fff);
        let h9 = h[9] + ((t7 >>> 5) | hibit);
        let c = 0;
        let d0 = c + h0 * r0 + h1 * (5 * r9) + h2 * (5 * r8) + h3 * (5 * r7) + h4 * (5 * r6);
        c = d0 >>> 13;
        d0 &= 0x1fff;
        d0 += h5 * (5 * r5) + h6 * (5 * r4) + h7 * (5 * r3) + h8 * (5 * r2) + h9 * (5 * r1);
        c += d0 >>> 13;
        d0 &= 0x1fff;
        let d1 = c + h0 * r1 + h1 * r0 + h2 * (5 * r9) + h3 * (5 * r8) + h4 * (5 * r7);
        c = d1 >>> 13;
        d1 &= 0x1fff;
        d1 += h5 * (5 * r6) + h6 * (5 * r5) + h7 * (5 * r4) + h8 * (5 * r3) + h9 * (5 * r2);
        c += d1 >>> 13;
        d1 &= 0x1fff;
        let d2 = c + h0 * r2 + h1 * r1 + h2 * r0 + h3 * (5 * r9) + h4 * (5 * r8);
        c = d2 >>> 13;
        d2 &= 0x1fff;
        d2 += h5 * (5 * r7) + h6 * (5 * r6) + h7 * (5 * r5) + h8 * (5 * r4) + h9 * (5 * r3);
        c += d2 >>> 13;
        d2 &= 0x1fff;
        let d3 = c + h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * (5 * r9);
        c = d3 >>> 13;
        d3 &= 0x1fff;
        d3 += h5 * (5 * r8) + h6 * (5 * r7) + h7 * (5 * r6) + h8 * (5 * r5) + h9 * (5 * r4);
        c += d3 >>> 13;
        d3 &= 0x1fff;
        let d4 = c + h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
        c = d4 >>> 13;
        d4 &= 0x1fff;
        d4 += h5 * (5 * r9) + h6 * (5 * r8) + h7 * (5 * r7) + h8 * (5 * r6) + h9 * (5 * r5);
        c += d4 >>> 13;
        d4 &= 0x1fff;
        let d5 = c + h0 * r5 + h1 * r4 + h2 * r3 + h3 * r2 + h4 * r1;
        c = d5 >>> 13;
        d5 &= 0x1fff;
        d5 += h5 * r0 + h6 * (5 * r9) + h7 * (5 * r8) + h8 * (5 * r7) + h9 * (5 * r6);
        c += d5 >>> 13;
        d5 &= 0x1fff;
        let d6 = c + h0 * r6 + h1 * r5 + h2 * r4 + h3 * r3 + h4 * r2;
        c = d6 >>> 13;
        d6 &= 0x1fff;
        d6 += h5 * r1 + h6 * r0 + h7 * (5 * r9) + h8 * (5 * r8) + h9 * (5 * r7);
        c += d6 >>> 13;
        d6 &= 0x1fff;
        let d7 = c + h0 * r7 + h1 * r6 + h2 * r5 + h3 * r4 + h4 * r3;
        c = d7 >>> 13;
        d7 &= 0x1fff;
        d7 += h5 * r2 + h6 * r1 + h7 * r0 + h8 * (5 * r9) + h9 * (5 * r8);
        c += d7 >>> 13;
        d7 &= 0x1fff;
        let d8 = c + h0 * r8 + h1 * r7 + h2 * r6 + h3 * r5 + h4 * r4;
        c = d8 >>> 13;
        d8 &= 0x1fff;
        d8 += h5 * r3 + h6 * r2 + h7 * r1 + h8 * r0 + h9 * (5 * r9);
        c += d8 >>> 13;
        d8 &= 0x1fff;
        let d9 = c + h0 * r9 + h1 * r8 + h2 * r7 + h3 * r6 + h4 * r5;
        c = d9 >>> 13;
        d9 &= 0x1fff;
        d9 += h5 * r4 + h6 * r3 + h7 * r2 + h8 * r1 + h9 * r0;
        c += d9 >>> 13;
        d9 &= 0x1fff;
        c = ((c << 2) + c) | 0;
        c = (c + d0) | 0;
        d0 = c & 0x1fff;
        c = c >>> 13;
        d1 += c;
        h[0] = d0;
        h[1] = d1;
        h[2] = d2;
        h[3] = d3;
        h[4] = d4;
        h[5] = d5;
        h[6] = d6;
        h[7] = d7;
        h[8] = d8;
        h[9] = d9;
    }
    finalize() {
        const { h, pad } = this;
        const g = new Uint16Array(10);
        let c = h[1] >>> 13;
        h[1] &= 0x1fff;
        for (let i = 2; i < 10; i++) {
            h[i] += c;
            c = h[i] >>> 13;
            h[i] &= 0x1fff;
        }
        h[0] += c * 5;
        c = h[0] >>> 13;
        h[0] &= 0x1fff;
        h[1] += c;
        c = h[1] >>> 13;
        h[1] &= 0x1fff;
        h[2] += c;
        g[0] = h[0] + 5;
        c = g[0] >>> 13;
        g[0] &= 0x1fff;
        for (let i = 1; i < 10; i++) {
            g[i] = h[i] + c;
            c = g[i] >>> 13;
            g[i] &= 0x1fff;
        }
        g[9] -= 1 << 13;
        let mask = (c ^ 1) - 1;
        for (let i = 0; i < 10; i++)
            g[i] &= mask;
        mask = ~mask;
        for (let i = 0; i < 10; i++)
            h[i] = (h[i] & mask) | g[i];
        h[0] = (h[0] | (h[1] << 13)) & 0xffff;
        h[1] = ((h[1] >>> 3) | (h[2] << 10)) & 0xffff;
        h[2] = ((h[2] >>> 6) | (h[3] << 7)) & 0xffff;
        h[3] = ((h[3] >>> 9) | (h[4] << 4)) & 0xffff;
        h[4] = ((h[4] >>> 12) | (h[5] << 1) | (h[6] << 14)) & 0xffff;
        h[5] = ((h[6] >>> 2) | (h[7] << 11)) & 0xffff;
        h[6] = ((h[7] >>> 5) | (h[8] << 8)) & 0xffff;
        h[7] = ((h[8] >>> 8) | (h[9] << 5)) & 0xffff;
        let f = h[0] + pad[0];
        h[0] = f & 0xffff;
        for (let i = 1; i < 8; i++) {
            f = (((h[i] + pad[i]) | 0) + (f >>> 16)) | 0;
            h[i] = f & 0xffff;
        }
    }
    update(data) {
        (0, _assert_js_1.exists)(this);
        const { buffer, blockLen } = this;
        data = (0, utils_js_1.toBytes)(data);
        const len = data.length;
        for (let pos = 0; pos < len;) {
            const take = Math.min(blockLen - this.pos, len - pos);
            // Fast path: we have at least one block in input
            if (take === blockLen) {
                for (; blockLen <= len - pos; pos += blockLen)
                    this.process(data, pos);
                continue;
            }
            buffer.set(data.subarray(pos, pos + take), this.pos);
            this.pos += take;
            pos += take;
            if (this.pos === blockLen) {
                this.process(buffer, 0, false);
                this.pos = 0;
            }
        }
        return this;
    }
    destroy() {
        this.h.fill(0);
        this.r.fill(0);
        this.buffer.fill(0);
        this.pad.fill(0);
    }
    digestInto(out) {
        (0, _assert_js_1.exists)(this);
        (0, _assert_js_1.output)(out, this);
        this.finished = true;
        const { buffer, h } = this;
        let { pos } = this;
        if (pos) {
            buffer[pos++] = 1;
            // buffer.subarray(pos).fill(0);
            for (; pos < 16; pos++)
                buffer[pos] = 0;
            this.process(buffer, 0, true);
        }
        this.finalize();
        let opos = 0;
        for (let i = 0; i < 8; i++) {
            out[opos++] = h[i] >>> 0;
            out[opos++] = h[i] >>> 8;
        }
        return out;
    }
    digest() {
        const { buffer, outputLen } = this;
        this.digestInto(buffer);
        const res = buffer.slice(0, outputLen);
        this.destroy();
        return res;
    }
}
function wrapConstructorWithKey(hashCons) {
    const hashC = (msg, key) => hashCons(key).update((0, utils_js_1.toBytes)(msg)).digest();
    const tmp = hashCons(new Uint8Array(32));
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = (key) => hashCons(key);
    return hashC;
}
exports.wrapConstructorWithKey = wrapConstructorWithKey;
exports.poly1305 = wrapConstructorWithKey((key) => new Poly1305(key));

},{"./_assert.js":5,"./utils.js":11}],7:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.polyval = exports.ghash = exports._toGHASHKey = void 0;
const utils_js_1 = require("./utils.js");
const _assert_js_1 = require("./_assert.js");
// GHash from AES-GCM and its little-endian "mirror image" Polyval from AES-SIV.
// Implemented in terms of GHash with conversion function for keys
// GCM GHASH from NIST SP800-38d, SIV from RFC 8452.
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
// GHASH   modulo: x^128 + x^7   + x^2   + x     + 1
// POLYVAL modulo: x^128 + x^127 + x^126 + x^121 + 1
const BLOCK_SIZE = 16;
// TODO: rewrite
// temporary padding buffer
const ZEROS16 = /* @__PURE__ */ new Uint8Array(16);
const ZEROS32 = (0, utils_js_1.u32)(ZEROS16);
const POLY = 0xe1; // v = 2*v % POLY
// v = 2*v % POLY
// NOTE: because x + x = 0 (add/sub is same), mul2(x) != x+x
// We can multiply any number using montgomery ladder and this function (works as double, add is simple xor)
const mul2 = (s0, s1, s2, s3) => {
    const hiBit = s3 & 1;
    return {
        s3: (s2 << 31) | (s3 >>> 1),
        s2: (s1 << 31) | (s2 >>> 1),
        s1: (s0 << 31) | (s1 >>> 1),
        s0: (s0 >>> 1) ^ ((POLY << 24) & -(hiBit & 1)), // reduce % poly
    };
};
const swapLE = (n) => (((n >>> 0) & 0xff) << 24) |
    (((n >>> 8) & 0xff) << 16) |
    (((n >>> 16) & 0xff) << 8) |
    ((n >>> 24) & 0xff) |
    0;
/**
 * `mulX_POLYVAL(ByteReverse(H))` from spec
 * @param k mutated in place
 */
function _toGHASHKey(k) {
    k.reverse();
    const hiBit = k[15] & 1;
    // k >>= 1
    let carry = 0;
    for (let i = 0; i < k.length; i++) {
        const t = k[i];
        k[i] = (t >>> 1) | carry;
        carry = (t & 1) << 7;
    }
    k[0] ^= -hiBit & 0xe1; // if (hiBit) n ^= 0xe1000000000000000000000000000000;
    return k;
}
exports._toGHASHKey = _toGHASHKey;
const estimateWindow = (bytes) => {
    if (bytes > 64 * 1024)
        return 8;
    if (bytes > 1024)
        return 4;
    return 2;
};
class GHASH {
    // We select bits per window adaptively based on expectedLength
    constructor(key, expectedLength) {
        this.blockLen = BLOCK_SIZE;
        this.outputLen = BLOCK_SIZE;
        this.s0 = 0;
        this.s1 = 0;
        this.s2 = 0;
        this.s3 = 0;
        this.finished = false;
        key = (0, utils_js_1.toBytes)(key);
        (0, _assert_js_1.bytes)(key, 16);
        const kView = (0, utils_js_1.createView)(key);
        let k0 = kView.getUint32(0, false);
        let k1 = kView.getUint32(4, false);
        let k2 = kView.getUint32(8, false);
        let k3 = kView.getUint32(12, false);
        // generate table of doubled keys (half of montgomery ladder)
        const doubles = [];
        for (let i = 0; i < 128; i++) {
            doubles.push({ s0: swapLE(k0), s1: swapLE(k1), s2: swapLE(k2), s3: swapLE(k3) });
            ({ s0: k0, s1: k1, s2: k2, s3: k3 } = mul2(k0, k1, k2, k3));
        }
        const W = estimateWindow(expectedLength || 1024);
        if (![1, 2, 4, 8].includes(W))
            throw new Error(`ghash: wrong window size=${W}, should be 2, 4 or 8`);
        this.W = W;
        const bits = 128; // always 128 bits;
        const windows = bits / W;
        const windowSize = (this.windowSize = 2 ** W);
        const items = [];
        // Create precompute table for window of W bits
        for (let w = 0; w < windows; w++) {
            // truth table: 00, 01, 10, 11
            for (let byte = 0; byte < windowSize; byte++) {
                // prettier-ignore
                let s0 = 0, s1 = 0, s2 = 0, s3 = 0;
                for (let j = 0; j < W; j++) {
                    const bit = (byte >>> (W - j - 1)) & 1;
                    if (!bit)
                        continue;
                    const { s0: d0, s1: d1, s2: d2, s3: d3 } = doubles[W * w + j];
                    (s0 ^= d0), (s1 ^= d1), (s2 ^= d2), (s3 ^= d3);
                }
                items.push({ s0, s1, s2, s3 });
            }
        }
        this.t = items;
    }
    _updateBlock(s0, s1, s2, s3) {
        (s0 ^= this.s0), (s1 ^= this.s1), (s2 ^= this.s2), (s3 ^= this.s3);
        const { W, t, windowSize } = this;
        // prettier-ignore
        let o0 = 0, o1 = 0, o2 = 0, o3 = 0;
        const mask = (1 << W) - 1; // 2**W will kill performance.
        let w = 0;
        for (const num of [s0, s1, s2, s3]) {
            for (let bytePos = 0; bytePos < 4; bytePos++) {
                const byte = (num >>> (8 * bytePos)) & 0xff;
                for (let bitPos = 8 / W - 1; bitPos >= 0; bitPos--) {
                    const bit = (byte >>> (W * bitPos)) & mask;
                    const { s0: e0, s1: e1, s2: e2, s3: e3 } = t[w * windowSize + bit];
                    (o0 ^= e0), (o1 ^= e1), (o2 ^= e2), (o3 ^= e3);
                    w += 1;
                }
            }
        }
        this.s0 = o0;
        this.s1 = o1;
        this.s2 = o2;
        this.s3 = o3;
    }
    update(data) {
        data = (0, utils_js_1.toBytes)(data);
        (0, _assert_js_1.exists)(this);
        const b32 = (0, utils_js_1.u32)(data);
        const blocks = Math.floor(data.length / BLOCK_SIZE);
        const left = data.length % BLOCK_SIZE;
        for (let i = 0; i < blocks; i++) {
            this._updateBlock(b32[i * 4 + 0], b32[i * 4 + 1], b32[i * 4 + 2], b32[i * 4 + 3]);
        }
        if (left) {
            ZEROS16.set(data.subarray(blocks * BLOCK_SIZE));
            this._updateBlock(ZEROS32[0], ZEROS32[1], ZEROS32[2], ZEROS32[3]);
            ZEROS32.fill(0); // clean tmp buffer
        }
        return this;
    }
    destroy() {
        const { t } = this;
        // clean precompute table
        for (const elm of t) {
            (elm.s0 = 0), (elm.s1 = 0), (elm.s2 = 0), (elm.s3 = 0);
        }
    }
    digestInto(out) {
        (0, _assert_js_1.exists)(this);
        (0, _assert_js_1.output)(out, this);
        this.finished = true;
        const { s0, s1, s2, s3 } = this;
        const o32 = (0, utils_js_1.u32)(out);
        o32[0] = s0;
        o32[1] = s1;
        o32[2] = s2;
        o32[3] = s3;
        return out;
    }
    digest() {
        const res = new Uint8Array(BLOCK_SIZE);
        this.digestInto(res);
        this.destroy();
        return res;
    }
}
class Polyval extends GHASH {
    constructor(key, expectedLength) {
        key = (0, utils_js_1.toBytes)(key);
        const ghKey = _toGHASHKey(key.slice());
        super(ghKey, expectedLength);
        ghKey.fill(0);
    }
    update(data) {
        data = (0, utils_js_1.toBytes)(data);
        (0, _assert_js_1.exists)(this);
        const b32 = (0, utils_js_1.u32)(data);
        const left = data.length % BLOCK_SIZE;
        const blocks = Math.floor(data.length / BLOCK_SIZE);
        for (let i = 0; i < blocks; i++) {
            this._updateBlock(swapLE(b32[i * 4 + 3]), swapLE(b32[i * 4 + 2]), swapLE(b32[i * 4 + 1]), swapLE(b32[i * 4 + 0]));
        }
        if (left) {
            ZEROS16.set(data.subarray(blocks * BLOCK_SIZE));
            this._updateBlock(swapLE(ZEROS32[3]), swapLE(ZEROS32[2]), swapLE(ZEROS32[1]), swapLE(ZEROS32[0]));
            ZEROS32.fill(0); // clean tmp buffer
        }
        return this;
    }
    digestInto(out) {
        (0, _assert_js_1.exists)(this);
        (0, _assert_js_1.output)(out, this);
        this.finished = true;
        // tmp ugly hack
        const { s0, s1, s2, s3 } = this;
        const o32 = (0, utils_js_1.u32)(out);
        o32[0] = s0;
        o32[1] = s1;
        o32[2] = s2;
        o32[3] = s3;
        return out.reverse();
    }
}
function wrapConstructorWithKey(hashCons) {
    const hashC = (msg, key) => hashCons(key, msg.length).update((0, utils_js_1.toBytes)(msg)).digest();
    const tmp = hashCons(new Uint8Array(16), 0);
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = (key, expectedLength) => hashCons(key, expectedLength);
    return hashC;
}
exports.ghash = wrapConstructorWithKey((key, expectedLength) => new GHASH(key, expectedLength));
exports.polyval = wrapConstructorWithKey((key, expectedLength) => new Polyval(key, expectedLength));

},{"./_assert.js":5,"./utils.js":11}],8:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.unsafe = exports.siv = exports.gcm = exports.cfb = exports.cbc = exports.ecb = exports.ctr = exports.expandKeyDecLE = exports.expandKeyLE = void 0;
// prettier-ignore
const utils_js_1 = require("./utils.js");
const _polyval_js_1 = require("./_polyval.js");
const _assert_js_1 = require("./_assert.js");
/*
AES (Advanced Encryption Standard) aka Rijndael block cipher.

Data is split into 128-bit blocks. Encrypted in 10/12/14 rounds (128/192/256 bits). In every round:
1. **S-box**, table substitution
2. **Shift rows**, cyclic shift left of all rows of data array
3. **Mix columns**, multiplying every column by fixed polynomial
4. **Add round key**, round_key xor i-th column of array

Resources:
- FIPS-197 https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf
- Original proposal: https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/aes-development/rijndael-ammended.pdf
*/
const BLOCK_SIZE = 16;
const BLOCK_SIZE32 = 4;
const EMPTY_BLOCK = new Uint8Array(BLOCK_SIZE);
const POLY = 0x11b; // 1 + x + x**3 + x**4 + x**8
// TODO: remove multiplication, binary ops only
function mul2(n) {
    return (n << 1) ^ (POLY & -(n >> 7));
}
function mul(a, b) {
    let res = 0;
    for (; b > 0; b >>= 1) {
        // Montgomery ladder
        res ^= a & -(b & 1); // if (b&1) res ^=a (but const-time).
        a = mul2(a); // a = 2*a
    }
    return res;
}
// AES S-box is generated using finite field inversion,
// an affine transform, and xor of a constant 0x63.
const sbox = /* @__PURE__ */ (() => {
    let t = new Uint8Array(256);
    for (let i = 0, x = 1; i < 256; i++, x ^= mul2(x))
        t[i] = x;
    const box = new Uint8Array(256);
    box[0] = 0x63; // first elm
    for (let i = 0; i < 255; i++) {
        let x = t[255 - i];
        x |= x << 8;
        box[t[i]] = (x ^ (x >> 4) ^ (x >> 5) ^ (x >> 6) ^ (x >> 7) ^ 0x63) & 0xff;
    }
    return box;
})();
// Inverted S-box
const invSbox = /* @__PURE__ */ sbox.map((_, j) => sbox.indexOf(j));
// Rotate u32 by 8
const rotr32_8 = (n) => (n << 24) | (n >>> 8);
const rotl32_8 = (n) => (n << 8) | (n >>> 24);
// T-table is optimization suggested in 5.2 of original proposal (missed from FIPS-197). Changes:
// - LE instead of BE
// - bigger tables: T0 and T1 are merged into T01 table and T2 & T3 into T23;
//   so index is u16, instead of u8. This speeds up things, unexpectedly
function genTtable(sbox, fn) {
    if (sbox.length !== 256)
        throw new Error('Wrong sbox length');
    const T0 = new Uint32Array(256).map((_, j) => fn(sbox[j]));
    const T1 = T0.map(rotl32_8);
    const T2 = T1.map(rotl32_8);
    const T3 = T2.map(rotl32_8);
    const T01 = new Uint32Array(256 * 256);
    const T23 = new Uint32Array(256 * 256);
    const sbox2 = new Uint16Array(256 * 256);
    for (let i = 0; i < 256; i++) {
        for (let j = 0; j < 256; j++) {
            const idx = i * 256 + j;
            T01[idx] = T0[i] ^ T1[j];
            T23[idx] = T2[i] ^ T3[j];
            sbox2[idx] = (sbox[i] << 8) | sbox[j];
        }
    }
    return { sbox, sbox2, T0, T1, T2, T3, T01, T23 };
}
const tableEncoding = /* @__PURE__ */ genTtable(sbox, (s) => (mul(s, 3) << 24) | (s << 16) | (s << 8) | mul(s, 2));
const tableDecoding = /* @__PURE__ */ genTtable(invSbox, (s) => (mul(s, 11) << 24) | (mul(s, 13) << 16) | (mul(s, 9) << 8) | mul(s, 14));
const xPowers = /* @__PURE__ */ (() => {
    const p = new Uint8Array(16);
    for (let i = 0, x = 1; i < 16; i++, x = mul2(x))
        p[i] = x;
    return p;
})();
function expandKeyLE(key) {
    (0, _assert_js_1.bytes)(key);
    const len = key.length;
    if (![16, 24, 32].includes(len))
        throw new Error(`aes: wrong key size: should be 16, 24 or 32, got: ${len}`);
    const { sbox2 } = tableEncoding;
    const k32 = (0, utils_js_1.u32)(key);
    const Nk = k32.length;
    const subByte = (n) => applySbox(sbox2, n, n, n, n);
    const xk = new Uint32Array(len + 28); // expanded key
    xk.set(k32);
    // 4.3.1 Key expansion
    for (let i = Nk; i < xk.length; i++) {
        let t = xk[i - 1];
        if (i % Nk === 0)
            t = subByte(rotr32_8(t)) ^ xPowers[i / Nk - 1];
        else if (Nk > 6 && i % Nk === 4)
            t = subByte(t);
        xk[i] = xk[i - Nk] ^ t;
    }
    return xk;
}
exports.expandKeyLE = expandKeyLE;
function expandKeyDecLE(key) {
    const encKey = expandKeyLE(key);
    const xk = encKey.slice();
    const Nk = encKey.length;
    const { sbox2 } = tableEncoding;
    const { T0, T1, T2, T3 } = tableDecoding;
    // Inverse key by chunks of 4 (rounds)
    for (let i = 0; i < Nk; i += 4) {
        for (let j = 0; j < 4; j++)
            xk[i + j] = encKey[Nk - i - 4 + j];
    }
    encKey.fill(0);
    // apply InvMixColumn except first & last round
    for (let i = 4; i < Nk - 4; i++) {
        const x = xk[i];
        const w = applySbox(sbox2, x, x, x, x);
        xk[i] = T0[w & 0xff] ^ T1[(w >>> 8) & 0xff] ^ T2[(w >>> 16) & 0xff] ^ T3[w >>> 24];
    }
    return xk;
}
exports.expandKeyDecLE = expandKeyDecLE;
// Apply tables
function apply0123(T01, T23, s0, s1, s2, s3) {
    return (T01[((s0 << 8) & 0xff00) | ((s1 >>> 8) & 0xff)] ^
        T23[((s2 >>> 8) & 0xff00) | ((s3 >>> 24) & 0xff)]);
}
function applySbox(sbox2, s0, s1, s2, s3) {
    return (sbox2[(s0 & 0xff) | (s1 & 0xff00)] |
        (sbox2[((s2 >>> 16) & 0xff) | ((s3 >>> 16) & 0xff00)] << 16));
}
function encrypt(xk, s0, s1, s2, s3) {
    const { sbox2, T01, T23 } = tableEncoding;
    let k = 0;
    (s0 ^= xk[k++]), (s1 ^= xk[k++]), (s2 ^= xk[k++]), (s3 ^= xk[k++]);
    const rounds = xk.length / 4 - 2;
    for (let i = 0; i < rounds; i++) {
        const t0 = xk[k++] ^ apply0123(T01, T23, s0, s1, s2, s3);
        const t1 = xk[k++] ^ apply0123(T01, T23, s1, s2, s3, s0);
        const t2 = xk[k++] ^ apply0123(T01, T23, s2, s3, s0, s1);
        const t3 = xk[k++] ^ apply0123(T01, T23, s3, s0, s1, s2);
        (s0 = t0), (s1 = t1), (s2 = t2), (s3 = t3);
    }
    // last round (without mixcolumns, so using SBOX2 table)
    const t0 = xk[k++] ^ applySbox(sbox2, s0, s1, s2, s3);
    const t1 = xk[k++] ^ applySbox(sbox2, s1, s2, s3, s0);
    const t2 = xk[k++] ^ applySbox(sbox2, s2, s3, s0, s1);
    const t3 = xk[k++] ^ applySbox(sbox2, s3, s0, s1, s2);
    return { s0: t0, s1: t1, s2: t2, s3: t3 };
}
function decrypt(xk, s0, s1, s2, s3) {
    const { sbox2, T01, T23 } = tableDecoding;
    let k = 0;
    (s0 ^= xk[k++]), (s1 ^= xk[k++]), (s2 ^= xk[k++]), (s3 ^= xk[k++]);
    const rounds = xk.length / 4 - 2;
    for (let i = 0; i < rounds; i++) {
        const t0 = xk[k++] ^ apply0123(T01, T23, s0, s3, s2, s1);
        const t1 = xk[k++] ^ apply0123(T01, T23, s1, s0, s3, s2);
        const t2 = xk[k++] ^ apply0123(T01, T23, s2, s1, s0, s3);
        const t3 = xk[k++] ^ apply0123(T01, T23, s3, s2, s1, s0);
        (s0 = t0), (s1 = t1), (s2 = t2), (s3 = t3);
    }
    // Last round
    const t0 = xk[k++] ^ applySbox(sbox2, s0, s3, s2, s1);
    const t1 = xk[k++] ^ applySbox(sbox2, s1, s0, s3, s2);
    const t2 = xk[k++] ^ applySbox(sbox2, s2, s1, s0, s3);
    const t3 = xk[k++] ^ applySbox(sbox2, s3, s2, s1, s0);
    return { s0: t0, s1: t1, s2: t2, s3: t3 };
}
function getDst(len, dst) {
    if (!dst)
        return new Uint8Array(len);
    (0, _assert_js_1.bytes)(dst);
    if (dst.length < len)
        throw new Error(`aes: wrong destination length, expected at least ${len}, got: ${dst.length}`);
    return dst;
}
// TODO: investigate merging with ctr32
function ctrCounter(xk, nonce, src, dst) {
    (0, _assert_js_1.bytes)(nonce, BLOCK_SIZE);
    (0, _assert_js_1.bytes)(src);
    const srcLen = src.length;
    dst = getDst(srcLen, dst);
    const ctr = nonce;
    const c32 = (0, utils_js_1.u32)(ctr);
    // Fill block (empty, ctr=0)
    let { s0, s1, s2, s3 } = encrypt(xk, c32[0], c32[1], c32[2], c32[3]);
    const src32 = (0, utils_js_1.u32)(src);
    const dst32 = (0, utils_js_1.u32)(dst);
    // process blocks
    for (let i = 0; i + 4 <= src32.length; i += 4) {
        dst32[i + 0] = src32[i + 0] ^ s0;
        dst32[i + 1] = src32[i + 1] ^ s1;
        dst32[i + 2] = src32[i + 2] ^ s2;
        dst32[i + 3] = src32[i + 3] ^ s3;
        // Full 128 bit counter with wrap around
        let carry = 1;
        for (let i = ctr.length - 1; i >= 0; i--) {
            carry = (carry + (ctr[i] & 0xff)) | 0;
            ctr[i] = carry & 0xff;
            carry >>>= 8;
        }
        ({ s0, s1, s2, s3 } = encrypt(xk, c32[0], c32[1], c32[2], c32[3]));
    }
    // leftovers (less than block)
    // It's possible to handle > u32 fast, but is it worth it?
    const start = BLOCK_SIZE * Math.floor(src32.length / BLOCK_SIZE32);
    if (start < srcLen) {
        const b32 = new Uint32Array([s0, s1, s2, s3]);
        const buf = (0, utils_js_1.u8)(b32);
        for (let i = start, pos = 0; i < srcLen; i++, pos++)
            dst[i] = src[i] ^ buf[pos];
    }
    return dst;
}
// AES CTR with overflowing 32 bit counter
// It's possible to do 32le significantly simpler (and probably faster) by using u32.
// But, we need both, and perf bottleneck is in ghash anyway.
function ctr32(xk, isLE, nonce, src, dst) {
    (0, _assert_js_1.bytes)(nonce, BLOCK_SIZE);
    (0, _assert_js_1.bytes)(src);
    dst = getDst(src.length, dst);
    const ctr = nonce; // write new value to nonce, so it can be re-used
    const c32 = (0, utils_js_1.u32)(ctr);
    const view = (0, utils_js_1.createView)(ctr);
    const src32 = (0, utils_js_1.u32)(src);
    const dst32 = (0, utils_js_1.u32)(dst);
    const ctrPos = isLE ? 0 : 12;
    const srcLen = src.length;
    // Fill block (empty, ctr=0)
    let ctrNum = view.getUint32(ctrPos, isLE); // read current counter value
    let { s0, s1, s2, s3 } = encrypt(xk, c32[0], c32[1], c32[2], c32[3]);
    // process blocks
    for (let i = 0; i + 4 <= src32.length; i += 4) {
        dst32[i + 0] = src32[i + 0] ^ s0;
        dst32[i + 1] = src32[i + 1] ^ s1;
        dst32[i + 2] = src32[i + 2] ^ s2;
        dst32[i + 3] = src32[i + 3] ^ s3;
        ctrNum = (ctrNum + 1) >>> 0; // u32 wrap
        view.setUint32(ctrPos, ctrNum, isLE);
        ({ s0, s1, s2, s3 } = encrypt(xk, c32[0], c32[1], c32[2], c32[3]));
    }
    // leftovers (less than a block)
    const start = BLOCK_SIZE * Math.floor(src32.length / BLOCK_SIZE32);
    if (start < srcLen) {
        const b32 = new Uint32Array([s0, s1, s2, s3]);
        const buf = (0, utils_js_1.u8)(b32);
        for (let i = start, pos = 0; i < srcLen; i++, pos++)
            dst[i] = src[i] ^ buf[pos];
    }
    return dst;
}
/**
 * CTR: counter mode. Creates stream cipher.
 * Requires good IV. Parallelizable. OK, but no MAC.
 */
exports.ctr = (0, utils_js_1.wrapCipher)({ blockSize: 16, nonceLength: 16 }, function ctr(key, nonce) {
    (0, _assert_js_1.bytes)(key);
    (0, _assert_js_1.bytes)(nonce, BLOCK_SIZE);
    function processCtr(buf, dst) {
        const xk = expandKeyLE(key);
        const n = nonce.slice();
        const out = ctrCounter(xk, n, buf, dst);
        xk.fill(0);
        n.fill(0);
        return out;
    }
    return {
        encrypt: (plaintext, dst) => processCtr(plaintext, dst),
        decrypt: (ciphertext, dst) => processCtr(ciphertext, dst),
    };
});
function validateBlockDecrypt(data) {
    (0, _assert_js_1.bytes)(data);
    if (data.length % BLOCK_SIZE !== 0) {
        throw new Error(`aes/(cbc-ecb).decrypt ciphertext should consist of blocks with size ${BLOCK_SIZE}`);
    }
}
function validateBlockEncrypt(plaintext, pcks5, dst) {
    let outLen = plaintext.length;
    const remaining = outLen % BLOCK_SIZE;
    if (!pcks5 && remaining !== 0)
        throw new Error('aec/(cbc-ecb): unpadded plaintext with disabled padding');
    const b = (0, utils_js_1.u32)(plaintext);
    if (pcks5) {
        let left = BLOCK_SIZE - remaining;
        if (!left)
            left = BLOCK_SIZE; // if no bytes left, create empty padding block
        outLen = outLen + left;
    }
    const out = getDst(outLen, dst);
    const o = (0, utils_js_1.u32)(out);
    return { b, o, out };
}
function validatePCKS(data, pcks5) {
    if (!pcks5)
        return data;
    const len = data.length;
    if (!len)
        throw new Error(`aes/pcks5: empty ciphertext not allowed`);
    const lastByte = data[len - 1];
    if (lastByte <= 0 || lastByte > 16)
        throw new Error(`aes/pcks5: wrong padding byte: ${lastByte}`);
    const out = data.subarray(0, -lastByte);
    for (let i = 0; i < lastByte; i++)
        if (data[len - i - 1] !== lastByte)
            throw new Error(`aes/pcks5: wrong padding`);
    return out;
}
function padPCKS(left) {
    const tmp = new Uint8Array(16);
    const tmp32 = (0, utils_js_1.u32)(tmp);
    tmp.set(left);
    const paddingByte = BLOCK_SIZE - left.length;
    for (let i = BLOCK_SIZE - paddingByte; i < BLOCK_SIZE; i++)
        tmp[i] = paddingByte;
    return tmp32;
}
/**
 * ECB: Electronic CodeBook. Simple deterministic replacement.
 * Dangerous: always map x to y. See [AES Penguin](https://words.filippo.io/the-ecb-penguin/).
 */
exports.ecb = (0, utils_js_1.wrapCipher)({ blockSize: 16 }, function ecb(key, opts = {}) {
    (0, _assert_js_1.bytes)(key);
    const pcks5 = !opts.disablePadding;
    return {
        encrypt: (plaintext, dst) => {
            (0, _assert_js_1.bytes)(plaintext);
            const { b, o, out: _out } = validateBlockEncrypt(plaintext, pcks5, dst);
            const xk = expandKeyLE(key);
            let i = 0;
            for (; i + 4 <= b.length;) {
                const { s0, s1, s2, s3 } = encrypt(xk, b[i + 0], b[i + 1], b[i + 2], b[i + 3]);
                (o[i++] = s0), (o[i++] = s1), (o[i++] = s2), (o[i++] = s3);
            }
            if (pcks5) {
                const tmp32 = padPCKS(plaintext.subarray(i * 4));
                const { s0, s1, s2, s3 } = encrypt(xk, tmp32[0], tmp32[1], tmp32[2], tmp32[3]);
                (o[i++] = s0), (o[i++] = s1), (o[i++] = s2), (o[i++] = s3);
            }
            xk.fill(0);
            return _out;
        },
        decrypt: (ciphertext, dst) => {
            validateBlockDecrypt(ciphertext);
            const xk = expandKeyDecLE(key);
            const out = getDst(ciphertext.length, dst);
            const b = (0, utils_js_1.u32)(ciphertext);
            const o = (0, utils_js_1.u32)(out);
            for (let i = 0; i + 4 <= b.length;) {
                const { s0, s1, s2, s3 } = decrypt(xk, b[i + 0], b[i + 1], b[i + 2], b[i + 3]);
                (o[i++] = s0), (o[i++] = s1), (o[i++] = s2), (o[i++] = s3);
            }
            xk.fill(0);
            return validatePCKS(out, pcks5);
        },
    };
});
/**
 * CBC: Cipher-Block-Chaining. Key is previous round’s block.
 * Fragile: needs proper padding. Unauthenticated: needs MAC.
 */
exports.cbc = (0, utils_js_1.wrapCipher)({ blockSize: 16, nonceLength: 16 }, function cbc(key, iv, opts = {}) {
    (0, _assert_js_1.bytes)(key);
    (0, _assert_js_1.bytes)(iv, 16);
    const pcks5 = !opts.disablePadding;
    return {
        encrypt: (plaintext, dst) => {
            const xk = expandKeyLE(key);
            const { b, o, out: _out } = validateBlockEncrypt(plaintext, pcks5, dst);
            const n32 = (0, utils_js_1.u32)(iv);
            // prettier-ignore
            let s0 = n32[0], s1 = n32[1], s2 = n32[2], s3 = n32[3];
            let i = 0;
            for (; i + 4 <= b.length;) {
                (s0 ^= b[i + 0]), (s1 ^= b[i + 1]), (s2 ^= b[i + 2]), (s3 ^= b[i + 3]);
                ({ s0, s1, s2, s3 } = encrypt(xk, s0, s1, s2, s3));
                (o[i++] = s0), (o[i++] = s1), (o[i++] = s2), (o[i++] = s3);
            }
            if (pcks5) {
                const tmp32 = padPCKS(plaintext.subarray(i * 4));
                (s0 ^= tmp32[0]), (s1 ^= tmp32[1]), (s2 ^= tmp32[2]), (s3 ^= tmp32[3]);
                ({ s0, s1, s2, s3 } = encrypt(xk, s0, s1, s2, s3));
                (o[i++] = s0), (o[i++] = s1), (o[i++] = s2), (o[i++] = s3);
            }
            xk.fill(0);
            return _out;
        },
        decrypt: (ciphertext, dst) => {
            validateBlockDecrypt(ciphertext);
            const xk = expandKeyDecLE(key);
            const n32 = (0, utils_js_1.u32)(iv);
            const out = getDst(ciphertext.length, dst);
            const b = (0, utils_js_1.u32)(ciphertext);
            const o = (0, utils_js_1.u32)(out);
            // prettier-ignore
            let s0 = n32[0], s1 = n32[1], s2 = n32[2], s3 = n32[3];
            for (let i = 0; i + 4 <= b.length;) {
                // prettier-ignore
                const ps0 = s0, ps1 = s1, ps2 = s2, ps3 = s3;
                (s0 = b[i + 0]), (s1 = b[i + 1]), (s2 = b[i + 2]), (s3 = b[i + 3]);
                const { s0: o0, s1: o1, s2: o2, s3: o3 } = decrypt(xk, s0, s1, s2, s3);
                (o[i++] = o0 ^ ps0), (o[i++] = o1 ^ ps1), (o[i++] = o2 ^ ps2), (o[i++] = o3 ^ ps3);
            }
            xk.fill(0);
            return validatePCKS(out, pcks5);
        },
    };
});
/**
 * CFB: Cipher Feedback Mode. The input for the block cipher is the previous cipher output.
 * Unauthenticated: needs MAC.
 */
exports.cfb = (0, utils_js_1.wrapCipher)({ blockSize: 16, nonceLength: 16 }, function cfb(key, iv) {
    (0, _assert_js_1.bytes)(key);
    (0, _assert_js_1.bytes)(iv, 16);
    function processCfb(src, isEncrypt, dst) {
        const xk = expandKeyLE(key);
        const srcLen = src.length;
        dst = getDst(srcLen, dst);
        const src32 = (0, utils_js_1.u32)(src);
        const dst32 = (0, utils_js_1.u32)(dst);
        const next32 = isEncrypt ? dst32 : src32;
        const n32 = (0, utils_js_1.u32)(iv);
        // prettier-ignore
        let s0 = n32[0], s1 = n32[1], s2 = n32[2], s3 = n32[3];
        for (let i = 0; i + 4 <= src32.length;) {
            const { s0: e0, s1: e1, s2: e2, s3: e3 } = encrypt(xk, s0, s1, s2, s3);
            dst32[i + 0] = src32[i + 0] ^ e0;
            dst32[i + 1] = src32[i + 1] ^ e1;
            dst32[i + 2] = src32[i + 2] ^ e2;
            dst32[i + 3] = src32[i + 3] ^ e3;
            (s0 = next32[i++]), (s1 = next32[i++]), (s2 = next32[i++]), (s3 = next32[i++]);
        }
        // leftovers (less than block)
        const start = BLOCK_SIZE * Math.floor(src32.length / BLOCK_SIZE32);
        if (start < srcLen) {
            ({ s0, s1, s2, s3 } = encrypt(xk, s0, s1, s2, s3));
            const buf = (0, utils_js_1.u8)(new Uint32Array([s0, s1, s2, s3]));
            for (let i = start, pos = 0; i < srcLen; i++, pos++)
                dst[i] = src[i] ^ buf[pos];
            buf.fill(0);
        }
        xk.fill(0);
        return dst;
    }
    return {
        encrypt: (plaintext, dst) => processCfb(plaintext, true, dst),
        decrypt: (ciphertext, dst) => processCfb(ciphertext, false, dst),
    };
});
// TODO: merge with chacha, however gcm has bitLen while chacha has byteLen
function computeTag(fn, isLE, key, data, AAD) {
    const h = fn.create(key, data.length + (AAD?.length || 0));
    if (AAD)
        h.update(AAD);
    h.update(data);
    const num = new Uint8Array(16);
    const view = (0, utils_js_1.createView)(num);
    if (AAD)
        (0, utils_js_1.setBigUint64)(view, 0, BigInt(AAD.length * 8), isLE);
    (0, utils_js_1.setBigUint64)(view, 8, BigInt(data.length * 8), isLE);
    h.update(num);
    return h.digest();
}
/**
 * GCM: Galois/Counter Mode.
 * Good, modern version of CTR, parallel, with MAC.
 * Be careful: MACs can be forged.
 */
exports.gcm = (0, utils_js_1.wrapCipher)({ blockSize: 16, nonceLength: 12, tagLength: 16 }, function gcm(key, nonce, AAD) {
    (0, _assert_js_1.bytes)(nonce);
    // Nonce can be pretty much anything (even 1 byte). But smaller nonces less secure.
    if (nonce.length === 0)
        throw new Error('aes/gcm: empty nonce');
    const tagLength = 16;
    function _computeTag(authKey, tagMask, data) {
        const tag = computeTag(_polyval_js_1.ghash, false, authKey, data, AAD);
        for (let i = 0; i < tagMask.length; i++)
            tag[i] ^= tagMask[i];
        return tag;
    }
    function deriveKeys() {
        const xk = expandKeyLE(key);
        const authKey = EMPTY_BLOCK.slice();
        const counter = EMPTY_BLOCK.slice();
        ctr32(xk, false, counter, counter, authKey);
        if (nonce.length === 12) {
            counter.set(nonce);
        }
        else {
            // Spec (NIST 800-38d) supports variable size nonce.
            // Not supported for now, but can be useful.
            const nonceLen = EMPTY_BLOCK.slice();
            const view = (0, utils_js_1.createView)(nonceLen);
            (0, utils_js_1.setBigUint64)(view, 8, BigInt(nonce.length * 8), false);
            // ghash(nonce || u64be(0) || u64be(nonceLen*8))
            _polyval_js_1.ghash.create(authKey).update(nonce).update(nonceLen).digestInto(counter);
        }
        const tagMask = ctr32(xk, false, counter, EMPTY_BLOCK);
        return { xk, authKey, counter, tagMask };
    }
    return {
        encrypt: (plaintext) => {
            (0, _assert_js_1.bytes)(plaintext);
            const { xk, authKey, counter, tagMask } = deriveKeys();
            const out = new Uint8Array(plaintext.length + tagLength);
            ctr32(xk, false, counter, plaintext, out);
            const tag = _computeTag(authKey, tagMask, out.subarray(0, out.length - tagLength));
            out.set(tag, plaintext.length);
            xk.fill(0);
            return out;
        },
        decrypt: (ciphertext) => {
            (0, _assert_js_1.bytes)(ciphertext);
            if (ciphertext.length < tagLength)
                throw new Error(`aes/gcm: ciphertext less than tagLen (${tagLength})`);
            const { xk, authKey, counter, tagMask } = deriveKeys();
            const data = ciphertext.subarray(0, -tagLength);
            const passedTag = ciphertext.subarray(-tagLength);
            const tag = _computeTag(authKey, tagMask, data);
            if (!(0, utils_js_1.equalBytes)(tag, passedTag))
                throw new Error('aes/gcm: invalid ghash tag');
            const out = ctr32(xk, false, counter, data);
            authKey.fill(0);
            tagMask.fill(0);
            xk.fill(0);
            return out;
        },
    };
});
const limit = (name, min, max) => (value) => {
    if (!Number.isSafeInteger(value) || min > value || value > max)
        throw new Error(`${name}: invalid value=${value}, must be [${min}..${max}]`);
};
/**
 * AES-GCM-SIV: classic AES-GCM with nonce-misuse resistance.
 * Guarantees that, when a nonce is repeated, the only security loss is that identical
 * plaintexts will produce identical ciphertexts.
 * RFC 8452, https://datatracker.ietf.org/doc/html/rfc8452
 */
exports.siv = (0, utils_js_1.wrapCipher)({ blockSize: 16, nonceLength: 12, tagLength: 16 }, function siv(key, nonce, AAD) {
    const tagLength = 16;
    // From RFC 8452: Section 6
    const AAD_LIMIT = limit('AAD', 0, 2 ** 36);
    const PLAIN_LIMIT = limit('plaintext', 0, 2 ** 36);
    const NONCE_LIMIT = limit('nonce', 12, 12);
    const CIPHER_LIMIT = limit('ciphertext', 16, 2 ** 36 + 16);
    (0, _assert_js_1.bytes)(nonce);
    NONCE_LIMIT(nonce.length);
    if (AAD) {
        (0, _assert_js_1.bytes)(AAD);
        AAD_LIMIT(AAD.length);
    }
    function deriveKeys() {
        const len = key.length;
        if (len !== 16 && len !== 24 && len !== 32)
            throw new Error(`key length must be 16, 24 or 32 bytes, got: ${len} bytes`);
        const xk = expandKeyLE(key);
        const encKey = new Uint8Array(len);
        const authKey = new Uint8Array(16);
        const n32 = (0, utils_js_1.u32)(nonce);
        // prettier-ignore
        let s0 = 0, s1 = n32[0], s2 = n32[1], s3 = n32[2];
        let counter = 0;
        for (const derivedKey of [authKey, encKey].map(utils_js_1.u32)) {
            const d32 = (0, utils_js_1.u32)(derivedKey);
            for (let i = 0; i < d32.length; i += 2) {
                // aes(u32le(0) || nonce)[:8] || aes(u32le(1) || nonce)[:8] ...
                const { s0: o0, s1: o1 } = encrypt(xk, s0, s1, s2, s3);
                d32[i + 0] = o0;
                d32[i + 1] = o1;
                s0 = ++counter; // increment counter inside state
            }
        }
        xk.fill(0);
        return { authKey, encKey: expandKeyLE(encKey) };
    }
    function _computeTag(encKey, authKey, data) {
        const tag = computeTag(_polyval_js_1.polyval, true, authKey, data, AAD);
        // Compute the expected tag by XORing S_s and the nonce, clearing the
        // most significant bit of the last byte and encrypting with the
        // message-encryption key.
        for (let i = 0; i < 12; i++)
            tag[i] ^= nonce[i];
        tag[15] &= 0x7f; // Clear the highest bit
        // encrypt tag as block
        const t32 = (0, utils_js_1.u32)(tag);
        // prettier-ignore
        let s0 = t32[0], s1 = t32[1], s2 = t32[2], s3 = t32[3];
        ({ s0, s1, s2, s3 } = encrypt(encKey, s0, s1, s2, s3));
        (t32[0] = s0), (t32[1] = s1), (t32[2] = s2), (t32[3] = s3);
        return tag;
    }
    // actual decrypt/encrypt of message.
    function processSiv(encKey, tag, input) {
        let block = tag.slice();
        block[15] |= 0x80; // Force highest bit
        return ctr32(encKey, true, block, input);
    }
    return {
        encrypt: (plaintext) => {
            (0, _assert_js_1.bytes)(plaintext);
            PLAIN_LIMIT(plaintext.length);
            const { encKey, authKey } = deriveKeys();
            const tag = _computeTag(encKey, authKey, plaintext);
            const out = new Uint8Array(plaintext.length + tagLength);
            out.set(tag, plaintext.length);
            out.set(processSiv(encKey, tag, plaintext));
            encKey.fill(0);
            authKey.fill(0);
            return out;
        },
        decrypt: (ciphertext) => {
            (0, _assert_js_1.bytes)(ciphertext);
            CIPHER_LIMIT(ciphertext.length);
            const tag = ciphertext.subarray(-tagLength);
            const { encKey, authKey } = deriveKeys();
            const plaintext = processSiv(encKey, tag, ciphertext.subarray(0, -tagLength));
            const expectedTag = _computeTag(encKey, authKey, plaintext);
            encKey.fill(0);
            authKey.fill(0);
            if (!(0, utils_js_1.equalBytes)(tag, expectedTag))
                throw new Error('invalid polyval tag');
            return plaintext;
        },
    };
});
function isBytes32(a) {
    return (a != null &&
        typeof a === 'object' &&
        (a instanceof Uint32Array || a.constructor.name === 'Uint32Array'));
}
function encryptBlock(xk, block) {
    (0, _assert_js_1.bytes)(block, 16);
    if (!isBytes32(xk))
        throw new Error('_encryptBlock accepts result of expandKeyLE');
    const b32 = (0, utils_js_1.u32)(block);
    let { s0, s1, s2, s3 } = encrypt(xk, b32[0], b32[1], b32[2], b32[3]);
    (b32[0] = s0), (b32[1] = s1), (b32[2] = s2), (b32[3] = s3);
    return block;
}
function decryptBlock(xk, block) {
    (0, _assert_js_1.bytes)(block, 16);
    if (!isBytes32(xk))
        throw new Error('_decryptBlock accepts result of expandKeyLE');
    const b32 = (0, utils_js_1.u32)(block);
    let { s0, s1, s2, s3 } = decrypt(xk, b32[0], b32[1], b32[2], b32[3]);
    (b32[0] = s0), (b32[1] = s1), (b32[2] = s2), (b32[3] = s3);
    return block;
}
// Highly unsafe private functions for implementing new modes or ciphers based on AES
// Can change at any time, no API guarantees
exports.unsafe = {
    expandKeyLE,
    expandKeyDecLE,
    encrypt,
    decrypt,
    encryptBlock,
    decryptBlock,
    ctrCounter,
    ctr32,
};

},{"./_assert.js":5,"./_polyval.js":7,"./utils.js":11}],9:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getWebcryptoSubtle = exports.randomBytes = void 0;
const cr = typeof globalThis === 'object' && 'crypto' in globalThis ? globalThis.crypto : undefined;
function randomBytes(bytesLength = 32) {
    if (cr && typeof cr.getRandomValues === 'function')
        return cr.getRandomValues(new Uint8Array(bytesLength));
    throw new Error('crypto.getRandomValues must be defined');
}
exports.randomBytes = randomBytes;
function getWebcryptoSubtle() {
    if (cr && typeof cr.subtle === 'object' && cr.subtle != null)
        return cr.subtle;
    throw new Error('crypto.subtle must be defined');
}
exports.getWebcryptoSubtle = getWebcryptoSubtle;

},{}],10:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.secretbox = exports.xsalsa20poly1305 = exports.xsalsa20 = exports.salsa20 = exports.hsalsa = void 0;
const _assert_js_1 = require("./_assert.js");
const _arx_js_1 = require("./_arx.js");
const _poly1305_js_1 = require("./_poly1305.js");
const utils_js_1 = require("./utils.js");
// Salsa20 stream cipher was released in 2005.
// Salsa's goal was to implement AES replacement that does not rely on S-Boxes,
// which are hard to implement in a constant-time manner.
// https://cr.yp.to/snuffle.html, https://cr.yp.to/snuffle/salsafamily-20071225.pdf
/**
 * Salsa20 core function.
 */
// prettier-ignore
function salsaCore(s, k, n, out, cnt, rounds = 20) {
    // Based on https://cr.yp.to/salsa20.html
    let y00 = s[0], y01 = k[0], y02 = k[1], y03 = k[2], // "expa" Key     Key     Key
    y04 = k[3], y05 = s[1], y06 = n[0], y07 = n[1], // Key    "nd 3"  Nonce   Nonce
    y08 = cnt, y09 = 0, y10 = s[2], y11 = k[4], // Pos.   Pos.    "2-by"	Key
    y12 = k[5], y13 = k[6], y14 = k[7], y15 = s[3]; // Key    Key     Key     "te k"
    // Save state to temporary variables
    let x00 = y00, x01 = y01, x02 = y02, x03 = y03, x04 = y04, x05 = y05, x06 = y06, x07 = y07, x08 = y08, x09 = y09, x10 = y10, x11 = y11, x12 = y12, x13 = y13, x14 = y14, x15 = y15;
    for (let r = 0; r < rounds; r += 2) {
        x04 ^= (0, _arx_js_1.rotl)(x00 + x12 | 0, 7);
        x08 ^= (0, _arx_js_1.rotl)(x04 + x00 | 0, 9);
        x12 ^= (0, _arx_js_1.rotl)(x08 + x04 | 0, 13);
        x00 ^= (0, _arx_js_1.rotl)(x12 + x08 | 0, 18);
        x09 ^= (0, _arx_js_1.rotl)(x05 + x01 | 0, 7);
        x13 ^= (0, _arx_js_1.rotl)(x09 + x05 | 0, 9);
        x01 ^= (0, _arx_js_1.rotl)(x13 + x09 | 0, 13);
        x05 ^= (0, _arx_js_1.rotl)(x01 + x13 | 0, 18);
        x14 ^= (0, _arx_js_1.rotl)(x10 + x06 | 0, 7);
        x02 ^= (0, _arx_js_1.rotl)(x14 + x10 | 0, 9);
        x06 ^= (0, _arx_js_1.rotl)(x02 + x14 | 0, 13);
        x10 ^= (0, _arx_js_1.rotl)(x06 + x02 | 0, 18);
        x03 ^= (0, _arx_js_1.rotl)(x15 + x11 | 0, 7);
        x07 ^= (0, _arx_js_1.rotl)(x03 + x15 | 0, 9);
        x11 ^= (0, _arx_js_1.rotl)(x07 + x03 | 0, 13);
        x15 ^= (0, _arx_js_1.rotl)(x11 + x07 | 0, 18);
        x01 ^= (0, _arx_js_1.rotl)(x00 + x03 | 0, 7);
        x02 ^= (0, _arx_js_1.rotl)(x01 + x00 | 0, 9);
        x03 ^= (0, _arx_js_1.rotl)(x02 + x01 | 0, 13);
        x00 ^= (0, _arx_js_1.rotl)(x03 + x02 | 0, 18);
        x06 ^= (0, _arx_js_1.rotl)(x05 + x04 | 0, 7);
        x07 ^= (0, _arx_js_1.rotl)(x06 + x05 | 0, 9);
        x04 ^= (0, _arx_js_1.rotl)(x07 + x06 | 0, 13);
        x05 ^= (0, _arx_js_1.rotl)(x04 + x07 | 0, 18);
        x11 ^= (0, _arx_js_1.rotl)(x10 + x09 | 0, 7);
        x08 ^= (0, _arx_js_1.rotl)(x11 + x10 | 0, 9);
        x09 ^= (0, _arx_js_1.rotl)(x08 + x11 | 0, 13);
        x10 ^= (0, _arx_js_1.rotl)(x09 + x08 | 0, 18);
        x12 ^= (0, _arx_js_1.rotl)(x15 + x14 | 0, 7);
        x13 ^= (0, _arx_js_1.rotl)(x12 + x15 | 0, 9);
        x14 ^= (0, _arx_js_1.rotl)(x13 + x12 | 0, 13);
        x15 ^= (0, _arx_js_1.rotl)(x14 + x13 | 0, 18);
    }
    // Write output
    let oi = 0;
    out[oi++] = (y00 + x00) | 0;
    out[oi++] = (y01 + x01) | 0;
    out[oi++] = (y02 + x02) | 0;
    out[oi++] = (y03 + x03) | 0;
    out[oi++] = (y04 + x04) | 0;
    out[oi++] = (y05 + x05) | 0;
    out[oi++] = (y06 + x06) | 0;
    out[oi++] = (y07 + x07) | 0;
    out[oi++] = (y08 + x08) | 0;
    out[oi++] = (y09 + x09) | 0;
    out[oi++] = (y10 + x10) | 0;
    out[oi++] = (y11 + x11) | 0;
    out[oi++] = (y12 + x12) | 0;
    out[oi++] = (y13 + x13) | 0;
    out[oi++] = (y14 + x14) | 0;
    out[oi++] = (y15 + x15) | 0;
}
/**
 * hsalsa hashing function, used primarily in xsalsa, to hash
 * key and nonce into key' and nonce'.
 * Same as salsaCore, but there doesn't seem to be a way to move the block
 * out without 25% performance hit.
 */
// prettier-ignore
function hsalsa(s, k, i, o32) {
    let x00 = s[0], x01 = k[0], x02 = k[1], x03 = k[2], x04 = k[3], x05 = s[1], x06 = i[0], x07 = i[1], x08 = i[2], x09 = i[3], x10 = s[2], x11 = k[4], x12 = k[5], x13 = k[6], x14 = k[7], x15 = s[3];
    for (let r = 0; r < 20; r += 2) {
        x04 ^= (0, _arx_js_1.rotl)(x00 + x12 | 0, 7);
        x08 ^= (0, _arx_js_1.rotl)(x04 + x00 | 0, 9);
        x12 ^= (0, _arx_js_1.rotl)(x08 + x04 | 0, 13);
        x00 ^= (0, _arx_js_1.rotl)(x12 + x08 | 0, 18);
        x09 ^= (0, _arx_js_1.rotl)(x05 + x01 | 0, 7);
        x13 ^= (0, _arx_js_1.rotl)(x09 + x05 | 0, 9);
        x01 ^= (0, _arx_js_1.rotl)(x13 + x09 | 0, 13);
        x05 ^= (0, _arx_js_1.rotl)(x01 + x13 | 0, 18);
        x14 ^= (0, _arx_js_1.rotl)(x10 + x06 | 0, 7);
        x02 ^= (0, _arx_js_1.rotl)(x14 + x10 | 0, 9);
        x06 ^= (0, _arx_js_1.rotl)(x02 + x14 | 0, 13);
        x10 ^= (0, _arx_js_1.rotl)(x06 + x02 | 0, 18);
        x03 ^= (0, _arx_js_1.rotl)(x15 + x11 | 0, 7);
        x07 ^= (0, _arx_js_1.rotl)(x03 + x15 | 0, 9);
        x11 ^= (0, _arx_js_1.rotl)(x07 + x03 | 0, 13);
        x15 ^= (0, _arx_js_1.rotl)(x11 + x07 | 0, 18);
        x01 ^= (0, _arx_js_1.rotl)(x00 + x03 | 0, 7);
        x02 ^= (0, _arx_js_1.rotl)(x01 + x00 | 0, 9);
        x03 ^= (0, _arx_js_1.rotl)(x02 + x01 | 0, 13);
        x00 ^= (0, _arx_js_1.rotl)(x03 + x02 | 0, 18);
        x06 ^= (0, _arx_js_1.rotl)(x05 + x04 | 0, 7);
        x07 ^= (0, _arx_js_1.rotl)(x06 + x05 | 0, 9);
        x04 ^= (0, _arx_js_1.rotl)(x07 + x06 | 0, 13);
        x05 ^= (0, _arx_js_1.rotl)(x04 + x07 | 0, 18);
        x11 ^= (0, _arx_js_1.rotl)(x10 + x09 | 0, 7);
        x08 ^= (0, _arx_js_1.rotl)(x11 + x10 | 0, 9);
        x09 ^= (0, _arx_js_1.rotl)(x08 + x11 | 0, 13);
        x10 ^= (0, _arx_js_1.rotl)(x09 + x08 | 0, 18);
        x12 ^= (0, _arx_js_1.rotl)(x15 + x14 | 0, 7);
        x13 ^= (0, _arx_js_1.rotl)(x12 + x15 | 0, 9);
        x14 ^= (0, _arx_js_1.rotl)(x13 + x12 | 0, 13);
        x15 ^= (0, _arx_js_1.rotl)(x14 + x13 | 0, 18);
    }
    let oi = 0;
    o32[oi++] = x00;
    o32[oi++] = x05;
    o32[oi++] = x10;
    o32[oi++] = x15;
    o32[oi++] = x06;
    o32[oi++] = x07;
    o32[oi++] = x08;
    o32[oi++] = x09;
}
exports.hsalsa = hsalsa;
/**
 * Salsa20 from original paper.
 * With 12-byte nonce, it's not safe to use fill it with random (CSPRNG), due to collision chance.
 */
exports.salsa20 = (0, _arx_js_1.createCipher)(salsaCore, {
    allowShortKeys: true,
    counterRight: true,
});
/**
 * xsalsa20 eXtended-nonce salsa.
 * With 24-byte nonce, it's safe to use fill it with random (CSPRNG).
 */
exports.xsalsa20 = (0, _arx_js_1.createCipher)(salsaCore, {
    counterRight: true,
    extendNonceFn: hsalsa,
});
/**
 * xsalsa20-poly1305 eXtended-nonce salsa.
 * With 24-byte nonce, it's safe to use fill it with random (CSPRNG).
 * Also known as secretbox from libsodium / nacl.
 */
exports.xsalsa20poly1305 = (0, utils_js_1.wrapCipher)({ blockSize: 64, nonceLength: 24, tagLength: 16 }, (key, nonce) => {
    const tagLength = 16;
    (0, _assert_js_1.bytes)(key, 32);
    (0, _assert_js_1.bytes)(nonce, 24);
    return {
        encrypt: (plaintext, output) => {
            (0, _assert_js_1.bytes)(plaintext);
            // This is small optimization (calculate auth key with same call as encryption itself) makes it hard
            // to separate tag calculation and encryption itself, since 32 byte is half-block of salsa (64 byte)
            const clength = plaintext.length + 32;
            if (output) {
                (0, _assert_js_1.bytes)(output, clength);
            }
            else {
                output = new Uint8Array(clength);
            }
            output.set(plaintext, 32);
            (0, exports.xsalsa20)(key, nonce, output, output);
            const authKey = output.subarray(0, 32);
            const tag = (0, _poly1305_js_1.poly1305)(output.subarray(32), authKey);
            // Clean auth key, even though JS provides no guarantees about memory cleaning
            output.set(tag, tagLength);
            output.subarray(0, tagLength).fill(0);
            return output.subarray(tagLength);
        },
        decrypt: (ciphertext) => {
            (0, _assert_js_1.bytes)(ciphertext);
            const clength = ciphertext.length;
            if (clength < tagLength)
                throw new Error('encrypted data should be at least 16 bytes');
            // Create new ciphertext array:
            // auth tag      auth tag from ciphertext ciphertext
            // [bytes 0..16] [bytes 16..32]           [bytes 32..]
            // 16 instead of 32, because we already have 16 byte tag
            const ciphertext_ = new Uint8Array(clength + tagLength); // alloc
            ciphertext_.set(ciphertext, tagLength);
            // Each xsalsa20 calls to hsalsa to calculate key, but seems not much perf difference
            // Separate call to calculate authkey, since first bytes contains tag
            const authKey = (0, exports.xsalsa20)(key, nonce, new Uint8Array(32)); // alloc(32)
            const tag = (0, _poly1305_js_1.poly1305)(ciphertext_.subarray(32), authKey);
            if (!(0, utils_js_1.equalBytes)(ciphertext_.subarray(16, 32), tag))
                throw new Error('invalid tag');
            const plaintext = (0, exports.xsalsa20)(key, nonce, ciphertext_); // alloc
            // Clean auth key, even though JS provides no guarantees about memory cleaning
            plaintext.subarray(0, 32).fill(0);
            authKey.fill(0);
            return plaintext.subarray(32);
        },
    };
});
/**
 * Alias to xsalsa20poly1305, for compatibility with libsodium / nacl
 */
function secretbox(key, nonce) {
    const xs = (0, exports.xsalsa20poly1305)(key, nonce);
    return { seal: xs.encrypt, open: xs.decrypt };
}
exports.secretbox = secretbox;

},{"./_arx.js":4,"./_assert.js":5,"./_poly1305.js":6,"./utils.js":11}],11:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.u64Lengths = exports.setBigUint64 = exports.wrapCipher = exports.Hash = exports.equalBytes = exports.checkOpts = exports.concatBytes = exports.toBytes = exports.bytesToUtf8 = exports.utf8ToBytes = exports.asyncLoop = exports.nextTick = exports.numberToBytesBE = exports.bytesToNumberBE = exports.hexToNumber = exports.hexToBytes = exports.bytesToHex = exports.isLE = exports.createView = exports.u32 = exports.u16 = exports.u8 = void 0;
/*! noble-ciphers - MIT License (c) 2023 Paul Miller (paulmillr.com) */
const _assert_js_1 = require("./_assert.js");
// Cast array to different type
const u8 = (arr) => new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
exports.u8 = u8;
const u16 = (arr) => new Uint16Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 2));
exports.u16 = u16;
const u32 = (arr) => new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
exports.u32 = u32;
// Cast array to view
const createView = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
exports.createView = createView;
// big-endian hardware is rare. Just in case someone still decides to run ciphers:
// early-throw an error because we don't support BE yet.
exports.isLE = new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44;
if (!exports.isLE)
    throw new Error('Non little-endian hardware is not supported');
// Array where index 0xf0 (240) is mapped to string 'f0'
const hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));
/**
 * @example bytesToHex(Uint8Array.from([0xca, 0xfe, 0x01, 0x23])) // 'cafe0123'
 */
function bytesToHex(bytes) {
    (0, _assert_js_1.bytes)(bytes);
    // pre-caching improves the speed 6x
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += hexes[bytes[i]];
    }
    return hex;
}
exports.bytesToHex = bytesToHex;
// We use optimized technique to convert hex string to byte array
const asciis = { _0: 48, _9: 57, _A: 65, _F: 70, _a: 97, _f: 102 };
function asciiToBase16(char) {
    if (char >= asciis._0 && char <= asciis._9)
        return char - asciis._0;
    if (char >= asciis._A && char <= asciis._F)
        return char - (asciis._A - 10);
    if (char >= asciis._a && char <= asciis._f)
        return char - (asciis._a - 10);
    return;
}
/**
 * @example hexToBytes('cafe0123') // Uint8Array.from([0xca, 0xfe, 0x01, 0x23])
 */
function hexToBytes(hex) {
    if (typeof hex !== 'string')
        throw new Error('hex string expected, got ' + typeof hex);
    const hl = hex.length;
    const al = hl / 2;
    if (hl % 2)
        throw new Error('padded hex string expected, got unpadded hex of length ' + hl);
    const array = new Uint8Array(al);
    for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
        const n1 = asciiToBase16(hex.charCodeAt(hi));
        const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
        if (n1 === undefined || n2 === undefined) {
            const char = hex[hi] + hex[hi + 1];
            throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
        }
        array[ai] = n1 * 16 + n2;
    }
    return array;
}
exports.hexToBytes = hexToBytes;
function hexToNumber(hex) {
    if (typeof hex !== 'string')
        throw new Error('hex string expected, got ' + typeof hex);
    // Big Endian
    return BigInt(hex === '' ? '0' : `0x${hex}`);
}
exports.hexToNumber = hexToNumber;
// BE: Big Endian, LE: Little Endian
function bytesToNumberBE(bytes) {
    return hexToNumber(bytesToHex(bytes));
}
exports.bytesToNumberBE = bytesToNumberBE;
function numberToBytesBE(n, len) {
    return hexToBytes(n.toString(16).padStart(len * 2, '0'));
}
exports.numberToBytesBE = numberToBytesBE;
// There is no setImmediate in browser and setTimeout is slow.
// call of async fn will return Promise, which will be fullfiled only on
// next scheduler queue processing step and this is exactly what we need.
const nextTick = async () => { };
exports.nextTick = nextTick;
// Returns control to thread each 'tick' ms to avoid blocking
async function asyncLoop(iters, tick, cb) {
    let ts = Date.now();
    for (let i = 0; i < iters; i++) {
        cb(i);
        // Date.now() is not monotonic, so in case if clock goes backwards we return return control too
        const diff = Date.now() - ts;
        if (diff >= 0 && diff < tick)
            continue;
        await (0, exports.nextTick)();
        ts += diff;
    }
}
exports.asyncLoop = asyncLoop;
/**
 * @example utf8ToBytes('abc') // new Uint8Array([97, 98, 99])
 */
function utf8ToBytes(str) {
    if (typeof str !== 'string')
        throw new Error(`string expected, got ${typeof str}`);
    return new Uint8Array(new TextEncoder().encode(str)); // https://bugzil.la/1681809
}
exports.utf8ToBytes = utf8ToBytes;
/**
 * @example bytesToUtf8(new Uint8Array([97, 98, 99])) // 'abc'
 */
function bytesToUtf8(bytes) {
    return new TextDecoder().decode(bytes);
}
exports.bytesToUtf8 = bytesToUtf8;
/**
 * Normalizes (non-hex) string or Uint8Array to Uint8Array.
 * Warning: when Uint8Array is passed, it would NOT get copied.
 * Keep in mind for future mutable operations.
 */
function toBytes(data) {
    if (typeof data === 'string')
        data = utf8ToBytes(data);
    else if ((0, _assert_js_1.isBytes)(data))
        data = data.slice();
    else
        throw new Error(`Uint8Array expected, got ${typeof data}`);
    return data;
}
exports.toBytes = toBytes;
/**
 * Copies several Uint8Arrays into one.
 */
function concatBytes(...arrays) {
    let sum = 0;
    for (let i = 0; i < arrays.length; i++) {
        const a = arrays[i];
        (0, _assert_js_1.bytes)(a);
        sum += a.length;
    }
    const res = new Uint8Array(sum);
    for (let i = 0, pad = 0; i < arrays.length; i++) {
        const a = arrays[i];
        res.set(a, pad);
        pad += a.length;
    }
    return res;
}
exports.concatBytes = concatBytes;
function checkOpts(defaults, opts) {
    if (opts == null || typeof opts !== 'object')
        throw new Error('options must be defined');
    const merged = Object.assign(defaults, opts);
    return merged;
}
exports.checkOpts = checkOpts;
// Compares 2 u8a-s in kinda constant time
function equalBytes(a, b) {
    if (a.length !== b.length)
        return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++)
        diff |= a[i] ^ b[i];
    return diff === 0;
}
exports.equalBytes = equalBytes;
// For runtime check if class implements interface
class Hash {
}
exports.Hash = Hash;
/**
 * @__NO_SIDE_EFFECTS__
 */
const wrapCipher = (params, c) => {
    Object.assign(c, params);
    return c;
};
exports.wrapCipher = wrapCipher;
// Polyfill for Safari 14
function setBigUint64(view, byteOffset, value, isLE) {
    if (typeof view.setBigUint64 === 'function')
        return view.setBigUint64(byteOffset, value, isLE);
    const _32n = BigInt(32);
    const _u32_max = BigInt(0xffffffff);
    const wh = Number((value >> _32n) & _u32_max);
    const wl = Number(value & _u32_max);
    const h = isLE ? 4 : 0;
    const l = isLE ? 0 : 4;
    view.setUint32(byteOffset + h, wh, isLE);
    view.setUint32(byteOffset + l, wl, isLE);
}
exports.setBigUint64 = setBigUint64;
function u64Lengths(ciphertext, AAD) {
    const num = new Uint8Array(16);
    const view = (0, exports.createView)(num);
    setBigUint64(view, 0, BigInt(AAD ? AAD.length : 0), true);
    setBigUint64(view, 8, BigInt(ciphertext.length), true);
    return num;
}
exports.u64Lengths = u64Lengths;

},{"./_assert.js":5}],12:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.gcm = exports.ctr = exports.cbc = exports.utils = exports.managedNonce = exports.getWebcryptoSubtle = exports.randomBytes = void 0;
// We use WebCrypto aka globalThis.crypto, which exists in browsers and node.js 16+.
// node.js versions earlier than v19 don't declare it in global scope.
// For node.js, package.js on#exports field mapping rewrites import
// from `crypto` to `cryptoNode`, which imports native module.
// Makes the utils un-importable in browsers without a bundler.
// Once node.js 18 is deprecated, we can just drop the import.
//
// Use full path so that Node.js can rewrite it to `cryptoNode.js`.
const crypto_1 = require("@noble/ciphers/crypto");
Object.defineProperty(exports, "randomBytes", {
  enumerable: true,
  get: function () {
    return crypto_1.randomBytes;
  }
});
Object.defineProperty(exports, "getWebcryptoSubtle", {
  enumerable: true,
  get: function () {
    return crypto_1.getWebcryptoSubtle;
  }
});
const utils_js_1 = require("./utils.js");
const _assert_js_1 = require("./_assert.js");
// Uses CSPRG for nonce, nonce injected in ciphertext
function managedNonce(fn) {
  (0, _assert_js_1.number)(fn.nonceLength);
  return (key, ...args) => ({
    encrypt: (plaintext, ...argsEnc) => {
      const {
        nonceLength
      } = fn;
      const nonce = (0, crypto_1.randomBytes)(nonceLength);
      const ciphertext = fn(key, nonce, ...args).encrypt(plaintext, ...argsEnc);
      const out = (0, utils_js_1.concatBytes)(nonce, ciphertext);
      ciphertext.fill(0);
      return out;
    },
    decrypt: (ciphertext, ...argsDec) => {
      const {
        nonceLength
      } = fn;
      const nonce = ciphertext.subarray(0, nonceLength);
      const data = ciphertext.subarray(nonceLength);
      return fn(key, nonce, ...args).decrypt(data, ...argsDec);
    }
  });
}
exports.managedNonce = managedNonce;
// Overridable
exports.utils = {
  async encrypt(key, keyParams, cryptParams, plaintext) {
    const cr = (0, crypto_1.getWebcryptoSubtle)();
    const iKey = await cr.importKey('raw', key, keyParams, true, ['encrypt']);
    const ciphertext = await cr.encrypt(cryptParams, iKey, plaintext);
    return new Uint8Array(ciphertext);
  },
  async decrypt(key, keyParams, cryptParams, ciphertext) {
    const cr = (0, crypto_1.getWebcryptoSubtle)();
    const iKey = await cr.importKey('raw', key, keyParams, true, ['decrypt']);
    const plaintext = await cr.decrypt(cryptParams, iKey, ciphertext);
    return new Uint8Array(plaintext);
  }
};
const mode = {
  CBC: 'AES-CBC',
  CTR: 'AES-CTR',
  GCM: 'AES-GCM'
};
function getCryptParams(algo, nonce, AAD) {
  if (algo === mode.CBC) return {
    name: mode.CBC,
    iv: nonce
  };
  if (algo === mode.CTR) return {
    name: mode.CTR,
    counter: nonce,
    length: 64
  };
  if (algo === mode.GCM) {
    if (AAD) return {
      name: mode.GCM,
      iv: nonce,
      additionalData: AAD
    };else return {
      name: mode.GCM,
      iv: nonce
    };
  }
  throw new Error('unknown aes block mode');
}
function generate(algo) {
  return (key, nonce, AAD) => {
    (0, _assert_js_1.bytes)(key);
    (0, _assert_js_1.bytes)(nonce);
    const keyParams = {
      name: algo,
      length: key.length * 8
    };
    const cryptParams = getCryptParams(algo, nonce, AAD);
    return {
      // keyLength,
      encrypt(plaintext) {
        (0, _assert_js_1.bytes)(plaintext);
        return exports.utils.encrypt(key, keyParams, cryptParams, plaintext);
      },
      decrypt(ciphertext) {
        (0, _assert_js_1.bytes)(ciphertext);
        return exports.utils.decrypt(key, keyParams, cryptParams, ciphertext);
      }
    };
  };
}
exports.cbc = generate(mode.CBC);
exports.ctr = generate(mode.CTR);
exports.gcm = generate(mode.GCM);
// // Type tests
// import { siv, gcm, ctr, ecb, cbc } from '../aes.js';
// import { xsalsa20poly1305 } from '../salsa.js';
// import { chacha20poly1305, xchacha20poly1305 } from '../chacha.js';
// const wsiv = managedNonce(siv);
// const wgcm = managedNonce(gcm);
// const wctr = managedNonce(ctr);
// const wcbc = managedNonce(cbc);
// const wsalsapoly = managedNonce(xsalsa20poly1305);
// const wchacha = managedNonce(chacha20poly1305);
// const wxchacha = managedNonce(xchacha20poly1305);
// // should fail
// const wcbc2 = managedNonce(managedNonce(cbc));
// const wecb = managedNonce(ecb);

},{"./_assert.js":5,"./utils.js":11,"@noble/ciphers/crypto":9}],13:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.output = exports.exists = exports.hash = exports.bytes = exports.bool = exports.number = exports.isBytes = void 0;
function number(n) {
    if (!Number.isSafeInteger(n) || n < 0)
        throw new Error(`positive integer expected, not ${n}`);
}
exports.number = number;
function bool(b) {
    if (typeof b !== 'boolean')
        throw new Error(`boolean expected, not ${b}`);
}
exports.bool = bool;
// copied from utils
function isBytes(a) {
    return (a instanceof Uint8Array ||
        (a != null && typeof a === 'object' && a.constructor.name === 'Uint8Array'));
}
exports.isBytes = isBytes;
function bytes(b, ...lengths) {
    if (!isBytes(b))
        throw new Error('Uint8Array expected');
    if (lengths.length > 0 && !lengths.includes(b.length))
        throw new Error(`Uint8Array expected of length ${lengths}, not of length=${b.length}`);
}
exports.bytes = bytes;
function hash(h) {
    if (typeof h !== 'function' || typeof h.create !== 'function')
        throw new Error('Hash should be wrapped by utils.wrapConstructor');
    number(h.outputLen);
    number(h.blockLen);
}
exports.hash = hash;
function exists(instance, checkFinished = true) {
    if (instance.destroyed)
        throw new Error('Hash instance has been destroyed');
    if (checkFinished && instance.finished)
        throw new Error('Hash#digest() has already been called');
}
exports.exists = exists;
function output(out, instance) {
    bytes(out);
    const min = instance.outputLen;
    if (out.length < min) {
        throw new Error(`digestInto() expects output buffer of length at least ${min}`);
    }
}
exports.output = output;
const assert = { number, bool, bytes, hash, exists, output };
exports.default = assert;

},{}],14:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.HashMD = exports.Maj = exports.Chi = void 0;
const _assert_js_1 = require("./_assert.js");
const utils_js_1 = require("./utils.js");
// Polyfill for Safari 14
function setBigUint64(view, byteOffset, value, isLE) {
    if (typeof view.setBigUint64 === 'function')
        return view.setBigUint64(byteOffset, value, isLE);
    const _32n = BigInt(32);
    const _u32_max = BigInt(0xffffffff);
    const wh = Number((value >> _32n) & _u32_max);
    const wl = Number(value & _u32_max);
    const h = isLE ? 4 : 0;
    const l = isLE ? 0 : 4;
    view.setUint32(byteOffset + h, wh, isLE);
    view.setUint32(byteOffset + l, wl, isLE);
}
// Choice: a ? b : c
const Chi = (a, b, c) => (a & b) ^ (~a & c);
exports.Chi = Chi;
// Majority function, true if any two inpust is true
const Maj = (a, b, c) => (a & b) ^ (a & c) ^ (b & c);
exports.Maj = Maj;
/**
 * Merkle-Damgard hash construction base class.
 * Could be used to create MD5, RIPEMD, SHA1, SHA2.
 */
class HashMD extends utils_js_1.Hash {
    constructor(blockLen, outputLen, padOffset, isLE) {
        super();
        this.blockLen = blockLen;
        this.outputLen = outputLen;
        this.padOffset = padOffset;
        this.isLE = isLE;
        this.finished = false;
        this.length = 0;
        this.pos = 0;
        this.destroyed = false;
        this.buffer = new Uint8Array(blockLen);
        this.view = (0, utils_js_1.createView)(this.buffer);
    }
    update(data) {
        (0, _assert_js_1.exists)(this);
        const { view, buffer, blockLen } = this;
        data = (0, utils_js_1.toBytes)(data);
        const len = data.length;
        for (let pos = 0; pos < len;) {
            const take = Math.min(blockLen - this.pos, len - pos);
            // Fast path: we have at least one block in input, cast it to view and process
            if (take === blockLen) {
                const dataView = (0, utils_js_1.createView)(data);
                for (; blockLen <= len - pos; pos += blockLen)
                    this.process(dataView, pos);
                continue;
            }
            buffer.set(data.subarray(pos, pos + take), this.pos);
            this.pos += take;
            pos += take;
            if (this.pos === blockLen) {
                this.process(view, 0);
                this.pos = 0;
            }
        }
        this.length += data.length;
        this.roundClean();
        return this;
    }
    digestInto(out) {
        (0, _assert_js_1.exists)(this);
        (0, _assert_js_1.output)(out, this);
        this.finished = true;
        // Padding
        // We can avoid allocation of buffer for padding completely if it
        // was previously not allocated here. But it won't change performance.
        const { buffer, view, blockLen, isLE } = this;
        let { pos } = this;
        // append the bit '1' to the message
        buffer[pos++] = 0b10000000;
        this.buffer.subarray(pos).fill(0);
        // we have less than padOffset left in buffer, so we cannot put length in
        // current block, need process it and pad again
        if (this.padOffset > blockLen - pos) {
            this.process(view, 0);
            pos = 0;
        }
        // Pad until full block byte with zeros
        for (let i = pos; i < blockLen; i++)
            buffer[i] = 0;
        // Note: sha512 requires length to be 128bit integer, but length in JS will overflow before that
        // You need to write around 2 exabytes (u64_max / 8 / (1024**6)) for this to happen.
        // So we just write lowest 64 bits of that value.
        setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE);
        this.process(view, 0);
        const oview = (0, utils_js_1.createView)(out);
        const len = this.outputLen;
        // NOTE: we do division by 4 later, which should be fused in single op with modulo by JIT
        if (len % 4)
            throw new Error('_sha2: outputLen should be aligned to 32bit');
        const outLen = len / 4;
        const state = this.get();
        if (outLen > state.length)
            throw new Error('_sha2: outputLen bigger than state');
        for (let i = 0; i < outLen; i++)
            oview.setUint32(4 * i, state[i], isLE);
    }
    digest() {
        const { buffer, outputLen } = this;
        this.digestInto(buffer);
        const res = buffer.slice(0, outputLen);
        this.destroy();
        return res;
    }
    _cloneInto(to) {
        to || (to = new this.constructor());
        to.set(...this.get());
        const { blockLen, buffer, length, finished, destroyed, pos } = this;
        to.length = length;
        to.pos = pos;
        to.finished = finished;
        to.destroyed = destroyed;
        if (length % blockLen)
            to.buffer.set(buffer);
        return to;
    }
}
exports.HashMD = HashMD;

},{"./_assert.js":13,"./utils.js":20}],15:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.crypto = void 0;
exports.crypto = typeof globalThis === 'object' && 'crypto' in globalThis ? globalThis.crypto : undefined;

},{}],16:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.hmac = exports.HMAC = void 0;
const _assert_js_1 = require("./_assert.js");
const utils_js_1 = require("./utils.js");
// HMAC (RFC 2104)
class HMAC extends utils_js_1.Hash {
    constructor(hash, _key) {
        super();
        this.finished = false;
        this.destroyed = false;
        (0, _assert_js_1.hash)(hash);
        const key = (0, utils_js_1.toBytes)(_key);
        this.iHash = hash.create();
        if (typeof this.iHash.update !== 'function')
            throw new Error('Expected instance of class which extends utils.Hash');
        this.blockLen = this.iHash.blockLen;
        this.outputLen = this.iHash.outputLen;
        const blockLen = this.blockLen;
        const pad = new Uint8Array(blockLen);
        // blockLen can be bigger than outputLen
        pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
        for (let i = 0; i < pad.length; i++)
            pad[i] ^= 0x36;
        this.iHash.update(pad);
        // By doing update (processing of first block) of outer hash here we can re-use it between multiple calls via clone
        this.oHash = hash.create();
        // Undo internal XOR && apply outer XOR
        for (let i = 0; i < pad.length; i++)
            pad[i] ^= 0x36 ^ 0x5c;
        this.oHash.update(pad);
        pad.fill(0);
    }
    update(buf) {
        (0, _assert_js_1.exists)(this);
        this.iHash.update(buf);
        return this;
    }
    digestInto(out) {
        (0, _assert_js_1.exists)(this);
        (0, _assert_js_1.bytes)(out, this.outputLen);
        this.finished = true;
        this.iHash.digestInto(out);
        this.oHash.update(out);
        this.oHash.digestInto(out);
        this.destroy();
    }
    digest() {
        const out = new Uint8Array(this.oHash.outputLen);
        this.digestInto(out);
        return out;
    }
    _cloneInto(to) {
        // Create new instance without calling constructor since key already in state and we don't know it.
        to || (to = Object.create(Object.getPrototypeOf(this), {}));
        const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
        to = to;
        to.finished = finished;
        to.destroyed = destroyed;
        to.blockLen = blockLen;
        to.outputLen = outputLen;
        to.oHash = oHash._cloneInto(to.oHash);
        to.iHash = iHash._cloneInto(to.iHash);
        return to;
    }
    destroy() {
        this.destroyed = true;
        this.oHash.destroy();
        this.iHash.destroy();
    }
}
exports.HMAC = HMAC;
/**
 * HMAC: RFC2104 message authentication code.
 * @param hash - function that would be used e.g. sha256
 * @param key - message key
 * @param message - message data
 */
const hmac = (hash, key, message) => new HMAC(hash, key).update(message).digest();
exports.hmac = hmac;
exports.hmac.create = (hash, key) => new HMAC(hash, key);

},{"./_assert.js":13,"./utils.js":20}],17:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.pbkdf2Async = exports.pbkdf2 = void 0;
const _assert_js_1 = require("./_assert.js");
const hmac_js_1 = require("./hmac.js");
const utils_js_1 = require("./utils.js");
// Common prologue and epilogue for sync/async functions
function pbkdf2Init(hash, _password, _salt, _opts) {
    (0, _assert_js_1.hash)(hash);
    const opts = (0, utils_js_1.checkOpts)({ dkLen: 32, asyncTick: 10 }, _opts);
    const { c, dkLen, asyncTick } = opts;
    (0, _assert_js_1.number)(c);
    (0, _assert_js_1.number)(dkLen);
    (0, _assert_js_1.number)(asyncTick);
    if (c < 1)
        throw new Error('PBKDF2: iterations (c) should be >= 1');
    const password = (0, utils_js_1.toBytes)(_password);
    const salt = (0, utils_js_1.toBytes)(_salt);
    // DK = PBKDF2(PRF, Password, Salt, c, dkLen);
    const DK = new Uint8Array(dkLen);
    // U1 = PRF(Password, Salt + INT_32_BE(i))
    const PRF = hmac_js_1.hmac.create(hash, password);
    const PRFSalt = PRF._cloneInto().update(salt);
    return { c, dkLen, asyncTick, DK, PRF, PRFSalt };
}
function pbkdf2Output(PRF, PRFSalt, DK, prfW, u) {
    PRF.destroy();
    PRFSalt.destroy();
    if (prfW)
        prfW.destroy();
    u.fill(0);
    return DK;
}
/**
 * PBKDF2-HMAC: RFC 2898 key derivation function
 * @param hash - hash function that would be used e.g. sha256
 * @param password - password from which a derived key is generated
 * @param salt - cryptographic salt
 * @param opts - {c, dkLen} where c is work factor and dkLen is output message size
 */
function pbkdf2(hash, password, salt, opts) {
    const { c, dkLen, DK, PRF, PRFSalt } = pbkdf2Init(hash, password, salt, opts);
    let prfW; // Working copy
    const arr = new Uint8Array(4);
    const view = (0, utils_js_1.createView)(arr);
    const u = new Uint8Array(PRF.outputLen);
    // DK = T1 + T2 + ⋯ + Tdklen/hlen
    for (let ti = 1, pos = 0; pos < dkLen; ti++, pos += PRF.outputLen) {
        // Ti = F(Password, Salt, c, i)
        const Ti = DK.subarray(pos, pos + PRF.outputLen);
        view.setInt32(0, ti, false);
        // F(Password, Salt, c, i) = U1 ^ U2 ^ ⋯ ^ Uc
        // U1 = PRF(Password, Salt + INT_32_BE(i))
        (prfW = PRFSalt._cloneInto(prfW)).update(arr).digestInto(u);
        Ti.set(u.subarray(0, Ti.length));
        for (let ui = 1; ui < c; ui++) {
            // Uc = PRF(Password, Uc−1)
            PRF._cloneInto(prfW).update(u).digestInto(u);
            for (let i = 0; i < Ti.length; i++)
                Ti[i] ^= u[i];
        }
    }
    return pbkdf2Output(PRF, PRFSalt, DK, prfW, u);
}
exports.pbkdf2 = pbkdf2;
async function pbkdf2Async(hash, password, salt, opts) {
    const { c, dkLen, asyncTick, DK, PRF, PRFSalt } = pbkdf2Init(hash, password, salt, opts);
    let prfW; // Working copy
    const arr = new Uint8Array(4);
    const view = (0, utils_js_1.createView)(arr);
    const u = new Uint8Array(PRF.outputLen);
    // DK = T1 + T2 + ⋯ + Tdklen/hlen
    for (let ti = 1, pos = 0; pos < dkLen; ti++, pos += PRF.outputLen) {
        // Ti = F(Password, Salt, c, i)
        const Ti = DK.subarray(pos, pos + PRF.outputLen);
        view.setInt32(0, ti, false);
        // F(Password, Salt, c, i) = U1 ^ U2 ^ ⋯ ^ Uc
        // U1 = PRF(Password, Salt + INT_32_BE(i))
        (prfW = PRFSalt._cloneInto(prfW)).update(arr).digestInto(u);
        Ti.set(u.subarray(0, Ti.length));
        await (0, utils_js_1.asyncLoop)(c - 1, asyncTick, () => {
            // Uc = PRF(Password, Uc−1)
            PRF._cloneInto(prfW).update(u).digestInto(u);
            for (let i = 0; i < Ti.length; i++)
                Ti[i] ^= u[i];
        });
    }
    return pbkdf2Output(PRF, PRFSalt, DK, prfW, u);
}
exports.pbkdf2Async = pbkdf2Async;

},{"./_assert.js":13,"./hmac.js":16,"./utils.js":20}],18:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.scryptAsync = exports.scrypt = void 0;
const _assert_js_1 = require("./_assert.js");
const sha256_js_1 = require("./sha256.js");
const pbkdf2_js_1 = require("./pbkdf2.js");
const utils_js_1 = require("./utils.js");
// RFC 7914 Scrypt KDF
// The main Scrypt loop: uses Salsa extensively.
// Six versions of the function were tried, this is the fastest one.
// prettier-ignore
function XorAndSalsa(prev, pi, input, ii, out, oi) {
    // Based on https://cr.yp.to/salsa20.html
    // Xor blocks
    let y00 = prev[pi++] ^ input[ii++], y01 = prev[pi++] ^ input[ii++];
    let y02 = prev[pi++] ^ input[ii++], y03 = prev[pi++] ^ input[ii++];
    let y04 = prev[pi++] ^ input[ii++], y05 = prev[pi++] ^ input[ii++];
    let y06 = prev[pi++] ^ input[ii++], y07 = prev[pi++] ^ input[ii++];
    let y08 = prev[pi++] ^ input[ii++], y09 = prev[pi++] ^ input[ii++];
    let y10 = prev[pi++] ^ input[ii++], y11 = prev[pi++] ^ input[ii++];
    let y12 = prev[pi++] ^ input[ii++], y13 = prev[pi++] ^ input[ii++];
    let y14 = prev[pi++] ^ input[ii++], y15 = prev[pi++] ^ input[ii++];
    // Save state to temporary variables (salsa)
    let x00 = y00, x01 = y01, x02 = y02, x03 = y03, x04 = y04, x05 = y05, x06 = y06, x07 = y07, x08 = y08, x09 = y09, x10 = y10, x11 = y11, x12 = y12, x13 = y13, x14 = y14, x15 = y15;
    // Main loop (salsa)
    for (let i = 0; i < 8; i += 2) {
        x04 ^= (0, utils_js_1.rotl)(x00 + x12 | 0, 7);
        x08 ^= (0, utils_js_1.rotl)(x04 + x00 | 0, 9);
        x12 ^= (0, utils_js_1.rotl)(x08 + x04 | 0, 13);
        x00 ^= (0, utils_js_1.rotl)(x12 + x08 | 0, 18);
        x09 ^= (0, utils_js_1.rotl)(x05 + x01 | 0, 7);
        x13 ^= (0, utils_js_1.rotl)(x09 + x05 | 0, 9);
        x01 ^= (0, utils_js_1.rotl)(x13 + x09 | 0, 13);
        x05 ^= (0, utils_js_1.rotl)(x01 + x13 | 0, 18);
        x14 ^= (0, utils_js_1.rotl)(x10 + x06 | 0, 7);
        x02 ^= (0, utils_js_1.rotl)(x14 + x10 | 0, 9);
        x06 ^= (0, utils_js_1.rotl)(x02 + x14 | 0, 13);
        x10 ^= (0, utils_js_1.rotl)(x06 + x02 | 0, 18);
        x03 ^= (0, utils_js_1.rotl)(x15 + x11 | 0, 7);
        x07 ^= (0, utils_js_1.rotl)(x03 + x15 | 0, 9);
        x11 ^= (0, utils_js_1.rotl)(x07 + x03 | 0, 13);
        x15 ^= (0, utils_js_1.rotl)(x11 + x07 | 0, 18);
        x01 ^= (0, utils_js_1.rotl)(x00 + x03 | 0, 7);
        x02 ^= (0, utils_js_1.rotl)(x01 + x00 | 0, 9);
        x03 ^= (0, utils_js_1.rotl)(x02 + x01 | 0, 13);
        x00 ^= (0, utils_js_1.rotl)(x03 + x02 | 0, 18);
        x06 ^= (0, utils_js_1.rotl)(x05 + x04 | 0, 7);
        x07 ^= (0, utils_js_1.rotl)(x06 + x05 | 0, 9);
        x04 ^= (0, utils_js_1.rotl)(x07 + x06 | 0, 13);
        x05 ^= (0, utils_js_1.rotl)(x04 + x07 | 0, 18);
        x11 ^= (0, utils_js_1.rotl)(x10 + x09 | 0, 7);
        x08 ^= (0, utils_js_1.rotl)(x11 + x10 | 0, 9);
        x09 ^= (0, utils_js_1.rotl)(x08 + x11 | 0, 13);
        x10 ^= (0, utils_js_1.rotl)(x09 + x08 | 0, 18);
        x12 ^= (0, utils_js_1.rotl)(x15 + x14 | 0, 7);
        x13 ^= (0, utils_js_1.rotl)(x12 + x15 | 0, 9);
        x14 ^= (0, utils_js_1.rotl)(x13 + x12 | 0, 13);
        x15 ^= (0, utils_js_1.rotl)(x14 + x13 | 0, 18);
    }
    // Write output (salsa)
    out[oi++] = (y00 + x00) | 0;
    out[oi++] = (y01 + x01) | 0;
    out[oi++] = (y02 + x02) | 0;
    out[oi++] = (y03 + x03) | 0;
    out[oi++] = (y04 + x04) | 0;
    out[oi++] = (y05 + x05) | 0;
    out[oi++] = (y06 + x06) | 0;
    out[oi++] = (y07 + x07) | 0;
    out[oi++] = (y08 + x08) | 0;
    out[oi++] = (y09 + x09) | 0;
    out[oi++] = (y10 + x10) | 0;
    out[oi++] = (y11 + x11) | 0;
    out[oi++] = (y12 + x12) | 0;
    out[oi++] = (y13 + x13) | 0;
    out[oi++] = (y14 + x14) | 0;
    out[oi++] = (y15 + x15) | 0;
}
function BlockMix(input, ii, out, oi, r) {
    // The block B is r 128-byte chunks (which is equivalent of 2r 64-byte chunks)
    let head = oi + 0;
    let tail = oi + 16 * r;
    for (let i = 0; i < 16; i++)
        out[tail + i] = input[ii + (2 * r - 1) * 16 + i]; // X ← B[2r−1]
    for (let i = 0; i < r; i++, head += 16, ii += 16) {
        // We write odd & even Yi at same time. Even: 0bXXXXX0 Odd:  0bXXXXX1
        XorAndSalsa(out, tail, input, ii, out, head); // head[i] = Salsa(blockIn[2*i] ^ tail[i-1])
        if (i > 0)
            tail += 16; // First iteration overwrites tmp value in tail
        XorAndSalsa(out, head, input, (ii += 16), out, tail); // tail[i] = Salsa(blockIn[2*i+1] ^ head[i])
    }
}
// Common prologue and epilogue for sync/async functions
function scryptInit(password, salt, _opts) {
    // Maxmem - 1GB+1KB by default
    const opts = (0, utils_js_1.checkOpts)({
        dkLen: 32,
        asyncTick: 10,
        maxmem: 1024 ** 3 + 1024,
    }, _opts);
    const { N, r, p, dkLen, asyncTick, maxmem, onProgress } = opts;
    (0, _assert_js_1.number)(N);
    (0, _assert_js_1.number)(r);
    (0, _assert_js_1.number)(p);
    (0, _assert_js_1.number)(dkLen);
    (0, _assert_js_1.number)(asyncTick);
    (0, _assert_js_1.number)(maxmem);
    if (onProgress !== undefined && typeof onProgress !== 'function')
        throw new Error('progressCb should be function');
    const blockSize = 128 * r;
    const blockSize32 = blockSize / 4;
    if (N <= 1 || (N & (N - 1)) !== 0 || N >= 2 ** (blockSize / 8) || N > 2 ** 32) {
        // NOTE: we limit N to be less than 2**32 because of 32 bit variant of Integrify function
        // There is no JS engines that allows alocate more than 4GB per single Uint8Array for now, but can change in future.
        throw new Error('Scrypt: N must be larger than 1, a power of 2, less than 2^(128 * r / 8) and less than 2^32');
    }
    if (p < 0 || p > ((2 ** 32 - 1) * 32) / blockSize) {
        throw new Error('Scrypt: p must be a positive integer less than or equal to ((2^32 - 1) * 32) / (128 * r)');
    }
    if (dkLen < 0 || dkLen > (2 ** 32 - 1) * 32) {
        throw new Error('Scrypt: dkLen should be positive integer less than or equal to (2^32 - 1) * 32');
    }
    const memUsed = blockSize * (N + p);
    if (memUsed > maxmem) {
        throw new Error(`Scrypt: parameters too large, ${memUsed} (128 * r * (N + p)) > ${maxmem} (maxmem)`);
    }
    // [B0...Bp−1] ← PBKDF2HMAC-SHA256(Passphrase, Salt, 1, blockSize*ParallelizationFactor)
    // Since it has only one iteration there is no reason to use async variant
    const B = (0, pbkdf2_js_1.pbkdf2)(sha256_js_1.sha256, password, salt, { c: 1, dkLen: blockSize * p });
    const B32 = (0, utils_js_1.u32)(B);
    // Re-used between parallel iterations. Array(iterations) of B
    const V = (0, utils_js_1.u32)(new Uint8Array(blockSize * N));
    const tmp = (0, utils_js_1.u32)(new Uint8Array(blockSize));
    let blockMixCb = () => { };
    if (onProgress) {
        const totalBlockMix = 2 * N * p;
        // Invoke callback if progress changes from 10.01 to 10.02
        // Allows to draw smooth progress bar on up to 8K screen
        const callbackPer = Math.max(Math.floor(totalBlockMix / 10000), 1);
        let blockMixCnt = 0;
        blockMixCb = () => {
            blockMixCnt++;
            if (onProgress && (!(blockMixCnt % callbackPer) || blockMixCnt === totalBlockMix))
                onProgress(blockMixCnt / totalBlockMix);
        };
    }
    return { N, r, p, dkLen, blockSize32, V, B32, B, tmp, blockMixCb, asyncTick };
}
function scryptOutput(password, dkLen, B, V, tmp) {
    const res = (0, pbkdf2_js_1.pbkdf2)(sha256_js_1.sha256, password, B, { c: 1, dkLen });
    B.fill(0);
    V.fill(0);
    tmp.fill(0);
    return res;
}
/**
 * Scrypt KDF from RFC 7914.
 * @param password - pass
 * @param salt - salt
 * @param opts - parameters
 * - `N` is cpu/mem work factor (power of 2 e.g. 2**18)
 * - `r` is block size (8 is common), fine-tunes sequential memory read size and performance
 * - `p` is parallelization factor (1 is common)
 * - `dkLen` is output key length in bytes e.g. 32.
 * - `asyncTick` - (default: 10) max time in ms for which async function can block execution
 * - `maxmem` - (default: `1024 ** 3 + 1024` aka 1GB+1KB). A limit that the app could use for scrypt
 * - `onProgress` - callback function that would be executed for progress report
 * @returns Derived key
 */
function scrypt(password, salt, opts) {
    const { N, r, p, dkLen, blockSize32, V, B32, B, tmp, blockMixCb } = scryptInit(password, salt, opts);
    if (!utils_js_1.isLE)
        (0, utils_js_1.byteSwap32)(B32);
    for (let pi = 0; pi < p; pi++) {
        const Pi = blockSize32 * pi;
        for (let i = 0; i < blockSize32; i++)
            V[i] = B32[Pi + i]; // V[0] = B[i]
        for (let i = 0, pos = 0; i < N - 1; i++) {
            BlockMix(V, pos, V, (pos += blockSize32), r); // V[i] = BlockMix(V[i-1]);
            blockMixCb();
        }
        BlockMix(V, (N - 1) * blockSize32, B32, Pi, r); // Process last element
        blockMixCb();
        for (let i = 0; i < N; i++) {
            // First u32 of the last 64-byte block (u32 is LE)
            const j = B32[Pi + blockSize32 - 16] % N; // j = Integrify(X) % iterations
            for (let k = 0; k < blockSize32; k++)
                tmp[k] = B32[Pi + k] ^ V[j * blockSize32 + k]; // tmp = B ^ V[j]
            BlockMix(tmp, 0, B32, Pi, r); // B = BlockMix(B ^ V[j])
            blockMixCb();
        }
    }
    if (!utils_js_1.isLE)
        (0, utils_js_1.byteSwap32)(B32);
    return scryptOutput(password, dkLen, B, V, tmp);
}
exports.scrypt = scrypt;
/**
 * Scrypt KDF from RFC 7914.
 */
async function scryptAsync(password, salt, opts) {
    const { N, r, p, dkLen, blockSize32, V, B32, B, tmp, blockMixCb, asyncTick } = scryptInit(password, salt, opts);
    if (!utils_js_1.isLE)
        (0, utils_js_1.byteSwap32)(B32);
    for (let pi = 0; pi < p; pi++) {
        const Pi = blockSize32 * pi;
        for (let i = 0; i < blockSize32; i++)
            V[i] = B32[Pi + i]; // V[0] = B[i]
        let pos = 0;
        await (0, utils_js_1.asyncLoop)(N - 1, asyncTick, () => {
            BlockMix(V, pos, V, (pos += blockSize32), r); // V[i] = BlockMix(V[i-1]);
            blockMixCb();
        });
        BlockMix(V, (N - 1) * blockSize32, B32, Pi, r); // Process last element
        blockMixCb();
        await (0, utils_js_1.asyncLoop)(N, asyncTick, () => {
            // First u32 of the last 64-byte block (u32 is LE)
            const j = B32[Pi + blockSize32 - 16] % N; // j = Integrify(X) % iterations
            for (let k = 0; k < blockSize32; k++)
                tmp[k] = B32[Pi + k] ^ V[j * blockSize32 + k]; // tmp = B ^ V[j]
            BlockMix(tmp, 0, B32, Pi, r); // B = BlockMix(B ^ V[j])
            blockMixCb();
        });
    }
    if (!utils_js_1.isLE)
        (0, utils_js_1.byteSwap32)(B32);
    return scryptOutput(password, dkLen, B, V, tmp);
}
exports.scryptAsync = scryptAsync;

},{"./_assert.js":13,"./pbkdf2.js":17,"./sha256.js":19,"./utils.js":20}],19:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sha224 = exports.sha256 = void 0;
const _md_js_1 = require("./_md.js");
const utils_js_1 = require("./utils.js");
// SHA2-256 need to try 2^128 hashes to execute birthday attack.
// BTC network is doing 2^67 hashes/sec as per early 2023.
// Round constants:
// first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
// prettier-ignore
const SHA256_K = /* @__PURE__ */ new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);
// Initial state:
// first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19
// prettier-ignore
const SHA256_IV = /* @__PURE__ */ new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);
// Temporary buffer, not used to store anything between runs
// Named this way because it matches specification.
const SHA256_W = /* @__PURE__ */ new Uint32Array(64);
class SHA256 extends _md_js_1.HashMD {
    constructor() {
        super(64, 32, 8, false);
        // We cannot use array here since array allows indexing by variable
        // which means optimizer/compiler cannot use registers.
        this.A = SHA256_IV[0] | 0;
        this.B = SHA256_IV[1] | 0;
        this.C = SHA256_IV[2] | 0;
        this.D = SHA256_IV[3] | 0;
        this.E = SHA256_IV[4] | 0;
        this.F = SHA256_IV[5] | 0;
        this.G = SHA256_IV[6] | 0;
        this.H = SHA256_IV[7] | 0;
    }
    get() {
        const { A, B, C, D, E, F, G, H } = this;
        return [A, B, C, D, E, F, G, H];
    }
    // prettier-ignore
    set(A, B, C, D, E, F, G, H) {
        this.A = A | 0;
        this.B = B | 0;
        this.C = C | 0;
        this.D = D | 0;
        this.E = E | 0;
        this.F = F | 0;
        this.G = G | 0;
        this.H = H | 0;
    }
    process(view, offset) {
        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
        for (let i = 0; i < 16; i++, offset += 4)
            SHA256_W[i] = view.getUint32(offset, false);
        for (let i = 16; i < 64; i++) {
            const W15 = SHA256_W[i - 15];
            const W2 = SHA256_W[i - 2];
            const s0 = (0, utils_js_1.rotr)(W15, 7) ^ (0, utils_js_1.rotr)(W15, 18) ^ (W15 >>> 3);
            const s1 = (0, utils_js_1.rotr)(W2, 17) ^ (0, utils_js_1.rotr)(W2, 19) ^ (W2 >>> 10);
            SHA256_W[i] = (s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16]) | 0;
        }
        // Compression function main loop, 64 rounds
        let { A, B, C, D, E, F, G, H } = this;
        for (let i = 0; i < 64; i++) {
            const sigma1 = (0, utils_js_1.rotr)(E, 6) ^ (0, utils_js_1.rotr)(E, 11) ^ (0, utils_js_1.rotr)(E, 25);
            const T1 = (H + sigma1 + (0, _md_js_1.Chi)(E, F, G) + SHA256_K[i] + SHA256_W[i]) | 0;
            const sigma0 = (0, utils_js_1.rotr)(A, 2) ^ (0, utils_js_1.rotr)(A, 13) ^ (0, utils_js_1.rotr)(A, 22);
            const T2 = (sigma0 + (0, _md_js_1.Maj)(A, B, C)) | 0;
            H = G;
            G = F;
            F = E;
            E = (D + T1) | 0;
            D = C;
            C = B;
            B = A;
            A = (T1 + T2) | 0;
        }
        // Add the compressed chunk to the current hash value
        A = (A + this.A) | 0;
        B = (B + this.B) | 0;
        C = (C + this.C) | 0;
        D = (D + this.D) | 0;
        E = (E + this.E) | 0;
        F = (F + this.F) | 0;
        G = (G + this.G) | 0;
        H = (H + this.H) | 0;
        this.set(A, B, C, D, E, F, G, H);
    }
    roundClean() {
        SHA256_W.fill(0);
    }
    destroy() {
        this.set(0, 0, 0, 0, 0, 0, 0, 0);
        this.buffer.fill(0);
    }
}
// Constants from https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
class SHA224 extends SHA256 {
    constructor() {
        super();
        this.A = 0xc1059ed8 | 0;
        this.B = 0x367cd507 | 0;
        this.C = 0x3070dd17 | 0;
        this.D = 0xf70e5939 | 0;
        this.E = 0xffc00b31 | 0;
        this.F = 0x68581511 | 0;
        this.G = 0x64f98fa7 | 0;
        this.H = 0xbefa4fa4 | 0;
        this.outputLen = 28;
    }
}
/**
 * SHA2-256 hash function
 * @param message - data that would be hashed
 */
exports.sha256 = (0, utils_js_1.wrapConstructor)(() => new SHA256());
exports.sha224 = (0, utils_js_1.wrapConstructor)(() => new SHA224());

},{"./_md.js":14,"./utils.js":20}],20:[function(require,module,exports){
"use strict";

/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.randomBytes = exports.wrapXOFConstructorWithOpts = exports.wrapConstructorWithOpts = exports.wrapConstructor = exports.checkOpts = exports.Hash = exports.concatBytes = exports.toBytes = exports.utf8ToBytes = exports.asyncLoop = exports.nextTick = exports.hexToBytes = exports.bytesToHex = exports.byteSwap32 = exports.byteSwapIfBE = exports.byteSwap = exports.isLE = exports.rotl = exports.rotr = exports.createView = exports.u32 = exports.u8 = exports.isBytes = void 0;
// We use WebCrypto aka globalThis.crypto, which exists in browsers and node.js 16+.
// node.js versions earlier than v19 don't declare it in global scope.
// For node.js, package.json#exports field mapping rewrites import
// from `crypto` to `cryptoNode`, which imports native module.
// Makes the utils un-importable in browsers without a bundler.
// Once node.js 18 is deprecated (2025-04-30), we can just drop the import.
const crypto_1 = require("@noble/hashes/crypto");
const _assert_js_1 = require("./_assert.js");
// export { isBytes } from './_assert.js';
// We can't reuse isBytes from _assert, because somehow this causes huge perf issues
function isBytes(a) {
  return a instanceof Uint8Array || a != null && typeof a === 'object' && a.constructor.name === 'Uint8Array';
}
exports.isBytes = isBytes;
// Cast array to different type
const u8 = arr => new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
exports.u8 = u8;
const u32 = arr => new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
exports.u32 = u32;
// Cast array to view
const createView = arr => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
exports.createView = createView;
// The rotate right (circular right shift) operation for uint32
const rotr = (word, shift) => word << 32 - shift | word >>> shift;
exports.rotr = rotr;
// The rotate left (circular left shift) operation for uint32
const rotl = (word, shift) => word << shift | word >>> 32 - shift >>> 0;
exports.rotl = rotl;
exports.isLE = new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44;
// The byte swap operation for uint32
const byteSwap = word => word << 24 & 0xff000000 | word << 8 & 0xff0000 | word >>> 8 & 0xff00 | word >>> 24 & 0xff;
exports.byteSwap = byteSwap;
// Conditionally byte swap if on a big-endian platform
exports.byteSwapIfBE = exports.isLE ? n => n : n => (0, exports.byteSwap)(n);
// In place byte swap for Uint32Array
function byteSwap32(arr) {
  for (let i = 0; i < arr.length; i++) {
    arr[i] = (0, exports.byteSwap)(arr[i]);
  }
}
exports.byteSwap32 = byteSwap32;
// Array where index 0xf0 (240) is mapped to string 'f0'
const hexes = /* @__PURE__ */Array.from({
  length: 256
}, (_, i) => i.toString(16).padStart(2, '0'));
/**
 * @example bytesToHex(Uint8Array.from([0xca, 0xfe, 0x01, 0x23])) // 'cafe0123'
 */
function bytesToHex(bytes) {
  (0, _assert_js_1.bytes)(bytes);
  // pre-caching improves the speed 6x
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += hexes[bytes[i]];
  }
  return hex;
}
exports.bytesToHex = bytesToHex;
// We use optimized technique to convert hex string to byte array
const asciis = {
  _0: 48,
  _9: 57,
  _A: 65,
  _F: 70,
  _a: 97,
  _f: 102
};
function asciiToBase16(char) {
  if (char >= asciis._0 && char <= asciis._9) return char - asciis._0;
  if (char >= asciis._A && char <= asciis._F) return char - (asciis._A - 10);
  if (char >= asciis._a && char <= asciis._f) return char - (asciis._a - 10);
  return;
}
/**
 * @example hexToBytes('cafe0123') // Uint8Array.from([0xca, 0xfe, 0x01, 0x23])
 */
function hexToBytes(hex) {
  if (typeof hex !== 'string') throw new Error('hex string expected, got ' + typeof hex);
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2) throw new Error('padded hex string expected, got unpadded hex of length ' + hl);
  const array = new Uint8Array(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    const n1 = asciiToBase16(hex.charCodeAt(hi));
    const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
    if (n1 === undefined || n2 === undefined) {
      const char = hex[hi] + hex[hi + 1];
      throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
    }
    array[ai] = n1 * 16 + n2;
  }
  return array;
}
exports.hexToBytes = hexToBytes;
// There is no setImmediate in browser and setTimeout is slow.
// call of async fn will return Promise, which will be fullfiled only on
// next scheduler queue processing step and this is exactly what we need.
const nextTick = async () => {};
exports.nextTick = nextTick;
// Returns control to thread each 'tick' ms to avoid blocking
async function asyncLoop(iters, tick, cb) {
  let ts = Date.now();
  for (let i = 0; i < iters; i++) {
    cb(i);
    // Date.now() is not monotonic, so in case if clock goes backwards we return return control too
    const diff = Date.now() - ts;
    if (diff >= 0 && diff < tick) continue;
    await (0, exports.nextTick)();
    ts += diff;
  }
}
exports.asyncLoop = asyncLoop;
/**
 * @example utf8ToBytes('abc') // new Uint8Array([97, 98, 99])
 */
function utf8ToBytes(str) {
  if (typeof str !== 'string') throw new Error(`utf8ToBytes expected string, got ${typeof str}`);
  return new Uint8Array(new TextEncoder().encode(str)); // https://bugzil.la/1681809
}
exports.utf8ToBytes = utf8ToBytes;
/**
 * Normalizes (non-hex) string or Uint8Array to Uint8Array.
 * Warning: when Uint8Array is passed, it would NOT get copied.
 * Keep in mind for future mutable operations.
 */
function toBytes(data) {
  if (typeof data === 'string') data = utf8ToBytes(data);
  (0, _assert_js_1.bytes)(data);
  return data;
}
exports.toBytes = toBytes;
/**
 * Copies several Uint8Arrays into one.
 */
function concatBytes(...arrays) {
  let sum = 0;
  for (let i = 0; i < arrays.length; i++) {
    const a = arrays[i];
    (0, _assert_js_1.bytes)(a);
    sum += a.length;
  }
  const res = new Uint8Array(sum);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const a = arrays[i];
    res.set(a, pad);
    pad += a.length;
  }
  return res;
}
exports.concatBytes = concatBytes;
// For runtime check if class implements interface
class Hash {
  // Safe version that clones internal state
  clone() {
    return this._cloneInto();
  }
}
exports.Hash = Hash;
const toStr = {}.toString;
function checkOpts(defaults, opts) {
  if (opts !== undefined && toStr.call(opts) !== '[object Object]') throw new Error('Options should be object or undefined');
  const merged = Object.assign(defaults, opts);
  return merged;
}
exports.checkOpts = checkOpts;
function wrapConstructor(hashCons) {
  const hashC = msg => hashCons().update(toBytes(msg)).digest();
  const tmp = hashCons();
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = () => hashCons();
  return hashC;
}
exports.wrapConstructor = wrapConstructor;
function wrapConstructorWithOpts(hashCons) {
  const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
  const tmp = hashCons({});
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = opts => hashCons(opts);
  return hashC;
}
exports.wrapConstructorWithOpts = wrapConstructorWithOpts;
function wrapXOFConstructorWithOpts(hashCons) {
  const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
  const tmp = hashCons({});
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = opts => hashCons(opts);
  return hashC;
}
exports.wrapXOFConstructorWithOpts = wrapXOFConstructorWithOpts;
/**
 * Secure PRNG. Uses `crypto.getRandomValues`, which defers to OS.
 */
function randomBytes(bytesLength = 32) {
  if (crypto_1.crypto && typeof crypto_1.crypto.getRandomValues === 'function') {
    return crypto_1.crypto.getRandomValues(new Uint8Array(bytesLength));
  }
  throw new Error('crypto.getRandomValues must be defined');
}
exports.randomBytes = randomBytes;

},{"./_assert.js":13,"@noble/hashes/crypto":15}],21:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.encode = exports.decode = void 0;
/**
  Base32768 is a binary-to-text encoding optimised for UTF-16-encoded text.
  (e.g. Windows, Java, JavaScript)
*/

// Z is a number, usually a uint15 but sometimes a uint7

const BITS_PER_CHAR = 15; // Base32768 is a 15-bit encoding
const BITS_PER_BYTE = 8;
const pairStrings = ['ҠҿԀԟڀڿݠޟ߀ߟကဟႠႿᄀᅟᆀᆟᇠሿበቿዠዿጠጿᎠᏟᐠᙟᚠᛟកសᠠᡟᣀᣟᦀᦟ᧠᧿ᨠᨿᯀᯟᰀᰟᴀᴟ⇠⇿⋀⋟⍀⏟␀␟─❟➀➿⠀⥿⦠⦿⨠⩟⪀⪿⫠⭟ⰀⰟⲀⳟⴀⴟⵀⵟ⺠⻟㇀㇟㐀䶟䷀龿ꀀꑿ꒠꒿ꔀꗿꙀꙟꚠꛟ꜀ꝟꞀꞟꡀꡟ', 'ƀƟɀʟ'];
const lookupE = {};
const lookupD = {};
pairStrings.forEach((pairString, r) => {
  // Decompression
  const encodeRepertoire = [];
  pairString.match(/../gu).forEach(pair => {
    const first = pair.codePointAt(0);
    const last = pair.codePointAt(1);
    for (let codePoint = first; codePoint <= last; codePoint++) {
      encodeRepertoire.push(String.fromCodePoint(codePoint));
    }
  });
  const numZBits = BITS_PER_CHAR - BITS_PER_BYTE * r; // 0 -> 15, 1 -> 7
  lookupE[numZBits] = encodeRepertoire;
  encodeRepertoire.forEach((chr, z) => {
    lookupD[chr] = [numZBits, z];
  });
});
const encode = uint8Array => {
  const length = uint8Array.length;
  let str = '';
  let z = 0;
  let numZBits = 0;
  for (let i = 0; i < length; i++) {
    const uint8 = uint8Array[i];

    // Take most significant bit first
    for (let j = BITS_PER_BYTE - 1; j >= 0; j--) {
      const bit = uint8 >> j & 1;
      z = (z << 1) + bit;
      numZBits++;
      if (numZBits === BITS_PER_CHAR) {
        str += lookupE[numZBits][z];
        z = 0;
        numZBits = 0;
      }
    }
  }
  if (numZBits !== 0) {
    // Final bits require special treatment.

    // z = bbbbbbcccccccc, numZBits = 14, padBits = 1
    // z = bbbbbcccccccc, numZBits = 13, padBits = 2
    // z = bbbbcccccccc, numZBits = 12, padBits = 3
    // z = bbbcccccccc, numZBits = 11, padBits = 4
    // z = bbcccccccc, numZBits = 10, padBits = 5
    // z = bcccccccc, numZBits = 9, padBits = 6
    // z = cccccccc, numZBits = 8, padBits = 7
    // => Pad `z` out to 15 bits using 1s, then encode as normal (r = 0)

    // z = ccccccc, numZBits = 7, padBits = 0
    // z = cccccc, numZBits = 6, padBits = 1
    // z = ccccc, numZBits = 5, padBits = 2
    // z = cccc, numZBits = 4, padBits = 3
    // z = ccc, numZBits = 3, padBits = 4
    // z = cc, numZBits = 2, padBits = 5
    // z = c, numZBits = 1, padBits = 6
    // => Pad `z` out to 7 bits using 1s, then encode specially (r = 1)

    while (!(numZBits in lookupE)) {
      z = (z << 1) + 1;
      numZBits++;
    }
    str += lookupE[numZBits][z];
  }
  return str;
};
exports.encode = encode;
const decode = str => {
  const length = str.length;

  // This length is a guess. There's a chance we allocate one more byte here
  // than we actually need. But we can count and slice it off later
  const uint8Array = new Uint8Array(Math.floor(length * BITS_PER_CHAR / BITS_PER_BYTE));
  let numUint8s = 0;
  let uint8 = 0;
  let numUint8Bits = 0;
  for (let i = 0; i < length; i++) {
    const chr = str.charAt(i);
    if (!(chr in lookupD)) {
      throw new Error(`Unrecognised Base32768 character: ${chr}`);
    }
    const [numZBits, z] = lookupD[chr];
    if (numZBits !== BITS_PER_CHAR && i !== length - 1) {
      throw new Error('Secondary character found before end of input at position ' + String(i));
    }

    // Take most significant bit first
    for (let j = numZBits - 1; j >= 0; j--) {
      const bit = z >> j & 1;
      uint8 = (uint8 << 1) + bit;
      numUint8Bits++;
      if (numUint8Bits === BITS_PER_BYTE) {
        uint8Array[numUint8s] = uint8;
        numUint8s++;
        uint8 = 0;
        numUint8Bits = 0;
      }
    }
  }

  // Final padding bits! Requires special consideration!
  // Remember how we always pad with 1s?
  // Note: there could be 0 such bits, check still works though
  if (uint8 !== (1 << numUint8Bits) - 1) {
    throw new Error('Padding mismatch');
  }
  return new Uint8Array(uint8Array.buffer, 0, numUint8s);
};
exports.decode = decode;

},{}],22:[function(require,module,exports){
var DEF_PAD_LENGTH = 16;

/**
 * Append PKCS#7 padding to a buffer or a string.
 *
 * @see {@link http://tools.ietf.org/html/rfc5652|RFC 5652 section 6.3}
 *
 * @param {!(string|Uint8Array|Uint8ClampedArray)} data - the data to be padded
 * @param {number=} size - the block size to pad for
 * @return {!(string|Uint8Array|Uint8ClampedArray)} the padded data, if the function succeed
 */
function pad(data, size) {
  var out = data;
  if (typeof size !== 'number') {
    size = DEF_PAD_LENGTH;
  } else if (size > 255) {
    throw new RangeError('pad(): PKCS#7 padding cannot be longer than 255 bytes');
  } else if (size < 0) {
    throw new RangeError('pad(): PKCS#7 padding size must be positive');
  }
  if (typeof data === 'string') {
    var padLen = size - data.length % size;
    if (isNaN(padLen)) padLen = 0;
    var padChar = String.fromCharCode(padLen);
    for (var i = 0; i < padLen; i++) {
      out += padChar;
    }
  } else if (data instanceof Uint8Array || data instanceof Uint8ClampedArray) {
    var baseLen = data.byteLength;
    padLen = size - baseLen % size;
    if (isNaN(padLen)) padLen = 0;
    var newLen = baseLen + padLen;
    out = new data.constructor(newLen);
    out.set(data);
    for (i = baseLen; i < newLen; i++) {
      out[i] = padLen;
    }
  } else {
    throw new TypeError('pad(): data could not be padded');
  }
  return out;
}

/**
 * Remove the PKCS#7 padding from a buffer or a string.
 *
 * @see {@link http://tools.ietf.org/html/rfc5652|RFC 5652 section 6.3}
 *
 * @param {!(string|Uint8Array|Uint8ClampedArray)} data - the data to be unpadded
 * @return {!(string|Uint8Array|Uint8ClampedArray)} the unpadded data, if the function succeed
 */
function unpad(data) {
  var out = data;
  if (typeof data === 'string' && data.length > 0) {
    var padLen = data.charCodeAt(data.length - 1);
    if (padLen > data.length) {
      throw new Error('unpad(): cannot remove ' + padLen + ' bytes from a ' +
        data.length + '-byte(s) string');
    }
    for (var i = data.length - 2, end = data.length - padLen; i >= end; i--) {
      if (data.charCodeAt(i) !== padLen) {
        throw new Error('unpad(): found a padding byte of ' + data.charCodeAt(i) +
          ' instead of ' + padLen + ' at position ' + i);
      }
    }
    out = data.substring(0, end);
  } else if (data instanceof Uint8Array || data instanceof Uint8ClampedArray) {
    var baseLen = data.byteLength;
    padLen = data[baseLen - 1];
    var newLen = baseLen - padLen;
    if (newLen < 0) {
      throw new Error('unpad(): cannot remove ' + padLen + ' bytes from a ' +
        baseLen + '-byte(s) string');
    }
    for (i = baseLen - 2; i >= newLen; i--) {
      if (data[i] !== padLen) {
        throw new Error('unpad(): found a padding byte of ' + data[i] +
          ' instead of ' + padLen + ' at position ' + i);
      }
    }
    out = data.slice(0, newLen);
  }
  return out;
}

module.exports = { pad: pad, unpad: unpad };

},{}],23:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.codec = exports.base64url = exports.base64 = exports.base32hex = exports.base32 = exports.base16 = void 0;
/* eslint-disable @typescript-eslint/strict-boolean-expressions */
function parse(string, encoding, opts) {
  var _opts$out;
  if (opts === void 0) {
    opts = {};
  }

  // Build the character lookup table:
  if (!encoding.codes) {
    encoding.codes = {};
    for (var i = 0; i < encoding.chars.length; ++i) {
      encoding.codes[encoding.chars[i]] = i;
    }
  } // The string must have a whole number of bytes:

  if (!opts.loose && string.length * encoding.bits & 7) {
    throw new SyntaxError('Invalid padding');
  } // Count the padding bytes:

  var end = string.length;
  while (string[end - 1] === '=') {
    --end; // If we get a whole number of bytes, there is too much padding:

    if (!opts.loose && !((string.length - end) * encoding.bits & 7)) {
      throw new SyntaxError('Invalid padding');
    }
  } // Allocate the output:

  var out = new ((_opts$out = opts.out) != null ? _opts$out : Uint8Array)(end * encoding.bits / 8 | 0); // Parse the data:

  var bits = 0; // Number of bits currently in the buffer

  var buffer = 0; // Bits waiting to be written out, MSB first

  var written = 0; // Next byte to write

  for (var _i = 0; _i < end; ++_i) {
    // Read one character from the string:
    var value = encoding.codes[string[_i]];
    if (value === undefined) {
      throw new SyntaxError('Invalid character ' + string[_i]);
    } // Append the bits to the buffer:

    buffer = buffer << encoding.bits | value;
    bits += encoding.bits; // Write out some bits if the buffer has a byte's worth:

    if (bits >= 8) {
      bits -= 8;
      out[written++] = 0xff & buffer >> bits;
    }
  } // Verify that we have received just enough bits:

  if (bits >= encoding.bits || 0xff & buffer << 8 - bits) {
    throw new SyntaxError('Unexpected end of data');
  }
  return out;
}
function stringify(data, encoding, opts) {
  if (opts === void 0) {
    opts = {};
  }
  var _opts = opts,
    _opts$pad = _opts.pad,
    pad = _opts$pad === void 0 ? true : _opts$pad;
  var mask = (1 << encoding.bits) - 1;
  var out = '';
  var bits = 0; // Number of bits currently in the buffer

  var buffer = 0; // Bits waiting to be written out, MSB first

  for (var i = 0; i < data.length; ++i) {
    // Slurp data into the buffer:
    buffer = buffer << 8 | 0xff & data[i];
    bits += 8; // Write out as much as we can:

    while (bits > encoding.bits) {
      bits -= encoding.bits;
      out += encoding.chars[mask & buffer >> bits];
    }
  } // Partial character:

  if (bits) {
    out += encoding.chars[mask & buffer << encoding.bits - bits];
  } // Add padding characters until we hit a byte boundary:

  if (pad) {
    while (out.length * encoding.bits & 7) {
      out += '=';
    }
  }
  return out;
}

/* eslint-disable @typescript-eslint/strict-boolean-expressions */
var base16Encoding = {
  chars: '0123456789ABCDEF',
  bits: 4
};
var base32Encoding = {
  chars: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
  bits: 5
};
var base32HexEncoding = {
  chars: '0123456789ABCDEFGHIJKLMNOPQRSTUV',
  bits: 5
};
var base64Encoding = {
  chars: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
  bits: 6
};
var base64UrlEncoding = {
  chars: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
  bits: 6
};
var base16 = exports.base16 = {
  parse: function parse$1(string, opts) {
    return parse(string.toUpperCase(), base16Encoding, opts);
  },
  stringify: function stringify$1(data, opts) {
    return stringify(data, base16Encoding, opts);
  }
};
var base32 = exports.base32 = {
  parse: function parse$1(string, opts) {
    if (opts === void 0) {
      opts = {};
    }
    return parse(opts.loose ? string.toUpperCase().replace(/0/g, 'O').replace(/1/g, 'L').replace(/8/g, 'B') : string, base32Encoding, opts);
  },
  stringify: function stringify$1(data, opts) {
    return stringify(data, base32Encoding, opts);
  }
};
var base32hex = exports.base32hex = {
  parse: function parse$1(string, opts) {
    return parse(string, base32HexEncoding, opts);
  },
  stringify: function stringify$1(data, opts) {
    return stringify(data, base32HexEncoding, opts);
  }
};
var base64 = exports.base64 = {
  parse: function parse$1(string, opts) {
    return parse(string, base64Encoding, opts);
  },
  stringify: function stringify$1(data, opts) {
    return stringify(data, base64Encoding, opts);
  }
};
var base64url = exports.base64url = {
  parse: function parse$1(string, opts) {
    return parse(string, base64UrlEncoding, opts);
  },
  stringify: function stringify$1(data, opts) {
    return stringify(data, base64UrlEncoding, opts);
  }
};
var codec = exports.codec = {
  parse: parse,
  stringify: stringify
};

},{}]},{},[1]);
