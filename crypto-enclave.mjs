import { split, combine } from "shamir-secret-sharing";
import crypto from "crypto";
import { ethers } from "ethers";

const IV_LENGTH = 16;

export class CryptoEnclave {
  constructor(encryptionKey) {
    if (!encryptionKey || encryptionKey.length !== 64) {
      throw new Error(
        "Encryption key must be a 64-character hex string (256-bit)."
      );
    }
    this.encryptionKey = Buffer.from(encryptionKey, "hex");
  }

  async generateAndSplitSecret(numShares, threshold) {
    // ethers.Wallet.createRandom() uses a cryptographically secure random number generator (CSPRNG)
    // to generate a 256-bit private key, which provides high entropy (well over 128 bits).
    const wallet = ethers.Wallet.createRandom();
    const privateKeyHex = wallet.privateKey.replace("0x", "");
    const privateKey = new Uint8Array(Buffer.from(privateKeyHex, "hex"));

    const shares = await split(privateKey, numShares, threshold);
    if (!Array.isArray(shares)) {
      throw new Error(
        "split() did not return an array, check library version!"
      );
    }

    const encryptedShares = shares.map((s) =>
      this.encrypt(Buffer.from(s).toString("hex"))
    );
    return { address: wallet.address, encryptedShares };
  }

  async splitSecret(secret, numShares, threshold) {
    const privateKeyHex = secret.replace("0x", "");
    const privateKey = new Uint8Array(Buffer.from(privateKeyHex, "hex"));
    const shares = await split(privateKey, numShares, threshold);
    if (!Array.isArray(shares)) {
      throw new Error(
        "split() did not return an array, check library version!"
      );
    }
    return shares.map((s) => Buffer.from(s).toString("hex"));
  }

  async combineShares(hexShares) {
    const shares = hexShares.map((s) => new Uint8Array(Buffer.from(s, "hex")));
    const secret = await combine(shares);
    return "0x" + Buffer.from(secret).toString("hex");
  }

  async signMessageWithShares(encryptedHexShares, message) {
    const decryptedHexShares = encryptedHexShares.map((s) => this.decrypt(s));

    const shares = decryptedHexShares.map(
      (s) => new Uint8Array(Buffer.from(s, "hex"))
    );
    const privateKey = await combine(shares);
    const wallet = new ethers.Wallet(
      "0x" + Buffer.from(privateKey).toString("hex")
    );

    const signature = await wallet.signMessage(message);
    return signature;
  }

  encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv("aes-256-cbc", this.encryptionKey, iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString("hex") + ":" + encrypted.toString("hex");
  }

  decrypt(text) {
    const textParts = text.split(":");
    const iv = Buffer.from(textParts.shift(), "hex");
    const encryptedText = Buffer.from(textParts.join(":"), "hex");
    const decipher = crypto.createDecipheriv(
      "aes-256-cbc",
      this.encryptionKey,
      iv
    );
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  }
}
