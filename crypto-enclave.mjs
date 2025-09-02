import { split, combine } from "shamir-secret-sharing";
import crypto from "crypto";
import { ethers } from "ethers";

const IV_LENGTH = 16;

export class CryptoError extends Error {
  constructor(message, code = 'CRYPTO_ERROR', details = {}) {
    super(message);
    this.code = code;
    this.details = details;
  }
}

export class CryptoEnclave {
  constructor(encryptionKey) {
    if (!encryptionKey || typeof encryptionKey !== 'string') {
      throw new CryptoError('Encryption key must be a string', 'INVALID_KEY_TYPE');
    }
    if (encryptionKey.length !== 64) {
      throw new CryptoError('Encryption key must be 64 characters (256-bit)', 'INVALID_KEY_LENGTH');
    }
    try {
      this.encryptionKey = Buffer.from(encryptionKey, "hex");
    } catch (error) {
      throw new CryptoError('Invalid hex encoding in key', 'INVALID_KEY_FORMAT', { error: error.message });
    }
  }

  async generateAndSplitSecret(numShares, threshold) {
    try {
      if (!Number.isInteger(numShares) || numShares < 2) {
        throw new CryptoError('numShares must be integer >= 2', 'INVALID_SHARES');
      }
      if (!Number.isInteger(threshold) || threshold > numShares) {
        throw new CryptoError('Invalid threshold value', 'INVALID_THRESHOLD');
      }

      const wallet = ethers.Wallet.createRandom();
      const privateKeyHex = wallet.privateKey.replace("0x", "");
      const privateKey = new Uint8Array(Buffer.from(privateKeyHex, "hex"));

      const shares = await split(privateKey, numShares, threshold);
      if (!Array.isArray(shares) || shares.length !== numShares) {
        throw new CryptoError('Share generation failed', 'SHARE_GEN_ERROR');
      }

      const encryptedShares = await Promise.all(
        shares.map(async (share, idx) => {
          try {
            return this.encrypt(Buffer.from(share).toString("hex"));
          } catch (error) {
            throw new CryptoError(
              `Failed to encrypt share ${idx}`,
              'SHARE_ENCRYPTION_ERROR',
              { shareIndex: idx, error: error.message }
            );
          }
        })
      );

      return { address: wallet.address, encryptedShares };
    } catch (error) {
      if (error instanceof CryptoError) throw error;
      throw new CryptoError('Failed to generate and split secret', 'SECRET_GEN_ERROR', { 
        error: error.message 
      });
    }
  }

  async signMessageWithShares(encryptedHexShares, message) {
    if (!Array.isArray(encryptedHexShares)) {
      throw new CryptoError('Shares must be an array', 'INVALID_SHARES_FORMAT');
    }
    if (!message) {
      throw new CryptoError('Message is required', 'MISSING_MESSAGE');
    }

    try {
      const decryptedShares = await Promise.all(
        encryptedHexShares.map(async (share, idx) => {
          try {
            const decrypted = this.decrypt(share);
            return new Uint8Array(Buffer.from(decrypted, "hex"));
          } catch (error) {
            throw new CryptoError(
              `Failed to decrypt share ${idx}`,
              'SHARE_DECRYPTION_ERROR',
              { shareIndex: idx, error: error.message }
            );
          }
        })
      );

      const privateKey = await combine(decryptedShares);
      if (!privateKey?.length) {
        throw new CryptoError('Share combination failed', 'COMBINE_ERROR');
      }

      const wallet = new ethers.Wallet(
        "0x" + Buffer.from(privateKey).toString("hex")
      );

      const signature = await wallet.signMessage(message);
      return signature;
    } catch (error) {
      if (error instanceof CryptoError) throw error;
      throw new CryptoError('Message signing failed', 'SIGNING_ERROR', { 
        error: error.message 
      });
    }
  }

  encrypt(text) {
    if (!text) {
      throw new CryptoError('Text is required for encryption', 'MISSING_TEXT');
    }

    try {
      const iv = crypto.randomBytes(IV_LENGTH);
      const cipher = crypto.createCipheriv(
        "aes-256-cbc",
        this.encryptionKey,
        iv
      );
      const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
      return `${iv.toString("hex")}:${encrypted.toString("hex")}`;
    } catch (error) {
      throw new CryptoError('Encryption failed', 'ENCRYPTION_ERROR', { 
        error: error.message 
      });
    }
  }

  decrypt(text) {
    if (!text?.includes(":")) {
      throw new CryptoError('Invalid encrypted format', 'INVALID_ENCRYPTED_FORMAT');
    }

    try {
      const [ivHex, encryptedHex] = text.split(":");
      if (!ivHex || !encryptedHex) {
        throw new CryptoError('Missing IV or encrypted data', 'INVALID_ENCRYPTED_DATA');
      }

      const iv = Buffer.from(ivHex, "hex");
      const encryptedText = Buffer.from(encryptedHex, "hex");
      
      const decipher = crypto.createDecipheriv(
        "aes-256-cbc",
        this.encryptionKey,
        iv
      );
      
      const decrypted = Buffer.concat([
        decipher.update(encryptedText),
        decipher.final()
      ]);
      
      return decrypted.toString();
    } catch (error) {
      if (error instanceof CryptoError) throw error;
      throw new CryptoError('Decryption failed', 'DECRYPTION_ERROR', { 
        error: error.message 
      });
    }
  }
}
