/**
 * Cryptography Module - AES + RSA Hybrid Encryption
 * Anggota 1: Encryption & Decryption
 */

// ==================== RSA KEY GENERATION ====================

/**
 * Generate RSA key pair (public + private)
 */
async function generateRSAKeyPair() {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"  // ✅ Use SHA-256
    },
    true,
    ["encrypt", "decrypt"]
  );

  // Export keys to PEM format
  const publicKey = await exportPublicKey(keyPair.publicKey);
  const privateKey = await exportPrivateKey(keyPair.privateKey);

  return { publicKey, privateKey, keyPair };
}

async function exportPublicKey(key) {
  const exported = await window.crypto.subtle.exportKey("spki", key);
  const exportedAsBase64 = arrayBufferToBase64(exported);
  return `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64}\n-----END PUBLIC KEY-----`;
}

async function exportPrivateKey(key) {
  const exported = await window.crypto.subtle.exportKey("pkcs8", key);
  const exportedAsBase64 = arrayBufferToBase64(exported);
  return `-----BEGIN PRIVATE KEY-----\n${exportedAsBase64}\n-----END PRIVATE KEY-----`;
}

async function importPublicKey(pemKey) {
  const pemContents = pemKey.replace("-----BEGIN PUBLIC KEY-----", "")
                            .replace("-----END PUBLIC KEY-----", "")
                            .replace(/\s/g, "");
  const binaryDer = base64ToArrayBuffer(pemContents);
  
  return await window.crypto.subtle.importKey(
    "spki",
    binaryDer,
    { 
      name: "RSA-OAEP", 
      hash: "SHA-256"  // ✅ Use SHA-256
    },
    true,
    ["encrypt"]
  );
}

async function importPrivateKey(pemKey) {
  const pemContents = pemKey.replace("-----BEGIN PRIVATE KEY-----", "")
                            .replace("-----END PRIVATE KEY-----", "")
                            .replace(/\s/g, "");
  const binaryDer = base64ToArrayBuffer(pemContents);
  
  return await window.crypto.subtle.importKey(
    "pkcs8",
    binaryDer,
    { 
      name: "RSA-OAEP", 
      hash: "SHA-256"  // ✅ Use SHA-256
    },
    true,
    ["decrypt"]
  );
}

// ==================== AES ENCRYPTION ====================

/**
 * Encrypt file with AES-256-GCM
 */
async function encryptFileWithAES(file) {
  // Generate random AES key
  const aesKey = await window.crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  // Generate random IV (Initialization Vector)
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  // Read file as ArrayBuffer
  const fileBuffer = await file.arrayBuffer();

  // Encrypt file
  const encryptedData = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    aesKey,
    fileBuffer
  );

  // Export AES key
  const exportedKey = await window.crypto.subtle.exportKey("raw", aesKey);

  return {
    encryptedData: encryptedData,
    aesKey: exportedKey,
    iv: iv,
    aesKeyObject: aesKey
  };
}

/**
 * Decrypt file with AES-256-GCM
 */
async function decryptFileWithAES(encryptedData, aesKeyRaw, iv) {
  // Import AES key
  const aesKey = await window.crypto.subtle.importKey(
    "raw",
    aesKeyRaw,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );

  // Decrypt
  const decryptedData = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    aesKey,
    encryptedData
  );

  return decryptedData;
}

// ==================== RSA ENCRYPTION ====================

/**
 * Encrypt AES key with RSA public key
 */
async function encryptAESKeyWithRSA(aesKeyRaw, publicKeyPem) {
  const publicKey = await importPublicKey(publicKeyPem);

  // Encrypt AES key with RSA
  const encryptedKey = await window.crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    aesKeyRaw
  );

  return arrayBufferToBase64(encryptedKey);
}

/**
 * Decrypt AES key with RSA private key
 */
async function decryptAESKeyWithRSA(encryptedKeyBase64, privateKeyPem) {
  console.log('🔐 RSA Decrypt - Starting...');
  console.log('🔐 Encrypted key (base64 length):', encryptedKeyBase64.length);
  console.log('🔐 Private key (PEM length):', privateKeyPem.length);
  console.log('🔐 Private key preview:', privateKeyPem.substring(0, 80));
  
  try {
    const privateKey = await importPrivateKey(privateKeyPem);
    console.log('✅ Private key imported successfully');
    
    const encryptedKey = base64ToArrayBuffer(encryptedKeyBase64);
    console.log('🔐 Encrypted key buffer size:', encryptedKey.byteLength);

    // Decrypt AES key with RSA
    const decryptedKey = await window.crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      encryptedKey
    );

    console.log('✅ RSA decryption successful! AES key size:', decryptedKey.byteLength);
    return decryptedKey;
    
  } catch (error) {
    console.error('❌ RSA Decrypt failed:', error);
    console.error('❌ Error name:', error.name);
    console.error('❌ Error message:', error.message);
    throw error;
  }
}

// ==================== HELPER FUNCTIONS ====================

function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = window.atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function uint8ArrayToBase64(uint8Array) {
  return arrayBufferToBase64(uint8Array.buffer);
}

function base64ToUint8Array(base64) {
  return new Uint8Array(base64ToArrayBuffer(base64));
}

// ==================== COMPLETE ENCRYPTION WORKFLOW ====================

/**
 * Complete file encryption process
 * Returns encrypted file + encrypted key ready for upload
 */
async function encryptFileForUpload(file, userPublicKeyPem) {
  // 1. Encrypt file with AES
  const { encryptedData, aesKey, iv } = await encryptFileWithAES(file);

  // 2. Encrypt AES key with RSA public key
  const encryptedAESKey = await encryptAESKeyWithRSA(aesKey, userPublicKeyPem);

  // 3. Combine encrypted data + IV
  const encryptedBlob = new Blob([iv, encryptedData]);

  return {
    encryptedFile: encryptedBlob,
    encryptedKey: encryptedAESKey
  };
}

/**
 * Complete file decryption process
 * ✅ FIXED: Auto-detects owner vs recipient based on privateKey parameter
 */
/**
 * Complete file decryption process
 * ✅ FIXED: Menerima object file dari server
 */
async function decryptFileFromDownload(fileData) {
  console.log('🔍 RAW fileData received:', fileData);
  console.log('🔍 Type of fileData:', typeof fileData);
  console.log('🔍 Keys in fileData:', Object.keys(fileData));
  
  try {
    console.log('🔓 Starting decryption...');
    console.log('📦 File data received:', {
      hasContent: !!fileData.content,
      hasEncryptedKey: !!fileData.encrypted_key,
      isOwner: fileData.is_owner
    });

    if (!fileData) {
      throw new Error('Missing file data');
    }

    if (!fileData.content) {
      throw new Error('Missing encrypted content');
    }

    if (!fileData.encrypted_key) {
      throw new Error('Missing encrypted key');
    }

    // 1. Decode encrypted content
    console.log('📦 Decoding encrypted content...');
    const encryptedBuffer = base64ToArrayBuffer(fileData.content);
    console.log('📦 Encrypted buffer size:', encryptedBuffer.byteLength);
    
    // 2. Extract IV (first 12 bytes) and encrypted data
    const iv = new Uint8Array(encryptedBuffer.slice(0, 12));
    const encryptedData = encryptedBuffer.slice(12);

    console.log('📦 IV length:', iv.length);
    console.log('📦 Encrypted data length:', encryptedData.byteLength);

    let aesKeyRaw;

    // 3. Determine if owner or recipient
    if (fileData.is_owner) {
      // ✅ OWNER: encrypted_key is raw AES key
      console.log('👤 Owner mode: Using raw AES key');
      aesKeyRaw = base64ToArrayBuffer(fileData.encrypted_key);
    } else {
      // ✅ RECIPIENT: encrypted_key is RSA-encrypted
      console.log('📨 Recipient mode: Decrypting AES key with RSA private key');
      
      // Ambil private key dari localStorage
      const privateKeyPem = localStorage.getItem('user_private_key');
      if (!privateKeyPem) {
        throw new Error('No private key found in localStorage. Please login again.');
      }
      
      console.log('🔐 Private key PEM length:', privateKeyPem.length);
      console.log('🔐 Encrypted key base64 length:', fileData.encrypted_key.length);
      
      aesKeyRaw = await decryptAESKeyWithRSA(fileData.encrypted_key, privateKeyPem);
    }

    console.log('🔑 AES key size:', aesKeyRaw.byteLength, 'bytes');

    // Validate AES key size (AES-256 = 32 bytes)
    if (aesKeyRaw.byteLength !== 32) {
      console.warn(`⚠️ Unexpected AES key size: ${aesKeyRaw.byteLength} bytes. Expected 32 bytes.`);
    }

    // 4. Decrypt file with AES
    console.log('🔓 Decrypting file with AES...');
    const decryptedData = await decryptFileWithAES(encryptedData, aesKeyRaw, iv);

    console.log('✅ Decryption complete! Size:', decryptedData.byteLength, 'bytes');
    return decryptedData;

  } catch (error) {
    console.error('❌ Decryption failed:', error);
    console.error('Error name:', error.name);
    console.error('Error message:', error.message);
    throw error;
  }
}

/**
 * Decrypt AES key with RSA private key
 * (Pastikan fungsi ini ada di crypto.js)
 */
async function decryptAESKeyWithRSA(encryptedKeyBase64, privateKeyPem) {
  console.log('🔐 RSA Decrypt - Starting...');
  console.log('🔐 Encrypted key (base64 length):', encryptedKeyBase64.length);
  console.log('🔐 Private key (PEM length):', privateKeyPem.length);
  console.log('🔐 Private key preview:', privateKeyPem.substring(0, 80));
  
  try {
    const privateKey = await importPrivateKey(privateKeyPem);
    console.log('✅ Private key imported successfully');
    
    const encryptedKey = base64ToArrayBuffer(encryptedKeyBase64);
    console.log('🔐 Encrypted key buffer size:', encryptedKey.byteLength);

    // Decrypt AES key with RSA
    const decryptedKey = await window.crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      encryptedKey
    );

    console.log('✅ RSA decryption successful! AES key size:', decryptedKey.byteLength);
    return decryptedKey;
    
  } catch (error) {
    console.error('❌ RSA Decrypt failed:', error);
    console.error('❌ Error name:', error.name);
    console.error('❌ Error message:', error.message);
    
    // Coba dengan format hash yang berbeda
    try {
      console.log('🔄 Retrying with explicit SHA-256...');
      const privateKey = await importPrivateKey(privateKeyPem);
      const encryptedKey = base64ToArrayBuffer(encryptedKeyBase64);
      
      const decryptedKey = await window.crypto.subtle.decrypt(
        { 
          name: "RSA-OAEP",
          hash: "SHA-256" 
        },
        privateKey,
        encryptedKey
      );
      
      console.log('✅ Second attempt successful!');
      return decryptedKey;
    } catch (secondError) {
      console.error('❌ Second attempt also failed:', secondError);
      throw error; // Throw original error
    }
  }
}
/**
 * Test private key with dummy data
 */
async function testPrivateKey(privateKeyPem) {
  try {
    console.log('🔍 Testing private key...');
    
    // Buat dummy data untuk test
    const testData = new TextEncoder().encode('test');
    
    // Import private key
    const privateKey = await importPrivateKey(privateKeyPem);
    
    // Coba encrypt dengan public key dulu
    const publicKeyPem = localStorage.getItem('user_public_key');
    if (publicKeyPem) {
      const publicKey = await importPublicKey(publicKeyPem);
      
      // Encrypt test data
      const encrypted = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        testData
      );
      
      // Decrypt dengan private key
      const decrypted = await window.crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        encrypted
      );
      
      const success = arraysEqual(new Uint8Array(testData), new Uint8Array(decrypted));
      console.log('Private key test:', success ? '✅ PASSED' : '❌ FAILED');
    }
  } catch (error) {
    console.error('Private key test failed:', error);
  }
}

function arraysEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}