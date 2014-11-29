package ru.hwsec.teamara;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class SymApplet {

    private static byte[] trans;
    private static AESKey eAesKey;
    private static AESKey dAesKey;
    private static byte[] gMacKey;
    private static byte[] vMacKey;
    private static short offsetGMacKey;
    private static short offsetVMacKey;
    private static MessageDigest sha = null;
    private static Cipher cph = null;

    public static void init(
        byte[] eIV, short offsetEIV,
        byte[] dIV, short offsetDIV,
        byte[] eAesKeyBytes, short offsetEAesKey,
        byte[] dAesKeyBytes, short offsetDAesKey,
        byte[] gMacKeyBytes, short offsetGMacKey,
        byte[] vMacKeyBytes, short offsetVMacKey
    ) {
        // We are using 128 bit / 16 byte AES and we use
        // encryption IV 16 (0..15) bytes
        // decryption IV 16 (16..31) bytes
        // padded final round input 16 or output of sha 20 (32..51) bytes
        // Total: 48 bytes
        trans = JCSystem.makeTransientByteArray((short)52, JCSystem.CLEAR_ON_DESELECT);
        Util.arrayCopy(eIV, offsetEIV, trans, (short)0, (short)16);
        Util.arrayCopy(dIV, offsetDIV, trans, (short)16, (short)16);

        eAesKey = getAesKey(eAesKeyBytes, offsetEAesKey);
        dAesKey = getAesKey(dAesKeyBytes, offsetDAesKey);
        
        gMacKey = gMacKeyBytes;
        vMacKey = vMacKeyBytes;
        SymApplet.offsetGMacKey = offsetGMacKey;
        SymApplet.offsetVMacKey = offsetVMacKey;

        if(sha == null)
            sha = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);

        if(cph == null)
            cph = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
    }
    
    private static AESKey getAesKey(byte[] keyBytes, short offset) {
    	AESKey newKey = (AESKey)KeyBuilder.buildKey(
            KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
            KeyBuilder.LENGTH_AES_128,
            false
        );
    	newKey.setKey(keyBytes, offset);
    	return newKey;
    }

    /* These functions were written initially (we spend time writing them)
     * but we could not get them to work on the smartcard. Leaving them here as proof of grief.
     */
    /*
    public static void generateMac(
        byte[] input, short offsetInput, short lengthInput,
        byte[] output, short offsetOutput
    ) {
    	// Initialize signature with generation mac key and for signing
        sig.init(gMacKey, Signature.MODE_SIGN);
        // Calculate remaining unpadded bytes
        byte rembytes = (byte)(lengthInput % 16);
        if(lengthInput > 16) {
        	// Perform AES on the 16 byte aligned part
        	sig.update(input, offsetInput, (short)(lengthInput - rembytes));
        	// Update offsets
        	offsetInput += (short)(lengthInput - rembytes);
        }
        // Copy remaining bytes to aestrans
        Util.arrayCopy(input, offsetInput, aestrans, (short)32, (short)16);
        // Pad and align to 16 bytes
        aestrans[(short)32 + rembytes] = (byte)0x80;
        for(byte i = (byte)0; i < (short)(16 - rembytes - 1); i++)
            aestrans[(short)47 - i] = (byte)0;
        // Perform doFinal on last block
        sig.sign(aestrans, (short)32, (short)16, output, offsetOutput);
    }

    public static boolean verifyMac(
        byte[] input, short offsetInput, short lengthInput,
        byte[] mac, short offsetMac
    ) {
    	// Initialize signature with generation mac key and for signing
        sig.init(vMacKey, Signature.MODE_VERIFY);
        // Calculate remaining unpadded bytes and the nr of padding bytes
        byte rembytes = (byte)(lengthInput % 16);
        if(lengthInput > 16) {
        	// Perform AES on the 16 byte aligned part
        	sig.update(input, offsetInput, (short)(lengthInput - rembytes));
        	// Update offsets
        	offsetInput += (short)(lengthInput - rembytes);
        }
        // Copy remaining bytes to aestrans
        Util.arrayCopy(input, offsetInput, aestrans, (short)32, rembytes);
        // Pad and align to 16 bytes
        aestrans[(short)32 + rembytes] = (byte)0x80;
        for(byte i = (byte)0; i < (short)(16 - rembytes - 1); i++)
            aestrans[(short)47 - i] = (byte)0;
        // Perform doFinal on last block
        return sig.verify(aestrans, (short)32, (short)16, mac, offsetMac, (short)16);
    } */
    
    public static void generateMac(
            byte[] input, short offsetInput, short lengthInput,
            byte[] output, short offsetOutput
        ) {
    	sha.reset();
    	sha.update(gMacKey, offsetGMacKey, (short)16);
    	sha.doFinal(input, offsetInput, lengthInput, output, offsetOutput);
    }
    
    public static boolean verifyMac(
            byte[] input, short offsetInput, short lengthInput,
            byte[] mac, short offsetMac
        ) {
    	sha.reset();
    	sha.update(gMacKey, offsetGMacKey, (short)16);
    	sha.doFinal(input, offsetInput, lengthInput, trans, (short)32);
    	for(short i = 0; i < (short)20; i++)
    		if(mac[i] != trans[i + (short)32])
    			return false;
    	return true;
    }

    public static void encrypt(
        byte[] input, short offsetInput, short lengthInput,
        byte[] output, short offsetOutput
    ) {
    	// Initialize cipher in encryption mode with encryption IV (first 16 bytes of aestrans)
        cph.init(eAesKey, Cipher.MODE_ENCRYPT, trans, (short)0, (short)16);
        // Calculate remaining unpadded bytes and the nr of padding bytes
        byte rembytes = (byte)(lengthInput % 16);
        byte padBytes = (byte)(16 - rembytes);
        if(lengthInput >= 16) {
        	// Perform AES on the 16 byte aligned part
        	cph.update(input, offsetInput, (short)(lengthInput - rembytes), output, offsetOutput);
        	// Update offsets
        	offsetInput += (short)(lengthInput - rembytes);
        	offsetOutput += (short)(lengthInput - rembytes);
        }
        // Copy remaining bytes to aestrans
        Util.arrayCopy(input, offsetInput, trans, (short)32, rembytes);
        // Pad and align to 16 bytes
        for(byte i = (byte)0; i < padBytes; i++)
            trans[47 - i] = padBytes;
        // Perform doFinal on last block
        cph.doFinal(trans, (short)32, (short)16, output, offsetOutput);
        // Update IV
        Util.arrayCopy(output, offsetOutput, trans, (short)0, (short)16);
    }
    
    public static void decrypt(
        byte[] input, short offsetInput, short lengthInput,
        byte[] output, short offsetOutput
    ) {
    	// Initialize cipher in encryption mode with decryption IV (second 16 bytes of aestrans)
        cph.init(dAesKey, Cipher.MODE_DECRYPT, trans, (short)16, (short)16);
        // Perform all decryption at once
        cph.doFinal(input, offsetInput, lengthInput, output, offsetOutput);
        // Update decryption IV to ciphertext of the round
        Util.arrayCopy(input, (short)(offsetInput + lengthInput - 16), trans, (short)16, (short)16);
    }
}
