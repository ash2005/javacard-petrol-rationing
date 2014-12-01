package ru.hwsec.teamara;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Provider;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SymTerminal {
	
	static {
		cryptoProvider = new BouncyCastleProvider();        
    }

	private static Provider cryptoProvider;
	private static SecretKeySpec eAesKey, dAesKey;
	private static byte[] gMacKey, vMacKey;
	private static IvParameterSpec eIV, dIV;
	
	public static void init(
		byte[] eIVBytes, byte[] dIVBytes,
		byte[] eAesKeyBytes, byte[] dAesKeyBytes, byte[] gMacKeyBytes, byte[] vMacKeyBytes
	) throws GeneralSecurityException {
	    eAesKey = new SecretKeySpec(eAesKeyBytes, "AES");
	    dAesKey = new SecretKeySpec(dAesKeyBytes, "AES");
	    gMacKey = gMacKeyBytes;
	    vMacKey = vMacKeyBytes;
	    eIV = new IvParameterSpec(eIVBytes);
	    dIV = new IvParameterSpec(dIVBytes);
	}
	
	/* These do not work because the card does not support them. Proof of grief.
	 */
	/*
	public static byte[] generateMac(byte[] plaintext) throws GeneralSecurityException {
		Mac m = Mac.getInstance("AESCMAC", cryptoProvider);
		m.init(gAesKey);
		return m.doFinal(plaintext);
	}
	
	public static boolean verifyMac(byte[] plaintext, byte[] mac) throws GeneralSecurityException {
		Mac m = Mac.getInstance("AESCMAC", cryptoProvider);
		m.init(vAesKey);
		byte[] gmac = m.doFinal(plaintext);
		return MessageDigest.isEqual(mac, gmac);
	} */
	
	public static byte[] generateMac(byte[] plaintext) throws GeneralSecurityException {
		MessageDigest m = MessageDigest.getInstance("SHA1", cryptoProvider);
		m.update(gMacKey);
		return m.digest(plaintext);
	}
	
	public static boolean verifyMac(byte[] plaintext, byte[] mac) throws GeneralSecurityException {
		MessageDigest m = MessageDigest.getInstance("SHA1", cryptoProvider);
		m.update(vMacKey);
		return MessageDigest.isEqual(mac, m.digest(plaintext));
	}
	
	public static byte[] encrypt(byte[] plaintext) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", cryptoProvider);
	    cipher.init(Cipher.ENCRYPT_MODE, eAesKey, eIV);
	    byte[] ciphertext = cipher.doFinal(plaintext);
	    byte[] newIV = new byte[16];
	    System.arraycopy(ciphertext, ciphertext.length - 16, newIV, 0, 16);
	    eIV = new IvParameterSpec(newIV);
	    return ciphertext;
	} 
	
	public static byte[] decrypt(byte[] ciphertext) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", cryptoProvider);
	    cipher.init(Cipher.DECRYPT_MODE, dAesKey, dIV);
	    byte[] plaintext = cipher.doFinal(ciphertext); 
	    byte[] newIV = new byte[16];
	    System.arraycopy(ciphertext, ciphertext.length - 16, newIV, 0, 16);
	    dIV = new IvParameterSpec(newIV);
	    return plaintext;
	}
	
	public static void main(String[] arg) throws GeneralSecurityException {
		byte[] test_eIV = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
		byte[] test_eAesKey = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};
		//byte[] test_sAesKey = {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26};
		byte[] test_sAesKey = {(byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16, (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6, (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88, (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c};
		byte[] input = {(byte)0x6b, (byte)0xc1, (byte)0xbe, (byte)0xe2, (byte)0x2e, (byte)0x40, (byte)0x9f, (byte)0x96, (byte)0xe9, (byte)0x3d, (byte)0x7e, (byte)0x11, (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2a};
		//byte[] input = {};
		
		SymApplet.init(test_eIV, (short)0, test_eIV, (short)0, test_eAesKey, (short)0, test_eAesKey, (short)0, test_sAesKey, (short)0, test_sAesKey, (short)0);
		SymTerminal.init(test_eIV, test_eIV, test_eAesKey, test_eAesKey, test_sAesKey, test_sAesKey);
		
		byte[] cardCiphertext = new byte[32];
		SymApplet.encrypt(input, (short)0, (short)input.length, cardCiphertext, (short)0);
		byte[] terminalCiphertext = SymTerminal.encrypt(input);
		
		boolean eq = true;
		for(int i = 0; i < cardCiphertext.length; i++)
			if(cardCiphertext[i] != terminalCiphertext[i])
				eq = false;
		System.out.println(eq);
		
		byte[] cardMac = new byte[20];
		SymApplet.generateMac(input, (short)0, (short)input.length, cardMac, (short)0);
		System.out.println(SymApplet.verifyMac(input, (short)0, (short)input.length, cardMac, (short)0));
		
		byte[] terminalMac = SymTerminal.generateMac(input);
		System.out.println(SymTerminal.verifyMac(input, terminalMac));
		
		for(int i = 0; i < cardMac.length; i++)
			if(cardMac[i] != terminalMac[i])
				eq = false;
		System.out.println(eq);
	}
}
