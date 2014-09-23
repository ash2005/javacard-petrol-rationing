package ru.hwsec.teamara;

import javacard.framework.ISOException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Signature;

public class SOTest2 {

	private static byte[] PLAINTEXT ;
	private static ECPrivateKey            objECDSAPriKey=null;    // Object for ECDSA Private Key
	private static ECPublicKey             objECDSAPubKey=null;    // Object for ECDSA Public Key
	private static KeyPair                 objECDSAKeyPair=null;   // Object for ECDSA Key Pair
	private static Signature               objECDSASign=null;      // Object for ECDSA Signature

	final static short  BAS     =  0;

	final static byte[] SecP192r1_P = {     // 24
	    (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
	    (byte)0xFE,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
	    (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF};
	final static byte[] SecP192r1_A = {     // 24
	    (byte)0xFC,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
	    (byte)0xFE,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
	    (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF};
	final static byte[] SecP192r1_B = {     // 24
	  (byte)0xB1,(byte)0xB9,(byte)0x46,(byte)0xC1,(byte)0xEC,(byte)0xDE,(byte)0xB8,(byte)0xFE,
	  (byte)0x49,(byte)0x30,(byte)0x24,(byte)0x72,(byte)0xAB,(byte)0xE9,(byte)0xA7,(byte)0x0F,
	  (byte)0xE7,(byte)0x80,(byte)0x9C,(byte)0xE5,(byte)0x19,(byte)0x05,(byte)0x21,(byte)0x64};
	final static byte[] SecP192r1_S = {     // 20
	  (byte)0xD5,(byte)0x96,(byte)0x21,(byte)0xE1,(byte)0xEA,(byte)0x20,(byte)0x81,(byte)0xD3,
	  (byte)0x28,(byte)0x95,(byte)0x57,(byte)0xED,(byte)0x64,(byte)0x2F,(byte)0x42,(byte)0xC8,
	  (byte)0x6F,(byte)0xAE,(byte)0x45,(byte)0x30};
	final static byte[] SecP192r1_G = {     // 25
	  (byte)0x12,(byte)0x10,(byte)0xFF,(byte)0x82,(byte)0xFD,(byte)0x0A,(byte)0xFF,(byte)0xF4,
	  (byte)0x00,(byte)0x88,(byte)0xA1,(byte)0x43,(byte)0xEB,(byte)0x20,(byte)0xBF,(byte)0x7C,
	  (byte)0xF6,(byte)0x90,(byte)0x30,(byte)0xB0,(byte)0x0E,(byte)0xA8,(byte)0x8D,(byte)0x18,(byte)0x03};
	final static byte[] SecP192r1_N = {     // 24
	  (byte)0x31,(byte)0x28,(byte)0xD2,(byte)0xB4,(byte)0xB1,(byte)0xC9,(byte)0x6B,(byte)0x14,
	  (byte)0x36,(byte)0xF8,(byte)0xDE,(byte)0x99,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
	  (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF};
	final static short  SecP192r1_H =  1;

	//======================================================================================
	public static void main(String[] args) {

	    objECDSAPriKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_192, false);
        objECDSAPubKey = (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC,  KeyBuilder.LENGTH_EC_FP_192, false);

        // set EC Domain Parameters
        objECDSAPubKey.setFieldFP(SecP192r1_P, BAS, (short)24);
        objECDSAPubKey.setA(SecP192r1_A, BAS, (short)24);
        objECDSAPubKey.setB(SecP192r1_B, BAS, (short)24);
        objECDSAPubKey.setG(SecP192r1_G, BAS, (short)25);
        objECDSAPubKey.setK(SecP192r1_H);
        objECDSAPubKey.setR(SecP192r1_N, BAS, (short)24);

        objECDSAKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_192);
        
     // On-Card Key Generation Process
        objECDSAKeyPair.genKeyPair();

        // Obtain Key References
        objECDSAPriKey = (ECPrivateKey)objECDSAKeyPair.getPrivate();
        objECDSAPubKey = (ECPublicKey)objECDSAKeyPair.getPublic();  

        // Create Signature Object
        objECDSASign = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
        
     // Init with Private Key
        objECDSASign.init(objECDSAPriKey, Signature.MODE_SIGN);
        short   sSignLen=0 ;
        // Sign Data
        //sSignLen = objECDSASign.sign(PLAINTEXT, BAS, (short)80, buf, BAS);

 	    return; 
	}
}
