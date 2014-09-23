package ru.hwsec.teamara;

import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Signature;

public class CACertTest {
	
	private static final byte[] ROOT_PRIVATE =
		new byte[]{(byte)0x24, (byte)0x44, (byte)0xac, (byte)0x5a, (byte)0xc2, (byte)0xa5, (byte)0xe1, (byte)0xad, (byte)0x2a, (byte)0x41, (byte)0x38, (byte)0xf9, (byte)0xa8, (byte)0xda};
	private static final byte[] ROOT_PUBLIC =
		new byte[]{(byte)0x04, (byte)0x84, (byte)0x4d, (byte)0x9a, (byte)0x8f, (byte)0x58, (byte)0xee, (byte)0x5a, (byte)0x28, (byte)0x42, (byte)0x28, (byte)0x04, (byte)0xea, (byte)0x40, (byte)0x18, (byte)0x1a, (byte)0xd7, (byte)0x93, (byte)0x74, (byte)0xaf, (byte)0xf8, (byte)0xaf, (byte)0xa2, (byte)0xa6, (byte)0x8d, (byte)0x0f, (byte)0xc6, (byte)0xa9, (byte)0x2d};
	
	private static final byte[] P = 
		new byte[]{(byte)0x00, (byte)0xdb, (byte)0x7c, (byte)0x2a, (byte)0xbf, (byte)0x62, (byte)0xe3, (byte)0x5e, (byte)0x66, (byte)0x80, (byte)0x76, (byte)0xbe, (byte)0xad, (byte)0x20, (byte)0x8b};
	private static final byte[] A = 
		new byte[]{(byte)0x00, (byte)0xdb, (byte)0x7c, (byte)0x2a, (byte)0xbf, (byte)0x62, (byte)0xe3, (byte)0x5e, (byte)0x66, (byte)0x80, (byte)0x76, (byte)0xbe, (byte)0xad, (byte)0x20, (byte)0x88};
	private static final byte[] B = 
		new byte[]{(byte)0x65, (byte)0x9e, (byte)0xf8, (byte)0xba, (byte)0x04, (byte)0x39, (byte)0x16, (byte)0xee, (byte)0xde, (byte)0x89, (byte)0x11, (byte)0x70, (byte)0x2b, (byte)0x22};
	private static final byte[] G = 
		new byte[]{(byte)0x04, (byte)0x09, (byte)0x48, (byte)0x72, (byte)0x39, (byte)0x99, (byte)0x5a, (byte)0x5e, (byte)0xe7, (byte)0x6b, (byte)0x55, (byte)0xf9, (byte)0xc2, (byte)0xf0, (byte)0x98, (byte)0xa8, (byte)0x9c, (byte)0xe5, (byte)0xaf, (byte)0x87, (byte)0x24, (byte)0xc0, (byte)0xa2, (byte)0x3e, (byte)0x0e, (byte)0x0f, (byte)0xf7, (byte)0x75, (byte)0x00};
	private static final byte[] N = 
		new byte[]{(byte)0x00, (byte)0xdb, (byte)0x7c, (byte)0x2a, (byte)0xbf, (byte)0x62, (byte)0xe3, (byte)0x5e, (byte)0x76, (byte)0x28, (byte)0xdf, (byte)0xac, (byte)0x65, (byte)0x61, (byte)0xc5};
	
	private static final byte[] DATA_TO_SIGN =
		new byte[]{(byte)0x30, (byte)0x32, (byte)0x30, (byte)0x10, (byte)0x06, (byte)0x07, (byte)0x2a, (byte)0x86, (byte)0x48, (byte)0xce, (byte)0x3d, (byte)0x02, (byte)0x01, (byte)0x06, (byte)0x05, (byte)0x2b, (byte)0x81, (byte)0x04, (byte)0x00, (byte)0x06, (byte)0x03, (byte)0x1e, (byte)0x00, (byte)0x04, (byte)0x6e, (byte)0xf2, (byte)0xa1, (byte)0x6c, (byte)0x34, (byte)0x16, (byte)0x3b, (byte)0xc0, (byte)0x60, (byte)0x3a, (byte)0x97, (byte)0xce, (byte)0xfa, (byte)0x48, (byte)0x38, (byte)0xba, (byte)0x28, (byte)0xfe, (byte)0x11, (byte)0x0b, (byte)0x41, (byte)0x30, (byte)0xf1, (byte)0x25, (byte)0x28, (byte)0x6f, (byte)0x2b, (byte)0x23};
	private static final byte[] SIGNATURE = 
		new byte[]{(byte)0x30, (byte)0x21, (byte)0x02, (byte)0x0e, (byte)0x0e, (byte)0x0d, (byte)0x6c, (byte)0xc8, (byte)0x9b, (byte)0xf1, (byte)0x68, (byte)0xbe, (byte)0xc4, (byte)0xf6, (byte)0x4e, (byte)0x11, (byte)0xf8, (byte)0x96, (byte)0x02, (byte)0x0f, (byte)0x00, (byte)0xa4, (byte)0xf6, (byte)0x3e, (byte)0xc9, (byte)0xcc, (byte)0x72, (byte)0xaf, (byte)0xf8, (byte)0x5c, (byte)0xa1, (byte)0x7f, (byte)0x8e, (byte)0x76, (byte)0x43};

	public static void main(String[] args) {
		ECPrivateKey privateKey = (ECPrivateKey)KeyBuilder.buildKey(
				KeyBuilder.TYPE_EC_FP_PRIVATE,
				KeyBuilder.LENGTH_EC_FP_112,
				true
		);
		
		privateKey.setFieldFP(P, (short)0, (short)P.length);
		privateKey.setA(A, (short)0, (short)A.length);
		privateKey.setB(B, (short)0, (short)B.length);
		privateKey.setG(G, (short)0, (short)G.length);
		privateKey.setR(N, (short)0, (short)N.length);
		privateKey.setK((short)1);		
		privateKey.setS(ROOT_PRIVATE, (short)0, (short)ROOT_PRIVATE.length);
		
		ECPublicKey publicKey = (ECPublicKey)KeyBuilder.buildKey(
				KeyBuilder.TYPE_EC_FP_PUBLIC,
				KeyBuilder.LENGTH_EC_FP_112,
				true
		);
		
		publicKey.setFieldFP(P, (short)0, (short)P.length);
		publicKey.setA(A, (short)0, (short)A.length);
		publicKey.setB(B, (short)0, (short)B.length);
		publicKey.setG(G, (short)0, (short)G.length);
		publicKey.setR(N, (short)0, (short)N.length);
		publicKey.setK((short)1);		
		publicKey.setW(ROOT_PUBLIC, (short)0, (short)ROOT_PUBLIC.length);
		
		System.out.println(privateKey.isInitialized());
		System.out.println(publicKey.isInitialized());
		
		Signature s = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
		s.init(publicKey, Signature.MODE_VERIFY);
		boolean result = s.verify(
			DATA_TO_SIGN,
			(short)0,
			(short)DATA_TO_SIGN.length,
			SIGNATURE, 
			(short)0,
			(short)SIGNATURE.length
		);
		
		System.out.println(result);
	}

}
