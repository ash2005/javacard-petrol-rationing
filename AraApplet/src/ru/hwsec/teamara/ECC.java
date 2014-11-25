package ru.hwsec.teamara;

import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;

public final class ECC {
	
	public static final byte[] P = new byte[]{
		(byte)0x00, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
		(byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
		(byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
		(byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
		(byte)0xfe, (byte)0xff, (byte)0xff, (byte)0xee, (byte)0x37
	};

	public static final byte[] A = new byte[]{(byte)0x00};

	public static final byte[] B = new byte[]{(byte)0x03};

	public static final byte[] G = new byte[]{
		(byte)0x04, (byte)0xdb, (byte)0x4f, (byte)0xf1, (byte)0x0e,
		(byte)0xc0, (byte)0x57, (byte)0xe9, (byte)0xae, (byte)0x26,
		(byte)0xb0, (byte)0x7d, (byte)0x02, (byte)0x80, (byte)0xb7,
		(byte)0xf4, (byte)0x34, (byte)0x1d, (byte)0xa5, (byte)0xd1,
		(byte)0xb1, (byte)0xea, (byte)0xe0, (byte)0x6c, (byte)0x7d,
		(byte)0x9b, (byte)0x2f, (byte)0x2f, (byte)0x6d, (byte)0x9c,
		(byte)0x56, (byte)0x28, (byte)0xa7, (byte)0x84, (byte)0x41,
		(byte)0x63, (byte)0xd0, (byte)0x15, (byte)0xbe, (byte)0x86,
		(byte)0x34, (byte)0x40, (byte)0x82, (byte)0xaa, (byte)0x88,
		(byte)0xd9, (byte)0x5e, (byte)0x2f, (byte)0x9d

	};

	public static final byte[] N = new byte[] {
		(byte)0x00, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
		(byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
		(byte)0xff, (byte)0xff, (byte)0xfe, (byte)0x26, (byte)0xf2,
		(byte)0xfc, (byte)0x17, (byte)0x0f, (byte)0x69, (byte)0x46,
		(byte)0x6a, (byte)0x74, (byte)0xde, (byte)0xfd, (byte)0x8d
	};

	public static final short COFACTOR = 0x01;
	
	public static final byte[] CHARGING_TERMINAL_INTERMEDIATE = new byte[]{
		(byte)0x04, (byte)0x6c, (byte)0x86, (byte)0x79, (byte)0x4a, (byte)0xae, (byte)0x6d, (byte)0xf0, (byte)0x92, (byte)0x55,	(byte)0x62, (byte)0x3b, (byte)0x5b, (byte)0x55, (byte)0xe5,
		(byte)0x48, (byte)0xaf, (byte)0xfc, (byte)0xa2, (byte)0xd8,	(byte)0xcb, (byte)0x31, (byte)0xec, (byte)0x5f, (byte)0x63,	(byte)0x52, (byte)0x9e, (byte)0x4e, (byte)0xd1, (byte)0x38,
		(byte)0xc4, (byte)0xcc, (byte)0x03, (byte)0x76, (byte)0xed,	(byte)0x59, (byte)0x34, (byte)0xb8, (byte)0xcb, (byte)0xe1,	(byte)0xb6, (byte)0x42, (byte)0xe8, (byte)0x80, (byte)0xe6,
		(byte)0x50, (byte)0x10, (byte)0xa3, (byte)0x91
	};

	public static final byte[] PUMP_TERMINAL_INTERMEDIATE = new byte[]{
		(byte)0x04, (byte)0x8f, (byte)0x4c, (byte)0x7e, (byte)0xe8,	(byte)0x97, (byte)0x10, (byte)0x25, (byte)0x3e, (byte)0x64,	(byte)0xb6, (byte)0xa7, (byte)0xde, (byte)0xd1, (byte)0xba,
		(byte)0x50, (byte)0xa6, (byte)0xd0, (byte)0xb2, (byte)0xac,	(byte)0x0d, (byte)0x1c, (byte)0x95, (byte)0x2e, (byte)0x0a,	(byte)0x59, (byte)0xde, (byte)0x03, (byte)0xc3, (byte)0x3a,
		(byte)0xd4, (byte)0xe9, (byte)0x69, (byte)0x46, (byte)0x73,	(byte)0xc0, (byte)0xdc, (byte)0x65, (byte)0xdb, (byte)0x66,	(byte)0xb6, (byte)0xdf, (byte)0xc8, (byte)0x33, (byte)0x65,
		(byte)0x19, (byte)0x7a, (byte)0x2b, (byte)0x04
	};

	private static ECPublicKey getBlankPublicKey() {
		ECPublicKey publicKey = (ECPublicKey)KeyBuilder.buildKey(
				KeyBuilder.TYPE_EC_FP_PUBLIC,
				KeyBuilder.LENGTH_EC_FP_192,
				false
		);

		publicKey.setFieldFP(P, (short)0, (short)P.length);
		publicKey.setA(A, (short)0, (short)A.length);
		publicKey.setB(B, (short)0, (short)B.length);
		publicKey.setG(G, (short)0, (short)G.length);
		publicKey.setR(N, (short)0, (short)N.length);
		publicKey.setK(COFACTOR);

		return publicKey;
	}

	public static ECPublicKey getChargingIntermediateKey() {
		ECPublicKey publicKey = getBlankPublicKey();
		publicKey.setW(CHARGING_TERMINAL_INTERMEDIATE, (short)0, (short)CHARGING_TERMINAL_INTERMEDIATE.length);
		return publicKey;
	}

	public static ECPublicKey getPumpIntermediateKey() {
		ECPublicKey publicKey = getBlankPublicKey();
		publicKey.setW(PUMP_TERMINAL_INTERMEDIATE, (short)0, (short)CHARGING_TERMINAL_INTERMEDIATE.length);
		return publicKey;
	}

	private static boolean verifySignature(byte[] signedKey, short offset, ECPublicKey key) {
		Signature s = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
		s.init(key, Signature.MODE_VERIFY);
		return s.verify(
			signedKey, offset, (short)49,
			signedKey, (short)49, (short)55
		);
	}

	public static boolean verifyChargingTerminal(byte[] signedKey, short offset) {
		getChargingIntermediateKey();
		return verifySignature(signedKey, offset, getChargingIntermediateKey());
	}

	public static boolean verifyPumpTerminal(byte[] signedKey, short offset) {
		return verifySignature(signedKey, offset, getPumpIntermediateKey());
	}
}
