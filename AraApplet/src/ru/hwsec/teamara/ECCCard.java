package ru.hwsec.teamara;

import javacard.security.ECPublicKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;

public final class ECCCard {
	
	public static byte[] PRIVATE_KEY_BYTES = {
        (byte)0x00, (byte)0xa2, (byte)0x7c, (byte)0x91, (byte)0xa2, (byte)0x97, (byte)0x8d, (byte)0x91, (byte)0xd6, (byte)0x06, (byte)0x5a, (byte)0x01, (byte)0x8c, (byte)0xde, (byte)0x2f,
        (byte)0x61, (byte)0x6f, (byte)0x54, (byte)0x1f, (byte)0xb5, (byte)0x33, (byte)0xe9, (byte)0xba, (byte)0xac, (byte)0xf1
    };

	public static byte[] PUBLIC_KEY_BYTES = {
        (byte)0x04, (byte)0x01, (byte)0x5b, (byte)0x41, (byte)0x1c, (byte)0x20, (byte)0x6d, (byte)0xff, (byte)0x82, (byte)0x17, (byte)0xc6, (byte)0x39, (byte)0x5e, (byte)0x49, (byte)0xe6,
        (byte)0x14, (byte)0x2e, (byte)0x86, (byte)0x11, (byte)0x01, (byte)0xb3, (byte)0x4f, (byte)0xe2, (byte)0x87, (byte)0x47, (byte)0xcd, (byte)0x00, (byte)0xa5, (byte)0x46, (byte)0x1f,
        (byte)0xae, (byte)0x4f, (byte)0x96, (byte)0xd8, (byte)0x43, (byte)0x11, (byte)0xef, (byte)0x7c, (byte)0x41, (byte)0x82, (byte)0x10, (byte)0x13, (byte)0x6f, (byte)0xc5, (byte)0x88,
        (byte)0x28, (byte)0x7d, (byte)0xb8, (byte)0x73, (byte)0x69, (byte)0x08
    };

    public static byte[] SIGNATURE_BYTES = {
        (byte)0x30, (byte)0x34, (byte)0x02, (byte)0x18, (byte)0x0f, (byte)0xa3, (byte)0xda, (byte)0xd3, (byte)0x65, (byte)0x44, (byte)0x30, (byte)0xf4, (byte)0x06, (byte)0x7a, (byte)0x7e,
        (byte)0xc7, (byte)0xac, (byte)0x79, (byte)0x9c, (byte)0x76, (byte)0x51, (byte)0x88, (byte)0x97, (byte)0x1c, (byte)0x5a, (byte)0xa7, (byte)0x4b, (byte)0x60, (byte)0x02, (byte)0x18,
        (byte)0x6d, (byte)0x15, (byte)0x24, (byte)0xb8, (byte)0xd9, (byte)0xde, (byte)0xe0, (byte)0xc1, (byte)0xb7, (byte)0xe5, (byte)0x88, (byte)0x11, (byte)0xe2, (byte)0xdc, (byte)0x12,
        (byte)0x32, (byte)0x4d, (byte)0xc0, (byte)0x6a, (byte)0xa2, (byte)0xbc, (byte)0xd1, (byte)0x48, (byte)0x5f
    };

	public static final short FIELD_E = (short)15;

	public static final byte[] A = new byte[]{
		//(byte)0x00, // Uncomment this if you are using the card.
        (byte)0x17, (byte)0x85, (byte)0x8f, (byte)0xeb, (byte)0x7a, (byte)0x98, (byte)0x97, (byte)0x51, (byte)0x69, (byte)0xe1, (byte)0x71, (byte)0xf7, (byte)0x7b, (byte)0x40,
        (byte)0x87, (byte)0xde, (byte)0x09, (byte)0x8a, (byte)0xc8, (byte)0xa9, (byte)0x11, (byte)0xdf, (byte)0x7b, (byte)0x01
    };

	public static final byte[] B = new byte[]{
        (byte)0x00, (byte)0xfd, (byte)0xfb, (byte)0x49, (byte)0xbf, (byte)0xe6, (byte)0xc3, (byte)0xa8, (byte)0x9f, (byte)0xac, (byte)0xad, (byte)0xaa, (byte)0x7a, (byte)0x1e, (byte)0x5b,
        (byte)0xbc, (byte)0x7c, (byte)0xc1, (byte)0xc2, (byte)0xe5, (byte)0xd8, (byte)0x31, (byte)0x47, (byte)0x88, (byte)0x14
    };

	public static final byte[] G = new byte[]{
        (byte)0x04, (byte)0x01, (byte)0xf4, (byte)0x81, (byte)0xbc, (byte)0x5f, (byte)0x0f, (byte)0xf8, (byte)0x4a, (byte)0x74, (byte)0xad, (byte)0x6c, (byte)0xdf, (byte)0x6f, (byte)0xde,
        (byte)0xf4, (byte)0xbf, (byte)0x61, (byte)0x79, (byte)0x62, (byte)0x53, (byte)0x72, (byte)0xd8, (byte)0xc0, (byte)0xc5, (byte)0xe1, (byte)0x00, (byte)0x25, (byte)0xe3, (byte)0x99,
        (byte)0xf2, (byte)0x90, (byte)0x37, (byte)0x12, (byte)0xcc, (byte)0xf3, (byte)0xea, (byte)0x9e, (byte)0x3a, (byte)0x1a, (byte)0xd1, (byte)0x7f, (byte)0xb0, (byte)0xb3, (byte)0x20,
        (byte)0x1b, (byte)0x6a, (byte)0xf7, (byte)0xce, (byte)0x1b, (byte)0x05
	};

	public static final byte[] N = new byte[] {
        (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0xc7, (byte)0xf3,
        (byte)0x4a, (byte)0x77, (byte)0x8f, (byte)0x44, (byte)0x3a, (byte)0xcc, (byte)0x92, (byte)0x0e, (byte)0xba, (byte)0x49
	};

	public static final short COFACTOR = 0x02;

	public static final byte[] CHARGING_TERMINAL_INTERMEDIATE = new byte[]{
        (byte)0x04, (byte)0x00, (byte)0xbc, (byte)0xd8, (byte)0xf4, (byte)0x74, (byte)0xd1, (byte)0x8a, (byte)0xd4, (byte)0xec, (byte)0x45, (byte)0xdf, (byte)0x75, (byte)0x75, (byte)0xc5,
        (byte)0x97, (byte)0x64, (byte)0xa1, (byte)0xe4, (byte)0xd8, (byte)0x04, (byte)0xa2, (byte)0x3d, (byte)0xec, (byte)0x69, (byte)0x1b, (byte)0x01, (byte)0x63, (byte)0xe1, (byte)0xff,
        (byte)0x19, (byte)0x31, (byte)0xfa, (byte)0xdd, (byte)0xe0, (byte)0xf7, (byte)0x5e, (byte)0xac, (byte)0x88, (byte)0xd7, (byte)0x71, (byte)0x9c, (byte)0x05, (byte)0x07, (byte)0xf2,
        (byte)0x01, (byte)0x94, (byte)0x44, (byte)0x76, (byte)0xc3, (byte)0x69
	};

	public static final byte[] PUMP_TERMINAL_INTERMEDIATE = new byte[]{
        (byte)0x04, (byte)0x01, (byte)0x09, (byte)0xc5, (byte)0x3f, (byte)0xcd, (byte)0x96, (byte)0x1b, (byte)0xd9, (byte)0xea, (byte)0x8c, (byte)0x01, (byte)0xcf, (byte)0x06, (byte)0xa6,
        (byte)0xeb, (byte)0x34, (byte)0xb1, (byte)0x3a, (byte)0xa8, (byte)0x5b, (byte)0x78, (byte)0xb6, (byte)0xbc, (byte)0x33, (byte)0x3b, (byte)0x01, (byte)0x6a, (byte)0xa4, (byte)0xb3,
        (byte)0xc8, (byte)0x81, (byte)0x79, (byte)0xef, (byte)0x46, (byte)0x4c, (byte)0x71, (byte)0x2f, (byte)0x2c, (byte)0xfe, (byte)0x50, (byte)0xc8, (byte)0x86, (byte)0x8c, (byte)0x9d,
        (byte)0xee, (byte)0x3f, (byte)0x4f, (byte)0x05, (byte)0xbd, (byte)0x0a
	};

	private static ECPublicKey getBlankPublicKey() {
		ECPublicKey publicKey = (ECPublicKey)KeyBuilder.buildKey(
				KeyBuilder.TYPE_EC_F2M_PUBLIC,
				KeyBuilder.LENGTH_EC_F2M_193,
				false
		);

		publicKey.setFieldF2M(FIELD_E);
		publicKey.setB(B, (short)0, (short)B.length);
		publicKey.setA(A, (short)0, (short)A.length);
		publicKey.setG(G, (short)0, (short)G.length);
		publicKey.setR(N, (short)0, (short)N.length);
		publicKey.setK(COFACTOR);

		return publicKey;
	}

	
	private static ECPrivateKey getBlankPrivateKey() {
		ECPrivateKey privateKey = (ECPrivateKey)KeyBuilder.buildKey(
				KeyBuilder.TYPE_EC_F2M_PUBLIC,
				KeyBuilder.LENGTH_EC_F2M_193,
				false
		);

		privateKey.setFieldF2M(FIELD_E);
		privateKey.setB(B, (short)0, (short)B.length);
		privateKey.setA(A, (short)0, (short)A.length);
		privateKey.setG(G, (short)0, (short)G.length);
		privateKey.setR(N, (short)0, (short)N.length);
		privateKey.setK(COFACTOR);

		return privateKey;
	}

	public static ECPrivateKey getPrivateKey(byte[] secretScalar){
		ECPrivateKey privateKey = getBlankPrivateKey();
		privateKey.setS(secretScalar, (short) 0, (short) 25);
		return privateKey;
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
			signedKey, offset, (short)51,
			signedKey, (short)(51 + offset), (short)54
		);
	}

	public static boolean verifyChargingTerminal(byte[] signedKey, short offset) {
		return verifySignature(signedKey, offset, getChargingIntermediateKey());
	}

	public static boolean verifyPumpTerminal(byte[] signedKey, short offset) {
		return verifySignature(signedKey, offset, getPumpIntermediateKey());
	}
}
