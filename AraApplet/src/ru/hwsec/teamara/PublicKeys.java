package ru.hwsec.teamara;

import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;

public final class PublicKeys {

	public static final byte[] CHARGING_TERMINAL_INTERMEDIATE = new byte[]{
		(byte)0x04, (byte)0x6c, (byte)0x86, (byte)0x79, (byte)0x4a, 
		(byte)0xae, (byte)0x6d, (byte)0xf0, (byte)0x92, (byte)0x55, 
		(byte)0x62, (byte)0x3b, (byte)0x5b, (byte)0x55, (byte)0xe5,
		(byte)0x48, (byte)0xaf, (byte)0xfc, (byte)0xa2, (byte)0xd8, 
		(byte)0xcb, (byte)0x31, (byte)0xec, (byte)0x5f, (byte)0x63, 
		(byte)0x52, (byte)0x9e, (byte)0x4e, (byte)0xd1, (byte)0x38,
		(byte)0xc4, (byte)0xcc, (byte)0x03, (byte)0x76, (byte)0xed, 
		(byte)0x59, (byte)0x34, (byte)0xb8, (byte)0xcb, (byte)0xe1, 
		(byte)0xb6, (byte)0x42, (byte)0xe8, (byte)0x80, (byte)0xe6,
		(byte)0x50, (byte)0x10, (byte)0xa3, (byte)0x91
	};
	
	public static final byte[] PUMP_TERMINAL_INTERMEDIATE = new byte[]{
		(byte)0x04, (byte)0x8f, (byte)0x4c, (byte)0x7e, (byte)0xe8, 
		(byte)0x97, (byte)0x10, (byte)0x25, (byte)0x3e, (byte)0x64,
		(byte)0xb6, (byte)0xa7, (byte)0xde, (byte)0xd1, (byte)0xba,
		(byte)0x50, (byte)0xa6, (byte)0xd0, (byte)0xb2, (byte)0xac, 
		(byte)0x0d, (byte)0x1c, (byte)0x95, (byte)0x2e, (byte)0x0a, 
		(byte)0x59, (byte)0xde, (byte)0x03, (byte)0xc3, (byte)0x3a,
		(byte)0xd4, (byte)0xe9, (byte)0x69, (byte)0x46, (byte)0x73, 
		(byte)0xc0, (byte)0xdc, (byte)0x65, (byte)0xdb, (byte)0x66, 
		(byte)0xb6, (byte)0xdf, (byte)0xc8, (byte)0x33, (byte)0x65,
		(byte)0x19, (byte)0x7a, (byte)0x2b, (byte)0x04
	};
	
	private static ECPublicKey getBlankPublicKey() {
		ECPublicKey publicKey = (ECPublicKey)KeyBuilder.buildKey(
				KeyBuilder.TYPE_EC_FP_PUBLIC,
				KeyBuilder.LENGTH_EC_FP_192,
				true
		);
		
		publicKey.setFieldFP(CurveParameters.PRIME, (short)0, (short)CurveParameters.PRIME.length);
		publicKey.setA(CurveParameters.A, (short)0, (short)CurveParameters.A.length);
		publicKey.setB(CurveParameters.B, (short)0, (short)CurveParameters.B.length);
		publicKey.setG(CurveParameters.G, (short)0, (short)CurveParameters.G.length);
		publicKey.setR(CurveParameters.N, (short)0, (short)CurveParameters.N.length);
		publicKey.setK(CurveParameters.COFACTOR);
		
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
	
	private static boolean verifySignature(byte[] id, ECPublicKey key) {
		Signature s = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
		s.init(key, Signature.MODE_VERIFY);
		return s.verify(
			id,
			(short)0,
			(short)(192 * 2),
			id, 
			(short)(192 * 2),
			(short)55
		);
	}
	
	public static boolean verifyChargingTerminal(byte[] id) {
		return verifySignature(id, getChargingIntermediateKey());
	}
	
	public static boolean verifyPumpTerminal(byte[] id) {
		return verifySignature(id, getPumpIntermediateKey());
	}
}
