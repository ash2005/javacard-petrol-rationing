package ru.hwsec.teamara;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;

import javax.crypto.KeyAgreement;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ECCTerminal {

	static {
        Security.addProvider(new BouncyCastleProvider());
        cryptoProvider = new BouncyCastleProvider();
    }

	private static Provider cryptoProvider;

	public static byte[] PUBLIC_KEY_BYTES = new byte[]{
        (byte)0x04, (byte)0x01, (byte)0x96, (byte)0x96, (byte)0x64, (byte)0x3a, (byte)0x14, (byte)0xda, (byte)0xe5, (byte)0x7c, (byte)0x15, (byte)0x83, (byte)0x6b, (byte)0x48, (byte)0x6f,
        (byte)0x83, (byte)0xac, (byte)0x4f, (byte)0x36, (byte)0x0a, (byte)0x47, (byte)0x9d, (byte)0x4b, (byte)0x9d, (byte)0x3e, (byte)0x85, (byte)0x01, (byte)0xd1, (byte)0x2d, (byte)0xf9,
        (byte)0x13, (byte)0x3a, (byte)0x70, (byte)0xee, (byte)0x9b, (byte)0xbb, (byte)0x58, (byte)0x65, (byte)0xc2, (byte)0x3d, (byte)0x29, (byte)0x9f, (byte)0xdb, (byte)0x54, (byte)0xac,
        (byte)0x2f, (byte)0x11, (byte)0x52, (byte)0x63, (byte)0xf2, (byte)0x9a
    };

    public static byte[] PRIVATE_KEY_BYTES = new byte[]{
        (byte)0x00, (byte)0xf1, (byte)0xaf, (byte)0x06, (byte)0xac, (byte)0xa7, (byte)0x0d, (byte)0xf8, (byte)0x3f, (byte)0x89, (byte)0xd8, (byte)0x96, (byte)0x57, (byte)0x72, (byte)0x7d,
        (byte)0x93, (byte)0x79, (byte)0x1a, (byte)0xe8, (byte)0x76, (byte)0x7d, (byte)0xac, (byte)0x98, (byte)0x25, (byte)0x99
    };

    public static byte[] SIGNATURE_BYTES = new byte[]{
        (byte)0x30, (byte)0x34, (byte)0x02, (byte)0x18, (byte)0x0c, (byte)0x4f, (byte)0xa8, (byte)0xdf, (byte)0x6f, (byte)0xd2, (byte)0x43, (byte)0x15, (byte)0xd3, (byte)0xf6, (byte)0xaa,
        (byte)0xb0, (byte)0xbd, (byte)0x34, (byte)0x6a, (byte)0x35, (byte)0x2a, (byte)0x9b, (byte)0xd7, (byte)0xb4, (byte)0x35, (byte)0x3e, (byte)0xbe, (byte)0x50, (byte)0x02, (byte)0x18,
        (byte)0x7f, (byte)0xa1, (byte)0x6a, (byte)0xd5, (byte)0x00, (byte)0x94, (byte)0xd2, (byte)0x90, (byte)0xa5, (byte)0xb4, (byte)0x6f, (byte)0xe3, (byte)0x85, (byte)0x7b, (byte)0xc8,
        (byte)0x48, (byte)0xcd, (byte)0xc8, (byte)0x03, (byte)0xc0, (byte)0x05, (byte)0x02, (byte)0xed, (byte)0x8f
    };

    public static byte[] CARD_INTERMEDIATE_X = new byte[]{
        (byte)0x00, (byte)0x7f, (byte)0x43, (byte)0x93, (byte)0x44, (byte)0xac, (byte)0x58, (byte)0x0f, (byte)0xd7, (byte)0x9c, (byte)0x62, (byte)0xf0, (byte)0xb6, (byte)0xab, (byte)0x19, (byte)0x97,
        (byte)0x12, (byte)0x49, (byte)0x7a, (byte)0x7a, (byte)0xbd, (byte)0xf6, (byte)0x9e, (byte)0x76, (byte)0xb7
	};

	public static byte[] CARD_INTERMEDIATE_Y = new byte[]{
        (byte)0x00, (byte)0x7d, (byte)0x84, (byte)0x2e, (byte)0x25, (byte)0x6a, (byte)0xcd, (byte)0x7d, (byte)0x56, (byte)0x96, (byte)0x67, (byte)0x2e, (byte)0x0b, (byte)0x89, (byte)0x7f, (byte)0x9b,
        (byte)0x75, (byte)0x11, (byte)0xae, (byte)0xfb, (byte)0x93, (byte)0x0f, (byte)0x71, (byte)0x41, (byte)0x65
	};
	
	public static PublicKey getPublicKey(byte[] x, byte[] y) throws GeneralSecurityException {
		ECPoint cardIntermediatePoint = new ECPoint(new BigInteger(x), new BigInteger(y));
		AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("sect193r1"));
        ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
		ECPublicKeySpec keyspec = new ECPublicKeySpec(cardIntermediatePoint, ecParameters);
		KeyFactory keyfactory = KeyFactory.getInstance("EC", cryptoProvider);
		return keyfactory.generatePublic(keyspec);
	}
	
	public static PublicKey getPublicKey(byte[] key) throws GeneralSecurityException {
		byte[] x = new byte[25];
		byte[] y = new byte[25];
		System.arraycopy(key, 1, x, 0, 25);
		System.arraycopy(key, 26, y, 0, 25);
		return getPublicKey(x, y);
	}
	
	public static PrivateKey getPrivateKey(byte[] s) throws GeneralSecurityException {
		AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("sect193r1"));
    	ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
		ECPrivateKeySpec keyspec = new ECPrivateKeySpec(new BigInteger(s), ecParameters);
		KeyFactory keyfactory = KeyFactory.getInstance("EC", cryptoProvider);
		return keyfactory.generatePrivate(keyspec);
	}

	public static boolean verifyCardKey(byte[] cardKey, byte[] cardSignature) throws GeneralSecurityException {
		PublicKey cardIntermediateKey = getPublicKey(CARD_INTERMEDIATE_X, CARD_INTERMEDIATE_Y);
		Signature signer = Signature.getInstance("SHA1withECDSA", cryptoProvider);
        signer.initVerify(cardIntermediateKey);
        signer.update(cardKey);
        return signer.verify(cardSignature);
	}

    public static byte[] performDH(byte[] publicKey) throws GeneralSecurityException {
    	KeyAgreement DH = KeyAgreement.getInstance("ECDH", cryptoProvider);
    	DH.init(getPrivateKey(PRIVATE_KEY_BYTES));
    	DH.doPhase(getPublicKey(publicKey), true);
    	return DH.generateSecret();
    }
    
    public static byte[] performSignature(byte[] data) throws GeneralSecurityException {
    	Signature sign = Signature.getInstance("SHA1withECDSA", cryptoProvider);
    	sign.initSign(getPrivateKey(PRIVATE_KEY_BYTES));
    	sign.update(data);
    	return sign.sign();
    }
    
    public static boolean performSignatureVerification(byte[] data, byte[] signature) throws GeneralSecurityException {

		PublicKey terminalKey = getPublicKey(PUBLIC_KEY_BYTES);
		Signature signer = Signature.getInstance("SHA1withECDSA", cryptoProvider);
        signer.initVerify(terminalKey);
        signer.update(data);
        return signer.verify(signature);
        
    }
    
    public static boolean performSignatureVerification(byte[] data, byte[] signature, byte[] OTHER_PUBLIC_KEY_BYTES) throws GeneralSecurityException {

		PublicKey otherKey = getPublicKey(OTHER_PUBLIC_KEY_BYTES);
		System.out.println("debug1");
		Signature signer = Signature.getInstance("SHA1withECDSA", cryptoProvider);
        signer.initVerify(otherKey);
        System.out.println("debug2");
        signer.update(data);
        System.out.println("debug3");
        return signer.verify(signature);
        
    }
    
}
