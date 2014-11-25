package ru.hwsec.teamara;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ECC {

	static {
        Security.addProvider(new BouncyCastleProvider());
        cryptoProvider = new BouncyCastleProvider();
    }

	private static Provider cryptoProvider;

	private static byte[] CARD_INTERMEDIATE_X = new byte[]{
        (byte)0x00, (byte)0x7f, (byte)0x43, (byte)0x93, (byte)0x44, (byte)0xac, (byte)0x58, (byte)0x0f, (byte)0xd7, (byte)0x9c, (byte)0x62, (byte)0xf0, (byte)0xb6, (byte)0xab, (byte)0x19, (byte)0x97,
        (byte)0x12, (byte)0x49, (byte)0x7a, (byte)0x7a, (byte)0xbd, (byte)0xf6, (byte)0x9e, (byte)0x76, (byte)0xb7
	};

	private static byte[] CARD_INTERMEDIATE_Y = new byte[]{
        (byte)0x00, (byte)0x7d, (byte)0x84, (byte)0x2e, (byte)0x25, (byte)0x6a, (byte)0xcd, (byte)0x7d, (byte)0x56, (byte)0x96, (byte)0x67, (byte)0x2e, (byte)0x0b, (byte)0x89, (byte)0x7f, (byte)0x9b,
        (byte)0x75, (byte)0x11, (byte)0xae, (byte)0xfb, (byte)0x93, (byte)0x0f, (byte)0x71, (byte)0x41, (byte)0x65
	};

	public static boolean verifyCardKey(byte[] cardKey, byte[] cardSignature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException, InvalidParameterSpecException {
		ECPoint cardIntermediatePoint = new ECPoint(
				new BigInteger(CARD_INTERMEDIATE_X),
				new BigInteger(CARD_INTERMEDIATE_Y)
		);
		AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("sect193r1"));
        ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
		ECPublicKeySpec keyspec = new ECPublicKeySpec(cardIntermediatePoint, ecParameters);
		KeyFactory keyfactory = KeyFactory.getInstance("EC", cryptoProvider);
		PublicKey cardIntermediateKey = keyfactory.generatePublic(keyspec);
		Signature signer = Signature.getInstance("SHA1withECDSA", cryptoProvider);
        signer.initVerify(cardIntermediateKey);
        signer.update(cardKey);
        return signer.verify(cardSignature);
	}
}
