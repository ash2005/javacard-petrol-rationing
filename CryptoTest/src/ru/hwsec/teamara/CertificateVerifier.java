package ru.hwsec.teamara;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.sun.xml.internal.messaging.saaj.util.ByteInputStream;

public class CertificateVerifier {
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	private static final String ROOT_CA_CERT = 
		"-----BEGIN CERTIFICATE-----\r\n" +
		"MIIBzDCCAZagAwIBAgIJANuHCuydv32EMAoGCCqGSM49BAMCMGgxCzAJBgNVBAYT\r\n" +
		"Ak5MMRYwFAYDVQQIDA1Ob29yZC1CcmFiYW50MRIwEAYDVQQHDAlFaW5kaG92ZW4x\r\n" +
		"DTALBgNVBAoMBFRVL2UxDDAKBgNVBAsMA0lTVDEQMA4GA1UEAwwHVGVhbUFSQTAe\r\n" +
		"Fw0xNDA5MTUxNjUxMjlaFw0yNDA5MTIxNjUxMjlaMGgxCzAJBgNVBAYTAk5MMRYw\r\n" +
		"FAYDVQQIDA1Ob29yZC1CcmFiYW50MRIwEAYDVQQHDAlFaW5kaG92ZW4xDTALBgNV\r\n" +
		"BAoMBFRVL2UxDDAKBgNVBAsMA0lTVDEQMA4GA1UEAwwHVGVhbUFSQTAyMBAGByqG\r\n" +
		"SM49AgEGBSuBBAAGAx4ABAs9PdS9740rFrXZ7s5ECTDb5EHOud4svb96DuyjUDBO\r\n" +
		"MB0GA1UdDgQWBBR54mqVSGxLLVHGxCHkRtx79J8DvTAfBgNVHSMEGDAWgBR54mqV\r\n" +
		"SGxLLVHGxCHkRtx79J8DvTAMBgNVHRMEBTADAQH/MAoGCCqGSM49BAMCAyQAMCEC\r\n" +
		"DhzpvUHksFCX9PPPe7EIAg8A0QqeijQWxBJeklg1Gnk=\r\n" +
		"-----END CERTIFICATE-----";
	
	private static final String ROOT_CA_PRIV_KEY =
		"-----BEGIN EC PARAMETERS-----\r\n" +
		"BgUrgQQABg==\r\n" +
		"-----END EC PARAMETERS-----\r\n" +
		"-----BEGIN EC PRIVATE KEY-----\r\n" +
		"MD4CAQEEDoN3ZlvLbQg+823dQ0x+oAcGBSuBBAAGoSADHgAECz091L3vjSsWtdnu\r\n" +
		"zkQJMNvkQc653iy9v3oO7A==\r\n" +
		"-----END EC PRIVATE KEY-----\r\n";
	
	private static final String ROOT_CA_PUB_KEY = 
		//"-----BEGIN PUBLIC KEY-----\r\n" +
		"MDIwEAYHKoZIzj0CAQYFK4EEAAYDHgAECz091L3vjSsWtdnuzkQJMNvkQc653iy9\r\n" +
		"v3oO7A==\r\n";// +
		//"-----END PUBLIC KEY-----";
	
	private static final String CARD0_CERT = 
		"-----BEGIN CERTIFICATE-----\r\n" +
		"MIIBXzCCASkCAQEwCgYIKoZIzj0EAwIwaDELMAkGA1UEBhMCTkwxFjAUBgNVBAgM\r\n" +
		"DU5vb3JkLUJyYWJhbnQxEjAQBgNVBAcMCUVpbmRob3ZlbjENMAsGA1UECgwEVFUv\r\n" +
		"ZTEMMAoGA1UECwwDSVNUMRAwDgYDVQQDDAdUZWFtQVJBMB4XDTE0MDkxNTE2NTMw\r\n" +
		"M1oXDTE1MDkxNTE2NTMwM1owWjELMAkGA1UEBhMCTkwxFjAUBgNVBAgMDU5vb3Jk\r\n" +
		"LUJyYWJhbnQxDTALBgNVBAoMBFRVL2UxDDAKBgNVBAsMA0lTVDEWMBQGA1UEAwwN\r\n" +
		"VGVhbUFSQS1jYXJkMDAyMBAGByqGSM49AgEGBSuBBAAGAx4ABE3m7+lVUI3Hiw+O\r\n" +
		"+oA0gfprey+19JhcVXIwvycwCgYIKoZIzj0EAwIDJAAwIQIPAMRqW0dM4bQr803b\r\n" +
		"a0j1Ag5jwHd+Um43NS4z6yrEww==\r\n" +
		"-----END CERTIFICATE-----";


	
	public static boolean verifyCert(String cert) {
		return true;
	}
	
	public static void fromPEM(String pemCert) throws javax.security.cert.CertificateException, CertificateException, NoSuchProviderException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		CertificateFactory cf = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
		X509Certificate cert = (X509Certificate)cf.generateCertificate(new ByteInputStream(CARD0_CERT.getBytes(), CARD0_CERT.getBytes().length));
		
		byte[] keyBytes = new sun.misc.BASE64Decoder().decodeBuffer(ROOT_CA_PUB_KEY);
		X509EncodedKeySpec keyspec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyfactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        PublicKey pk = keyfactory.generatePublic(keyspec);
        
        try {
			cert.verify(pk, "BC");
			System.out.println("yes");
		} catch (InvalidKeyException e) {
			System.out.println("fuck");
		} catch (SignatureException e) {
			System.out.println("fuck");
		}
	}
}