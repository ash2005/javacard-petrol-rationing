package ru.hwsec.teamara;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;


public class CACertTest {

	public static void main(String[] args) throws CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, javax.security.cert.CertificateException, IOException{
		CertificateVerifier.fromPEM("a");
	}

}
