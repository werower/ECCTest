package eu.topsquad;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ECCTest {
	private static short IV_LENGTH = 16;
	private static short VI_BASE64_LENGTH = (short) (Math.ceil((double) (IV_LENGTH * 8) / 24) * 4);

	private static char[] keyStorePassword = "password".toCharArray();
	private static char[] keyEntryPassword = keyStorePassword;
	private static String keyAlias = "S2PrivateKey";
	private static String keyStoreName = "s2ckeystore.ks";

	private static KeyPairGenerator kpg;
	private static Cipher cipher;
	private static KeyStore ks;

	public static void main(String args[]) throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		initializeKeyPairGenerator();
		initializeCipher();

		ks = loadKeyStore();
		
		String plainText = "Look mah, I'm a message!";
		System.out.println("Original plaintext message: " + plainText);

		KeyPair keyPairLocal = loadKeysFromKeyStore();
	
		if (keyPairLocal == null) {
			keyPairLocal = generateECKeys();
			saveKeysToKeyStore(keyPairLocal);
		}

		exportPublicKey(keyPairLocal.getPublic());

		PublicKey remotePublicKey = loadRemotePublicKey(
				"MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE6rqe7lvKLG03RT6vFbA20eXJfNPz2uVM70jzajraop0TJVf/2HyZ+js+0e5EtCjd8Sh+2W0LweFr+6yHVaueJ0uWZoqCISkbqPoP3ozcur7wf7Ms9ami36n2B3Pstjmy");

		SecretKey secretKeyLocal = deriveSecretKey(keyPairLocal.getPrivate(), remotePublicKey);
		System.out.println("secretKeyLocal: " + secretKeyLocal.getAlgorithm() + " format: " + secretKeyLocal.getFormat()
				+ " ENcoded: " + base64Encode(secretKeyLocal.getEncoded()));

		encryptUsingSecretLocal(plainText, secretKeyLocal);
		
		String ivAndCipherTextAsBase64 = "MSwA/CujkvErhOpHlB6r/g==f8dmHL4ZLoP7GWcM+H8kX9KLZ5YZ4Gw2/ZOISbWZZuotmXTRsPS6FzY=";
		decryptUsingRemotePublicKey(secretKeyLocal, ivAndCipherTextAsBase64);
	}


	private static void encryptUsingSecretLocal(String plainText, SecretKey secretKeyLocal) throws Exception {
		byte[] iv = new SecureRandom().generateSeed(IV_LENGTH);
		String cipherText = encryptString(secretKeyLocal, iv, plainText);
		String ivBase64 = base64Encode(iv);
		System.out.println("Encrypted cipher text: " + ivBase64 + cipherText);
	}


	private static String exportPublicKey(PublicKey publicKey) {
		String format = publicKey.getFormat();
		byte[] en = publicKey.getEncoded();

		System.out.println("Public Key Format: " + format);
		System.out.println("Copy to remote app Publick Key Base64: " + base64Encode(en));

		return base64Encode(en);
	}

	private static PublicKey loadRemotePublicKey(String base64EncodedPublicKey) throws Exception {
		PublicKey publicKey = KeyFactory.getInstance("EC", "SunEC")
				.generatePublic(new X509EncodedKeySpec(base64Decode(base64EncodedPublicKey)));
		return publicKey;
	}

	public static void initializeKeyPairGenerator() {
		try {
			kpg = KeyPairGenerator.getInstance("EC", "SunEC");
			ECGenParameterSpec ecsp = new ECGenParameterSpec("secp384r1");
			kpg.initialize(ecsp);
		} catch (Exception e) {
			e.printStackTrace();
			e.printStackTrace();
		}
	}

	public static void initializeCipher() throws Exception {
		cipher = Cipher.getInstance("AES/GCM/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
	}

	public static KeyPair generateECKeys() {
		KeyPair kpU = kpg.genKeyPair();
		PrivateKey privKeyU = kpU.getPrivate();
		PublicKey pubKeyU = kpU.getPublic();
		System.out.println("User priv: " + privKeyU.toString());
		System.out.println("User pub: " + pubKeyU.toString());
		return kpU;
	}

	private static SecretKey deriveSecretKey(PrivateKey privateKey, PublicKey publicKey) throws Exception {
		KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME);
		keyAgreement.init(privateKey);
		keyAgreement.doPhase(publicKey, true);

		SecretKey key = keyAgreement.generateSecret("AES");
		System.out.println("Shared key length: " + key.getEncoded().length);
		return key;
	}

	public static String encryptString(SecretKey key, byte[] iv, String plainText) throws Exception {
		IvParameterSpec ivSpec = new IvParameterSpec(iv);

		byte[] plainTextBytes = plainText.getBytes("UTF-8");
		byte[] cipherText;

		cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
		cipherText = new byte[cipher.getOutputSize(plainTextBytes.length)];

		int encryptLength = cipher.update(plainTextBytes, 0, plainTextBytes.length, cipherText, 0);
		encryptLength += cipher.doFinal(cipherText, encryptLength);

		return base64Encode(cipherText);
	}

	public static String decryptString(SecretKey key, byte[] iv, String cipherText) throws Exception {
		Key decryptionKey = new SecretKeySpec(key.getEncoded(), key.getAlgorithm());
		IvParameterSpec ivSpec = new IvParameterSpec(iv);

		byte[] cipherTextBytes = base64Decode(cipherText);
		byte[] plainText;

		cipher.init(Cipher.DECRYPT_MODE, decryptionKey, ivSpec);
		plainText = new byte[cipher.getOutputSize(cipherTextBytes.length)];
		int decryptLength = cipher.update(cipherTextBytes, 0, cipherTextBytes.length, plainText, 0);
		decryptLength += cipher.doFinal(plainText, decryptLength);

		return new String(plainText, "UTF-8");
	}

	public static String bytesToHex(byte[] data, int length) {
		String digits = "0123456789ABCDEF";
		StringBuffer buffer = new StringBuffer();

		for (int i = 0; i != length; i++) {
			int v = data[i] & 0xff;

			buffer.append(digits.charAt(v >> 4));
			buffer.append(digits.charAt(v & 0xf));
		}

		return buffer.toString();
	}

	public static String base64Encode(byte[] data) {
		return Base64.getEncoder().encodeToString(data);
	}

	public static byte[] base64Decode(String encodedText) {
		return Base64.getDecoder().decode(encodedText);
	}

	public static KeyStore loadKeyStore() throws Exception {
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		File file = new File(keyStoreName);
		if (file.exists()) {
			try (InputStream keyStoreStream = new FileInputStream(file)) {
				ks.load(keyStoreStream, keyStorePassword);
				return ks;
			}
		}
		return createKeyStore();
	}

	public static KeyStore createKeyStore() throws Exception {
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(null, keyStorePassword);
		return ks;
	}

	public static void saveKeysToKeyStore(KeyPair keyPair) throws Exception {
		Certificate[] selfCert = SelfSignedCertificateGenerator.getCerts(keyPair);

		PrivateKey privateKey = keyPair.getPrivate();
		ks.setKeyEntry(keyAlias, privateKey, keyEntryPassword, selfCert);

		try (OutputStream keyStoreOut = new FileOutputStream(keyStoreName)) {
			ks.store(keyStoreOut, keyStorePassword);
		}
	}

	public static KeyPair loadKeysFromKeyStore() throws Exception {
		Key key = ks.getKey(keyAlias, keyEntryPassword);
		if (key instanceof PrivateKey) {
			Certificate cert = ks.getCertificate(keyAlias);
			PublicKey publicKey = cert.getPublicKey();
			return new KeyPair(publicKey, (PrivateKey) key);
		}
		return null;
	}
	

	private static void decryptUsingRemotePublicKey(SecretKey secretKeyLocal, String ivAndCipherTextAsBase64) throws Exception {
		try {
		String ivAsBase64 = ivAndCipherTextAsBase64.substring(0, VI_BASE64_LENGTH);
		byte[] remoteIv = base64Decode(ivAsBase64);
		String cipherText = ivAndCipherTextAsBase64.substring(VI_BASE64_LENGTH);
		String decryptedPlainText = decryptString(secretKeyLocal, remoteIv, cipherText);
		System.out.println("Decrypted cipher text: " + decryptedPlainText);
		}catch(javax.crypto.AEADBadTagException e) {
			System.out.println("Exception while decrypting. Please check if remote public key and ciphertext was generated correctly using: "
					+ "Public key from this appication, private key of remote applciation.");
			throw e;
		}
	}
	
	
}
