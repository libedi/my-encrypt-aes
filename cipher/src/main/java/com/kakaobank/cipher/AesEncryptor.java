package com.kakaobank.cipher;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.Charsets;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

/**
 * AES-128 / CBC mode Cipher Util class
 * @author 박상준
 *
 */
public class AesEncryptor {
	private static final String CRYPTO_ALGORITHM = "AES/CBC/PKCS5Padding";
	private static final String CRYPTO_TYPE = "AES";
	private static final Charset CHARSET = Charsets.UTF_8;
	private static final int KEY_SIZE = 128;

	private static final String DEFAULT_SECRET_KEY = "1ad6f2us8dl3fh8e";
	private static final String IV = "2d9587b0c1d37a6e";
	
	private static volatile AesEncryptor instance;
	
	public static AesEncryptor getInstance() {
		if(instance == null){
			synchronized(AesEncryptor.class) {
				if(instance == null) {
					instance = new AesEncryptor();
				}
			}
		}
		return instance;
	}
	
	/**
	 * Generate random SecretKey Object
	 * @return SecretKey
	 * @throws NoSuchAlgorithmException
	 */
	public SecretKey generateSecretKey() throws NoSuchAlgorithmException {
		KeyGenerator generator = KeyGenerator.getInstance(CRYPTO_TYPE);
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		generator.init(KEY_SIZE, random);
		return generator.generateKey();
	}
	
	/**
	 * Get SecretKey Object by encoded-secretKey String
	 * @param encodedKeyString Hex-encoded key String
	 * @return SecretKey
	 * @throws DecoderException
	 */
	public SecretKey getSecretKey(String encodedKeyString) throws DecoderException {
		return getSecretKey(Hex.decodeHex(encodedKeyString.toCharArray()));
	}
	
	/**
	 * Get SecretKey Object
	 * @param keyByte
	 * @return SecretKey
	 */
	private SecretKey getSecretKey(byte[] keyByte) {
		return new SecretKeySpec(keyByte, CRYPTO_TYPE);
	}
	
	/**
	 * Get Default SecretKey Object
	 * @return SecretKey
	 * @throws UnsupportedEncodingException
	 */
	private SecretKey getDefaultSecretKey() throws UnsupportedEncodingException {
		return getSecretKey(DEFAULT_SECRET_KEY.getBytes(CHARSET));
	}
	
	/**
	 * Get SecretKey String
	 * @param secretKey
	 * @return encoded-secretKey String
	 */
	public static String getSecretKeyString(SecretKey secretKey) {
		return Hex.encodeHexString(secretKey.getEncoded());
	}
	
	/**
	 * Encode plainText using default SecretKey
	 * @param text plainText
	 * @return encoded-base64 text
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws UnsupportedEncodingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public String encode(String text) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, 
			InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException, 
			BadPaddingException {
		
		return encode(text, getDefaultSecretKey());
	}
	
	/**
	 * Encode plainText using random SecretKey
	 * @param text plainText
	 * @param secretKey
	 * @return encoded-base64 text
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws UnsupportedEncodingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public String encode(String text, SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, 
			InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException, 
			IllegalBlockSizeException, BadPaddingException {
		
		if(text == null || secretKey == null) {
			throw new IllegalArgumentException("Argument must be not null.");
		}
		Cipher cipher = Cipher.getInstance(CRYPTO_ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(IV.getBytes(CHARSET)));
		return Base64.encodeBase64String(cipher.doFinal(text.getBytes(CHARSET)));
	}
	
	/**
	 * Decode encoded-base64 text using default SecretKey
	 * @param encodedBase64Text
	 * @return decoded text
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws UnsupportedEncodingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public String decode(String encodedBase64Text) throws InvalidKeyException, NoSuchAlgorithmException, 
			NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException, 
			IllegalBlockSizeException, BadPaddingException {
		
		return decode(encodedBase64Text, getDefaultSecretKey());
	}
	
	/**
	 * Decode encoded-base64 text using random SecretKey
	 * @param encodedBase64Text
	 * @param secretKey
	 * @return decoded text
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws UnsupportedEncodingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public String decode(String encodedBase64Text, SecretKey secretKey) throws NoSuchAlgorithmException, 
			NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, 
			UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
		
		if(encodedBase64Text == null || secretKey == null) {
			throw new IllegalArgumentException("Argument must be not null.");
		}
		Cipher cipher = Cipher.getInstance(CRYPTO_ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(IV.getBytes(CHARSET)));
		return new String(cipher.doFinal(Base64.decodeBase64(encodedBase64Text.getBytes(CHARSET))), CHARSET);
	}
}
