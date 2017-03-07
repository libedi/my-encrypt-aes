package com.kakaobank.cipher;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import javax.crypto.SecretKey;

import org.junit.Before;
import org.junit.Test;

public class TestAesCipher {
	private AES128Cipher cipher;
	
	@Before
	public void setUp() throws Exception {
		this.cipher = AES128Cipher.getInstance();
		assertNotNull(cipher);
	}
	
	@Test
	public void testCipherByDefaultSK() throws Exception {
		String text = "Test String";
		String encodedText = this.cipher.encode(text);
		System.out.println("ENCODED TEXT by DEFAULT SK : " + encodedText);
		String decodeText = this.cipher.decode(encodedText);
		System.out.println("DECODED TEXT by DEFAULT SK  : "+ decodeText);
		assertEquals(text, decodeText);
	}
	
	@Test
	public void testCipher() throws Exception {
		String text = "Test String";
		SecretKey sk = this.cipher.generateSecretKey();
		String key = AES128Cipher.getSecretKeyString(sk);
		String encodedText = this.cipher.encode(text, this.cipher.getSecretKey(key));
		System.out.println("ENCODED TEXT by RANDOM SK : " + encodedText);
		String decodeText = this.cipher.decode(encodedText, sk);
		System.out.println("DECODED TEXT by RANDOM SK : " + decodeText);
		assertEquals(text, decodeText);
	}
}
