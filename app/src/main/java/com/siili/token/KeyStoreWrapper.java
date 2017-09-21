package com.siili.token;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import static java.lang.String.format;

/**
 * Created by Pawel Bochenski on 15.05.2017.
 */
@RequiresApi(api = 23)
public class KeyStoreWrapper {

    static class Ciphered{
        public byte[] value;
        public byte[] iv;

        public Ciphered(byte[] value, byte[] iv) {
            this.value = value;
            this.iv = iv;
        }
    }

    private final static String ANDROID_KEY_STORE = "AndroidKeyStore";


    public static Ciphered encrypt(byte[] toEncrypt, String alias) throws GeneralSecurityException {
            return  doTransformation(Cipher.ENCRYPT_MODE, toEncrypt, null, alias);
    }

    public static byte[] decrypt(Ciphered toDecrypt, String alias) throws GeneralSecurityException {
            return doTransformation(Cipher.DECRYPT_MODE, toDecrypt.value, toDecrypt.iv, alias).value;
    }

    private static Ciphered doTransformation(int cipherMode, byte[] input, byte[] iv, String keyAlias) throws GeneralSecurityException{
        try {
            SecretKey key = getKey(keyAlias);
            Cipher cipher = Cipher.getInstance(format("%s/%s/%s",
                    KeyProperties.KEY_ALGORITHM_AES,
                    KeyProperties.BLOCK_MODE_GCM,
                    KeyProperties.ENCRYPTION_PADDING_NONE));

            if(iv != null){
                GCMParameterSpec ivParameterSpec = new GCMParameterSpec(128,iv);
                cipher.init(cipherMode, key, ivParameterSpec);
            } else  {
                cipher.init(cipherMode, key);
            }
            return new Ciphered(cipher.doFinal(input), cipher.getIV());
        } catch (IOException e) {
            throw new GeneralSecurityException();
        }
    }

    private static SecretKey getKey(String alias) throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        keyStore.load(null);

        KeyStore.Entry entry = keyStore.getEntry(alias, null);
        SecretKey key;
        if(entry == null){
            key = generateSecretKeyApi23(alias);
        } else  {
            key = ((KeyStore.SecretKeyEntry) entry ).getSecretKey();
        }
        return key;
    }

    private static SecretKey generateSecretKeyApi23(String alias) throws GeneralSecurityException {
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);
        KeyGenParameterSpec keySpec = builder
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationValidityDurationSeconds(5)
                .build();
        KeyGenerator kg = KeyGenerator.getInstance("AES", ANDROID_KEY_STORE);
        kg.init(keySpec);
        return kg.generateKey();
    }
}
