package com.siili.token;

import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.security.keystore.UserNotAuthenticatedException;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Toast;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Arrays;

import javax.crypto.SecretKey;

public class Example2 extends AppCompatActivity {

    private byte[] secret = {1,2,3,4};

    private int ENCRYPT_REQ = 101;
    private int DECRYPT_REQ = 102;
    SharedPreferences sharedPreferences;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_example2);

        findViewById(R.id.button1).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                tryEncrypt();
            }
        });

        findViewById(R.id.button2).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                tryDecrypt();
            }
        });

        findViewById(R.id.button3).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                getKey();
            }
        });

        sharedPreferences = getSharedPreferences("DEMO", Context.MODE_PRIVATE);
    }



    private void tryEncrypt() {

            try {
                KeyStoreWrapper.Ciphered encrypted = KeyStoreWrapper.encrypt(secret, "SOME_ALIAS");

                String encoded = new String(Base64.encode(encrypted.value, Base64.DEFAULT));
                String iv = new String(Base64.encode(encrypted.iv, Base64.DEFAULT));
                Log.d("DEMO", "encrypted = \n"+ encoded);

                sharedPreferences.edit()
                        .putString("KEYSTORE_ENCRYPTED_DATA", encoded)
                        .putString("KEYSTORE_ENCRYPTED_IV", iv)
                        .apply();

                Toast.makeText(this, "SUCCESS", Toast.LENGTH_LONG).show();

            } catch (UserNotAuthenticatedException e) {
                Log.d("DEMO", "user not authenticated");
                showLockScreen(ENCRYPT_REQ);
            } catch (GeneralSecurityException e) {
                //todo: remove printstacktrace
                e.printStackTrace();
                Toast.makeText(this, "encryption error", Toast.LENGTH_LONG).show();
            }

    }

    private void tryDecrypt(){

        byte[] data = Base64.decode(sharedPreferences.getString("KEYSTORE_ENCRYPTED_DATA", ""), Base64.DEFAULT);
        byte[] iv = Base64.decode(sharedPreferences.getString("KEYSTORE_ENCRYPTED_IV", ""), Base64.DEFAULT);
        try{
            byte[] decrypted = KeyStoreWrapper.decrypt(new KeyStoreWrapper.Ciphered(data,iv), "SOME_ALIAS");
            Toast.makeText(this, Arrays.toString(decrypted), Toast.LENGTH_LONG).show();

        } catch (UserNotAuthenticatedException e) {
            showLockScreen(DECRYPT_REQ);
        } catch (GeneralSecurityException e) {
            //todo: remove printstacktrace
            e.printStackTrace();
            Toast.makeText(this, "decryption error", Toast.LENGTH_LONG).show();
        }
    }

    private void showLockScreen(int reqCode) {
        KeyguardManager manager = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);
        Intent intent = manager.createConfirmDeviceCredentialIntent(null, null);
        if (intent != null) {
            startActivityForResult(intent, reqCode);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == ENCRYPT_REQ && resultCode == RESULT_OK) {
            tryEncrypt();
        }

        if (requestCode == DECRYPT_REQ && resultCode == RESULT_OK){
            tryDecrypt();
        }
    }

    private void getKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            KeyStore.Entry entry = keyStore.getEntry("SOME_ALIAS", null);
            SecretKey key =  key = ((KeyStore.SecretKeyEntry) entry ).getSecretKey();
            Log.d("DEMO", "encoded key = ["+ Arrays.toString(key.getEncoded()) +"]" );
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException | UnrecoverableEntryException e) {
            e.printStackTrace();
        }
    }
}
