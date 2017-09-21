package com.siili.token;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

import com.tozny.crypto.android.AesCbcWithIntegrity;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

public class Example1 extends AppCompatActivity {
    SecureRandom random = new SecureRandom();
    SharedPreferences sharedPreferences;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_example1);

        final EditText pin = (EditText) findViewById(R.id.editText);

        findViewById(R.id.button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                encrypt("secret token", pin.getText().toString());
            }
        });

        findViewById(R.id.button2).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                decrypt(pin.getText().toString());
            }
        });

        sharedPreferences = getSharedPreferences("DEMO", Context.MODE_PRIVATE);
    }

    private void encrypt(String s, String pinFromEdit) {
        byte[] salt = new byte[32];
        random.nextBytes(salt);

        try {
            //generate keys
            AesCbcWithIntegrity.SecretKeys keys = AesCbcWithIntegrity.generateKeyFromPassword(pinFromEdit, salt);
            //encrypt
            AesCbcWithIntegrity.CipherTextIvMac ciphered = AesCbcWithIntegrity.encrypt(s, keys);

            String saltString = new String(Base64.encode(salt, Base64.DEFAULT));

            //store ciphered and salt
            Log.d("DEMO", "ciphered= \n" + ciphered.toString());
            Log.d("DEMO", "salt= \n" + saltString);
            sharedPreferences.edit().putString("salt", saltString).apply();
            sharedPreferences.edit().putString("ciphered", ciphered.toString()).apply();
            Toast.makeText(this, "Encryption succeeded", Toast.LENGTH_SHORT).show();
        } catch (GeneralSecurityException | UnsupportedEncodingException e) {
            Toast.makeText(this, "Encryption failed", Toast.LENGTH_LONG).show();
        }
    }

    private void decrypt(String pin) {
        //read salt and ciphered text
        String saltString = sharedPreferences.getString("salt", "");
        String cipheredString = sharedPreferences.getString("ciphered", "");

        Log.d("DEMO", "loaded data:");
        Log.d("DEMO", "ciphered = \n" + cipheredString);
        Log.d("DEMO", "salt= \n" + saltString);

        AesCbcWithIntegrity.CipherTextIvMac ciphered = new AesCbcWithIntegrity.CipherTextIvMac(cipheredString);

        try {
            //generate keys
            AesCbcWithIntegrity.SecretKeys keys = AesCbcWithIntegrity.generateKeyFromPassword(pin, Base64.decode(saltString, Base64.DEFAULT));

            byte[] decrypted = AesCbcWithIntegrity.decrypt(ciphered, keys);

            String decryptedString = new String(decrypted);
            Toast.makeText(this, decryptedString, Toast.LENGTH_LONG).show();
            Log.d("DEMO", "decrypted = " + decryptedString);
        } catch (GeneralSecurityException e) {
            Toast.makeText(this, "Decryption failed", Toast.LENGTH_LONG).show();
        }
    }
}
