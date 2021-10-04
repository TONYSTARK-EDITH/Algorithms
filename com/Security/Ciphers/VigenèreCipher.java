package com.Security.Ciphers;

/**
 * <h1>VigenèreCipher</h1>
 * Vigenère Cipher is a method of encrypting alphabetic text. It uses a simple form of polyalphabetic substitution.
 * A polyalphabetic cipher is any cipher based on substitution, using multiple substitution alphabets .
 * The encryption of the original text is done using the Vigenère square or Vigenère table.
 */
public class VigenèreCipher implements Cipher {

    private char[] stringToEncrypt;
    private char[] encryptedString;
    private char[] key;

    public VigenèreCipher() {
    }

    VigenèreCipher(String string, String key) {
        this.stringToEncrypt = string.toCharArray();
        this.key = key.toCharArray();
    }


    /**
     * The key will be repeated until the length of the key is equal to the
     * plain string which is to be encrypted
     *
     * @param length The length of the string to be encrypted
     * @param key    The key which is used to encrypt the string
     * @return The key with the length of the string
     */
    private char[] generateKey(int length, char[] key) {
        char[] extendedKey = new char[length];
        int ix = 0;
        for (int i = 0; i < length; i++) {
            extendedKey[i] = key[ix++];
            if (ix >= key.length) ix = 0;
        }
        return extendedKey;
    }

    /**
     * It returns the index of the character based on the character in
     * the alphabet table
     *
     * @param i Character where it needs to get the index of the alphabets
     * @return index of the character
     */
    private int indexOfAlphabets(char i) {
        if (Character.isLowerCase(i)) {
            return i % 97;
        }
        return i % 65;
    }


    /**
     * <h2>Encryption</h2>
     *
     * @param stringToEncrypt string to be encrypted
     * @param key             key which is used to encrypt the string
     * @return The encrypted string
     */
    @Override
    public char[] encrypt(char[] stringToEncrypt, char[] key) {
        char[] encryptedString = new char[stringToEncrypt.length];
        char[] extendedKey = generateKey(stringToEncrypt.length, key);
        System.out.println(String.valueOf(extendedKey));
        for (int i = 0; i < stringToEncrypt.length; i++) {
            System.out.println((indexOfAlphabets(stringToEncrypt[i]) + indexOfAlphabets(extendedKey[i])));
            encryptedString[i] = lowerAlphabets[(indexOfAlphabets(stringToEncrypt[i]) + indexOfAlphabets(extendedKey[i])) % 26];
        }
        return encryptedString;
    }

    /**
     * <h2>Decryption</h2>
     *
     * @param encryptedString The encrypted string that need to decrypted
     * @param key             The key which is used to decrypt the string
     * @return The decrypted string
     */
    @Override
    public char[] decrypt(char[] encryptedString, char[] key) {
        char[] decryptedString = new char[encryptedString.length];
        char[] extendedKey;
        if (encryptedString.length != key.length) {
            extendedKey = generateKey(encryptedString.length, key);
        } else {
            extendedKey = key;
        }
        for (int i = 0; i < encryptedString.length; i++) {
            decryptedString[i] = lowerAlphabets[(indexOfAlphabets(encryptedString[i]) -
                    indexOfAlphabets(extendedKey[i]) + 26) % 26];
        }
        return decryptedString;
    }

    /**
     * Encrypt for accessing the object's string
     *
     * @return Encrypted String
     */
    @Override
    public char[] encrypt() {
        encryptedString = encrypt(stringToEncrypt, key);
        return encryptedString;
    }

    /**
     * Decrypt for decrypting the object's string
     *
     * @return Decrypted String
     */
    @Override
    public char[] decrypt() {
        return decrypt(encryptedString, key);
    }



}
