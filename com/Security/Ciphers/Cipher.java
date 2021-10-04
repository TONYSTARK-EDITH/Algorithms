package com.Security.Ciphers;

public interface Cipher {
    char[] lowerAlphabets = {
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
    };

    char[] upperAlphabets = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
            'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
    };


    char[] encrypt(char[] stringToEncrypt, char[] key);

    char[] decrypt(char[] encryptedString, char[] key);

    /**
     * Encryption method polymorphism for the input strings
     *
     * @param stringToEncrypt The string datatype to encrypt
     * @param key             The string datatype key
     * @return character array of the encrypted string
     */
    default char[] encrypt(String stringToEncrypt, String key) {
        return encrypt(stringToEncrypt.toCharArray(), key.toCharArray());
    }

    /**
     * Decryption method polymorphism for the parameter Strings
     *
     * @param encryptedString The string datatype to decrypt
     * @param key             The string datatype key
     * @return character array of the decrypted string
     */
    default char[] decrypt(String encryptedString, String key) {
        return decrypt(encryptedString.toCharArray(), key.toCharArray());
    }


    /**
     * Encrypt for accessing the object's string
     *
     * @return Encrypted String
     */
    char[] encrypt();

    /**
     * Decrypt for decrypting the object's string
     *
     * @return Decrypted String
     */
    char[] decrypt();

    default char[] decrypt(char[] encryptedString, String key) {
        return decrypt(encryptedString, key.toCharArray());
    }
}
