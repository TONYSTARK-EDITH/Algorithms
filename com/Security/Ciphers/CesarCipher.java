package com.Security.Ciphers;

/**
 * <h1>Cesar Cipher</h1>
 * In cryptography, a Caesar cipher, also known as Caesar's cipher, the shift cipher, Caesar's code or Caesar shift, is
 * one of the simplest and most widely known encryption techniques. It is a type of substitution cipher in which each
 * letter in the plaintext is replaced by a letter some fixed number of positions down the alphabet. For example, with
 * a left shift of 3, D would be replaced by A, E would become B, and so on. The method is named after Julius Caesar,
 * who used it in his private correspondence
 */
public class CesarCipher implements Cipher {


    private char[] stringToEncrypt;
    private char[] encryptedString;
    private int key;

    public CesarCipher() {
    }

    CesarCipher(String string, int key) {
        this.stringToEncrypt = string.toCharArray();
        this.key = key;
    }


    /**
     * <h2>Encryption</h2>
     * Encryption is done by taking each character and mapping it to
     * the index of the character array and then adding the key to the
     * index and taking the remainder of the index when divided by 26
     * then adding the resultant character of the index in the respective
     * character array
     *
     * @param stringToEncrypt String to be encrypted
     * @param key             Key value to be used to encrypt the string
     * @return Encrypted string
     */
    @Override
    public char[] encrypt(char[] stringToEncrypt, char[] key) {
        char[] encryptedString = new char[stringToEncrypt.length];
        int newIndex;
        int Key = Integer.parseInt(String.valueOf(key));
        for (int i = 0; i < stringToEncrypt.length; i++) {
            char ele = stringToEncrypt[i];
            if (Character.isAlphabetic(ele)) {
                if (Character.isLowerCase(ele)) {
                    newIndex = (ele % 97 + Key) % 26;
                    encryptedString[i] = lowerAlphabets[newIndex];
                } else {
                    newIndex = (ele % 65 + Key) % 26;
                    encryptedString[i] = upperAlphabets[newIndex];
                }
            } else {
                encryptedString[i] = ele;
            }
        }

        return encryptedString;
    }

    /**
     * <h2>Encryption</h2>
     * Decryption is carried out by iterating over the characters and finding
     * the respective indices in their respective character arrays and then
     * subtracting the index by the key and get the respective character from
     * the respective character array.
     *
     * @param encryptedString The encrypted string to be decrypted
     * @param key             Key value to be used to decrypt the string
     * @return The Decrypted String
     */

    @Override
    public char[] decrypt(char[] encryptedString, char[] key) {
        char[] decryptedString = new char[encryptedString.length];
        int newIndex;
        int Key = Integer.parseInt(String.valueOf(key));
        for (int i = 0; i < encryptedString.length; i++) {
            char ele = encryptedString[i];
            if (Character.isAlphabetic(ele)) {
                if (Character.isLowerCase(ele)) {
                    newIndex = (ele % 97 - Key) % 26;
                    if (newIndex < 0) newIndex += 26;
                    System.out.println(newIndex);
                    decryptedString[i] = lowerAlphabets[newIndex];
                } else {
                    newIndex = (ele % 65 - Key) % 26;
                    if (newIndex < 0) newIndex += 26;
                    decryptedString[i] = upperAlphabets[newIndex];
                }
            } else {
                decryptedString[i] = ele;
            }
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
        encryptedString = encrypt(this.stringToEncrypt, ("" + key).toCharArray());
        return encryptedString;
    }

    /**
     * Decrypt for decrypting the object's string
     *
     * @return Decrpyted String
     */
    @Override
    public char[] decrypt() {
        return decrypt(encryptedString, ("" + key).toCharArray());
    }

}