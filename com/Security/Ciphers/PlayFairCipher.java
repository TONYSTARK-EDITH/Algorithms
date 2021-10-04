package com.Security.Ciphers;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * <h1>Play Fair Cipher</h1>
 * The Playfair cipher or Playfair square or Wheatstone–Playfair cipher is a manual symmetric encryption technique and
 * was the first literal digram substitution cipher. The scheme was invented in 1854 by Charles Wheatstone, but bears
 * the name of Lord Playfair for promoting its use.
 * <p>
 * The technique encrypts pairs of letters (bigrams or digrams), instead of single letters as in the simple substitution
 * cipher and rather more complex Vigenère cipher systems then in use. The Playfair is thus significantly harder to
 * break since the frequency analysis used for simple substitution ciphers does not work with it. The frequency analysis
 * of bigrams is possible, but considerably more difficult. With 600[1] possible bigrams rather than the 26 possible
 * monograms (single symbols, usually letters in this context), a considerably larger cipher text is required in order
 * to be useful.
 */
public class PlayFairCipher implements Cipher {

    private char[] stringToEncrypt;
    private char[] key;
    private char[] encryptedString;

    public PlayFairCipher() {
    }

    PlayFairCipher(String string, String key) {
        this.stringToEncrypt = string.toCharArray();
        this.key = key.toCharArray();
    }

    private final char[][] cipherMatrix = new char[5][5];
    private char[][] digramWords;
    private int row, col;

    /**
     * The key square is a 5×5 grid of alphabets that acts as the key for encrypting the plaintext.
     * Each of the 25 alphabets must be unique and one letter of the alphabet (usually J) is omitted from the table
     * (as the table can hold only 25 alphabets). If the plaintext contains J, then it is replaced by I.
     * The initial alphabets in the key square are the unique alphabets of the key in the order
     * in which they appear followed by the remaining letters of the alphabet in order.
     *
     * @param key A set of the string key
     */
    private void generateCipherMatrix(Set<Character> key) {
        int row = 0, col = 0;
        for (char i : key) {
            cipherMatrix[row][col++] = i;
            if (col >= 5) {
                col = 0;
                row++;
            }
        }
        for (int i = col; i < 5; i++) {
            for (char j : lowerAlphabets) {
                if (j != 'j' && !key.contains(j)) {
                    cipherMatrix[row][i] = j;
                    key.add(j);
                    break;
                }
            }
        }
        for (int i = row + 1; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                for (char k : lowerAlphabets) {
                    if (k != 'j' && !key.contains(k)) {
                        cipherMatrix[i][j] = k;
                        key.add(k);
                        break;
                    }
                }
            }
        }
    }

    private void fillString(char[] stringToEncrypt) {
        for (int i = 0; i < stringToEncrypt.length; i++) {
            if (stringToEncrypt[i] == ' ') stringToEncrypt[i] = 'x';
            if (Character.isUpperCase(stringToEncrypt[i]))
                stringToEncrypt[i] = Character.toLowerCase(stringToEncrypt[i]);
        }
    }

    /**
     * This method will split the words to two characters in order to map
     * with the 5x5 matrix we have generated .
     * Rules :
     * If two elements are same then "x" will be added
     * If the length of the string is odd then the last element will be added with "z"
     * If the character "j" is in the string then it will be replaced to "i"
     *
     * @param string String to be split into two parts
     */
    private int splitWordsToPairs(char[] string) {
        int lengthh = 0;
        digramWords = new char[string.length][2];
        int length = string.length, n = 0;
        for (int i = 0; i < length; i++) {
            if (i + 1 < length) {
                if (string[i] != string[i + 1]) {
                    digramWords[n][0] = string[i];
                    digramWords[n++][1] = string[i + 1];
                    lengthh++;
                    i++;
                } else {
                    digramWords[n][0] = string[i];
                    digramWords[n++][1] = 'x';
                    lengthh++;
                }
            } else {
                digramWords[n][0] = string[i];
                digramWords[n++][1] = 'z';
                lengthh++;
            }
        }
        System.out.println(Arrays.deepToString(digramWords));
        return lengthh;
    }

    /**
     * It gets the row and col of the character in the 5x5 matrix
     *
     * @param key The character on which we get the row index and the col index
     */
    private void indexOf(char key) {
        if (key == 'j') key = 'i';
        for (int row = 0; row < 5; row++) {
            for (int col = 0; col < 5; col++) {
                if (cipherMatrix[row][col] == key) {
                    this.row = row;
                    this.col = col;
                    return;
                }
            }
        }
    }


    /**
     * <h2>Encryption</h2>
     * This will encrypt the given string using play fair cipher algorithm <br>
     * <b>Rules:</b>
     * <ol>
     *     <li>
     *         If both the letters are in the same column:
     *         Take the letter below each one
     *         (going back to the top if at the bottom).
     *     </li>
     *     <li>
     *         If both the letters are in the same row:
     *         Take the letter to the right of each one
     *         (going back to the leftmost if at the rightmost position).
     *     </li>
     *     <li>
     *         If neither of the above rules is true:
     *         Form a rectangle with the two letters and take
     *         the letters on the horizontal opposite corner of the rectangle.
     *     </li>
     *
     * </ol>
     *
     * @param stringToEncrypt String to be encrypted
     * @param key             key value to be used to encrypt the string
     * @return char[]  The encrypted string
     */

    @Override
    public char[] encrypt(char[] stringToEncrypt, char[] key) {
        fillString(stringToEncrypt);
        Set<Character> keySet = new LinkedHashSet<>();
        for (char c : key) {
            if (c != 'j' || c != 'J')
                keySet.add(Character.toLowerCase(c));
            else keySet.add('i');
        }
        generateCipherMatrix(keySet);
        for (char[] i : cipherMatrix) System.out.println(Arrays.toString(i));
        int length = splitWordsToPairs(stringToEncrypt);
        char[] encryptedString = new char[length * 2];
        int n = 0;
        for (int i = 0; i < length; i++) {
            if (digramWords[i] == null) break;
            int frow, fcol, erow, ecol;
            indexOf(digramWords[i][0]);
            frow = this.row;
            fcol = this.col;
            indexOf(digramWords[i][1]);
            erow = this.row;
            ecol = this.col;
            if (fcol == ecol) {
                frow = frow < 4 ? frow + 1 : 0;
                erow = erow < 4 ? erow + 1 : 0;
                encryptedString[n] = cipherMatrix[frow][fcol];
                encryptedString[n + 1] = cipherMatrix[erow][ecol];
            } else if (frow == erow) {
                fcol = fcol < 4 ? fcol + 1 : 0;
                ecol = ecol < 4 ? ecol + 1 : 0;
                encryptedString[n] = cipherMatrix[frow][fcol];
                encryptedString[n + 1] = cipherMatrix[erow][ecol];
            } else {
                encryptedString[n] = cipherMatrix[frow][ecol];
                encryptedString[n + 1] = cipherMatrix[erow][fcol];
            }
            n += 2;

        }
        return encryptedString;
    }

    /**
     * <h2>Decryption</h2>
     * The Decryption process takes places based on the following rules
     * <ol>
     *     <li>
     *         If both the letters are in the same column:
     *         Take the letter above each one
     *         (going back to the bottom if at the top).
     *     </li>
     *     <li>
     *         If both the letters are in the same row:
     *         Take the letter to the left of each one
     *         (going back to the rightmost if at the leftmost position).
     *     </li>
     *     <li>
     *         If neither of the above rules is true:
     *         Form a rectangle with the two letters and
     *         take the letters on the horizontal opposite corner of the rectangle.
     *     </li>
     * </ol>
     *
     * @param encryptedString String to be decrypted
     * @param key             key value to be used to decrypt the string
     * @return Decrypted String
     */
    @Override
    public char[] decrypt(char[] encryptedString, char[] key) {

        Set<Character> keySet = new LinkedHashSet<>();
        for (char c : key) {
            if (c != 'j' || c != 'J')
                keySet.add(Character.toLowerCase(c));
            else keySet.add('i');
        }
        generateCipherMatrix(keySet);
        int length = splitWordsToPairs(encryptedString);
        char[] decryptedString = new char[length * 2];
        int n = 0;
        for (int i = 0; i < length; i++) {
            if (digramWords[i] == null) break;
            int frow, fcol, erow, ecol;
            indexOf(digramWords[i][0]);
            frow = this.row;
            fcol = this.col;
            indexOf(digramWords[i][1]);
            erow = this.row;
            ecol = this.col;
            if (fcol == ecol) {
                frow = frow > 0 ? frow - 1 : 4;
                erow = erow > 0 ? erow - 1 : 4;
                decryptedString[n] = cipherMatrix[frow][fcol];
                decryptedString[n + 1] = cipherMatrix[erow][ecol];
            } else if (frow == erow) {
                fcol = fcol > 0 ? fcol - 1 : 4;
                ecol = ecol > 0 ? ecol - 1 : 4;
                decryptedString[n] = cipherMatrix[frow][fcol];
                decryptedString[n + 1] = cipherMatrix[erow][ecol];
            } else {
                decryptedString[n] = cipherMatrix[frow][ecol];
                decryptedString[n + 1] = cipherMatrix[erow][fcol];
            }
            n += 2;
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
