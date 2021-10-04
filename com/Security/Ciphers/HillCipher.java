package com.Security.Ciphers;

import java.util.Arrays;

public class HillCipher implements Cipher {

    private char[] stringToEncrypt;
    private char[] key;
    private char[] encryptedString;
    private int[][] indexMatrix;
    private int[][] inverseIndexMatrix;
    private int[] indexArray = null;

    public HillCipher() {
    }


    HillCipher(String string, String key) throws Exception {
        if (string.length() * string.length() != key.length()) {
            throw new Exception("Key should be of length n*n");
        }
        stringToEncrypt = string.toCharArray();
        this.key = key.toCharArray();
    }

    private void generateIndexMatrix(char[] stringToEncrypt, char[] key, int length) {
        indexMatrix = new int[length][length];
        indexArray = new int[length];

        int keyIndex = 0;

        for (int row = 0; row < length; row++) {
            char ele = stringToEncrypt[row];
            if (Character.isLowerCase(ele)) {
                indexArray[row] = ele % 97;
            } else {
                indexArray[row] = ele % 65;
            }
            for (int col = 0; col < length; col++) {
                ele = key[keyIndex++];
                if (Character.isLowerCase(ele)) {
                    indexMatrix[row][col] = ele % 97;
                } else {
                    indexMatrix[row][col] = ele % 65;
                }
            }
        }
    }

    private void getCofactor(int[][] A, int[][] temp, int p, int q, int n) {
        int i = 0, j = 0;
        for (int row = 0; row < n; row++) {
            for (int col = 0; col < n; col++) {
                if (row != p && col != q) {
                    temp[i][j++] = A[row][col];
                    if (j == n - 1) {
                        j = 0;
                        i++;
                    }
                }
            }
        }
    }

    private int inverseDeterminant(int[][] A, int n, int length) {
        int D = 0;

        if (n == 1)
            return A[0][0];

        int[][] temp = new int[length][length];

        int sign = 1;

        for (int f = 0; f < n; f++) {
            getCofactor(A, temp, 0, f, n);
            D += sign * A[0][f] * inverseDeterminant(temp, n - 1, length);

            sign = -sign;
        }
        return D;
    }

    private void adjointOfMatrix(int[][] A, int[][] adj, int length) {
        if (length == 1) {
            adj[0][0] = 1;
            return;
        }
        int sign;
        int[][] temp = new int[length][length];
        for (int i = 0; i < length; i++) {
            for (int j = 0; j < length; j++) {
                getCofactor(A, temp, i, j, length);
                sign = ((i + j) % 2 == 0) ? 1 : -1;
                adj[j][i] = (sign) * (inverseDeterminant(temp, length - 1, length));
            }
        }
    }


    private void inverseMatrix(int length, int det) {
        inverseIndexMatrix = new int[length][length];
        adjointOfMatrix(indexMatrix, inverseIndexMatrix, length);
        for (int i = 0; i < length; i++) {
            for (int j = 0; j < length; j++) {
                if (inverseIndexMatrix[i][j] < 0) {
                    int t = Math.abs(inverseIndexMatrix[i][j]);
                    int s = t / 26 + 1;
                    inverseIndexMatrix[i][j] = 26 * s - t;
                }
                inverseIndexMatrix[i][j] = (inverseIndexMatrix[i][j] * det) % 26;
            }
        }
    }

    @Override
    public char[] encrypt(char[] stringToEncrypt, char[] key) {
        int length = stringToEncrypt.length;
        char[] encryptedString = new char[length];
        if (stringToEncrypt.length * stringToEncrypt.length != key.length) {
            try {
                throw new Exception("Key should be of length n*n");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        generateIndexMatrix(stringToEncrypt, key, length);
//        Arrays.deepToString(indexMatrix);
        for (int[] i : indexMatrix) System.out.println(Arrays.toString(i));

        for (int row = 0; row < length; row++) {
            int sum = 0;
            for (int col = 0; col < length; col++) {
                sum += indexMatrix[row][col] * indexArray[col];
            }
            System.out.println(sum%26);
            encryptedString[row] = lowerAlphabets[sum % 26];
        }

        return encryptedString;
    }

    @Override
    public char[] decrypt(char[] encryptedString, char[] key) {
        int length = encryptedString.length;
        char[] decryptedString = new char[length];
        generateIndexMatrix(encryptedString, key, length);
        for (int[] i : indexMatrix) System.out.println(Arrays.toString(i));
        int inverseDeterminant = Math.abs(inverseDeterminant(indexMatrix, length, length));
        for (int i = 1; i < 1000000; i++) {
            if ((inverseDeterminant * i) % 26 == 1) {
                inverseDeterminant = i;
                break;
            }
        }
        inverseMatrix(length, inverseDeterminant);
        for (int row = 0; row < length; row++) {
            int sum = 0;
            for (int col = 0; col < length; col++) {
                sum += inverseIndexMatrix[row][col] * indexArray[col];
            }
            decryptedString[row] = lowerAlphabets[sum % 26];
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
