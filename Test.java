import com.Security.Ciphers.*;

import java.util.Arrays;

public class Test {
//    public static void main(String[] args) {
////        Cipher hc = new CesarCipher();
//        // "19"
////        char[] encrypted = hc.encrypt("swaraj is my birth right","monarchy");
////        for (int i = 1; i < 20; i++)
////            System.out.println(String.valueOf(hc.decrypt("GCUA VQ DTGCM", String.valueOf(i))));
//        Cipher hc = new HillCipher();
////        Cipher pf = new PlayFairCipher();
//        char[] ef = hc.encrypt("pay", "rrfvsvcct");
//        System.out.printf("Encrypted : %s\nDecrypted : %s\n", Arrays.toString(ef), Arrays.toString(hc.decrypt(ef, "rrfvsvcct")));
////        char[] ef = pf.encrypt("SRI SAIRAM ENGINEERING COLLEGE", "monarchy");
////        System.out.printf("Encrypted : %s\nDecrypted : %s\n", Arrays.toString(ef), Arrays.toString(pf.decrypt(ef, "monarchy")));
////        ef = pf.encrypt("swarajxisxmyxbirthxright".toCharArray(), "monarchy".toCharArray());
////        System.out.printf("Encrypted : %s\nDecrypted : %s\n", Arrays.toString(ef), Arrays.toString(pf.decrypt(ef, "monarchy")));
////        ef = pf.encrypt("semesterxresult".toCharArray(), "examination".toCharArray());
////        System.out.printf("Encrypted : %s\nDecrypted : %s\n", Arrays.toString(ef), Arrays.toString(pf.decrypt(ef, "examination")));
//    }

    public static void main(String[] args) {
        Cipher des = new Des();
        char[] encrypted = des.encrypt("123456ABCD132536", "AABB09182736CCDD");

        System.out.printf("Encrypted - %s\nDecrypted - %s",
                Arrays.toString(encrypted),
                Arrays.toString(des.decrypt(String.valueOf(encrypted), "AABB09182736CCDD"))
        );

    }
}
