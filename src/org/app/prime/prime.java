package org.app.prime;

public class prime {
    public static boolean is_prime(long n) {
        if (n != 1 && n <= 3) return true;
        if (n % 2 == 0 || n % 3 == 0) return false;
        long s = 5;
        while (s * s <= n) {
            if (n % s == 0 || n % (s + 2L) == 0) {
                System.out.println(s+" "+(s+2L));
                return false;
            }
            s += 6;
        }
        return true;
    }

    public static void main(String[] args) {
        System.out.println(is_prime(1125899906848456441L));
    }
}
