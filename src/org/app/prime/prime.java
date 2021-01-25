package org.app.prime;

public class prime {
    public static boolean is_prime(long n) {
        /* 
            * This method checks a number whether it is prime or not 
            * n --> long 
            * base conditions 
                * if n is less than or equal to 3 and not equal to 1 then it returns true
                * if n is divided by either 2 or 3 then it returns false
            * Iterative Conditions
                * initialise a long variable as 5 
                * 5 is our iterations initial value
                * in while loop the condition should be the square of the init variable should be less than or equal to the n
                * Iteration stops when the n is divided by either init or init+2 
                * The iteration is incremented by 6 each times
        */

        /*
            * This algorithm is based on the mathematical expressions of prime number ie. every prime number can be expressed as 6n±1
            * except 2 and 3
        */
        if (n != 1 && n <= 3) return true;
        if (n % 2 == 0 || n % 3 == 0) return false;
        long init = 5;
        while (init * init <= n) {
            if (n % init == 0 || n % (init + 2L) == 0) {
                System.out.println(init+" "+(init+2L));
                return false;
            }
            init += 6;
        }
        return true;
    }

    public static void main(String[] args) {
        System.out.println(is_prime(1125899906848456441L));
    }
}
