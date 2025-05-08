import java.io.File;
import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;

/**
 * <h1>Crypto</h1>
 * <p>This class is a collection of methods for use in the other libraries contained in this project (DHE, RSA, and AES).</p>
 * <p>It uses relatively secure methods for generating large random values and tests for primality.</p>
 * <p>It provides mathematical functions for performing fast modular exponentiation and finding primitive roots and modular inverses.</p>
 */
public class Crypto {

    /**
     * <h3>fastMod</h3>
     * <p>Improved implementation of the fast modular exponentiation algorithm using BigInteger. This version correctly updates intermediate results.</p>
     * @param g The base
     * @param a The exponent
     * @param p The modulus
     * @return The result of g^a mod p
     */
    public static BigInteger fastMod(BigInteger g, BigInteger a, BigInteger p) {
        BigInteger result = BigInteger.ONE;
        // Convert the exponent to its binary representation
        String binaryExp = a.toString(2);
        for (int i = 0; i < binaryExp.length(); i++) {
            // Square the current result for every bit.
            result = result.multiply(result).mod(p);
            // If the current bit is 1, multiply by the base.
            if (binaryExp.charAt(i) == '1') {
                result = result.multiply(g).mod(p);
            }
        }
        return result;
    }

    /**
     * <h3>isValidG</h3>
     * <p>Tests candidate generator values (primitive root mod p) for DHE.</p>
     * <p>In order to be a valid generator, g must satisfy the conditions g^2 mod p != 1 and g^q mod p != 1 for p = 2q+1.</p>
     * @param g The candidate generator.
     * @param p The prime modulus.
     * @return True if g is a valid primitive root mod p, false otherwise.
     */
    public static boolean isValidG(BigInteger g, BigInteger p) {
        BigInteger q = p.subtract(BigInteger.ONE).divide(BigInteger.TWO);
        if (g.modPow(BigInteger.TWO, p).equals(BigInteger.ONE)) {
            return false;
        }
        return !g.modPow(q, p).equals(BigInteger.ONE);
    }

    /**
     * <h3>getGenerator</h3>
     * <p>Accepts a target bit width and a prime modulus, and checks candidate generator values starting at a random initial value until it finds a valid primitive root mod p.</p>
     * @param bits The target bit width for the generator candidate.
     * @param p The prime modulus.
     * @return A valid generator (primitive root) for the modulus.
     */
    public static BigInteger getGenerator(int bits, BigInteger p) {
        // Create a secure random instance
        SecureRandom random = new SecureRandom();
        // Generate an initial candidate for g with the given bit width.
        BigInteger g = new BigInteger(bits, random);
        // Ensure g is at least 2 (primitive roots must be greater than 1)
        if (g.compareTo(BigInteger.TWO) < 0) {
            g = BigInteger.TWO;
        }
        // Iterate until a valid generator is found or the candidate exceeds p
        while (g.compareTo(p) < 0) {
            if (isValidG(g, p)) {
                return g;
            }
            g = g.add(BigInteger.ONE);
        }
        return null; // In theory, for a safe prime, this should never happen.
    }

    /**
     * <h3>getRandom</h3>
     * <p>Securely generates a random BigInteger such that the value is only expressable with a number of bits in the range (minBits, maxBits).</p>
     * @param minBits The minimum size (bit width).
     * @param maxBits The maximum size.
     * @return A random BigInteger satisfying the requirements.
     */
    public static BigInteger getRandom(int minBits, int maxBits) {
        BigInteger result = new BigInteger(maxBits, Rand.getRand());
        while (result.bitLength() <= minBits) {
            result = new BigInteger(maxBits, Rand.getRand());
        }
        return result;
    }

    /**
     * <h3>checkPrime</h3>
     * <p>Checks a number for primality using trial division, Fermat's little theorem, and the Miller-Rabin test.</p>
     * @param p The candidate prime number.
     * @param numChecks The number of iterations of testing to perform.
     * @return True if the number is likely prime, false otherwise.
     */
    @SuppressWarnings({"CallToPrintStackTrace", "ConvertToTryWithResources"})
    public static boolean checkPrime(BigInteger p, int numChecks) {
        // Trial Division
        boolean isPrime = true;
        try {
            Scanner scan = new Scanner(new File("primes.txt"));
            while(scan.hasNext()) {
                BigInteger b = new BigInteger(scan.nextLine());
                if (p.mod(b).equals(BigInteger.ZERO)) {
                    isPrime = false;
                    break;
                }
            }
            scan.close();
        } catch (FileNotFoundException fnfEx) {
            fnfEx.printStackTrace();
        }
        if (!isPrime) {
            return false;
        }

        // Fermat's Little Theorem
        BigInteger pm = p.subtract(BigInteger.ONE);
        for (int i = 0; i < numChecks; i++) {
            BigInteger a = getRandom(1, p.bitLength() - 1);
            if (!fastMod(a, pm, p).equals(BigInteger.ONE)) {
                return false;
            }
        }

        // Miller-Rabin Test
        BigInteger s = BigInteger.ZERO;
        BigInteger d = pm;
        while (d.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
            s = s.add(BigInteger.ONE);
            d = d.shiftRight(1);
        }
        for (int i = 0; i < numChecks; i++) {
            BigInteger a = getRandom(1, p.bitLength() - 1);
            BigInteger x = fastMod(a, d, p);
            for (BigInteger j = BigInteger.ZERO; !j.equals(s); j = j.add(BigInteger.ONE)) {
                x = x.multiply(x).mod(p);
                if (x.equals(BigInteger.ONE) && !x.equals(BigInteger.ONE) && !x.equals(pm)) {
                    return false;
                }
            }
            if (!x.equals(BigInteger.ONE)) {
                return false;
            }
        }
        return isPrime;
    }

    /**
     * <h3>getPrime</h3>
     * <p>Generates random numbers and checks them against checkPrime() until one passes the tests.</p>
     * @param minBits The minimum bit width.
     * @param maxBits The maximum bit width.
     * @param numChecks The number of iterations for primality checking.
     * @return A likely prime number.
     */
    public static BigInteger getPrime(int minBits, int maxBits, int numChecks) {
        int i = 0;
        BigInteger p = getRandom(minBits, maxBits);
        while (!checkPrime(p, numChecks)) {
            i += 1;
            p = getRandom(minBits, maxBits);
        }
        System.out.printf("Checked %d numbers for primality%n", i);
        return p;
    }

    /**
     * <h3>getSafePrime</h3>
     * <p>Generates and checks prime numbers for use in DHE. A "safe" prime is defined as p = 2q+1, where q is also prime.</p>
     * @return A safe prime number.
     */
    public static BigInteger getSafePrime() {
        while (true) {
            BigInteger q = getPrime(2048, 3072, 10);
            BigInteger p = q.multiply(BigInteger.TWO).add(BigInteger.ONE);
            if (checkPrime(p, 10)) {
                return p;
            }
        }
    }

    /**
     * <h3>gcd</h3>
     * <p>Finds the greatest common divisor of two numbers using the Euclidean Algorithm.</p>
     * @param a First number.
     * @param b Second number.
     * @return The gcd of a and b.
     */
    public static BigInteger gcd(BigInteger a, BigInteger b) {
        if (b.equals(BigInteger.ZERO)) {
            return a;
        }
        return gcd(b, a.mod(b));
    }

    /**
     * <h3>extendedGCD</h3>
     * <p>Calculates the extended Euclidean algorithm, which returns  satisfying the relation: ax + by = gcd(a, b).</p>
     * @param a First number.
     * @param b Second number.
     * @return An array containing [gcd(a, b), x, y].
     */
    public static BigInteger[] extendedGCD(BigInteger a, BigInteger b) {
        if (b.equals(BigInteger.ZERO)) {
            return new BigInteger[]{a, BigInteger.ONE, BigInteger.ZERO};
        }
        BigInteger[] values = extendedGCD(b, a.mod(b));
        BigInteger gcd = values[0];
        BigInteger x1 = values[1];
        BigInteger y1 = values[2];
        BigInteger y = x1.subtract(a.divide(b).multiply(y1));
        System.out.printf("gcd = %s, a  = %s, b  = %s%n", gcd, y1, y);
        return new BigInteger[]{gcd, y1, y};
    }

    /**
     * <h3>modularInverse</h3>
     * <p>Computes the modular inverse (private key) of an RSA public key given e and phi.</p>
     * @param e The public exponent.
     * @param phi Euler's totient function value.
     * @return The modular inverse of e modulo phi.
     */
    public static BigInteger modularInverse(BigInteger e, BigInteger phi) {
        BigInteger[] result = extendedGCD(e, phi);
        BigInteger gcd = result[0];
        BigInteger x = result[1];
        if (!gcd.equals(BigInteger.ONE)) {
            throw new ArithmeticException("Inverse does not exist");
        }
        return x.mod(phi);
    }

    /**
     * <h3>main</h3>
     * <p>For testing purposes.</p>
     */
    public static void main(String[] args) {
        extendedGCD(new BigInteger("65537"), new BigInteger("3120"));
    }
}
