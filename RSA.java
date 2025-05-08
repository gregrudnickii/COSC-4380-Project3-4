import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * <h1>RSA</h1>
 * <p>This class implements a basic form of the RSA asymmetric encryption and digital signing system.</p>
 */
public class RSA {

    /**
     * <h3>p</h3>
     * <p>One of the two primes used to generate n</p>
     * <p><b>Do not leave this public</b></p>
     */
    public BigInteger p;
    // TODO: p will be initialized in the constructor.

    /**
     * <h3>q</h3>
     * <p>One of the two primes used to generate n</p>
     * <p><b>Do not leave this public</b></p>
     */
    public BigInteger q;
    // TODO: q will be initialized in the constructor.

    /**
     * <h3>phi</h3>
     * <p>The result of (p-1)(q-1)</p>
     * <p><b>Do not leave this public</b></p>
     */
    public BigInteger phi;
    // TODO: phi will be computed in the constructor.

    /**
     * <h3>n</h3>
     * <p>The result of p*q</p>
     */
    @SuppressWarnings("FieldMayBeFinal")
    private BigInteger n;

    /**
     * <h3>e</h3>
     * <p>Any number which is co-prime with n and one of two values (along with n) which make up the public key.</p>
     */
    private BigInteger e;

    /**
     * <h3>d</h3>
     * <p>The modular inverse of e and one of two values (along with n) which make up the private key.</p>
     * <p><b>Do not leave this public</b></p>
     */
    public BigInteger d;
    // TODO: d will be computed in the constructor.

    /**
     * <h3>RSA Constructor</h3>
     * <p>The constructor for the RSA class.</p>
     * <p>Accepts an int value indicating the desired bit width of the p and q parameters.</p>
     * <p>Generates random p and q, then from those derives n and phi</p>
     * @param bits The number of bits (bit width) desired for the p and q values.
     */
    public RSA(int bits) {
        // TODO: Implement RSA key generation
        SecureRandom secureRandom = new SecureRandom();
        p = BigInteger.probablePrime(bits, secureRandom);
        do {
            q = BigInteger.probablePrime(bits, secureRandom);
        } while (p.equals(q));
        n = p.multiply(q);
        phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        e = BigInteger.valueOf(65537);  // common choice for e
        while (e.compareTo(phi) >= 0 || !e.gcd(phi).equals(BigInteger.ONE)) {
            e = e.add(BigInteger.TWO);
        }
        d = e.modInverse(phi);
    }

    /**
     * <h3>getPubKey</h3>
     * <p>A simple getter method for the public key.</p>
     * @return An array of BigInteger containing e and n.
     */
    public BigInteger[] getPubKey() {
        return new BigInteger[] {e, n};
    }

    /**
     * <h3>encrypt</h3>
     * <p>Accepts a message String and a public key and returns the encrypted message.</p>
     * @param message A String containing a message (signed or in plaintext)
     * @param pubKey An array of BigInteger containing a public key [e, n].
     * @return The result of encrypting the message using the given public key.
     */
    public String encrypt(String message, BigInteger[] pubKey) {
        // TODO: Implement encryption
        BigInteger publicE = pubKey[0];
        BigInteger publicN = pubKey[1];
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        BigInteger messageInt = new BigInteger(1, messageBytes);
        if (messageInt.compareTo(publicN) >= 0) {
            throw new IllegalArgumentException("Message is too large for the given key size");
        }
        BigInteger encryptedInt = messageInt.modPow(publicE, publicN);
        return Base64.getEncoder().encodeToString(encryptedInt.toByteArray());
    }

    /**
     * <h3>decrypt</h3>
     * <p>Accepts a ciphertext and uses the private key stored in the member variables to decrypt.</p>
     * @param ciphertext A String containing an encryptedd message.
     * @return The result of decrypting the message using the private key [d, n].
     */
    public String decrypt(String ciphertext) {
        // TODO: Implement decryption
        byte[] cipherBytes = Base64.getDecoder().decode(ciphertext);
        BigInteger cipherInt = new BigInteger(1, cipherBytes);
        BigInteger decryptedInt = cipherInt.modPow(d, n);
        byte[] decryptedBytes = decryptedInt.toByteArray();
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
    
    
    
    private BigInteger hashMessage(String message) {
    try {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(message.getBytes(StandardCharsets.UTF_8));
        return new BigInteger(1, hash);
    } catch (Exception ex) {
        throw new RuntimeException("Hashing failed", ex);
    }

}

    /**
     * <h3>sign</h3>
     * <p>Accepts a message String and cryptographically signs the message using the private key stored in the member variables [d, n].</p>
     * @param message A String containing a message to be signed.
     * @return The result of encrypting the message using the private key [d, n].
     */
    public String sign(String message) {
    BigInteger hash = hashMessage(message);
    BigInteger signedInt = hash.modPow(d, n);
    return Base64.getEncoder().encodeToString(signedInt.toByteArray());
}

    /**
     * <h3>authenticate</h3>
     * <p>Accepts a signed (encrypted) message and a public key and uses the given public key to decrypt the message.</p>
     * @param message A String containing a signed message.
     * @param pubKey An array of BigInteger containing a public key [e, n].
     * @return The result of decrypting the message using the given public key.
     */
    public String authenticate(String signature, BigInteger[] pubKey) {
    BigInteger publicE = pubKey[0];
    BigInteger publicN = pubKey[1];
    byte[] signedBytes = Base64.getDecoder().decode(signature);
    BigInteger signedInt = new BigInteger(1, signedBytes);
    BigInteger recoveredHash = signedInt.modPow(publicE, publicN);
    return recoveredHash.toString(16); // Return the hash as a hex string for display
}

    public String getMessageHash(String message) {
    return hashMessage(message).toString(16);
}
    /**
     * <h3>main</h3>
     * <p><b>For testing purposes only.</b></p>
     * <p>Final submission should be a <b>safe</b> class implementation.</p>
     */
    public static void main(String[] args) {
        RSA a = new RSA(4096);
        BigInteger[] aPub = a.getPubKey();
        System.out.printf("p = %s%nq = %s%nn = %s%nphi = %s%ne = %s%nd = %s%n%n", a.p, a.q, aPub[1], a.phi, aPub[0], a.d);
        RSA b = new RSA(4096);
        BigInteger[] bPub = b.getPubKey();
        System.out.printf("p = %s%nq = %s%nn = %s%nphi = %s%ne = %s%nd = %s%n%n", b.p, b.q, bPub[1], b.phi, bPub[0], b.d);

        /**String message1 = "Hello RSA";
        System.out.printf("msg: %s%n", message1);
        String signed1 = a.sign(message1);
        System.out.printf("Signed by A ({msg}privA): %s%n", signed1);
        String cipher1 = a.encrypt(signed1, bPub);
        System.out.printf("Sent to B ({{msg}privA}pubB): %s%n", cipher1);

        String auth1 = b.decrypt(cipher1);
        System.out.printf("Received by B ({msg}privA): %s%n", auth1);
        String plain1 = b.authenticate(auth1, aPub);
        System.out.printf("Authenticated by B: %s%n", plain1);

        String message2 = "Hello RSA2";
        System.out.printf("msg: %s%n", message2);
        String cipher2 = b.encrypt(message2, aPub);
        System.out.printf("Sending to A ({msg}pubA): %s%n", cipher2);
        String signed2 = b.sign(cipher2);
        System.out.printf("Signed by B ({{msg}pubA}privB): %s%n", signed2);

        String auth2 = a.authenticate(signed2, bPub);
        System.out.printf("Authenticated by A ({msg}pubA): %s%n", auth2);
        String plain2 = a.decrypt(auth2);
        System.out.printf("Received by A: %s%n", plain2);
        */

        String message1 = "Hello RSA";
        System.out.printf("Message: %s%n", message1);

        // A signs the message
        String signature1 = a.sign(message1);
        System.out.printf("Signature (A's priv): %s%n%n", signature1);

        // A encrypts the message with B's public key
        String encryptedMessage1 = a.encrypt(message1, bPub);
        System.out.printf("Encrypted message (B's pub): %s%n%n", encryptedMessage1);

        // B decrypts the message with its private key
        String decryptedMessage1 = b.decrypt(encryptedMessage1);
        System.out.printf("Decrypted by B: %s%n", decryptedMessage1);

        // B authenticates the signature using A's public key
        String recoveredHash1 = b.authenticate(signature1, aPub);
        String expectedHash1 = b.getMessageHash(decryptedMessage1);
        System.out.printf("Signature valid? %s%n%n", expectedHash1.equals(recoveredHash1));


        System.out.println("=== B → A: Signed and Encrypted Message ===");

        String message2 = "Hello RSA2";
        System.out.printf("Message: %s%n", message2);

        // B signs the message
        String signature2 = b.sign(message2);
        System.out.printf("Signature (B's priv): %s%n%n", signature2);

        // B encrypts the message with A's public key
        String encryptedMessage2 = b.encrypt(message2, aPub);
        System.out.printf("Encrypted message (A's pub): %s%n%n", encryptedMessage2);

        // A decrypts the message with its private key
        String decryptedMessage2 = a.decrypt(encryptedMessage2);
        System.out.printf("Decrypted by A: %s%n", decryptedMessage2);

        // A authenticates the signature using B's public key
        String recoveredHash2 = a.authenticate(signature2, bPub);
        String expectedHash2 = a.getMessageHash(decryptedMessage2);
        System.out.printf("Signature valid? %s%n", expectedHash2.equals(recoveredHash2));
    }
}
