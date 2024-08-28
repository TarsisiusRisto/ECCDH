package skripsijava;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;

public class ECC {
    private BigInteger a;
    private BigInteger b;
    private BigInteger p; // Prime number for finite field
    private Point g; // Base point
    private BigInteger n; // Order of the base point
    private final SecureRandom random = new SecureRandom();

    public ECC() {
        generateRandomCurve();
    }

    private void generateRandomCurve() {
        do {
            p = BigInteger.probablePrime(128, random); // Generate a random 128-bit prime number
            a = new BigInteger(p.bitLength(), random).mod(p);
            b = new BigInteger(p.bitLength(), random).mod(p);
        } while (a.pow(3).multiply(BigInteger.valueOf(4)).add(b.pow(2).multiply(BigInteger.valueOf(27))).mod(p).equals(BigInteger.ZERO));

        BigInteger x;
        BigInteger y;
        do {
            x = new BigInteger(p.bitLength(), random).mod(p);
            y = new BigInteger(p.bitLength(), random).mod(p);
        } while (!isOnCurve(x, y));
        g = new Point(x, y);
        n = p; // Simplification for this example; in practice, n should be determined based on the curve
    }

    private boolean isOnCurve(BigInteger x, BigInteger y) {
        return y.pow(2).mod(p).equals(x.pow(3).add(a.multiply(x)).add(b).mod(p));
    }

    public class Point {
        public BigInteger x;
        public BigInteger y;

        public Point(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
        }

        public boolean isAtInfinity() {
            return x == null && y == null;
        }

        @Override
        public String toString() {
            return isAtInfinity() ? "Infinity" : "(" + x + ", " + y + ")";
        }
    }

    public Point addPoints(Point p1, Point p2) {
        if (p1.isAtInfinity()) return p2;
        if (p2.isAtInfinity()) return p1;

        BigInteger lambda;
        if (p1.x.equals(p2.x)) {
            if (!p1.y.equals(p2.y)) return new Point(null, null); // Infinity
            // Point doubling
            lambda = p1.x.pow(2).multiply(BigInteger.valueOf(3)).add(a).multiply(p1.y.multiply(BigInteger.valueOf(2)).modInverse(p)).mod(p);
        } else {
            // Point addition
            lambda = p2.y.subtract(p1.y).multiply(p2.x.subtract(p1.x).modInverse(p)).mod(p);
        }

        BigInteger x3 = lambda.pow(2).subtract(p1.x).subtract(p2.x).mod(p);
        BigInteger y3 = lambda.multiply(p1.x.subtract(x3)).subtract(p1.y).mod(p);
        return new Point(x3, y3);
    }

    public Point multiplyPoint(BigInteger k, Point p) {
        Point result = new Point(null, null); // Infinity
        Point addend = p;

        while (k.compareTo(BigInteger.ZERO) > 0) {
            if (k.and(BigInteger.ONE).equals(BigInteger.ONE)) {
                result = addPoints(result, addend);
            }
            addend = addPoints(addend, addend);
            k = k.shiftRight(1);
        }

        return result;
    }

    public Point[] encrypt(Point publicKey, Point message) {
        BigInteger k = new BigInteger(n.bitLength(), random).mod(n);
        Point kG = multiplyPoint(k, g);
        Point kY = multiplyPoint(k, publicKey);
        Point encryptedMessage = addPoints(message, kY);
        return new Point[]{kG, encryptedMessage}; // Return kG and encrypted message
    }

    public Point decrypt(BigInteger privateKey, Point kG, Point encryptedMessage) {
        Point kY = multiplyPoint(privateKey, kG);
        Point decryptedMessage = addPoints(encryptedMessage, new Point(kY.x, kY.y.negate().mod(p)));
        return decryptedMessage;
    }

    public static void main(String[] args) {
        ECC ecc = new ECC();

        BigInteger privateKey = new BigInteger(ecc.n.bitLength(), ecc.random).mod(ecc.n);
        Point publicKey = ecc.multiplyPoint(privateKey, ecc.g);

        try (Scanner scanner = new Scanner(System.in)) {
            System.out.print("Enter message to encrypt: ");
            String messageStr = scanner.nextLine();
            
            BigInteger messageInt = new BigInteger(messageStr.getBytes());
            Point message = ecc.new Point(messageInt, BigInteger.ZERO); // Simple conversion, assumes y = 0

            Point[] encryptedMessage = ecc.encrypt(publicKey, message);

            System.out.println("Curve parameters:");
            System.out.println("a: " + ecc.a);
            System.out.println("b: " + ecc.b);
            System.out.println("p: " + ecc.p);
            System.out.println("g: " + ecc.g);
            System.out.println("n: " + ecc.n);

            System.out.println("\nEncrypted Message: kG = " + encryptedMessage[0] + ", encryptedMessage = " + encryptedMessage[1]);

            Point decryptedMessage = ecc.decrypt(privateKey, encryptedMessage[0], encryptedMessage[1]);
            String decryptedMessageStr = new String(decryptedMessage.x.toByteArray());
            System.out.println("Decrypted Message: " + decryptedMessageStr);
        }
    }
}
