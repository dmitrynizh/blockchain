import java.io.*; import java.util.*; import java.security.*; import java.security.spec.*;
import java.nio.charset.StandardCharsets; import java.math.BigInteger;
// see https://bitzuma.com/posts/six-things-bitcoin-users-should-know-about-private-keys/
// EC:    https://stackoverflow.com/questions/11339788/tutorial-of-ecdsa-algorithm-to-sign-a-string
public class GenSig {
  public static void main(String[] args) {
    if (args.length < 1) System.out.println("Usage: GenSig nameOfFileToSign [privkey]");
    else try { // ECDSA - see https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm
        PrivateKey priv = null;
        if (args.length < 2) { /* Generate a new private/public ECDSA key pair */
          KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC"); // ("DSA", "SUN");
          SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
          keyGen.initialize(256, random);  // (1024, random);
          KeyPair pair = keyGen.generateKeyPair();
          priv = pair.getPrivate();
          PublicKey pub = pair.getPublic();
          String privateKeyHexValue = toHex(priv.getEncoded());
          System.out.println("-- privateKeyHexValue: " + privateKeyHexValue + " alg:" + priv.getFormat());
          String private64 = to64(priv.getEncoded());
          System.out.println("-- private64: " + private64);
          String private58 = to58(priv.getEncoded());
          System.out.println("-- private58: " + private58);
          String pubKeyHexValue = toHex(pub.getEncoded());
          System.out.println("-- pubKeyHexValue: " + pubKeyHexValue);
          String pubKey64 = to64(pub.getEncoded());
          System.out.println("-- pubKey64: " + pubKey64);
          String pubKey58 = to58(pub.getEncoded());
          System.out.println("-- pubKey58: " + pubKey58);
          /* Save new keys into files */
          try (PrintWriter out = new PrintWriter("new_sk.txt")) { out.println(privateKeyHexValue); }
          try (PrintWriter out = new PrintWriter("new_sk.64"))  { out.println(private64); }
          try (PrintWriter out = new PrintWriter("new_sk.58"))  { out.println(private58); }
          try (PrintWriter out = new PrintWriter("new_pk.txt")) { out.println(pubKeyHexValue); }
          try (PrintWriter out = new PrintWriter("new_pk.64"))  { out.println(pubKey64); }
          try (PrintWriter out = new PrintWriter("new_pk.58"))  { out.println(pubKey58); }
        } else try (BufferedReader br = new BufferedReader(new FileReader(args[1]))) {
              // see https://stackoverflow.com/questions/19353748/how-to-convert-byte-array-to-privatekey-or-publickey-type
              String val = br.readLine();
              byte[] sk = args[1].endsWith(".64") ? base64StringtoBytes(val) : hexStringToBytes(val);
              System.out.println("-- sk: " + toHex(sk));
              KeyFactory kf = KeyFactory.getInstance("EC");
              priv = kf.generatePrivate(new PKCS8EncodedKeySpec(sk));
              String privateKeyHexValue = toHex(priv.getEncoded());
            }
        /* Create a Signature object and initialize it with the private key */
        Signature s = Signature.getInstance("SHA256withECDSA"); // ("SHA1withDSA"); 
        s.initSign(priv);
        /* Update and sign the data */
        try (BufferedInputStream bufin = new BufferedInputStream(new FileInputStream(args[0]))) {
            for (byte[] buffer = new byte[1024]; bufin.available() != 0;)
              s.update(buffer, 0, bufin.read(buffer));
          }
        /* generate signature */
        byte[] sig = s.sign();
        String sigHex = toHex(sig);
        System.out.println("-- sigHex: " + sigHex);
        String sig64 = to64(sig);
        System.out.println("-- sig64: " + sig64);
        /* Save the signature in a file */
        // raw: try (FileOutputStream sigfos = new FileOutputStream("sig") {sigfos.write(sig);}
        try (PrintWriter out = new PrintWriter("new_sig.txt")) { out.println(sigHex); } // hex
        try (PrintWriter out = new PrintWriter("new_sig.64")) { out.println(sig64); } // 64
      } catch (Exception e) {
        System.err.println("Caught exception " + e.toString());
      }
  }
  static String toHex(byte[] data) {
    StringBuilder sb = new StringBuilder();
    for (byte b: data) sb.append(String.format("%02x", b&0xff));
    return sb.toString();
  }
  static String to64(byte[] data) { return Base64.getEncoder().encodeToString(data);  }
  static final String ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"; static final BigInteger ALPHABET_SIZE = BigInteger.valueOf(ALPHABET.length());
  static String to58(byte[] data) { // see https://github.com/nayuki/Bitcoin-Cryptography-Library/blob/master/java/io/nayuki/bitcoin/crypto/Base58Check.java
    StringBuilder sb = new StringBuilder();
    for (BigInteger quotrem[], num = new BigInteger(1, data); num.signum() != 0; num = quotrem[0])
      sb.append(ALPHABET.charAt((quotrem = num.divideAndRemainder(ALPHABET_SIZE))[1].intValue()));
    // Add '1' characters for leading 0-value bytes
    for (int i = 0; i < data.length && data[i] == 0; i++) sb.append(ALPHABET.charAt(0));
    return sb.reverse().toString();
  }
  static byte[] hexStringToBytes(String s) { // from stackoverflow
    int len = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2)
      data[i / 2] = (byte)((Character.digit(s.charAt(i), 16) << 4)
                           + Character.digit(s.charAt(i+1), 16));
    return data;
  }
  static byte[] base64StringtoBytes(String s) { // from stackoverflow
    return Base64.getDecoder().decode(s.getBytes(StandardCharsets.UTF_8));
  }
}
