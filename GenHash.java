import java.io.*;
import java.util.*;
import java.security.*;
import java.nio.file.Paths;
import java.nio.file.Files;
import static java.nio.charset.StandardCharsets.UTF_8;
import java.math.BigInteger;
class GenHash {
  // here seed is a mnemonic phrase such as generated from
  // a good-entropy random value and thne returned by BIP39,
  // see https://en.bitcoin.it/wiki/Mnemonic_phrase
  // seed_ext is "mnemonic passphrase", or seed extension.
  public static void main(String[] args) {
    if (args.length < 1) {
      System.out.println("Usage: GenHash seed-file-or-string-with-text string-with-text");
    }
    else try {
        String seed = args[0];
        if (args[0].indexOf(" ") < 0) // maybe a file
          try (BufferedReader br = new BufferedReader(new FileReader(args[0]))) {
              seed = br.readLine();
            }
        String seed_ext = (args.length > 1) ? args[1] : "";
        generate(seed, seed_ext);
      } catch (Exception e) {
        System.err.println("Caught exception " + e.toString());
      }
  }

  public static void generate(String seed, String seed_ext) throws Exception {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest((seed + seed_ext).getBytes(UTF_8));
        
      String hashHex = toHex(hash);
      System.out.println(String.format("SHA256 hash %d bytes: %s", hash.length, hashHex));
      System.out.println(String.format("SHA256 hash base64  : %s", to64(hash)));
      System.out.println(String.format("SHA256 hash base58  : %s", to58(hash)));
      System.out.println(String.format("SHA256 hash base58_ : %s", to58_(hash)));

      // check integrity...
      for (int i = 0; i < 1000; i++) {
        byte[] h = digest.digest((seed + i).getBytes(UTF_8));
        String h16 = toHex(h); String h_to_58_from_58_16 = toHex(as58(to58(h)));
        if (!h16.equals(h_to_58_from_58_16)) {
          // System.out.println(String.format(" bad base58 functions: "));
          System.out.println("-- h16:                " + h16);
          System.out.println("-- h_to_58_from_58_16: " + h_to_58_from_58_16);
        }
      }

      SecureRandom random = new SecureRandom(hash);

      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC"); // ("DSA", "SUN");
      keyGen.initialize(256, random);
      KeyPair pair = keyGen.generateKeyPair();
      PrivateKey priv = pair.getPrivate();
      PublicKey pub = pair.getPublic();

      String privateKeyHexValue = toHex(priv.getEncoded());
      System.out.println(String.format("private key %d bytes: %s", priv.getEncoded().length, privateKeyHexValue));
      String publickKeyHexValue = toHex(pub.getEncoded());
      System.out.println(String.format("publick key %d bytes: %s", pub.getEncoded().length, publickKeyHexValue));
      System.out.println(String.format("publick key base64  : %s", to64(pub.getEncoded())));
      System.out.println(String.format("publick key base58  : %s", to58(pub.getEncoded())));

    }
  static String toHex(byte[] data) {
    StringBuilder sb = new StringBuilder();
    for (byte b: data) sb.append(String.format("%02x", b&0xff));
    return sb.toString();
  }

  static String toHexTab(byte[] data) {
    StringBuilder sb = new StringBuilder();
    int count = 0;
    for (byte b: data) { 
      if (count++ % 32 == 0) sb.append("\n");
      sb.append(String.format("%02x ", b&0xff));
    }
    return sb.toString();
  }
  static String to64(byte[] data) { return Base64.getEncoder().encodeToString(data);  }
  static final String ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"; static char A1 = ALPH.charAt(0); static BigInteger ALPH_SIZE = BigInteger.valueOf(ALPH.length());
  static String to58_(byte[] data) { // see https://github.com/nayuki/Bitcoin-Cryptography-Library/blob/master/java/io/nayuki/bitcoin/crypto/Base58Check.java
    StringBuilder sb = new StringBuilder();
    for (BigInteger quotrem[], num = new BigInteger(1, data); num.signum() != 0; num = quotrem[0])
      sb.append(ALPH.charAt((quotrem = num.divideAndRemainder(ALPH_SIZE))[1].intValue()));
    return sb.reverse().toString();
  }
  static String to58(byte[] data) { // see https://github.com/nayuki/Bitcoin-Cryptography-Library/blob/master/java/io/nayuki/bitcoin/crypto/Base58Check.java
    StringBuilder sb = new StringBuilder();
    for (BigInteger quotrem[], num = new BigInteger(1, data); num.signum() != 0; num = quotrem[0])
      sb.append(ALPH.charAt((quotrem = num.divideAndRemainder(ALPH_SIZE))[1].intValue()));
    // Add '1' characters for leading 0-value bytes
    for (int i = 0; i < data.length && data[i] == 0; i++) sb.append(A1);
    return sb.reverse().toString();
  }
  static byte[] as58(String s) throws IOException { // seehttps://github.com/nayuki/Bitcoin-Cryptography-Library/blob/master/java/io/nayuki/bitcoin/crypto/Base58Check.java
    BigInteger num = BigInteger.ZERO;
    for (int d, i = 0; i < s.length(); i++, num = (num.multiply(ALPH_SIZE)).add(BigInteger.valueOf(d))) {
      d = ALPH.indexOf(s.charAt(i));
      if (d == -1) throw new IllegalArgumentException("Invalid character for Base58Check");
    }
    // Strip possible leading zero due to mandatory sign bit
    byte[] b = num.toByteArray();  if (b[0] == 0) b = Arrays.copyOfRange(b, 1, b.length);
    // Convert leading '1' characters to leading 0-value bytes
    ByteArrayOutputStream buf = new ByteArrayOutputStream();
    for (int i = 0; i < s.length() && s.charAt(i) == A1; i++) buf.write(0);
    buf.write(b);
    return buf.toByteArray();
  }
}
        
