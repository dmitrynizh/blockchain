import java.io.*; import java.util.*; import java.security.*; import java.security.spec.*;
import java.nio.charset.StandardCharsets; import java.math.BigInteger;
class VerSig {
  public static void main(String[] args) {
    if (args.length != 3) System.out.println("Usage: VerSig publickeyfile signaturefile datafile");
    else try {
        /* get encoded public key */
        byte[] pk = null, sigToVerify  = null;
        try (BufferedReader br = new BufferedReader(new FileReader(args[0]))) {
              // see https://stackoverflow.com/questions/19353748/how-to-convert-byte-array-to-privatekey-or-publickey-type
            String val = br.readLine();
            pk = args[0].endsWith(".64") ? base64StringtoBytes(val) : hexStringToBytes(val);
            System.out.println("-- pk: " + toHex(pk));
          }
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pk);
        KeyFactory keyFactory = KeyFactory.getInstance("EC"); // ("DSA", "SUN");
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

        /* input the signature bytes */
        try (BufferedReader br = new BufferedReader(new FileReader(args[1]))) {
            String val = br.readLine();
            sigToVerify = args[1].endsWith(".64") ? base64StringtoBytes(val) : hexStringToBytes(val);
            System.out.println("-- sigToVerify: " + toHex(sigToVerify));
          }

        /* create a Signature object and initialize it with the public key */
        Signature sig = Signature.getInstance("SHA256withECDSA"); //   ("SHA1withDSA", "SUN");
        sig.initVerify(pubKey);

        /* Update and verify the data */
        FileInputStream datafis = new FileInputStream(args[2]);
        BufferedInputStream bufin = new BufferedInputStream(datafis);
        byte[] buffer = new byte[1024];
        int len;
        while (bufin.available() != 0) {
          len = bufin.read(buffer);
          sig.update(buffer, 0, len);
        }
        bufin.close();

        boolean verifies = sig.verify(sigToVerify);
        System.out.println("signature verifies: " + verifies);
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


