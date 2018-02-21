import java.io.*;
import java.util.*;
import java.security.*;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;

class GenHash {
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

  // here seed is a mnemonic phrase such as generated from
  // a good-entropy random value and thne returned by BIP39,
  // see https://en.bitcoin.it/wiki/Mnemonic_phrase
  // seed_ext is "mnemonic passphrase", or seed extension.
  public static void main(String[] args) {
    if (args.length < 1) {
      System.out.println("Usage: GenHash nameOfFileWithWords [nameOfFileWithPassPhrase]");
    }
    else try {
        byte[] encoded = Files.readAllBytes(Paths.get(args[0]));
        String seed = new String(encoded, StandardCharsets.UTF_8);
        String seed_ext = "";
        if (args.length > 1) {
          seed_ext = new String(Files.readAllBytes(Paths.get(args[0])),
                                StandardCharsets.UTF_8);
        }
        generate(seed, seed_ext);
      } catch (Exception e) {
        System.err.println("Caught exception " + e.toString());
      }
  }

  public static void generate(String seed, String seed_ext) throws Exception {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = 
        digest.digest((seed + seed_ext).getBytes(StandardCharsets.UTF_8));
        
      String hashHex = toHex(hash);
      System.out.println(String.format("SHA256 hash %d bytes: %s", hash.length, hashHex));

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

    }
}
        
