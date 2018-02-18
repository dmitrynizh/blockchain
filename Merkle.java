

import java.io.*;
import java.util.*;
import java.security.*;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;

// Merkle for Dimitry's simple mining engine
class Merkle {
  static int difficulty = 1, zerobytes = 0, half = 0;
  static long nonce = 0; // this one is 64bit to prevent inf looping in absence of new data
  static String block_content;

  public static void main(String[] args) {
    if (args.length < 1) {
      System.out.println("Usage: Merkle file-with-transactions");
    } else // go ahead, mine!
      try {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        FileReader fileReader = new FileReader(args[0]);
        BufferedReader bufferedReader = new BufferedReader(fileReader);
        List<String> lines = new ArrayList<String>();
        String line = null;
        while ((line = bufferedReader.readLine()) != null) { 
          line = line.trim();
          if (line.length() > 0) lines.add(line);
        }
        bufferedReader.close();
        String[] txn_arr = lines.toArray(new String[lines.size()]);

        // just root
        byte[] root_hash = md.digest((txn_arr[0]).getBytes(StandardCharsets.UTF_8));
        for (int i = 1; i < txn_arr.length; i++) {
          byte[] hash = md.digest((txn_arr[i]).getBytes(StandardCharsets.UTF_8));
          byte[] two  = new byte[root_hash.length + hash.length];
          System.arraycopy(root_hash, 0, two, 0, root_hash.length);
          System.arraycopy(hash, 0, two, root_hash.length, hash.length);
          root_hash = md.digest(two);
          System.out.println("-- root_hash: " + toHex(root_hash));
        }
        System.out.println("-- root_hash: " + toHex(root_hash));
      } catch (Exception e) {
        System.err.println("Caught exception " + e.toString());
      }
  }
  static String toHex(byte[] data) {
    StringBuilder sb = new StringBuilder();
    for (byte b: data) sb.append(String.format("%02x", b&0xff));
    return sb.toString();
  }

}
