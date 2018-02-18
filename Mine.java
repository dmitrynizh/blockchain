// Dmitry's simple mining engine. 
//
// V2.0 16 feb 2017
//
// This variant is based on Merkle hashes and as the result the hash
// rate is independent of number of transactions. Overall mining speed
// can be slowed down by big Merkle trees, but only slightly so.
//
//  todo: save Merkle tree, autoadjust get_data frequency, integrate with hex txn formats
//        print out or save new block header
// maybe: add time to hash

import java.io.*;
import java.util.*;
import java.security.*;
import java.nio.charset.StandardCharsets;
class Mine {
  static int difficulty = 1, zerobytes, half, nonce, nonce_idx; static long start;
  static byte[] block_content, prev_header, root_hash;
  static MessageDigest md;   static String txns[]; 
  public static void main(String[] args) {
    if (args.length < 3) {
      System.out.println("Usage: Mine difficulty prev_block all_new_transactions");
    } else // go ahead, mine!
      try {
        md = MessageDigest.getInstance("SHA-256");
        get_data(args);                
        for (;nonce < Integer.MAX_VALUE; nonce++) {
          if (nonce != 0  && nonce % 1500000 == 0) // need to sync data every second or so; 
            get_data(args);
          block_content[nonce_idx]   = (byte)(nonce >>> 24);
          block_content[nonce_idx+1] = (byte)(nonce >>> 16);
          block_content[nonce_idx+2] = (byte)(nonce >>>  8);
          block_content[nonce_idx+2] = (byte)(nonce);
          byte[] hash = md.digest(block_content);
          boolean success = true;
          for (int i = 0; i < zerobytes && success; i++) 
            if (hash[i] != 0) success = false;
          if (success && half != 0 && (hash[zerobytes] & 0xf0) != 0) success = false;
          if (success) {
            long  milseconds = System.currentTimeMillis() - start;
            long mins = milseconds/1000/60, seconds = milseconds/1000%60;
            double MHs = nonce/milseconds/1000;
            System.out.println(String.format("\nnonce: %d time: %dm%ds %.1fMH/s hash: %s", nonce, mins, seconds, MHs, toHex(hash)));
            break;
          }
        }
      } catch (Exception e) {
        System.err.println("Caught exception " + e.toString());
      }
  }
  static void get_data(String[] args) throws Exception {
    if (nonce != 0 && nonce % 15000000 == 0) System.out.print(".");
    difficulty = Integer.parseInt(args[0]);
    zerobytes = difficulty/2;
    half = difficulty%2;
    boolean start_over = false;
    try (BufferedReader br = new BufferedReader(new FileReader(args[1]))) {
        List<String> lines = new ArrayList<String>();
        byte[] hdr = hexStringToBytes(br.readLine());
        if (!Arrays.equals(hdr, prev_header)) {
          prev_header = hdr;
          System.out.println((nonce>0?"\n":"") + "latest block header: " + toHex(prev_header));
          start_over = true;
        }
      }
    try (BufferedReader br = new BufferedReader(new FileReader(args[2]))) {
        List<String> lines = new ArrayList<String>();
        String txn = null, new_txns[];
        while ((txn = br.readLine()) != null)
          if ((txn = txn.trim()).length() > 0) lines.add(txn);
        new_txns = lines.toArray(new String[lines.size()]);
        if (!Arrays.equals(new_txns, txns)) { // must compute new Merkle
          txns = new_txns;
          byte[] hash1 = md.digest((new_txns[0]).getBytes(StandardCharsets.UTF_8));
          for (int i = 1; i < new_txns.length; i++) { // to do: save the tree
            byte[] hash2 = md.digest((new_txns[i]).getBytes(StandardCharsets.UTF_8));
            byte[] two  = new byte[hash1.length + hash2.length];
            System.arraycopy(hash1, 0, two, 0, hash1.length);
            System.arraycopy(hash2, 0, two, hash1.length, hash2.length);
            hash1 = md.digest(two);
          }
          root_hash = hash1;
          System.out.println((nonce>0?"\n":"") + "current root hash:   " + toHex(root_hash));
          start_over = true;
        }
      }
    if (start_over) { // build array of prev header, root hash, difficulty and 4 nonce bytes
      block_content = new byte[(nonce_idx = prev_header.length + root_hash.length + 1) + 4];
      System.arraycopy(prev_header, 0, block_content, 0, prev_header.length);
      System.arraycopy(root_hash, 0, block_content, prev_header.length, root_hash.length);
      block_content[nonce_idx-1] = (byte) difficulty;
      if (nonce != 0) System.out.println("New content arrived, start over! nonce=0.");
      nonce = 0; // start over
      start = System.currentTimeMillis(); 
    }
  }
  static String toHex(byte[] data) {
    StringBuilder sb = new StringBuilder();
    for (byte b: data) sb.append(String.format("%02x", b&0xff));
    return sb.toString();
  }
  static byte[] hexStringToBytes(String s) { // from stackoverflow
    int len = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2)
      data[i / 2] = (byte)((Character.digit(s.charAt(i), 16) << 4)
                           + Character.digit(s.charAt(i+1), 16));
    return data;
  }
}
