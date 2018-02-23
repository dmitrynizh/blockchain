import java.util.*; import java.io.*; import java.net.*; import java.math.*; import java.util.concurrent.atomic.*;
import java.security.*; import java.security.spec.*; import static java.nio.charset.StandardCharsets.UTF_8; 
public class CryptoBlockChain { // (c) 2018 dmitrynizh. MIT License.
  static class Block { String id, pk[]; int state, nonce; Block prev, alt; Set<String> records; long stamp;}
  static int node_maxcount, blk_difficulty, effort, max_blocks; static volatile boolean run = true;
  final static AtomicInteger block_count = new AtomicInteger(1);
  public static void main(String[] args) throws Exception { // run network
    node_maxcount  = (args.length > 0) ? Integer.parseInt(args[0]) : 7;
    blk_difficulty = (args.length > 1) ? Integer.parseInt(args[1]) : 6;
    effort         = (args.length > 2) ? 10000000*Integer.parseInt(args[2]) : 10000000;
    max_blocks     = (args.length > 3) ? Integer.parseInt(args[3]) : 10;
    Block zero = new Block(); zero.stamp = System.currentTimeMillis(); zero.id = "00";
    for (int i = 0; i < node_maxcount; i++) startNode(i, zero, InetAddress.getByName("230.1.1.1"));
  }
  static void startNode(int id, Block zero, InetAddress ip) throws Exception {
    Block b = new Block(); b.prev = zero; b.state = 2; b.records = new TreeSet<>((x, y)->x.compareTo(y));
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(256,SecureRandom.getInstance("SHA1PRNG"));
    KeyPair pair = keyGen.generateKeyPair(); Stack<String> mq = new Stack<String>(); // mq is thread safe
    startListener(ip, id, b, pair.getPublic(), KeyFactory.getInstance("EC"), mq);
    startMiner(ip, id, b, pair.getPrivate(), pair.getPublic(), mq);
  }
  static void startMiner(InetAddress ip, int id, Block scratch, PrivateKey sk, PublicKey pk, Stack<String> mq) {
    (new Thread() { @Override public void run() {
      try {
        MessageDigest md = MessageDigest.getInstance("SHA-256"); 
        DatagramSocket udpSocket = new DatagramSocket();
        int nonce_idx = 0, nonce = 0; byte[] header = null; 
        String pkinfo = "PK " + id + " " + to58(pk.getEncoded()); mq.push(pkinfo); 
        scratch.records.add(sign(String.format("MINT new coins. %d <-- 50btc mining reward", id, id), sk));
        while (run) {
          if (block_count.get() > max_blocks) { mq.push("ALL HALT AND DUMP"); run = false; } // halt
          else if (scratch.state != 0) { // reset as saw new txn/block.  future: proper Merkle
            String root = toHex(md.digest(txt(scratch).getBytes(UTF_8)));
            header = hexStringToBytes(scratch.prev.id + root + "00000000");
            nonce_idx = header.length-4; nonce = 0; scratch.state = 0;
          } // "Each node works on finding a difficult proof-of-work for its block" - see reference [1].
          for (int lim = randN(effort), i = 0; i <  lim && mq.isEmpty(); i++, nonce++) { // randN(effort) sets duration
            for (int x = 0, z = 24; x < 4; x++, z-=8) header[nonce_idx+x] = (byte)(nonce >>> z); // convert int to 4 bytes
            byte[] hash = md.digest(header);
            if (fit_p(hash, blk_difficulty) && scratch.state == 0) { // mined new block!!
              scratch.id = toHex(hash); scratch.stamp = System.currentTimeMillis(); scratch.state = 2; 
              mq.push(String.format("BLN\n%s\n%s\n%d %d\n|", scratch.id, scratch.prev.id, nonce, scratch.stamp) 
                      + txt(scratch).replace('[', ' ').replace(']', ' '));
              block_count.getAndIncrement(); // "When a node finds a proof-of-work, it broadcasts the block to all nodes" [1].
            } 
          } 
          if (mq.isEmpty() && randN(100) < 15)  { // in 15% cases, send payment to random-chosen node
            mq.push(sign(String.format("TXN at %tT %d --> %.3fbtc to %d",new Date(), id, 10*Math.random(), randN(1000)%node_maxcount), sk));
            mq.push(pkinfo);
          }
          if (!mq.isEmpty()) { // from [1]: "New transactions are broadcast to all nodes"
            String msgstr = mq.pop(); if (msgstr.equals("PK+")) msgstr = pkinfo;
            byte[] msg = msgstr.getBytes(); if (!msgstr.startsWith("BLN")) Thread.sleep(randN(700)); // still needed
            udpSocket.send(new DatagramPacket(msg, msg.length, ip, 9090));
            if (node_maxcount <= 10  || msgstr.startsWith("BLN")) { // log it
              if (node_maxcount >= 5) { // reduce clutter
                String[] a = msgstr.split(" "); 
                for (int i = 2; i< a.length; i++) { a[i] = abbrev("-- ", abbrev("", a[i], 6, 124), 6, 96); }
                msgstr = String.join(" ", a);
              }
              out("node" + id + "> " + msgstr);
            } Thread.sleep(randN(500)); // stil keep it
            if (msgstr.startsWith("ALL HALT")) // to force all nodes to quit
              for (int i = 0; i < 10; i++, Thread.sleep(100)) // 10 times plus delay is ugly but works
                udpSocket.send(new DatagramPacket(msg, msg.length, ip, 9090));
            else Thread.sleep(100);
          }
        } udpSocket.close(); out("node" + id + " sender exiting."); 
      } catch (Exception ex) { ex.printStackTrace(); } 
    }}).start();
  }
  static void startListener(InetAddress ip, int id, Block scratch, PublicKey pk, KeyFactory kf, Stack<String> mq) {
    (new Thread() { @Override public void run() { 
      try {
        MulticastSocket mcs = new MulticastSocket(9090); mcs.joinGroup(ip);
        DatagramPacket packet = new DatagramPacket(new byte[4*1024], 4*1024); 
        Signature sig = Signature.getInstance("SHA256withECDSA");
        scratch.pk = new String[node_maxcount]; boolean pkok = false;
        while (run) {
          mcs.receive(packet); // this call blocks until something arrives
          String msg = new String(packet.getData(), packet.getOffset(), packet.getLength());
          if (node_maxcount < 5) out("node" + id + "< " + msg);
          if (msg.startsWith("TXN") && !scratch.records.contains(msg)) { // add new record and set state to 1
            if (!pkok) { // time to validate the private key array
              pkok = true; String[] a = scratch.pk;
              for (int j = 0; j < a.length; j++) if (a[j] == null) { pkok = false; mq.push("PK? " + j + " ?"); }
            } // quote from reference [1]: "Each node collects new transactions into a block"
            if (!verifyTxn(id, msg, msg.split(" "), scratch.pk, sig, kf)) out("Verification FAILED: " + msg);            
            else { scratch.records.add(msg); scratch.state = 1; }
          } else if (msg.startsWith("BLN")) { // validate, then acquire new block and chain it
            String header_arr[] = msg.substring(0, msg.indexOf("|")).split("[\\r\\n\\s]+"), block_prev = header_arr[2];
            if (scratch.alt != null) { // time to resolve conflict. 
              if (block_prev.equals(scratch.alt.id)) 
                scratch.prev = scratch.alt; // "Nodes always consider the longest chain to be the correct one"[1]
              scratch.alt = null; 
            } // next, verify txns. "Nodes accept the block only if all transactions in it are valid and not already spent"[1]
            String[] txnsa = msg.substring(msg.indexOf("|")+2).split(", "); 
            for (String txn: txnsa) if (!verifyTxn(id, txn, txn.split(" "), scratch.pk, sig, kf)) out("Verification FAILED: " + txn);
            List<String> txns = Arrays.asList(txnsa); 
            boolean current_txn = true; // we want to make sure none of the txns are stored in prev blocks!
            for (Block b = scratch.prev; b.prev != null && (current_txn = Collections.disjoint(b.records, txns)); b = b.prev);
            if (!current_txn) out("-- node"+id+": block contains accepted txns, rejecting it: " + msg); // todo: if fromself, flush records
            else {                   // "Nodes express their acceptance of the block by working on creating the next block 
              Block b = new Block(); //  in the chain, using the hash of the accepted block as the previous hash" [1]
              if (!block_prev.equals(scratch.prev.id)) { // very rare
                if (block_prev.equals(scratch.prev.prev.id)) { // contestant
                  { b.prev = scratch.prev.prev; scratch.alt = b; } // "save the other branch in case it becomes longe"[1]
                } else out("-- node"+id+": Unresloved Collision with prev.id=" + scratch.prev.id + " " +  msg);
              } else { b.prev = scratch.prev; scratch.prev = b; }
              b.id = header_arr[1]; b.nonce = Integer.parseInt(header_arr[3]); b.stamp = Long.parseLong(header_arr[4]); 
              (b.records = new TreeSet<>((x, y)->x.compareTo(y))).addAll(txns);
              scratch.state = 2; scratch.records.removeAll(txns); // scratch.id = null;
              if (node_maxcount < 5 && scratch.records.size() != 0) out("node"+id+": not in the accepted block: " + txt(scratch));
            }
          } else if (msg.startsWith("PK? " + id + " ?")) mq.push("PK+"); // miner thread will re-send
          else   if (msg.startsWith("PK ")) { String[] a = msg.split(" "); scratch.pk[Integer.parseInt(a[1])] = a[2]; } 
        } 
        String blockchain = "";
        for (Block b = scratch.prev; b.prev != null; b = b.prev) 
          blockchain = String.format("=== BLOCK ===\n hash: %s\n prev: %s\nnonce: %d minted: %tc \n%s\n\n", b.id, b.prev.id, b.nonce, 
                                     new Date(b.stamp), txt(b)) + blockchain;
        try (PrintWriter out = new PrintWriter("blockchain"+id+".txt")) { out.println(blockchain); }
        out("node" + id + " listener exiting."); mcs.leaveGroup(ip); mcs.close();
      } catch (Exception ex) { ex.printStackTrace(); } 
    }}).start();
  }
  static int randN(int range) { return (int)Math.round(Math.random()*range); }
  static String out(String s) { System. out.println(s); return s; }
  static String txt(Block b) { return Arrays.toString(b.records.toArray(new String[0])); }
  static boolean fit_p(byte[] hash, int difficulty) { // does hash have given difficulty?
    int zerobytes = difficulty/2, half = difficulty%2;
    boolean success = true;
    for (int i = 0; i < zerobytes && success; i++) if (hash[i] != 0) success = false;
    if (success && half != 0 && (hash[zerobytes] & 0xf0) != 0) success = false;
    return success;
  }
  static String toHex(byte[] data) {
    StringBuilder sb = new StringBuilder();
    for (byte b: data) sb.append(String.format("%02x", b&0xff));
    return sb.toString();
  }
  static String abbrev(String b, String s, int d, int l) { return s.length() >= l ? b+s.substring(0, d)+"..."+s.substring(l-d) : s; }
  static byte[] hexStringToBytes(String s) { // from stackoverflow
    int len = s.length(); byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2)
      data[i / 2] = (byte)((Character.digit(s.charAt(i), 16) << 4)+ Character.digit(s.charAt(i+1), 16));
    return data;
  }
  static boolean verifyTxn(int id, String txn, String[] atr, String[] pk, Signature s, KeyFactory kf) { try {
      X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(as58(pk[Integer.parseInt(atr[3])]));
      s.initVerify(kf.generatePublic(pkSpec));
      s.update(txn.substring(0, txn.lastIndexOf(" ", txn.length()-20)).getBytes((UTF_8)));
      return s.verify(as58(atr[8]));                                                           
    } catch (Exception e) { out(e+"node"+id+": pending verification because of missing pk: " + Arrays.toString(pk)); return true; }}
  static String sign(String msg, PrivateKey sk) throws Exception {
    Signature s = Signature.getInstance("SHA256withECDSA"); s.initSign(sk); s.update(msg.getBytes(UTF_8));
    return msg + " " + to58(s.sign()) + " \n"; // last space is important!
  }
  static final String ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"; 
  static final char A1 = ALPH.charAt(0); static final BigInteger A_SZ = BigInteger.valueOf(ALPH.length());
  static String to58_(byte[] data) { // see https://github.com/nayuki/Bitcoin-Cryptography-Library/blob/master/java/io/nayuki/bitcoin/crypto/Base58Check.java
    StringBuilder sb = new StringBuilder();
    for (BigInteger quotrem[], num = new BigInteger(1, data); num.signum() != 0; num = quotrem[0])
      sb.append(ALPH.charAt((quotrem = num.divideAndRemainder(A_SZ))[1].intValue()));
    return sb.reverse().toString();
  }
  static String to58(byte[] data) { // see https://github.com/nayuki/Bitcoin-Cryptography-Library/blob/master/java/io/nayuki/bitcoin/crypto/Base58Check.java
    StringBuilder sb = new StringBuilder();
    for (BigInteger quotrem[], num = new BigInteger(1, data); num.signum() != 0; num = quotrem[0])
      sb.append(ALPH.charAt((quotrem = num.divideAndRemainder(A_SZ))[1].intValue()));
    for (int i = 0; i < data.length && data[i] == 0; i++) sb.append(A1);
    return sb.reverse().toString();
  }
  static byte[] as58(final String s) throws IOException { // seehttps://github.com/nayuki/Bitcoin-Cryptography-Library/blob/master/java/io/nayuki/bitcoin/crypto/Base58Check.java
    BigInteger n = BigInteger.ZERO;
    for (int d, i = 0; i < s.length(); i++, n = (n.multiply(A_SZ)).add(BigInteger.valueOf(d)))
      d = ALPH.indexOf(s.charAt(i));
    byte[] b = n.toByteArray();  if (b[0] == 0) b = Arrays.copyOfRange(b, 1, b.length);
    ByteArrayOutputStream buf = new ByteArrayOutputStream();
    for (int i = 0; i < s.length() && s.charAt(i) == A1; i++) buf.write(0);
    buf.write(b); return buf.toByteArray();
  }
} // references: [1] Satoshi Nakamoto, "Bitcoin: A Peer-to-Peer Electronic Cash System",2008
