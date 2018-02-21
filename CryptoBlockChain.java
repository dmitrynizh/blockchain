import java.util.*; import java.io.*; import java.net.*; import java.util.concurrent.atomic.*;
import java.security.*; import java.security.spec.*; import static java.nio.charset.StandardCharsets.UTF_8; 
public class CryptoBlockChain { // run: 'java BlockChain' or  'java BlockChain <nodes> <difficulty> <blocks>' 
  static class Block { String id = "", pk[]; int state, nonce; Block prev, alt; Set<String> records; long stamp;}
  static int node_maxcount, blk_difficulty, mine_ct, max_blocks; 
  final static AtomicBoolean run = new AtomicBoolean(true); 
  final static AtomicInteger block_count = new AtomicInteger(1);
  public static void main(String[] args) throws Exception { // run network
    node_maxcount  = (args.length > 0) ? Integer.parseInt(args[0]) : 7;
    blk_difficulty = (args.length > 1) ? Integer.parseInt(args[1]) : 6;
    mine_ct        = (args.length > 2) ? 10000000*Integer.parseInt(args[2]) : 10000000;
    max_blocks     = (args.length > 3) ? Integer.parseInt(args[3]) : 10;
    Block zero = new Block(); zero.stamp = System.currentTimeMillis();
    for (int i = 0; i < node_maxcount; i++)  startNode(i, zero);
  }
  static void startNode(int id, Block zero) throws Exception {
    Block b = new Block(); b.prev = zero; b.state = 2; b.records = new TreeSet<>((x, y)->x.compareTo(y));
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(256,SecureRandom.getInstance("SHA1PRNG"));
    KeyPair pair = keyGen.generateKeyPair(); Stack<String> mq = new Stack<String>();
    startListener(id, b, pair.getPrivate(), pair.getPublic(), mq);
    startMiner   (id, b, pair.getPrivate(), pair.getPublic(), mq);
  }
  static void startMiner(final int id, final Block scratch, PrivateKey sk, PublicKey pk, Stack<String> mq) throws IOException {
    (new Thread() { @Override public void run() {
      try {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        DatagramSocket udpSocket = new DatagramSocket();
        InetAddress mcIPAddress = InetAddress.getByName("230.1.1.1");
        int nonce_idx = 0, nonce = 0; byte[] header = null; 
        String pkinfo = "PK " + id + " " + to64(pk.getEncoded()); mq.push(pkinfo); 
        while (run.get()) {
          if (block_count.get() > max_blocks) { mq.push("ALL HALT AND DUMP"); run.set(false); } // halt
          else if (scratch.state != 0) { // reset // new txn/block future: new Merkle
            String root = toHex(md.digest(Arrays.toString(scratch.records.toArray(new String[0])).getBytes(UTF_8)));
            header = hexStringToBytes(scratch.prev.id + root + "00000000");
            nonce_idx = header.length-4; nonce = scratch.state = 0;
          } // "Each node works on finding a difficult proof-of-work for its block" - see reference [1].
          for (int lim = randN(mine_ct), i = 0; i <  lim && mq.isEmpty(); i++, nonce++) { // how long depends on randN(mine_ct)
            for (int x = 0, z = 24; x < 4; x++, z-=8) header[nonce_idx+x] = (byte)(nonce >>> z);
            byte[] hash = md.digest(header);
            if (fit_p(hash, blk_difficulty) && scratch.state == 0) { // mined new block!!
              scratch.id = toHex(hash); scratch.stamp = System.currentTimeMillis(); scratch.state = 2; 
              String txns = Arrays.toString(scratch.records.toArray(new String[0]));
              mq.push(String.format("BLN %s %s %d %d \n| ", scratch.id, scratch.prev.id, nonce, scratch.stamp) 
                      + sign(String.format("MINT ! reward %d with 50btc ! !", id, id), sk) 
                      + (scratch.records.isEmpty() ? "" : ", " + txns.substring(1,txns.length()-1))); // this substring strips [ and ]
              block_count.getAndIncrement(); // "When a node finds a proof-of-work, it broadcasts the block to all nodes" [1].
            } 
          } 
          if (mq.isEmpty() && randN(100) < 15)  // in 15% cases, send payment to random-chosen node
            mq.push(sign(String.format("TXN at %tT %d pays %.3fbtc to %d", new Date(), id, 10*Math.random(), randN(1000)%node_maxcount), sk));
          if (!mq.isEmpty()) { // from [1]: "New transactions are broadcast to all nodes"
            String msgstr = mq.pop(); if (msgstr.equals("PK+")) msgstr = pkinfo;
            byte[] msg = msgstr.getBytes();
            if (!msgstr.startsWith("BLN")) Thread.sleep(randN(500));
            udpSocket.send(new DatagramPacket(msg, msg.length, mcIPAddress, 9090));
            if (node_maxcount <= 10 || !msgstr.startsWith("TXN")) out("node" + id + "> " + msgstr);
            Thread.sleep(randN(500));
            if (msgstr.startsWith("ALL HALT")) // to force all nodes to quit
              for (int i = 0; i < 10; i++, Thread.sleep(100)) // 10 times plus delay is ugly but works
                udpSocket.send(new DatagramPacket(msg, msg.length, mcIPAddress, 9090));
            else Thread.sleep(100);
          }
        }
        udpSocket.close();
      } catch (Exception ex) { ex.printStackTrace(); }
      out("node" + id + " sender exiting.");
    }}).start();
  }
  static void startListener(final int id, final Block scratch, PrivateKey sk, PublicKey pk, Stack<String> mq) throws IOException {
    (new Thread() { @Override public void run() { 
      try {
        InetAddress mcIPAddress = InetAddress.getByName("230.1.1.1");
        MulticastSocket mcSocket = new MulticastSocket(9090);
        mcSocket.joinGroup(mcIPAddress);
        DatagramPacket packet = new DatagramPacket(new byte[4*1024], 4*1024); 
        KeyFactory kf = KeyFactory.getInstance("EC");
        Signature sig = Signature.getInstance("SHA256withECDSA"); //   ("SHA1withDSA", "SUN");
        scratch.pk = new String[node_maxcount]; boolean pkok = false;
        while (run.get()) {
          mcSocket.receive(packet);
          String msg = new String(packet.getData(), packet.getOffset(), packet.getLength());
          if (node_maxcount < 5) out("node" + id + "< " + msg);
          if (msg.startsWith("TXN") && !scratch.records.contains(msg)) { // add new record and set state to 1
            if (!pkok) { // time to validate the private key array
              pkok = true; String[] a = scratch.pk;
              for (int j = 0; j < a.length; j++) if (a[j] == null) { pkok = false; mq.push("PK? " + j + " ?"); }
            } // quote from reference [1]: "Each node collects new transactions into a block"
            scratch.records.add(msg); scratch.state = 1; 
          } else if (msg.startsWith("BLN")) { // validate, then acquire new block and chain it
            String[] header_arr = msg.substring(0, msg.indexOf("|")).split(" ");
            String block_prev = header_arr[2];
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
            if (!current_txn) out("-- block contains spent txns, rejecting it: " + msg);
            else { // proceed.  "Nodes express their acceptance of the block by working on creating the next block in the chain,
              Block b = new Block(); // using the hash of the accepted block as the previous hash" [1]
              if (!block_prev.equals(scratch.prev.id)) { // very rare
                if (block_prev.equals(scratch.prev.prev.id)) { // contestant
                  { b.prev = scratch.prev.prev; scratch.alt = b; } // "save the other branch in case it becomes longe"[1]
                } else out("-- node"+id+": Unresloved Collision with prev.id=" + scratch.prev.id + " " +  msg);
              } else { b.prev = scratch.prev; scratch.prev = b; }
              b.id = header_arr[1]; b.nonce = Integer.parseInt(header_arr[3]); b.stamp = Long.parseLong(header_arr[4]); 
              (b.records = new TreeSet<>((x, y)->x.compareTo(y))).addAll(txns);
              scratch.state = 2; scratch.records.removeAll(txns); // scratch.id = null;
              if (scratch.records.size() != 0) out("-- node"+id+": left out of last seen block: " + Arrays.toString(scratch.records.toArray(new String[0])));
            }
          } else if (msg.startsWith("PK? " + id + " ?")) mq.push("PK+"); // sender will re-send
          else if (msg.startsWith("PK ")) {
            String[] ma = msg.split(" "); 
            scratch.pk[Integer.parseInt(ma[1])] = ma[2]; 
          } else ; // complain? out("node "+id+ ": got unknown command!");
        }
        String blockchain = "";
        for (Block b = scratch.prev; b.prev != null; b = b.prev) 
          blockchain = String.format("======\n%s %s %d %d \n%s\n", b.id, b.prev.id, b.nonce, b.stamp, Arrays.toString(b.records.toArray(new String[0]))) + blockchain;
        try (PrintWriter out = new PrintWriter("blockchain"+id+".txt")) { out.println(blockchain); }
        mcSocket.leaveGroup(mcIPAddress);
        mcSocket.close();
      } catch (Exception ex) { ex.printStackTrace(); }
      out("node" + id + " listener exiting.");
    }}).start();
  }
  static String out(String s) { System. out.println(s); return s; }
  static int randN(int range) { return (int)Math.round(Math.random()*range); }
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
  static byte[] hexStringToBytes(String s) { // from stackoverflow
    int len = s.length(); byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2)
      data[i / 2] = (byte)((Character.digit(s.charAt(i), 16) << 4)+ Character.digit(s.charAt(i+1), 16));
    return data;
  }
  static String to64(byte[] a) { return Base64.getEncoder().encodeToString(a); }
  static byte[] as64(String s) { return Base64.getDecoder().decode(s.getBytes(UTF_8)); }
  static boolean verifyTxn(int id, String txn, String[] atr, String[] pk, Signature s, KeyFactory kf) { try {
      X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(as64(pk[Integer.parseInt(atr[3])]));
      s.initVerify(kf.generatePublic(pkSpec));
      s.update(txn.substring(0, txn.lastIndexOf(" ", txn.length()-20)).getBytes((UTF_8)));
      return s.verify(as64(atr[8]));                                                           
    } catch (Exception e) { out("node"+id+": pending verification because of missing pk: " + Arrays.toString(pk)); return true; }}
  static String sign(String msg, PrivateKey sk) throws Exception {
    Signature s = Signature.getInstance("SHA256withECDSA"); s.initSign(sk); s.update(msg.getBytes(UTF_8));
    return msg + " " + to64(s.sign()) + " \n"; // last space is important!
  }
} // references: [1] Satoshi Nakamoto. Bitcoin: A Peer-to-Peer Electronic Cash System.
