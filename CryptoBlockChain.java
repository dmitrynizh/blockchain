import java.util.*; import java.io.*; import java.net.*; import java.math.*; import java.util.concurrent.atomic.*;
import java.security.*; import java.security.spec.*; import static java.nio.charset.StandardCharsets.UTF_8; 
public class CryptoBlockChain { // (c) 2018 dmitrynizh. MIT License.
  static class Block { String hash; int state, nonce; Block prev, alt; Set<String> txns; HashMap<String, String[]>d; long stamp;}
  static int nodes, difficulty, effort, max_blocks; static class Cred { String pk; PrivateKey sk; Cred(String p, PrivateKey s) {pk=p;sk=s;}} 
  final static AtomicInteger block_count = new AtomicInteger(1); static volatile boolean run = true;
  public static void main(String[] args) throws Exception { // run network
    nodes      = (args.length > 0) ? Integer.parseInt(args[0]) : 7;
    difficulty = (args.length > 1) ? Integer.parseInt(args[1]) : 6; if (difficulty <= 10) difficulty *= 8;
    effort     = (args.length > 2) ? 10000000*Integer.parseInt(args[2]) : 10000000;
    max_blocks = (args.length > 3) ? Integer.parseInt(args[3]) : 10;
    Block zero = new Block(); zero.stamp = System.currentTimeMillis(); zero.hash = "00";
    for (int i = 0; i < nodes; i++) startNode(i, zero, new Block(), InetAddress.getByName("230.1.1.1"), new Stack<>(), new Vector<>());
  }
  static void startNode(int id, Block zero, Block b, InetAddress ip, Stack<String> mq, Vector<Cred> w) throws Exception {
    b.prev = zero; b.state = 2; b.txns = new TreeSet<>((x, y)->x.compareTo(y)); b.d = new HashMap<>();  
    startListener(ip, id, b, KeyFactory.getInstance("EC"), mq, MessageDigest.getInstance("SHA-256"), w); startMiner(ip, id, b, mq, MessageDigest.getInstance("SHA-256"), w);
  }
  static void startMiner(InetAddress ip, int id, Block scratch, Stack<String> mq, MessageDigest md, Vector<Cred> w) {
    (new Thread() { @Override public void run() {
      try {
        DatagramSocket udpSocket = new DatagramSocket(); int nonce_idx = 0, nonce = 0; byte[] header = null; 
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC"); keyGen.initialize(256,SecureRandom.getInstance("SHA1PRNG")); 
        KeyPair pair = keyGen.generateKeyPair(); PrivateKey sk = pair.getPrivate(); 
        String pk58 = to58(pair.getPublic().getEncoded()); w.add(new Cred(pk58, sk));
        while (run) {
          String coinbase = sign(String.format("MINT new BTC coins %s 50.0 %s mining reward SIG", pk58, pk58), sk);
          if (block_count.get() > max_blocks) { mq.push("ALL HALT AND DUMP"); run = false; } // halt
          else if (scratch.state != 0) { // reset as saw new txn/block.  future: proper Merkle
            scratch.txns.add(coinbase); String root = toHex(md.digest(txt(scratch).getBytes(UTF_8))); scratch.txns.remove(coinbase);
            // String all  = txt(scratch); System.out.println("-- all: " + all);
            header = hexStringToBytes(scratch.prev.hash + root + "00000000");
            nonce_idx = header.length-4; nonce = 0; scratch.state = 0;
          } // "Each node works on finding a difficult proof-of-work for its block" - see reference [1].
          for (int lim = (int)randN(effort), i = 0; i <  lim && mq.isEmpty(); i++, nonce++) { // randN(effort) sets duration
            for (int x = 0, z = 24; x < 4; x++, z-=8) header[nonce_idx+x] = (byte)(nonce >>> z); // convert int to 4 bytes
            byte[] hash = md.digest(header);
            if (fit_p(hash, difficulty) && scratch.state == 0) { // mined new block!!
              scratch.hash = toHex(hash); scratch.stamp = System.currentTimeMillis(); scratch.state = 2; 
              // scratch.txns.add(coinbase); scratch.v.add(coinbase.split(" "));
              mq.push(String.format("BLN\n%s\n%s\n%d %d\n| ", scratch.hash, scratch.prev.hash, nonce, scratch.stamp) 
                      + coinbase + (scratch.txns.isEmpty() ? "" : "," + txt(scratch).replace('[', ' ').replace(']', ' ')));
              pair=keyGen.generateKeyPair(); sk = pair.getPrivate(); pk58 = to58(pair.getPublic().getEncoded()); w.add(new Cred(pk58, sk)); // replace keys
              //scratch.txns.clear(); // hm.....
              block_count.getAndIncrement(); // "When a node finds a proof-of-work, it broadcasts the block to all nodes" [1].
            }} 
          if (mq.isEmpty() && randN(100) < 20 && block_count.get() > 3) { // in 20% cases, may pay to some pk out of w
            double sum = randN(75)/1.5, has = 0, rem = 0; String src[], v[], src_pk58 = null, src_h = null, payee_tx_hash = null; PrivateKey src_sk = null;
            synchronized(w) { 
              for (Cred p : w.toArray(new Cred[0]))
                if ((src = get(p.pk,scratch)) != null && (src_sk = p.sk) != null && !src[0].equals("spent") && ((has = Double.parseDouble(src[1])) >= sum)) break; 
            }
            if ((rem = has - sum) >= 0) { // when rem == 0, the 2nd output is 0 btc to _ (nobody)
              for (long k = randN(5); k > 0;) // look for some random payee pk
                for (Block b = scratch; b.prev != null; b = b.prev) 
                  for (Map.Entry<String, String[]> entry : new ArrayList<>(b.d.entrySet())) // chose a payee
                    if (entry.getValue()[0].equals("TXN") || entry.getValue()[0].equals("MINT")) { k--; payee_tx_hash = entry.getKey(); }
              if (payee_tx_hash != null) {
                String payee = get(payee_tx_hash,scratch)[6];
                if (payee.equals(src_pk58)) ; // log.println(" payee and src_pk58 match" + payee_tx); // do not use it
                else { // some other pk, normal case
                  for (Block b = scratch; b.prev != null; b = b.prev) // to find src txn hash loop blocks and txns
                    for (Map.Entry<String, String[]> entry : new ArrayList<>(b.d.entrySet())) // look for txn where src_pk58 is 1st payee, its hash is src_h
                      if (((v=entry.getValue())[0].equals("TXN") || v[0].equals("MINT")) && v[6].equals(src_pk58)) { src_h  = entry.getKey(); break;}
                  if (src_h != null) { // System.out.println("-- src_h: " + src_h);
                    mq.push(sign(String.format("TXN %tT %d %s %s %.3f %s %.3f %s SIG", new Date(), 0, src_h, src_pk58, sum, payee, rem, rem==0?"_":pk58), src_sk));                  
                    if (rem != 0) { pair=keyGen.generateKeyPair(); sk = pair.getPrivate(); pk58 = to58(pair.getPublic().getEncoded()); w.add(new Cred(pk58, sk)); }// replace keys
                  }}}}}
          if (!mq.isEmpty()) { // from [1]: "New transactions are broadcast to all nodes"
            String msgstr = mq.pop(); if (msgstr.equals("PK+")) msgstr = "PK " + id + " " + pk58;
            byte[] msg = msgstr.getBytes(); if (!msgstr.startsWith("BLN")) Thread.sleep(randN(700)); // still needed
            udpSocket.send(new DatagramPacket(msg, msg.length, ip, 9090));
            if (nodes <= 10  || msgstr.startsWith("BLN")) { // log it
              if (nodes >= 5) { // reduce clutter
                String[] a = msgstr.split(" "); 
                for (int i = 2; i< a.length; i++) a[i] = abbrev("", a[i], 6, 40);
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
  static void startListener(InetAddress ip, int id, Block scratch, KeyFactory kf, Stack<String> mq, MessageDigest md, Vector<Cred> w) {
    (new Thread() { @Override public void run() { 
      try (PrintWriter log = new PrintWriter("n"+id+".log"); PrintWriter bpw = new PrintWriter("balance"+id+".txt")) {
        MulticastSocket mcs = new MulticastSocket(9090); mcs.joinGroup(ip);
        DatagramPacket packet = new DatagramPacket(new byte[4*1024], 4*1024); 
        Signature sig = Signature.getInstance("SHA256withECDSA");
        while (run) {
          mcs.receive(packet); // this call blocks until something arrives
          String msg = new String(packet.getData(), packet.getOffset(), packet.getLength());
          if (nodes < 5) out("node" + id + "< " + msg);
          if (msg.startsWith("TXN") && !scratch.txns.contains(msg)) { // add new record and set state to 1
            scratch.txns.add(msg); // try not to do it.... if (verifyTxn(id, msg, md, scratch, sig, kf, log)) { scratch.txns.add(msg); scratch.state = 1; } 
          } else if (msg.startsWith("BLN")) { // validate, then acquire new block and chain it
            String hdr = msg.substring(0, msg.indexOf("|")), hdr_a[] = hdr.split("[\\r\\n\\s]+"), hash = hdr_a[1], prv = hdr_a[2]; boolean OK = true;
            // TODO: needs to incl merkle...if (!toHex(md.digest(prv+root+form("%x08",nonce)).getBytes(UTF_8))).equals(hash)) { out("Verification FAILED, block hash is wrong: " + hash); continue; }
            if (scratch.alt != null) { // time to resolve conflict.  // TODO: think about this and acceptTxn....
              if (prv.equals(scratch.alt.hash)) 
                scratch.prev = scratch.alt; // "Nodes always consider the longest chain to be the correct one"[1]
              scratch.alt = null; 
            } // next, verify txns. "Nodes accept the block only if all transactions in it are valid and not already spent"[1] 
            String[] txnsa = msg.substring(msg.indexOf("|")+2).split(", "); // Q: what about those already accepted??
            for (String txn: txnsa) if (!(OK=verifyTxn(id, txn, md, scratch, sig, kf, log))) break;
            if (OK) {
              List<String> txns = Arrays.asList(txnsa); // we want to make sure none of the new txns are stored in prev blocks!
              for (Block b = scratch.prev; b.prev != null && (OK = Collections.disjoint(b.txns, txns)); b = b.prev);
              if (OK) {                // "Nodes express their acceptance of the block by working on creating the next block  
                Block b = new Block(); //  in the chain, using the hash of the accepted block as the previous hash" [1]
                if (!prv.equals(scratch.prev.hash)) { // very rare
                  if (prv.equals(scratch.prev.prev.hash)) { // contestant
                    { b.prev = scratch.prev.prev; scratch.alt = b; } // "save the other branch in case it becomes longe"[1]
                  } else log.println("Unresloved Collision with prev.hash=" + scratch.prev.hash + " for block: " +  msg);
                } else { b.prev = scratch.prev; scratch.prev = b; } // norml case
                b.hash = hdr_a[1]; b.nonce = Integer.parseInt(hdr_a[3]); b.stamp = Long.parseLong(hdr_a[4]); 
                (b.txns = new TreeSet<>((x, y)->x.compareTo(y))).addAll(txns); b.d = new HashMap<>();
                for (String txn: txnsa) acceptTxn(id, txn, txn.split(" "), md, b);
                scratch.state = 2; scratch.txns.clear(); // scratch.txns.removeAll(txns); // scratch.hash = null;
                if (scratch.txns.size() != 0) log.println("node"+id+": not in the accepted block: " + txt(scratch));
              } else log.println("block contains invalid txns, rejecting it: " + msg); // todo: if fromself, flush txns
            } else log.println("block contains previously accepted txns, rejecting it: " + msg); // todo: if fromself, flush txns
            double b = Arrays.stream(w.toArray(new Cred[0])).map(p->get(p.pk,scratch)).filter(v->v!=null).mapToDouble(v->Double.parseDouble(v[1])).sum();
            bpw.println(String.format("At %tc my balance: %.3f ", new Date(), b)); bpw.flush();
          } 
        } 
        String blockchain = "", h_txn = "";
        for (Block b = scratch.prev; b.prev != null; b = b.prev, h_txn = "") { //log.println("B:"+b.hash+" txns: "+txt(b));
          for (String txn : b.txns.toArray(new String[0])) h_txn += to58(md.digest(txn.getBytes(UTF_8))) + "\n" + txn;
          blockchain = String.format("Mined: %tc\n hash: %s\n prev: %s\nnonce: %d\n txns:\n%s\n\n", 
                                     new Date(b.stamp), b.hash, b.prev.hash, b.nonce, h_txn) + blockchain;
        }
        try (PrintWriter out = new PrintWriter("blockchain"+id+".txt")) { out.println(blockchain); }
        out("node" + id + " listener exiting."); mcs.leaveGroup(ip); mcs.close();
      } catch (Exception ex) { ex.printStackTrace(); } 
    }}).start();
  }
  static long randN(long range) { return Math.round(Math.random()*range); }
  static String out(String s) { System. out.println(s); return s; }
  static String txt(Block b) { return Arrays.toString(b.txns.toArray(new String[0])); }
  static boolean fit_p(byte[] hash, int difficulty) { // does hash have given difficulty?
    int zerobytes = difficulty/2/8, rem = difficulty%8, lim = 1 << (8-rem);
    for (int i = 0; i < zerobytes; i++) if (hash[i] != 0) return false;
    return ((int)hash[zerobytes] & 0xff) < lim;
  }
  static String toHex(byte[] data) {
    StringBuilder sb = new StringBuilder();
    for (byte b: data) sb.append(String.format("%02x", b&0xff));
    return sb.toString();
  }
  static String abbrev(String b, String s, int d, int m) { int l=s.length(); return l < m ? s : b+s.substring(0, d)+"..."+s.substring(s.length()-d);}
  static byte[] hexStringToBytes(String s) { // from stackoverflow
    int len = s.length(); byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2)
      data[i / 2] = (byte)((Character.digit(s.charAt(i), 16) << 4)+ Character.digit(s.charAt(i+1), 16));
    return data;
  }
  static String[] get(String k, Block b) { String[] r=null; for (; b.prev != null && r == null; b = b.prev) r = b.d.get(k); return r; }
  static boolean verifyTxn(int id, String txn, MessageDigest md, Block scratch, Signature s, KeyFactory kf, PrintWriter log) { try { 
      String[] atr  = txn.split(" "); X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(as58(atr[4]));
      s.initVerify(kf.generatePublic(pkSpec));
      s.update(txn.substring(0, txn.lastIndexOf(" ", txn.length()-20)).getBytes((UTF_8)));
      if (!s.verify(as58(atr[10]))) { log.println("bad signature in " + txn); return false; }
      String hash = to58(md.digest(txn.getBytes(UTF_8)));
      if (get(hash, scratch) != null) { log.println("txn previously included in a block, " + txn); return false; } // we want to make sure none of the new txns are stored in prev blocks!
      if (!atr[0].equals("MINT")) { String bal[] = get(atr[4], scratch);
        if (bal == null) { log.println("txn src not found " + txn); return false; } // unknown pk or spent pk?
        if (bal[0].equals("spent")) { log.println("txn src is already spent " + txn); return false; } // unknown pk or spent pk?
        if (Double.parseDouble(bal[1])  != Double.parseDouble(atr[7]) + Double.parseDouble(atr[5])) { log.println("txn balances do not match " + txn); return false; } 
      }
    } catch (Exception e) { log.println(e+": verification failed. txn:" + txn); e.printStackTrace(); return false; } return true;}
  static void acceptTxn(int id, String txn, String[] atr, MessageDigest md, Block b) { 
    String hash = to58(md.digest(txn.getBytes(UTF_8))), a[] = {"spent", "0", txn}, o1[] = {"BTC",atr[5], txn}, o2[] = {"BTC",atr[7], txn};
    b.d.put(atr[4], a); b.d.put(hash, atr); b.d.put(atr[6], o1); b.d.put(atr[8], o2);  
  } 
  static String sign(String msg, PrivateKey sk) throws Exception {
    Signature s = Signature.getInstance("SHA256withECDSA"); s.initSign(sk); s.update(msg.getBytes(UTF_8));
    return msg + " " + to58(s.sign()) + " \n"; // last space is important, see txn.split(" ")!
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
    return  sb.reverse().toString();
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


// Command line options: perhaps, switch from args[] to props: CryptoBlockChain -Dn=7 -Dd=49 -Dcoin=XYZCoin ....
// int difficulty = toI(sprop("d","48")), nodes = toI(sprop("n", "7")

// Streams: byte stream does not work  static String toHex2(byte[] d) { return Arrays.stream(d).map(b->String.format("%02x", b&0xff)).reduce("",(a,b)->a+b); }
