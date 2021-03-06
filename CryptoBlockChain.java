import java.util.*; import java.io.*; import java.net.*; import java.math.*;
import java.security.*; import java.security.spec.*; import static java.nio.charset.StandardCharsets.UTF_8; 
public class CryptoBlockChain { // (c) 2018 dmitrynizh. MIT License.
  static class Block { String hash; int ht, state, nonce; Block prev, alt; Set<String> txns; HashMap<String,String>d; long stamp;}
  static class Tx { Tx(String val) { txt = val; len = txt.length(); a = txt.split(" "); } 
    String id, txt, a[]; int fee, len, ti, v; } // Tx state
  static class Cred { String pk; PrivateKey sk; Cred(String p, PrivateKey s) {pk=p;sk=s;}} 
  static int nodes, difficulty, effort, blockMx, reward=50000, PK_SZ = 16*1024;
  static volatile int block_count; static volatile boolean run = true; static Stack<String> ads = new Stack<>(); static final String E = "";
  public static void main(String[] args) throws Exception { // run network
    nodes      = (args.length > 0) ? toI(args[0]) : 7;
    difficulty = (args.length > 1) ? toI(args[1]) : 49; if (difficulty <= 10) difficulty *= 8;
    effort     = (args.length > 2) ? toI(args[2]) : 1; effort *= 10000000;
    blockMx = (args.length > 3) ? toI(args[3]) : 20;
    Block zero = new Block(); zero.stamp = System.currentTimeMillis(); zero.hash = "00";
    for (int i = 0; i < nodes; i++) startNode(i, zero, new Block(), InetAddress.getByName("230.1.1.1"), new Stack<>(), new Vector<>());
  }
  static void startNode(int id, Block zero, Block b, InetAddress ip, Stack<String> mq, Vector<Cred> w) throws Exception {
    b.prev = zero; b.state = 2; b.txns = new TreeSet<>((x, y)->x.compareTo(y)); b.d = new HashMap<>();  
    startListener(ip, id, b, KeyFactory.getInstance("EC"), mq, MessageDigest.getInstance("SHA-256"), w); startMiner(ip, id, b, mq, MessageDigest.getInstance("SHA-256"), w);
  }
  static void startMiner(InetAddress ip, int id, Block scratch, Stack<String> mq, MessageDigest md, Vector<Cred> w) {
    (new Thread() { @Override public void run() { try (PrintWriter log = new PrintWriter("miner"+id+".log")) {
        DatagramSocket udpSocket = new DatagramSocket(); int nonce = 0, fees, m=1000; byte[] header = null;
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC"); keyGen.initialize(256,SecureRandom.getInstance("SHA1PRNG")); 
        KeyPair pair = keyGen.generateKeyPair(); PrivateKey sk = pair.getPrivate(); 
        String pk58 = to58(pair.getPublic().getEncoded()), root, coinbase=null; w.add(new Cred(pk58, sk)); String txs=""; int f[]={0};
        Signature s = Signature.getInstance("SHA256withECDSA"); KeyFactory kf = KeyFactory.getInstance("EC"); //move up!
        while (run) { // mine continuously, rehashing when new stuff comes, and sending blocks, or txns
          if (scratch.prev.ht > blockMx || block_count > blockMx+blockMx/3) { mq.push("ALL HALT AND DUMP"); run = false; } // halt
          else if (scratch.state != 0) { // reset state as saw a new block. b.d detects and rejects any double spends in the new batch 
            Block b = new Block(); b.d = new HashMap<>(); b.prev = scratch.prev; fees = 0; txs = "";
            for (Tx tx : seq(toA(scratch.txns,"")).map(t->verifyTx(t,f,md,b,s,kf,log)).sorted((t1, t2)->m*t1.fee/t1.len - m*t2.fee/t2.len).toArray(Tx[]::new))
              if (tx.v == 0 && txs.length() + tx.len < PK_SZ) { fees+=tx.fee; txs+=", "+tx.txt; } // FIXME - below getBytes, not length.... same in TX Ctor.
              else if (tx.v < 0 || tx.v > 2) scratch.txns.remove(tx.txt);
            log(log, "valid new transactions: %s",txs);
            log(log, coinbase = sign(String.format("MINT new mBTC reward %s %d %s for mining", pk58, fees+reward, pk58), s, sk));
            txs = coinbase + txs; root = toHex(md.digest(txs.getBytes(UTF_8)));
            header = asHex(scratch.prev.hash+root+"00000000"); nonce = scratch.state = 0;
          } // "Each node works on finding a difficult proof-of-work for its block" - see reference [1].
          for (int nonce_idx = header.length-4, lim = randN(effort), i = 0; i <  lim && mq.isEmpty(); i++, nonce++) { // randN sets duration
            for (int x = 0, z = 24; x < 4; x++, z-=8) header[nonce_idx+x] = (byte)(nonce >>> z); // convert int to 4 bytes
            byte[] hash = md.digest(header);
            if (fit_p(hash, difficulty) && scratch.state == 0) { // mined new block!!
              scratch.state = 2; block_count++; // "When a node finds a proof-of-work, it broadcasts the block to all nodes" [1].
              mq.push(String.format("BLN\n%s\n%s\n%d %d\n| %s;", toHex(hash), scratch.prev.hash, nonce, System.currentTimeMillis() ,txs)); // : is end packet
              pair=keyGen.generateKeyPair(); sk = pair.getPrivate(); pk58 = to58(pair.getPublic().getEncoded()); w.add(new Cred(pk58, sk)); // replace keys
            }} 
          if (mq.isEmpty() && randN(100) < 30 && block_count > 3) { // in 30% cases, if funds available, may pay to some pk out of w
            if (ads.size() > nodes/4) { // just a heuristic, can be something else
              String ad = ads.elementAt(randN(ads.size()-1)), a[] = ad.split(" "), ppk = a[0], src, sa[], v[], src_pk58;
              int sum = toI(a[1]), fee = randN(sum)/100, has = 0, rem = 0; PrivateKey src_sk=null; //TODO: if from miner, check that miner mined that X blocks ago
              for (Cred p : w.toArray(new Cred[0])) { // pk must have UO that has sum or more and burried deep enough in blockchain
                src_pk58 = p.pk; src_sk = p.sk; src = get(src_pk58,scratch);
                if (get("pending:"+src_pk58,scratch) == null && src != null && get(src,scratch) == null 
                    && ((has = toI((sa=src.split(":"))[0])) >= sum+fee) && scratch.prev.ht - toI(sa[3]) > 3) { // found! 
                  rem = has-sum-fee; // when rem == 0, the 2nd output is 0 btc to _ (nobody)
                  String tx, sh = sa[2]; int si = toI(sa[1]); if(randN(100) > 20) ads.remove(ad); // 20% of posters forget remove ad - sims acidental pk reuse 
                  mq.push(tx=sign(String.format("TXN %tT %d %s %s %d %s %d %s", new Date(), si, sh, src_pk58, sum, ppk, rem, rem==0?"_":pk58), s, src_sk)); 
                  scratch.d.put("pending:"+src_pk58,tx); /*experimental - to avoid double withdrawals*/ //replace keys if rem != 0
                  if (rem != 0) {pair=keyGen.generateKeyPair(); sk = pair.getPrivate(); pk58 = to58(pair.getPublic().getEncoded()); w.add(new Cred(pk58, sk)); }
                  break; // this terminates loop
                }}} else if (ads.size() < nodes && randN(100) < 30) { // advertise some service/goods on 'physical world' ads desk. 
              String adv[] = {"Buying Coins", "Sell Merchandise", "Services", "Charity"}, ad = String.format("%s %d %s", pk58, randN(50000), adv[randN(3)]);
              nodeOut(id, ">" + "posted new craigslist ad: " + ad);
              pair=keyGen.generateKeyPair(); sk = pair.getPrivate(); pk58 = to58(pair.getPublic().getEncoded()); w.add(new Cred(pk58, sk)); ads.push(ad); 
            }}
          if (!mq.isEmpty()) { // from [1]: "New transactions are broadcast to all nodes"
            String msgstr = mq.pop(); if (msgstr.equals("PK+")) msgstr = "PK " + id + " " + pk58;
            byte[] msg = msgstr.getBytes(); if (!msgstr.startsWith("BLN")) Thread.sleep(randN(700)); // still needed
            udpSocket.send(new DatagramPacket(msg, msg.length, ip, 9090)); // test .send(new DatagramPacket("TEST".getBytes(), 4, ip, 9090+2));
            if (nodes <= 10  || msgstr.startsWith("BLN")) nodeOut(id, "> " + msgstr); 
            Thread.sleep(randN(500)); // still must have this delay
            if (msgstr.startsWith("ALL HALT")) // to force all nodes to quit
              for (int i = 0; i < 20; i++, Thread.sleep(100)) // 10 times plus delay is ugly but works
                udpSocket.send(new DatagramPacket(msg, msg.length, ip, 9090));
            else Thread.sleep(100);
          }
        } udpSocket.close(); nodeOut(id, "> sender exiting."); 
      } catch (Exception ex) { ex.printStackTrace(); } }}).start();
  }
  static void startListener(InetAddress ip, int id, Block scratch, KeyFactory kf, Stack<String> mq, MessageDigest md, Vector<Cred> w) {
    (new Thread() { @Override public void run() { 
      try (PrintWriter log = new PrintWriter("n"+id+".log"); PrintWriter bpw = new PrintWriter("balance"+id+".txt")) {
        MulticastSocket mcs = new MulticastSocket(9090); mcs.joinGroup(ip);
        DatagramPacket packet = new DatagramPacket(new byte[PK_SZ], PK_SZ); 
        Signature sig = Signature.getInstance("SHA256withECDSA");
        while (run) { Thread.sleep(randN(500)); mcs.receive(packet); // mcs.receive() waits for something to arrive
          String msg = new String(packet.getData(), packet.getOffset(), packet.getLength());
          if (nodes < 5) nodeOut(id, "< " + msg);
          if (msg.startsWith("TXN") && !scratch.txns.contains(msg)) { // add new record. set state to 1? or not?
            scratch.txns.add(msg); 
          } else if (msg.startsWith("BLN")) { // validate, then acquire new block and chain it
            if (!msg.endsWith(";")) { log.println("ERROR: block packet corrupted. sz:" + msg.length() + " txt: <" + msg + ">"); continue; }
            msg = msg.substring(0, msg.length()-2); // or -1???
            String hdr = msg.substring(0, msg.indexOf("|")), hdr_a[] = hdr.split("[\\r\\n\\s]+"), hash = hdr_a[1], prv = hdr_a[2]; 
            if (scratch.alt != null) { // time to resolve conflict.  // TODO: think about this and acceptTx....
              if (prv.equals(scratch.alt.hash)) 
                scratch.prev = scratch.alt; // "Nodes always consider the longest chain to be the correct one"[1]
              scratch.alt = null; 
            } // next, verify txns. "Nodes accept the block only if all transactions in it are valid and not already spent"[1] 
            String h="", txa[] = msg.substring(msg.indexOf("|")+2).split(", "); int i=txa.length-1; // Q: what about those already accepted??
            List<String> txns = Arrays.asList(txa); // we want to make sure none of the new txns are stored in prev blocks!
            Block b = new Block(), sp = scratch.prev, sa = scratch.alt;  // Nodes express their acceptance of the block by working on creating the next block  
            b.d = new HashMap<>(); // in the chain, using the hash of the accepted block as the previous hash - [1]
            if (!prv.equals(scratch.prev.hash)) { // very rare
              if (prv.equals(scratch.prev.prev.hash)) { // contestant
                b.prev = scratch.prev.prev;  
                b.ht = b.prev.ht+1; scratch.alt = b; // "save the other branch in case it becomes longer"[1]
              } else log.println("ERROR: seriously orphane block, not linking into chain. s.p.h:" + scratch.prev.hash + " block: " +  msg);
            } else { b.prev = scratch.prev; scratch.prev = b; b.ht = b.prev.ht+1; } // normal case
            for (int fee[] = {0}; i >= 0 && verifyTx(txa[i], fee, md, b, sig, kf, log).v == 0; i--); // done backwads to compute fees
            if (i == -1) { // all transactions valid and accepted. note: above, consider passing i in to check that i=0 is MINT
              b.hash = hdr_a[1]; b.nonce = toI(hdr_a[3]); b.stamp = Long.parseLong(hdr_a[4]); 
              (b.txns = new TreeSet<>((x, y)->x.compareTo(y))).addAll(txns); scratch.state = 2; scratch.txns.removeAll(txns); 
            } else { log.println("block's nth n="+i+" txn is invalid, rejecting whole block: " + msg); scratch.prev = sp; scratch.alt = sa; }
            int sum = map(w,c->get(c.pk,scratch)).filter(v->v!=null)
              .mapToInt(s->map(s.split("/"),v->v.split(":")).filter(v->get(v[1]+":"+v[2],scratch)==null).mapToInt(v->toI(v[0])).sum()).sum();
            bpw.printf("At %tc your BTC balance is: %8.3f \n", new Date(), ((double)sum)/1000.0); bpw.flush();
          }} // stop run, report
        String blockchain = "", h_txn = ""; Block s = scratch;
        for (Block b = s.prev; b.prev != null; b = b.prev, h_txn = "") { //log.println("B:"+b.hash+" txns: "+txt(b));
          for (String txn : b.txns.toArray(new String[0])) h_txn += to58(md.digest(txn.getBytes(UTF_8))) + ":" + txn;
          blockchain = String.format("Block: %d\nmined: %tc\n hash: %s\n prev: %s\nnonce: %d\n txns:\n%s\n\n", b.ht,
                                     new Date(b.stamp), b.hash, b.prev.hash, b.nonce, h_txn) + blockchain;
        } 
        try (PrintWriter pw = new PrintWriter("blockchain"+id+".txt")) { pw.println(blockchain); }
        log(bpw, "\nWallet balances\n", "", map(w,c->gall(c.pk,s)+" on key "+c.pk+".\n: : :").filter(st->!st.startsWith(" on"))
            .map(st->map(st.split("/"),e->e.split(":"))
                 .filter(r->r[0].charAt(0)==' '||get(r[1]+":"+r[2],s)==null).map(a->a[0]).reduce("you have available mBTC: ",(a,b)->a+" "+b))
            .map(v->v.replaceAll(" +", " ")).filter(v->v.indexOf(": on")<0));
        log(bpw, "\nSpending history\n", "",   map(w,c->gall(c.pk,s)+" on key "+c.pk+".\n: : :").filter(st->!st.startsWith(" on"))
            .map(st->map(st.split("/"),e->e.split(":"))
                 .filter(r->r[0].charAt(0)==' '||get(r[1]+":"+r[2],s)!=null).map(a->a[0]).reduce("you spent|redeemed mBTC: ",(a,b)->a+" "+b))
            .map(v->v.replaceAll(" +", " ")).filter(v->v.indexOf(": on")<0));
        nodeOut(id, "> listener exiting."); mcs.leaveGroup(ip); mcs.close();
        } catch (Exception ex) { ex.printStackTrace(); }}}).start();
  }
  static java.util.stream.Stream<Cred> sCred(Collection<Cred> c) { return c.stream(); }
  static <T>   java.util.stream.Stream<T> seq(Collection<T> c) { return c.stream(); }
  static <T>   java.util.stream.Stream<T> seq(T[] a) { return Arrays.stream(a); }
  static <X,Y> java.util.stream.Stream<Y> map(X[] a, java.util.function.Function<? super X,? extends Y> f) { return seq(a).map(f); }
  static <X,Y> java.util.stream.Stream<Y> map(Collection<X>c, java.util.function.Function<? super X,? extends Y> f) { return seq(c).map(f); }
  static <T> void log(PrintWriter pw, String hdr, String sep, java.util.stream.Stream<T> s) { pw.println(s.map(e->""+e).reduce(hdr,(a,b)->a+sep+b)); }
  @SuppressWarnings("unchecked") // from Stackoverflow
  static <T> T[] toA(Collection<T> c, Object e) { synchronized(c) {return c.toArray((T[])java.lang.reflect.Array.newInstance(e.getClass(), c.size()));}}
  static int randN(int range) { return (int)Math.round(Math.random()*range); }
  static void nodeOut(int id, String m) { 
    System.out.println("node" + id + (m = nodes >= 5 ? map(m.split(" "),s->s.startsWith("BL")?s:abbrev("",s,8,20)).reduce("",(a,b)->a+" "+b).trim():m));
  }
  static String txt(Set<String> s) { return Arrays.toString(s.toArray(new String[0])); }
  static boolean fit_p(byte[] hash, final int dif) { // does hash have given difficulty?
    for (int i = 0; i < dif/2/8; i++) if (hash[i] != 0) return false;
    return ((int)hash[dif/2/8] & 0xff) < (1 << (8 - dif%8));
  }
  static String toHex(byte[] data) { // this is 10% faster than a shorter s+= variant
    StringBuilder sb = new StringBuilder();
    for (byte b: data) sb.append(String.format("%02x", b&0xff));
    return sb.toString();
  }
  static String abbrev(String b, String s, int d, int m) { int l=s.length(); return l < m ? s : b+s.substring(0, 3)+".."+s.substring(s.length()-d);}
  static byte[] asHex(String s) { // from stackoverflow
    int len = s.length(); byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2)
      data[i / 2] = (byte)((Character.digit(s.charAt(i), 16) << 4)+ Character.digit(s.charAt(i+1), 16));
    return data;
  }
  static String get(String k, Block b)  { String r=null; for (; b.prev != null && r == null; b = b.prev) r = b.d.get(k); return r; }
  static String gall(String k, Block b) { String v,r=E;  for (; b.prev != null; b = b.prev) if ((v=b.d.get(k))!=null) r+=v; return r; }
  static double toD(String v) { return Double.parseDouble(v); } static int toI(String v) { return Integer .parseInt(v); }
  static String log(PrintWriter log, String f, Object... a) { String m=String.format(f, a); if (log != null) log.println(m); log.flush(); return m; }
  static Tx logTx(PrintWriter log, String msg, int stat, Tx tx) { if(log != null) log.println(msg+tx.txt); tx.v = stat; return tx; }
  static Tx verifyTx(String t, int[] fees, MessageDigest md, Block b, Signature s, KeyFactory kf, PrintWriter log) { 
    Tx tx = new Tx(t); String h = tx.id = to58(md.digest(t.getBytes(UTF_8))),a[] = tx.a, prev = "", preva[]=null; int outN = -1; 
    try { 
      s.initVerify(kf.generatePublic(new X509EncodedKeySpec(as58(a[4])))); s.update(t.substring(0, t.lastIndexOf(" SIG")).getBytes((UTF_8)));
      if (!s.verify(as58(a[10]))) return logTx(log,"bad signature in ", -1, tx);
      if ((prev=get(h, b)) != null) return logTx(log, "tx previously included in a block, ", 1+b.ht-toI(prev.substring(1+prev.lastIndexOf(":"))), tx);
      if (a[0].equals("MINT")) { // if tx is MINT, fees contains the sum of fees of all block's TXN txs.
        if (toI(a[5]) != fees[0]+reward) return logTx(log, "coinbase wrong amount ", -1, tx); 
      } else { 
        if ((prev=get(a[3], b)) == null) return logTx(log, "prev tx not found ", -1, tx);  else preva = prev.split(" ");
        if (!preva[(outN=toI(a[2]))+1].equals(a[4])) return logTx(log, "in-pk |"+(a[4])+"|and prev tx's out pk |"+preva[outN+1]+"| differ ", -1, tx); 
        if (get(a[2]+":"+a[3],b) != null) return logTx(log, "input is already spent ", -1, tx); 
        if ((tx.fee=toI(preva[outN]) - toI(a[7]) - toI(a[5])) < 0) return logTx(log, "tx src not enough balance", -1, tx); else fees[0]+=tx.fee;
      } // was: acceptTx(tx, h, atr, b.d, b.ht, 5, 7);
      b.d.put(a[2]+":"+a[3],t+":"+b.ht); b.d.put(h, t+":"+b.ht); for(int i=5;i<=7;i+=2) b.d.put(a[i+1], a[i]+":"+i+":"+h+":"+b.ht+":/"+b.d.getOrDefault(a[i+1],"")); 
    } catch (Exception e) { return logTx(log, e+": verification failed. tx:", -1, tx); } return tx;
  }
  static String sign(String msg, Signature s, PrivateKey sk) throws Exception {
    s.initSign(sk); s.update(msg.getBytes(UTF_8));
    return msg + " SIG " + to58(s.sign()) + " \n"; // last space is important, see txn.split(" ")!
  }
  static final String ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"; 
  static final char A1 = ALPH.charAt(0); static final BigInteger A_SZ = BigInteger.valueOf(ALPH.length());
  static String to58(byte[] data) { // see https://github.com/nayuki/Bitcoin-Cryptography-Library/blob/master/java/io/nayuki/bitcoin/crypto/Base58Check.java
    StringBuilder sb = new StringBuilder();
    for (BigInteger quotrem[], num = new BigInteger(1, data); num.signum() != 0; num = quotrem[0])
      sb.append(ALPH.charAt((quotrem = num.divideAndRemainder(A_SZ))[1].intValue()));
    for (int i = 0; i < data.length && data[i] == 0; i++) sb.append(A1);
    return  sb.reverse().toString();
  }
  static byte[] as58(final String s) throws IOException { // see https://github.com/nayuki/...
    BigInteger n = BigInteger.ZERO;
    for (int d, i = 0; i < s.length(); i++, n = (n.multiply(A_SZ)).add(BigInteger.valueOf(d)))
      d = ALPH.indexOf(s.charAt(i));
    byte[] b = n.toByteArray();  if (b[0] == 0) b = Arrays.copyOfRange(b, 1, b.length);
    ByteArrayOutputStream buf = new ByteArrayOutputStream();
    for (int i = 0; i < s.length() && s.charAt(i) == A1; i++) buf.write(0);
    buf.write(b); return buf.toByteArray();
  }
} // References: [1] Satoshi Nakamoto, "Bitcoin: A Peer-to-Peer Electronic Cash System",2008

// DEBUG
//    public String toString() { return String.format("{Tx %s %d %d %d %s}", id, v, fee, len, txt); }}

// NOTES 

// V1 is alomost DONE, V2 is coming soon!!!

// This is one the last few updates in CryptoBlockChain version V1
// based on simple, 1in-2-out transaction structure of fixed size and
// hard-coded verification process. All further updates will support
// transactions with variable number of ins and outs and FORTH-like,
// stack-machine based verification. 

// Current update of V1 is 212 lines of code, well under the announced
// limit of 300. The final version of V1 may be reformatted to be a bit
// more sparse, still under 300 lines. The version V2 may be a bit
// longer (in sparse variant) than 300, still will be always below
// 500 lines of self-contained code.

// CHANGES

// Introduced class Tx and verification with tx ordering and selection
// as follows (see also TestTxSelection.java).

// 1. With the block size fixed and limited (16 or 32k or so) the step
// of transaction verification in miner threads should include logic
// for reducing the batch to fit.  
//
// 2. The miner can gain in reward if before the transactions are
// pruned, they are ordered using fee per byte factor. Method verifyTx
// now returns class Tx {boolean ok; int fee; int len; String txt;}
// and
//
// txs = seq(scratch.txns).filter(t->null!=verifyTx(t,fee,md,b,sig,kf,log)).reduce("",(x,y)->x+", "+y));
// 
// became
//
// int fees = 0; String txs = "";
// for (Tx tx : seq(scratch.txns).map(t->verifyTx(t,md,b,sig,kf,log)).filter(t->t.ok)
//              .sorted((t1, t2)->1000*t1.fee/t1.len - 1000*t2.fee/t2.len).toArray(Tx[]::new))
//   { if (txs.length() + tx.len > TXLMX) break; fees+=tx.fee; txs+=tx.txt; }

// 3. As transactions verification in miner threads now includes
// accepting transactions into some b.d, question is what to do with
// those that fail verification. Mark them as bad or even remove from
// scratch.d or re-try again each time?  In old versions, the later
// happens all the time, with time wasted on it. There is only one
// advantage - if forking rearranges the chain, no bookkeeping is
// required. The following has been implemented in this update: if the
// 'cause' of rejection is some txn that is N blocks deep (3 is good
// enough) then such txn can be permanently removed from scratch.d. It
// looks as only those that depend on a txn in the same (not-yet
// mined) block, or 1 or up to 2 blocks down can be kept. Those with
// bad signatures, bad balance, bad tx hash etc etc are be permanently
// removed.  This is done with the class Tx shown above with status
// field v being int and filtering removed and v==0 set for valid TX
// with UO, 1 for SO depth 1, 2 for depth 2 and so on.  The for loop
// then does the following 3 things: accumulates valid txs with UOs,
// removes from scratch invalid ones with ok < 0 or ok > depth
// threshold and keeps the rest, see for (Tx tx :
// seq(scratch.txns).map(..) loop above.

// 4. In listeners, block verification includes hashing the
// transactions and doing
//
// if (!toHex(md.digest(prv+root+form("%x08",nonce)).getBytes(UTF_8))).equals(hash)) { out("Verification FAILED, block hash is wrong: " + hash); continue; }

// 5. Height. Added blockchain 'height' index in each
// block. alternative exists - a simple loop to get it. height(b) ->
// int with -1, -2, -3 etc meaning block has broken link that deep.

//  Ideas, possible TODO

// Block per hour. It is easy to switch to framework with automatic
// difficulty adjustment (chapter 4 of [1]). some part of the system
// needs to measure average block rate and change difficulty
// correspondingly. User can set -DBTH to desired value. Difficulty
// would start low to quickly mint a lot of coins and then gradually
// increase to deliver BTH blocks per hour on average.

// Maybe...Coinbase transactions probably should award to a new pk. currently
// 3rd and 6th fields are the same pk.

// Asking. node must be able to ask the network about a missing block
// or get the whole chain.  What about the asking node switching to a
// separate channel, or better, spawning a special thread to collect
// the responses?

// Maybe...The 'top set' concept. A node maintains a list of tops each leading to
// the same root (zero block) each being verified and containing valid
// txns. if there is more than one, and all of the same height, then
// node is not yet able to find the longest chain. txn count does not
// matter. longest chain wins.  Q: should the other ones (shorter) be
// immediately flashed or kept just in case? Maybe the later is more
// interesting.

// possibly, review and improve the 'spent out' detection. currently -
// pk is marked 'spent' in a block.d.

// multiple processes: late-comer must name the nodes (or at least,
// files) differently, how? simple hack: asking. asking the net about
// the value of 'nodes' and start from there.  simplest solution is
// cluster name: java -Dcluster=SF java -Dcluster=MY java
// -Dcluster=LA. Yet even simpler to run each cluster in a separate
// 'home' dir.

// Command line options: perhaps, switch from args[] to props:
// CryptoBlockChain -Dn=7 -Dd=49 -Dcoin=XYZCoin ....  int difficulty =
// toI(sprop("d","48")), nodes = toI(sprop("n", "7")

// Streams: byte stream does not work static String toHex2(byte[] d) {
// return Arrays.stream(d).map(b->String.format("%02x",
// b&0xff)).reduce("",(a,b)->a+b); }
