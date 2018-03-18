import java.util.*; import java.io.*; import java.net.*; import java.math.*;
import java.security.*; import java.security.spec.*; import static java.nio.charset.StandardCharsets.UTF_8; 

public class ForthLikeScriptingVerification {
  static class Block { String hash; int ht, state, nonce; Block prev, alt; Set<String> txns; HashMap<String,String>d; long stamp;}
  static int reward=50000; 
  static final String E = "";
    
  public static void main(String argv[]) throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC"); keyGen.initialize(256,SecureRandom.getInstance("SHA1PRNG")); 
    KeyPair pair = keyGen.generateKeyPair(); PrivateKey sk = pair.getPrivate(); 
    String pk58 = to58(pair.getPublic().getEncoded());
    Signature s = Signature.getInstance("SHA256withECDSA"); KeyFactory kf = KeyFactory.getInstance("EC"); //move up!
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    Block b = new Block(); b.d = new HashMap<>(); b.prev = new Block();

    // general Tx script format: 
    //
    // TXN signature* VDATE timestamp pk prev_tx_idx prev_tx_id CALL +* OPK scriptsz pkidx..... coins RET TXE
    //
    // 1in, 1 pk-check out: TXN s VDATE timestamp pk 6 asd..fgd CALL OPK 9 4 DUP pk ERRIFNEQ PK PKSIG coins RET TXE
    //
    // any number of sigs+impus and any number of outs. 2 in 2 out:
    //
    // TXN s s VDATE tm pk 6 asd..fgd CALL 1 SIGI ... CALL + OPK 9 4 DUP pk ERRIFNEQ PK PKSIG coins RET OPK 9 4 ... RET TXE
    // 
    // note OPK does subtraction, call does not do summation, hence after the last CALL n-1 + where N is number of inputs:
    //
    // txn output with pk hash can be: OPK 10 5 DUP SHA256 pkh ERRIFNEQ PK-hash PKSIG coins RET TXE


    // pk58's unspent ouput starts at index 6.
    //                0    1   2     3   4 5 6
    String prev_tx = "MINT new coins OPK 9 4 DUP "+pk58+" ERRIFNEQ PK-missmatch! PKSIG 50000 RET . . .  TXE";
    String prev_tx_hash = to58(md.digest(prev_tx.getBytes(UTF_8))); b.d.put(prev_tx_hash, prev_tx);
    
    String new_pk_1      = argv.length > 0 ? argv[0] : "new_pk_1";
    String new_pk_2_hash = argv.length > 1 ? argv[1] : "new_pk_2_hash";
    // ownter of prev_tx output consumes it and pays 25699 to pk new_pk_1 and 10000 to address new_pk_2_hash
    String tx = "VDATE "+System.currentTimeMillis()+" "+pk58+" 6 "+prev_tx_hash+" CALL"+
      " OPK 9 4 DUP "+new_pk_1+" ERRIFNEQ PK-missmatch PKSIG 25699 RET"+
      " OPK 10 5 DUP SHA256 "+new_pk_2_hash+" ERRIFNEQ PK-hash PKSIG 10000 RET TXE";
    tx = "TXN " + sign(tx, s, sk) +" "+ tx;
    // alternatively: sign pk58+" "+tx
    trace(""+new VerifyTx(new Tx(to58(md.digest(tx.getBytes(UTF_8))), tx), new PrintWriter(System.out))
          .verify(md, b, s, kf));
  }

  static class Tx { Tx(String h, String v) { id = h; txt = v; a = txt.split(" "); } 
    String id, txt, a[], siga[], ins = "", ous = ""; int fee, len, ti, v; boolean ok; // Tx state
    public String toString() { return String.format("{Tx %s %d %d %b %d %s %s}", id, fee, len, ok, v, ins, ous); }
  }
  static class VerifyTx { VerifyTx(Tx tx, PrintWriter w) { t=tx; pw=w;} // Runs u-FORTH machine for verification and acceptance
    PrintWriter pw;
    Tx t; String s1, s2, s3, a[]; int i1, i2; // temp 'registers'
    String[] ds = new String[20]; int dsi = -1, sz = 0; // data stack
    Tx rst[] = new Tx[10]; int ti = 1, rsi = -1; // return stack and its top 'cache'
    Tx retLog(int val, String msg, Object... a) { if(pw != null) pw.format(msg+"\n", a); pw.flush(); t.v = val; return t;}

    int popI() { return toI(ds[dsi--]); } long popL() { return toL(ds[dsi--]); }
    // returns Tx with flags/data and logs errors
    Tx verify(MessageDigest md, Block b, Signature s, KeyFactory kf) throws Exception { 
      int go = 100; 
      for (String w = ""; go>0; ti++, go--) {
        switch (w=trace((t.a[ti]))) {
        default: ds[++dsi] = w; trace("dsi:"+dsi);break;
        case "CALL": s1 = ds[dsi--]; if ((s2=get(s1,b))== null) return retLog(-1,"no such tx"); 
          i1 = popI(); if (get(s3=s1+":"+i1,b) != null) return retLog(-1,"output spent"); 
          t.ins+=s3+"/"; rst[++rsi] = t; t.ti = ti; t = new Tx(s1,s2); ti = i1-1;          trace("dsi:"+dsi);break;
        case "RET": t = rst[rsi--];  ti = t.ti; trace("dsi:"+dsi);break;
        case "DUP": ds[++dsi] = ds[dsi-1]; trace("dsi:"+dsi);break; // LHS ev 1st
        case "+": i1 = toI(ds[dsi--]) + toI(ds[dsi--]); ds[++dsi] = ""+i1; trace("dsi:"+dsi);break; // LHS ev 1st
        case "VDATE": if(toL(t.a[++ti]) > System.currentTimeMillis()) return retLog(-1,"too early"); trace("dsi:"+dsi);break;
        case "PKSIG": s.initVerify(kf.generatePublic(new X509EncodedKeySpec(as58(ds[dsi--])))); s.update(rst[rsi].txt.substring(rst[rsi].txt.indexOf("VDATE")).getBytes((UTF_8)));
            if (!s.verify(as58(ds[dsi--]))) return retLog(-1,"bad signature"); trace("dsi:"+dsi);break;
        case "OPK": ds[dsi]= ""+(toI(ds[dsi])-toI(s1=t.a[i1=-1+ti+toI(t.a[ti+1])]));
          t.ous+=t.a[ti+toI(t.a[ti+2])]+":"+s1+":"+i1+"/"; ti=i1+1; trace("dsi:"+dsi);break;
        case "TXE": if ((t.fee=popI()) < 0) return retLog(-1,"tx out > tx in"); t.ok = true; t.v=0; 
          map(t.ins.split("/"),k->b.d.put(k,t.txt)); b.d.put(t.id, t.txt); 
          for (String r : t.ous.split("/")) { a=r.split(":"); b.d.put(a[0], f("%s:%s:%s:%s:/%s",a[1],a[2],t.id,b.ht,b.d.getOrDefault(a[0],"")));}
          trace("dsi:"+dsi);  return t;
        case "SHA256": ds[dsi] = to58(md.digest(ds[dsi].getBytes(UTF_8))); trace("dsi:"+dsi);break;
        case "ERRIFNEQ": if (!(s1=ds[dsi--]).equals(s2=ds[dsi--])) return retLog(-1,"Error: %s %s and %s",t.a[ti+1],s1,s2); ti++; trace("dsi:"+dsi);break;
        }}
      return retLog(-1,"tx has too many commands");
    }}

  static String f(String s, Object... a) { return String.format(s, a); } static String trace(String m) { System.out.println(f("<%s>",m)); return m; }
  static String get(String k, Block b)  { String r=null; for (; b.prev != null && r == null; b = b.prev) r = b.d.get(k); return r; }

  //===============================================================================================================
  static <T>   java.util.stream.Stream<T> seq(Collection<T> c) { return c.stream(); }
  static <T>   java.util.stream.Stream<T> seq(T[] a) { return Arrays.stream(a); }
  static <X,Y> java.util.stream.Stream<Y> map(X[] a, java.util.function.Function<? super X,? extends Y> f) { return seq(a).map(f); }
  static <X,Y> java.util.stream.Stream<Y> map(Collection<X>c, java.util.function.Function<? super X,? extends Y> f) { return seq(c).map(f); }
  static <T> void log(PrintWriter pw, String hdr, String sep, java.util.stream.Stream<T> s) { pw.println(s.map(e->""+e).reduce(hdr,(a,b)->a+sep+b)); }
  @SuppressWarnings("unchecked") // from Stackoverflow
  static <T> T[] toA(Collection<T> c, Object e) { return c.toArray((T[])java.lang.reflect.Array.newInstance(e.getClass(), c.size())); }
  static int randN(int range) { return (int)Math.round(Math.random()*range); }

  static String txt(Set<String> s) { return Arrays.toString(s.toArray(new String[0])); }
  static boolean fit_p(byte[] hash, final int dif) { // does hash have given difficulty?
    for (int i = 0; i < dif/2/8; i++) if (hash[i] != 0) return false;
    return ((int)hash[dif/2/8] & 0xff) < (1 << (8 - dif%8));
  }
  static String toHex(byte[] data) {
    StringBuilder sb = new StringBuilder();
    for (byte b: data) sb.append(String.format("%02x", b&0xff));
    return sb.toString();
  }
  static String abbrev(String b, String s, int d, int m) { int l=s.length(); return l < m ? s : b+s.substring(0, d)+"..."+s.substring(s.length()-d);}
  static byte[] asHex(String s) { // from stackoverflow
    int len = s.length(); byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2)
      data[i / 2] = (byte)((Character.digit(s.charAt(i), 16) << 4)+ Character.digit(s.charAt(i+1), 16));
    return data;
  }

  // static String get(String k, Block b)  { String r=null; for (; b.prev != null && r == null; b = b.prev) r = b.d.get(k); return r; }
  static String gall(String k, Block b) { String v,r=E;  for (; b.prev != null; b = b.prev) if ((v=b.d.get(k))!=null) r+=v; return r; }
  static double toD(String v) { return Double.parseDouble(v); } static int toI(String v) { return Integer .parseInt(v); }
  static long toL(String v) { return Long.parseLong(v); }
  static String log(PrintWriter log, String f, Object... a) { String m=String.format(f, a); if (log != null) log.println(m); log.flush(); return m; }
  static String logVal(PrintWriter log, String msg, String val) { if(log != null) log.println(msg); return val; }
  static String sign(String msg, Signature s, PrivateKey sk) throws Exception {
    s.initSign(sk); s.update(msg.getBytes(UTF_8));
    return to58(s.sign());
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
} 

// NOTES

// Previous version contained signature* count SIG as preamble and
// sig_idx SIGI to get specific sigature onto stack butit is easy to
// see that tehse are not needed, hence moving the old example and SIg
// and SIGI word definitions here.

//  // general format: TXN signature* count SIG [timestamp VDATE] sig_idx SIGI pk prev_tx_idx prev_tx_id CALL OPK scriptsz pkidx..... coins RET TXE
//  // 1in, 1 pk-check out: TXN s 1 SIG timestamp VDATE 0 SIGI pk 6 asd..fgd CALL OPK 9 4 DUP pk ERRIFNEQ PK PKSIG coins RET TXE
//  // any number of sigs+impus and any number of outs. 2 in 2 out:
//  // TXN s s 2 SIG tm VDATE 0 SIGI pk 6 asd..fgd CALL 1 SIGI ... CALL + OPK 9 4 DUP pk ERRIFNEQ PK PKSIG coins RET OPK 9 4 ... RET TXE
//  // note OPK does subtraction, call does not do summation, hence after the last CALL n-1 + where N is number of inputs
//  // txn output with pk hash  can be: OPK 10 5 DUP SHA256 pkh ERRIFNEQ PK-hash PKSIG coins RET TXE
//  static String tx = "TXN AN1rKvtGkfApxfpj4Ht31N8ZCYYAvjLQvVadB8FVR7qXLWxXGM6fLjs2sc2TMk4THWTR5onYXmQcfyVDNbDzEK9moMHExRUNP 1 SIG 1520221955783 VDATE 0 SIGI aSq9DsNNvGhYxYyqA9wd2eduEAZ5AXWgJTbTKNhkbFdjL6LR6m4WBPBs1Kc5p6Ci1mWQFrryp12Q7wNAVFGLU7fHiNgJHdF8Cwqnn1WnwZcKt83N9Mz1FxA2ZMXR 6 4FnwBH9R1dzsgbdbFkMmsUAKcnrXfjvJGnHktiBZcxLz CALL OPK 9 4 DUP aSq9DsNNvGhYxYyqA9wd2eduEAZ5AXWgJTbTG9tsvAJhmjNhUQQNbwdGWFL8PchqxfoGfgDm94uWKR9JZPuC7C9j6j6n6xTCjTRCWJr1NiFMqbqzWcomSjSDxQdd ERRIFNEQ PK-missmatch PKSIG 25699 RET OPK 10 5 DUP SHA256 pkh ERRIFNEQ PK-hash PKSIG 10000 RET TXE";

//         case "SIG": sz = popI(); t.siga = new String[sz]; for (; --sz >= 0;) t.siga[sz] = ds[dsi--]; trace("dsi:"+dsi);break;
//         case "SIGI": ds[dsi] = t.siga[toI(ds[dsi])]; trace("dsi:"+dsi);break;

// IDEAS

// Currenty the payment script is activated with CALL, idx and txid
// are taken fromt he stack, converted to txid:idx for lookup and if
// something is thre, the input is spent. txid's text is fetched
// separately. There is more interesting way to deal with it, with
// CALL no longer needed: consider txid:idx as reference to compiled
// def in FORTH. it points into the midel of a tx - script to
// interpret to get paid - or it can point to a predefined script that gives "in
// txn xyz inpit N is spent".  a few more word definitinas are reuired
// but the system becomes flexible and can support other "threaded"
// definitions.

// With a separate dictionary of block, call it td, that is
// HashMap<String,Tx> one can have tx and scrpt references pointing to
// that where splitting is already done.


// code snippets ect

// // return stack with no cache - very hard!
// static String verifyTx_no_rs_cache(String tx, int[] fees, MessageDigest md, Block b, Signature s, KeyFactory kf, PrintWriter log) { 
//   // return stacks and pointer 
//   Tx[] rstx = new Tx[10]; int rsi = -1; String a[] = null;
//   // data stack
//   String[] ds = new String[20]; int dsi = -1, sz = 0;
//   rstx[++rsi] = new Tx(tx); rstx[rsi].i = 1;
//   boolean go = true; 
//   for (String w = ""; go; rstx[rsi].i++) {
//     switch (w=(rstx[rsi].a[rstx[rsi].i])) {
//     case "SIG": 
//       sz = toI(ds[dsi--]); a = new String[sz];  
//       for (; --sz >= 0;) a[sz] = ds[dsi--]; rstx[rsi].siga = a; break;
//     case "VDATE": if(toL(ds[--dsi]) > System.currentTimeMillis()) return logVal(log, "too early", null);
//     default: ds[dsi++] = w; 
//     }}
//   return null;
// }


