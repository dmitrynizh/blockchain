import java.util.*; import java.io.*; import java.net.*; import java.math.*;
import java.security.*; import java.security.spec.*; import static java.nio.charset.StandardCharsets.UTF_8; 

public class ForthLikeScriptingVerification {
  static class Block { String hash; int ht, state, nonce; Block prev, alt; Set<String> txns; HashMap<String,String>d; long stamp;}

  static int nodes, difficulty, effort, blockMx, reward=50000; static class Cred { String pk; PrivateKey sk; Cred(String p, PrivateKey s) {pk=p;sk=s;}} 
  static volatile int block_count; static volatile boolean run = true; static Stack<String> ads = new Stack<>(); static final String E = "";


  static String prev_tx = "MINT new coins _ _ OPK aSq9DsNNvGhYxYyqA9wd2eduEAZ5AXWgJTbTKNhkbFdjL6LR6m4WBPBs1Kc5p6Ci1mWQFrryp12Q7wNAVFGLU7fHiNgJHdF8Cwqnn1WnwZcKt83N9Mz1FxA2ZMXR 50000 PKSIG RET _ _   ",
  // this is actual text that was signed...
    real_signed_text = "TXN 19:32:07 5 4FnwBH9R1dzsgbdbFkMmsUAKcnrXfjvJGnHktiBZcxLz aSq9DsNNvGhYxYyqA9wd2eduEAZ5AXWgJTbTKNhkbFdjL6LR6m4WBPBs1Kc5p6Ci1mWQFrryp12Q7wNAVFGLU7fHiNgJHdF8Cwqnn1WnwZcKt83N9Mz1FxA2ZMXR 25699 aSq9DsNNvGhYxYyqA9wd2eduEAZ5AXWgJTbTG9tsvAJhmjNhUQQNbwdGWFL8PchqxfoGfgDm94uWKR9JZPuC7C9j6j6n6xTCjTRCWJr1NiFMqbqzWcomSjSDxQdd 24120 aSq9DsNNvGhYxYyqA9wd2eduEAZ5AXWgJTbTGCg2EgMipnLwbCq1L23x7DabKnznzAE7LtGd9qVZdx9czmR7GS9vU5XkgATpLfk3BEqFsctXQdpxA3HGfbPzNhJE", 

  // format: TXN signature* count SIG timestamp VDATE sig_idx SIGI pk prev_tx_idx prev_tx_id CALL OPK pk coins PKSIG RET TXE
    tx = "TXN AN1rKvtGkfApxfpj4Ht31N8ZCYYAvjLQvVadB8FVR7qXLWxXGM6fLjs2sc2TMk4THWTR5onYXmQcfyVDNbDzEK9moMHExRUNP 1 SIG 1520221955783 VDATE " +
    "0 SIGI aSq9DsNNvGhYxYyqA9wd2eduEAZ5AXWgJTbTKNhkbFdjL6LR6m4WBPBs1Kc5p6Ci1mWQFrryp12Q7wNAVFGLU7fHiNgJHdF8Cwqnn1WnwZcKt83N9Mz1FxA2ZMXR 6 " +
    "4FnwBH9R1dzsgbdbFkMmsUAKcnrXfjvJGnHktiBZcxLz CALL " +
    "OPK aSq9DsNNvGhYxYyqA9wd2eduEAZ5AXWgJTbTG9tsvAJhmjNhUQQNbwdGWFL8PchqxfoGfgDm94uWKR9JZPuC7C9j6j6n6xTCjTRCWJr1NiFMqbqzWcomSjSDxQdd 25699 PKSIG RET TXE";
    
  public static void main(String argv[]) throws Exception { new ForthLikeScriptingVerification().test(); }
  void test () throws Exception {
    Block b = new Block(); b.d = new HashMap<>();  
    trace(""+new TxVerifier().verify(tx, MessageDigest.getInstance("SHA-256"), b, 
                            Signature.getInstance("SHA256withECDSA"), KeyFactory.getInstance("EC"), 
                                  new PrintWriter(System.out)));
  }

  static class Tx {
    String hash; int fee; int len; String txt; boolean ok; int v; String[]  a; String[] siga; int i;
    Tx(String h, String v) { hash = h; txt = v; a = txt.split(" "); } 
    public String toString() { return String.format("{Tx %s %d %d %b %d %s}", hash, fee, len, ok, v, txt); }
  };

  class TxVerifier {
    String s1 = "", s2=""; int  i1=0, i2=0; // temp 'registers'
    String[] ds = new String[20]; int dsi = -1, sz = 0; // data stack
    int popI() { return toI(ds[dsi--]); } long popL() { return toL(ds[dsi--]); }
    Tx rst[] = new Tx[10], t; int ti = 1, rsi = -1; // return stack and its top 'cache'
    // returns Tx with flags/data and logs errors
    Tx verify(String txt, MessageDigest md, Block b, Signature s, KeyFactory kf, PrintWriter log) { 
      int go = 100; t = new Tx(to58(md.digest(txt.getBytes(UTF_8))), txt);
      for (String w = ""; go>0; ti++, go--) {
        switch (w=trace((t.a[ti]))) {
        case "CALL": s1 = ds[dsi--]; if ((s2=get(s1,b))== null) return retLog(log, "no such tx", -1, t); 
          i1 = popI(); if (get(s1+":"+i1,b) != null) return retLog(log, "output spent", -1, t); 
          rst[++rsi] = t; t.i = ti; t = new Tx(s1,s2); ti = i1-1; break;
        case "RET": t = rst[rsi--];  ti = t.i; break;
        case "SIG": sz = popI(); t.siga = new String[sz]; for (; --sz >= 0;) t.siga[sz] = ds[dsi--]; break;
        case "VDATE": if(popL() > System.currentTimeMillis()) return retLog(log, "too early", -1, t); break;
        case "SIGI": ds[dsi] = t.siga[toI(ds[dsi])]; break;
        case "PKSIG": try {  i1 = popI(); if(!(s1=ds[dsi--]).equals(ds[dsi--])) return retLog(log, "in/out pk mismatch", -1, t); 
            s.initVerify(kf.generatePublic(new X509EncodedKeySpec(as58(s1)))); s.update(real_signed_text.getBytes((UTF_8)));
            if (!s.verify(as58(ds[dsi--]))) return retLog(log,"bad signature", -1, t); ds[++dsi] = ""+i1;
          } catch (Exception e) { return retLog(log, e+": verification failed", -1, t); }  break;
        case "OPK": ds[dsi]  = ""+(toI(ds[dsi]) - toI(t.a[ti+2])); ti+=5; break;
        case "TXE": if ((t.fee=popI()) < 0) return retLog(log,"tx out > tx in", -1, t); t.ok = true; t.v=0; return t;
        default: ds[++dsi] = w; 
        }}
      return retLog(log,"tx has too many commands", -1, t);
    }}

  static String get(String k, Block b)  { return k.equals("4FnwBH9R1dzsgbdbFkMmsUAKcnrXfjvJGnHktiBZcxLz") ? prev_tx : null; }
  static Tx retLog(PrintWriter log, String msg, int v,Tx t) { if(log != null) log.println(msg); log.flush(); t.v = v; return t; }
  static String trace(String msg) { System.out.println("<<" + msg + ">>"); return msg; }


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



  //===============================================================================================================
  static java.util.stream.Stream<Cred> sCred(Collection<Cred> c) { return c.stream(); }
  static <T>   java.util.stream.Stream<T> seq(Collection<T> c) { return c.stream(); }
  static <T>   java.util.stream.Stream<T> seq(T[] a) { return Arrays.stream(a); }
  static <X,Y> java.util.stream.Stream<Y> map(X[] a, java.util.function.Function<? super X,? extends Y> f) { return seq(a).map(f); }
  static <X,Y> java.util.stream.Stream<Y> map(Collection<X>c, java.util.function.Function<? super X,? extends Y> f) { return seq(c).map(f); }
  static <T> void log(PrintWriter pw, String hdr, String sep, java.util.stream.Stream<T> s) { pw.println(s.map(e->""+e).reduce(hdr,(a,b)->a+sep+b)); }
  @SuppressWarnings("unchecked") // from Stackoverflow
  static <T> T[] toA(Collection<T> c, Object e) { return c.toArray((T[])java.lang.reflect.Array.newInstance(e.getClass(), c.size())); }
  static int randN(int range) { return (int)Math.round(Math.random()*range); }
  static void nodeOut(int id, String m) { 
    System.out.println("node" + id + (m = nodes >= 5 ? map(m.split(" "),s->s.startsWith("BL")?s:abbrev("",s,8,20)).reduce("",(a,b)->a+" "+b).trim():m));
  }
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

  static String sign(String msg, PrivateKey sk) throws Exception {
    Signature s = Signature.getInstance("SHA256withECDSA"); s.initSign(sk); s.update(msg.getBytes(UTF_8));
    return msg + " SIG " + to58(s.sign()) + " \n"; // last space is important, see txn.split(" ")!
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

