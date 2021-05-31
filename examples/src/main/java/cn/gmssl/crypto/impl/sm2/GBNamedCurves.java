package cn.gmssl.crypto.impl.sm2;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.x9.X9ECParameters;
import org.bc.asn1.x9.X9ECParametersHolder;
import org.bc.math.ec.ECCurve;
import org.bc.util.Strings;

public class GBNamedCurves {
   private static final Map<String, ASN1ObjectIdentifier> objIds = new HashMap();
   static final Map<ASN1ObjectIdentifier, String> names = new HashMap();
   private static final Map<ASN1ObjectIdentifier, X9ECParametersHolder> curves = new HashMap();
   private static X9ECParametersHolder sm2_256 = new X9ECParametersHolder() {
      protected X9ECParameters createParameters() {
         ECCurve.Fp var1 = new ECCurve.Fp(new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16), new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16), new BigInteger("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16));
         BigInteger var2 = new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16);
         BigInteger var3 = new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16);

         return new X9ECParameters(var1, var1.createPoint(var2, var3, false), new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16));
      }
   };

   static {
      defineCurve("sm2_256", new ASN1ObjectIdentifier("1.2.156.10197.1.301"), sm2_256);
   }

   private static void defineCurve(String var0, ASN1ObjectIdentifier var1, X9ECParametersHolder var2) {
      objIds.put(var0, var1);
      names.put(var1, var0);
      curves.put(var1, var2);
   }

   public static ASN1ObjectIdentifier getOID(String var0) {
      return (ASN1ObjectIdentifier)objIds.get(Strings.toLowerCase(var0));
   }

   public static X9ECParameters getByOID(ASN1ObjectIdentifier var0) {
      X9ECParametersHolder var1 = (X9ECParametersHolder)curves.get(var0);
      return var1 != null ? var1.getParameters() : null;
   }

   public static String getName(ASN1ObjectIdentifier var0) {
      return (String)names.get(var0);
   }
}
