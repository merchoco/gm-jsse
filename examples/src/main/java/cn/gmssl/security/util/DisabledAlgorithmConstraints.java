package cn.gmssl.security.util;

import java.security.AccessController;
import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.Key;
import java.security.PrivilegedAction;
import java.security.Security;
import java.security.interfaces.DSAKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHKey;

public class DisabledAlgorithmConstraints implements AlgorithmConstraints {
   public static final String PROPERTY_CERTPATH_DISABLED_ALGS = "jdk.certpath.disabledAlgorithms";
   public static final String PROPERTY_TLS_DISABLED_ALGS = "jdk.tls.disabledAlgorithms";
   private static Map<String, String[]> disabledAlgorithmsMap = Collections.synchronizedMap(new HashMap());
   private static Map<String, DisabledAlgorithmConstraints.KeySizeConstraints> keySizeConstraintsMap = Collections.synchronizedMap(new HashMap());
   private String[] disabledAlgorithms;
   private DisabledAlgorithmConstraints.KeySizeConstraints keySizeConstraints;

   public DisabledAlgorithmConstraints(String var1) {
      Map var2 = disabledAlgorithmsMap;
      synchronized(disabledAlgorithmsMap) {
         if (!disabledAlgorithmsMap.containsKey(var1)) {
            loadDisabledAlgorithmsMap(var1);
         }

         this.disabledAlgorithms = (String[])disabledAlgorithmsMap.get(var1);
         this.keySizeConstraints = (DisabledAlgorithmConstraints.KeySizeConstraints)keySizeConstraintsMap.get(var1);
      }
   }

   public final boolean permits(Set<CryptoPrimitive> var1, String var2, AlgorithmParameters var3) {
      if (var2 != null && var2.length() != 0) {
         if (var1 != null && !var1.isEmpty()) {
            Set var4 = null;
            String[] var8 = this.disabledAlgorithms;
            int var7 = this.disabledAlgorithms.length;

            for(int var6 = 0; var6 < var7; ++var6) {
               String var5 = var8[var6];
               if (var5 != null && !var5.isEmpty()) {
                  if (var5.equalsIgnoreCase(var2)) {
                     return false;
                  }

                  if (var4 == null) {
                     var4 = this.decomposes(var2);
                  }

                  Iterator var10 = var4.iterator();

                  while(var10.hasNext()) {
                     String var9 = (String)var10.next();
                     if (var5.equalsIgnoreCase(var9)) {
                        return false;
                     }
                  }
               }
            }

            return true;
         } else {
            throw new IllegalArgumentException("No cryptographic primitive specified");
         }
      } else {
         throw new IllegalArgumentException("No algorithm name specified");
      }
   }

   public final boolean permits(Set<CryptoPrimitive> var1, Key var2) {
      return this.checkConstraints(var1, "", var2, (AlgorithmParameters)null);
   }

   public final boolean permits(Set<CryptoPrimitive> var1, String var2, Key var3, AlgorithmParameters var4) {
      if (var2 != null && var2.length() != 0) {
         return this.checkConstraints(var1, var2, var3, var4);
      } else {
         throw new IllegalArgumentException("No algorithm name specified");
      }
   }

   protected Set<String> decomposes(String var1) {
      if (var1 != null && var1.length() != 0) {
         Pattern var2 = Pattern.compile("/");
         String[] var3 = var2.split(var1);
         HashSet var4 = new HashSet();
         String[] var8 = var3;
         int var7 = var3.length;

         for(int var6 = 0; var6 < var7; ++var6) {
            String var5 = var8[var6];
            if (var5 != null && var5.length() != 0) {
               Pattern var9 = Pattern.compile("with|and", 2);
               String[] var10 = var9.split(var5);
               String[] var14 = var10;
               int var13 = var10.length;

               for(int var12 = 0; var12 < var13; ++var12) {
                  String var11 = var14[var12];
                  if (var11 != null && var11.length() != 0) {
                     var4.add(var11);
                  }
               }
            }
         }

         if (var4.contains("SHA1") && !var4.contains("SHA-1")) {
            var4.add("SHA-1");
         }

         if (var4.contains("SHA-1") && !var4.contains("SHA1")) {
            var4.add("SHA1");
         }

         if (var4.contains("SHA224") && !var4.contains("SHA-224")) {
            var4.add("SHA-224");
         }

         if (var4.contains("SHA-224") && !var4.contains("SHA224")) {
            var4.add("SHA224");
         }

         if (var4.contains("SHA256") && !var4.contains("SHA-256")) {
            var4.add("SHA-256");
         }

         if (var4.contains("SHA-256") && !var4.contains("SHA256")) {
            var4.add("SHA256");
         }

         if (var4.contains("SHA384") && !var4.contains("SHA-384")) {
            var4.add("SHA-384");
         }

         if (var4.contains("SHA-384") && !var4.contains("SHA384")) {
            var4.add("SHA384");
         }

         if (var4.contains("SHA512") && !var4.contains("SHA-512")) {
            var4.add("SHA-512");
         }

         if (var4.contains("SHA-512") && !var4.contains("SHA512")) {
            var4.add("SHA512");
         }

         return var4;
      } else {
         return new HashSet();
      }
   }

   private boolean checkConstraints(Set<CryptoPrimitive> var1, String var2, Key var3, AlgorithmParameters var4) {
      if (var3 == null) {
         throw new IllegalArgumentException("The key cannot be null");
      } else if (var2 != null && var2.length() != 0 && !this.permits(var1, var2, var4)) {
         return false;
      } else if (!this.permits(var1, var3.getAlgorithm(), (AlgorithmParameters)null)) {
         return false;
      } else {
         return !this.keySizeConstraints.disables(var3);
      }
   }

   private static void loadDisabledAlgorithmsMap(final String var0) {
      String var1 = (String)AccessController.doPrivileged(new PrivilegedAction<String>() {
         public String run() {
            return Security.getProperty(var0);
         }
      });
      String[] var2 = null;
      if (var1 != null && !var1.isEmpty()) {
         if (var1.charAt(0) == '"' && var1.charAt(var1.length() - 1) == '"') {
            var1 = var1.substring(1, var1.length() - 1);
         }

         var2 = var1.split(",");

         for(int var3 = 0; var3 < var2.length; ++var3) {
            var2[var3] = var2[var3].trim();
         }
      }

      if (var2 == null) {
         var2 = new String[0];
      }

      disabledAlgorithmsMap.put(var0, var2);
      DisabledAlgorithmConstraints.KeySizeConstraints var4 = new DisabledAlgorithmConstraints.KeySizeConstraints(var2);
      keySizeConstraintsMap.put(var0, var4);
   }

   private static class KeySizeConstraint {
      private int minSize;
      private int maxSize;
      private int prohibitedSize = -1;
      // $FF: synthetic field
      private static int[] $SWITCH_TABLE$cn$gmssl$security$util$DisabledAlgorithmConstraints$KeySizeConstraint$Operator;

      public KeySizeConstraint(DisabledAlgorithmConstraints.KeySizeConstraint.Operator var1, int var2) {
         switch($SWITCH_TABLE$cn$gmssl$security$util$DisabledAlgorithmConstraints$KeySizeConstraint$Operator()[var1.ordinal()]) {
         case 1:
            this.minSize = 0;
            this.maxSize = Integer.MAX_VALUE;
            this.prohibitedSize = var2;
            break;
         case 2:
            this.minSize = var2;
            this.maxSize = var2;
            break;
         case 3:
            this.minSize = var2;
            this.maxSize = Integer.MAX_VALUE;
            break;
         case 4:
            this.minSize = var2 + 1;
            this.maxSize = Integer.MAX_VALUE;
            break;
         case 5:
            this.minSize = 0;
            this.maxSize = var2;
            break;
         case 6:
            this.minSize = 0;
            this.maxSize = var2 > 1 ? var2 - 1 : 0;
            break;
         default:
            this.minSize = Integer.MAX_VALUE;
            this.maxSize = -1;
         }

      }

      public boolean disables(Key var1) {
         int var2 = -1;
         if (var1 instanceof SecretKey) {
            SecretKey var3 = (SecretKey)var1;
            if (var3.getFormat().equals("RAW") && var3.getEncoded() != null) {
               var2 = var3.getEncoded().length * 8;
            }
         }

         if (var1 instanceof RSAKey) {
            RSAKey var4 = (RSAKey)var1;
            var2 = var4.getModulus().bitLength();
         } else if (var1 instanceof ECKey) {
            ECKey var5 = (ECKey)var1;
            var2 = var5.getParams().getOrder().bitLength();
         } else if (var1 instanceof DSAKey) {
            DSAKey var6 = (DSAKey)var1;
            var2 = var6.getParams().getP().bitLength();
         } else if (var1 instanceof DHKey) {
            DHKey var7 = (DHKey)var1;
            var2 = var7.getParams().getP().bitLength();
         }

         if (var2 == 0) {
            return true;
         } else if (var2 >= 0) {
            return var2 < this.minSize || var2 > this.maxSize || this.prohibitedSize == var2;
         } else {
            return false;
         }
      }

      // $FF: synthetic method
      static int[] $SWITCH_TABLE$cn$gmssl$security$util$DisabledAlgorithmConstraints$KeySizeConstraint$Operator() {
         int[] var10000 = $SWITCH_TABLE$cn$gmssl$security$util$DisabledAlgorithmConstraints$KeySizeConstraint$Operator;
         if ($SWITCH_TABLE$cn$gmssl$security$util$DisabledAlgorithmConstraints$KeySizeConstraint$Operator != null) {
            return var10000;
         } else {
            int[] var0 = new int[DisabledAlgorithmConstraints.KeySizeConstraint.Operator.values().length];

            try {
               var0[DisabledAlgorithmConstraints.KeySizeConstraint.Operator.EQ.ordinal()] = 1;
            } catch (NoSuchFieldError var6) {
               ;
            }

            try {
               var0[DisabledAlgorithmConstraints.KeySizeConstraint.Operator.GE.ordinal()] = 6;
            } catch (NoSuchFieldError var5) {
               ;
            }

            try {
               var0[DisabledAlgorithmConstraints.KeySizeConstraint.Operator.GT.ordinal()] = 5;
            } catch (NoSuchFieldError var4) {
               ;
            }

            try {
               var0[DisabledAlgorithmConstraints.KeySizeConstraint.Operator.LE.ordinal()] = 4;
            } catch (NoSuchFieldError var3) {
               ;
            }

            try {
               var0[DisabledAlgorithmConstraints.KeySizeConstraint.Operator.LT.ordinal()] = 3;
            } catch (NoSuchFieldError var2) {
               ;
            }

            try {
               var0[DisabledAlgorithmConstraints.KeySizeConstraint.Operator.NE.ordinal()] = 2;
            } catch (NoSuchFieldError var1) {
               ;
            }

            $SWITCH_TABLE$cn$gmssl$security$util$DisabledAlgorithmConstraints$KeySizeConstraint$Operator = var0;
            return var0;
         }
      }

      static enum Operator {
         EQ,
         NE,
         LT,
         LE,
         GT,
         GE;

         static DisabledAlgorithmConstraints.KeySizeConstraint.Operator of(String var0) {
            switch(var0.hashCode()) {
            case 60:
               if (var0.equals("<")) {
                  return LT;
               }
               break;
            case 62:
               if (var0.equals(">")) {
                  return GT;
               }
               break;
            case 1084:
               if (var0.equals("!=")) {
                  return NE;
               }
               break;
            case 1921:
               if (var0.equals("<=")) {
                  return LE;
               }
               break;
            case 1952:
               if (var0.equals("==")) {
                  return EQ;
               }
               break;
            case 1983:
               if (var0.equals(">=")) {
                  return GE;
               }
            }

            throw new IllegalArgumentException(var0 + " is not a legal Operator");
         }
      }
   }

   private static class KeySizeConstraints {
      private static final Pattern pattern = Pattern.compile("(\\S+)\\s+keySize\\s*(<=|<|==|!=|>|>=)\\s*(\\d+)");
      private Map<String, Set<DisabledAlgorithmConstraints.KeySizeConstraint>> constraintsMap = Collections.synchronizedMap(new HashMap());

      public KeySizeConstraints(String[] var1) {
         String[] var5 = var1;
         int var4 = var1.length;

         for(int var3 = 0; var3 < var4; ++var3) {
            String var2 = var5[var3];
            if (var2 != null && !var2.isEmpty()) {
               Matcher var6 = pattern.matcher(var2);
               if (var6.matches()) {
                  String var7 = var6.group(1);
                  DisabledAlgorithmConstraints.KeySizeConstraint.Operator var8 = DisabledAlgorithmConstraints.KeySizeConstraint.Operator.of(var6.group(2));
                  int var9 = Integer.parseInt(var6.group(3));
                  var7 = var7.toLowerCase(Locale.ENGLISH);
                  Map var10 = this.constraintsMap;
                  synchronized(this.constraintsMap) {
                     if (!this.constraintsMap.containsKey(var7)) {
                        this.constraintsMap.put(var7, new HashSet());
                     }

                     Set var11 = (Set)this.constraintsMap.get(var7);
                     DisabledAlgorithmConstraints.KeySizeConstraint var12 = new DisabledAlgorithmConstraints.KeySizeConstraint(var8, var9);
                     var11.add(var12);
                  }
               }
            }
         }

      }

      public boolean disables(Key var1) {
         String var2 = var1.getAlgorithm().toLowerCase(Locale.ENGLISH);
         Map var3 = this.constraintsMap;
         synchronized(this.constraintsMap) {
            if (this.constraintsMap.containsKey(var2)) {
               Set var4 = (Set)this.constraintsMap.get(var2);
               Iterator var6 = var4.iterator();

               while(var6.hasNext()) {
                  DisabledAlgorithmConstraints.KeySizeConstraint var5 = (DisabledAlgorithmConstraints.KeySizeConstraint)var6.next();
                  if (var5.disables(var1)) {
                     return true;
                  }
               }
            }

            return false;
         }
      }
   }
}
