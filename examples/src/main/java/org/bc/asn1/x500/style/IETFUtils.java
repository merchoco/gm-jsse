package org.bc.asn1.x500.style;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;
import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1String;
import org.bc.asn1.DERUniversalString;
import org.bc.asn1.x500.AttributeTypeAndValue;
import org.bc.asn1.x500.RDN;
import org.bc.asn1.x500.X500NameBuilder;
import org.bc.asn1.x500.X500NameStyle;
import org.bc.util.Strings;
import org.bc.util.encoders.Hex;

public class IETFUtils {
   public static RDN[] rDNsFromString(String var0, X500NameStyle var1) {
      X500NameTokenizer var2 = new X500NameTokenizer(var0);
      X500NameBuilder var3 = new X500NameBuilder(var1);

      while(var2.hasMoreTokens()) {
         String var4 = var2.nextToken();
         int var5 = var4.indexOf(61);
         if (var5 == -1) {
            throw new IllegalArgumentException("badly formated directory string");
         }

         String var6 = var4.substring(0, var5);
         String var7 = var4.substring(var5 + 1);
         ASN1ObjectIdentifier var8 = var1.attrNameToOID(var6);
         if (var7.indexOf(43) <= 0) {
            var3.addRDN(var8, var7);
         } else {
            X500NameTokenizer var9 = new X500NameTokenizer(var7, '+');
            String var10 = var9.nextToken();
            Vector var11 = new Vector();
            Vector var12 = new Vector();
            var11.addElement(var8);
            var12.addElement(var10);

            while(var9.hasMoreTokens()) {
               String var13 = var9.nextToken();
               int var14 = var13.indexOf(61);
               String var15 = var13.substring(0, var14);
               String var16 = var13.substring(var14 + 1);
               var11.addElement(var1.attrNameToOID(var15));
               var12.addElement(var16);
            }

            var3.addMultiValuedRDN(toOIDArray(var11), toValueArray(var12));
         }
      }

      return var3.build().getRDNs();
   }

   private static String[] toValueArray(Vector var0) {
      String[] var1 = new String[var0.size()];

      for(int var2 = 0; var2 != var1.length; ++var2) {
         var1[var2] = (String)var0.elementAt(var2);
      }

      return var1;
   }

   private static ASN1ObjectIdentifier[] toOIDArray(Vector var0) {
      ASN1ObjectIdentifier[] var1 = new ASN1ObjectIdentifier[var0.size()];

      for(int var2 = 0; var2 != var1.length; ++var2) {
         var1[var2] = (ASN1ObjectIdentifier)var0.elementAt(var2);
      }

      return var1;
   }

   public static ASN1ObjectIdentifier decodeAttrName(String var0, Hashtable var1) {
      if (Strings.toUpperCase(var0).startsWith("OID.")) {
         return new ASN1ObjectIdentifier(var0.substring(4));
      } else if (var0.charAt(0) >= '0' && var0.charAt(0) <= '9') {
         return new ASN1ObjectIdentifier(var0);
      } else {
         ASN1ObjectIdentifier var2 = (ASN1ObjectIdentifier)var1.get(Strings.toLowerCase(var0));
         if (var2 == null) {
            throw new IllegalArgumentException("Unknown object id - " + var0 + " - passed to distinguished name");
         } else {
            return var2;
         }
      }
   }

   public static ASN1Encodable valueFromHexString(String var0, int var1) throws IOException {
      var0 = Strings.toLowerCase(var0);
      byte[] var2 = new byte[(var0.length() - var1) / 2];

      for(int var3 = 0; var3 != var2.length; ++var3) {
         char var4 = var0.charAt(var3 * 2 + var1);
         char var5 = var0.charAt(var3 * 2 + var1 + 1);
         if (var4 < 'a') {
            var2[var3] = (byte)(var4 - 48 << 4);
         } else {
            var2[var3] = (byte)(var4 - 97 + 10 << 4);
         }

         if (var5 < 'a') {
            var2[var3] |= (byte)(var5 - 48);
         } else {
            var2[var3] |= (byte)(var5 - 97 + 10);
         }
      }

      return ASN1Primitive.fromByteArray(var2);
   }

   public static void appendRDN(StringBuffer var0, RDN var1, Hashtable var2) {
      if (var1.isMultiValued()) {
         AttributeTypeAndValue[] var3 = var1.getTypesAndValues();
         boolean var4 = true;

         for(int var5 = 0; var5 != var3.length; ++var5) {
            if (var4) {
               var4 = false;
            } else {
               var0.append('+');
            }

            appendTypeAndValue(var0, var3[var5], var2);
         }
      } else {
         appendTypeAndValue(var0, var1.getFirst(), var2);
      }

   }

   public static void appendTypeAndValue(StringBuffer var0, AttributeTypeAndValue var1, Hashtable var2) {
      String var3 = (String)var2.get(var1.getType());
      if (var3 != null) {
         var0.append(var3);
      } else {
         var0.append(var1.getType().getId());
      }

      var0.append('=');
      var0.append(valueToString(var1.getValue()));
   }

   public static String valueToString(ASN1Encodable var0) {
      StringBuffer var1 = new StringBuffer();
      if (var0 instanceof ASN1String && !(var0 instanceof DERUniversalString)) {
         String var2 = ((ASN1String)var0).getString();
         if (var2.length() > 0 && var2.charAt(0) == '#') {
            var1.append("\\" + var2);
         } else {
            var1.append(var2);
         }
      } else {
         try {
            var1.append("#" + bytesToString(Hex.encode(var0.toASN1Primitive().getEncoded("DER"))));
         } catch (IOException var4) {
            throw new IllegalArgumentException("Other value has no encoded form");
         }
      }

      int var5 = var1.length();
      int var3 = 0;
      if (var1.length() >= 2 && var1.charAt(0) == '\\' && var1.charAt(1) == '#') {
         var3 += 2;
      }

      for(; var3 != var5; ++var3) {
         if (var1.charAt(var3) == ',' || var1.charAt(var3) == '"' || var1.charAt(var3) == '\\' || var1.charAt(var3) == '+' || var1.charAt(var3) == '=' || var1.charAt(var3) == '<' || var1.charAt(var3) == '>' || var1.charAt(var3) == ';') {
            var1.insert(var3, "\\");
            ++var3;
            ++var5;
         }
      }

      return var1.toString();
   }

   private static String bytesToString(byte[] var0) {
      char[] var1 = new char[var0.length];

      for(int var2 = 0; var2 != var1.length; ++var2) {
         var1[var2] = (char)(var0[var2] & 255);
      }

      return new String(var1);
   }

   public static String canonicalize(String var0) {
      String var1 = Strings.toLowerCase(var0.trim());
      if (var1.length() > 0 && var1.charAt(0) == '#') {
         ASN1Primitive var2 = decodeObject(var1);
         if (var2 instanceof ASN1String) {
            var1 = Strings.toLowerCase(((ASN1String)var2).getString().trim());
         }
      }

      var1 = stripInternalSpaces(var1);
      return var1;
   }

   private static ASN1Primitive decodeObject(String var0) {
      try {
         return ASN1Primitive.fromByteArray(Hex.decode(var0.substring(1)));
      } catch (IOException var2) {
         throw new IllegalStateException("unknown encoding in name: " + var2);
      }
   }

   public static String stripInternalSpaces(String var0) {
      StringBuffer var1 = new StringBuffer();
      if (var0.length() != 0) {
         char var2 = var0.charAt(0);
         var1.append(var2);

         for(int var3 = 1; var3 < var0.length(); ++var3) {
            char var4 = var0.charAt(var3);
            if (var2 != ' ' || var4 != ' ') {
               var1.append(var4);
            }

            var2 = var4;
         }
      }

      return var1.toString();
   }

   public static boolean rDNAreEqual(RDN var0, RDN var1) {
      if (!var0.isMultiValued()) {
         return !var1.isMultiValued() ? atvAreEqual(var0.getFirst(), var1.getFirst()) : false;
      } else if (!var1.isMultiValued()) {
         return false;
      } else {
         AttributeTypeAndValue[] var2 = var0.getTypesAndValues();
         AttributeTypeAndValue[] var3 = var1.getTypesAndValues();
         if (var2.length != var3.length) {
            return false;
         } else {
            for(int var4 = 0; var4 != var2.length; ++var4) {
               if (!atvAreEqual(var2[var4], var3[var4])) {
                  return false;
               }
            }

            return true;
         }
      }
   }

   private static boolean atvAreEqual(AttributeTypeAndValue var0, AttributeTypeAndValue var1) {
      if (var0 == var1) {
         return true;
      } else if (var0 == null) {
         return false;
      } else if (var1 == null) {
         return false;
      } else {
         ASN1ObjectIdentifier var2 = var0.getType();
         ASN1ObjectIdentifier var3 = var1.getType();
         if (!var2.equals(var3)) {
            return false;
         } else {
            String var4 = canonicalize(valueToString(var0.getValue()));
            String var5 = canonicalize(valueToString(var1.getValue()));
            return var4.equals(var5);
         }
      }
   }
}
