package org.bc.asn1.x500.style;

import java.io.IOException;
import java.util.Hashtable;
import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1GeneralizedTime;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.DERIA5String;
import org.bc.asn1.DERPrintableString;
import org.bc.asn1.DERUTF8String;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;
import org.bc.asn1.x500.AttributeTypeAndValue;
import org.bc.asn1.x500.RDN;
import org.bc.asn1.x500.X500Name;
import org.bc.asn1.x500.X500NameStyle;
import org.bc.asn1.x509.X509ObjectIdentifiers;

public class BCStyle implements X500NameStyle {
   public static final X500NameStyle INSTANCE = new BCStyle();
   public static final ASN1ObjectIdentifier C = new ASN1ObjectIdentifier("2.5.4.6");
   public static final ASN1ObjectIdentifier O = new ASN1ObjectIdentifier("2.5.4.10");
   public static final ASN1ObjectIdentifier OU = new ASN1ObjectIdentifier("2.5.4.11");
   public static final ASN1ObjectIdentifier T = new ASN1ObjectIdentifier("2.5.4.12");
   public static final ASN1ObjectIdentifier CN = new ASN1ObjectIdentifier("2.5.4.3");
   public static final ASN1ObjectIdentifier SN = new ASN1ObjectIdentifier("2.5.4.5");
   public static final ASN1ObjectIdentifier STREET = new ASN1ObjectIdentifier("2.5.4.9");
   public static final ASN1ObjectIdentifier SERIALNUMBER;
   public static final ASN1ObjectIdentifier L;
   public static final ASN1ObjectIdentifier ST;
   public static final ASN1ObjectIdentifier SURNAME;
   public static final ASN1ObjectIdentifier GIVENNAME;
   public static final ASN1ObjectIdentifier INITIALS;
   public static final ASN1ObjectIdentifier GENERATION;
   public static final ASN1ObjectIdentifier UNIQUE_IDENTIFIER;
   public static final ASN1ObjectIdentifier BUSINESS_CATEGORY;
   public static final ASN1ObjectIdentifier POSTAL_CODE;
   public static final ASN1ObjectIdentifier DN_QUALIFIER;
   public static final ASN1ObjectIdentifier PSEUDONYM;
   public static final ASN1ObjectIdentifier DATE_OF_BIRTH;
   public static final ASN1ObjectIdentifier PLACE_OF_BIRTH;
   public static final ASN1ObjectIdentifier GENDER;
   public static final ASN1ObjectIdentifier COUNTRY_OF_CITIZENSHIP;
   public static final ASN1ObjectIdentifier COUNTRY_OF_RESIDENCE;
   public static final ASN1ObjectIdentifier NAME_AT_BIRTH;
   public static final ASN1ObjectIdentifier POSTAL_ADDRESS;
   public static final ASN1ObjectIdentifier DMD_NAME;
   public static final ASN1ObjectIdentifier TELEPHONE_NUMBER;
   public static final ASN1ObjectIdentifier NAME;
   public static final ASN1ObjectIdentifier EmailAddress;
   public static final ASN1ObjectIdentifier UnstructuredName;
   public static final ASN1ObjectIdentifier UnstructuredAddress;
   public static final ASN1ObjectIdentifier E;
   public static final ASN1ObjectIdentifier DC;
   public static final ASN1ObjectIdentifier UID;
   private static final Hashtable DefaultSymbols;
   private static final Hashtable DefaultLookUp;

   static {
      SERIALNUMBER = SN;
      L = new ASN1ObjectIdentifier("2.5.4.7");
      ST = new ASN1ObjectIdentifier("2.5.4.8");
      SURNAME = new ASN1ObjectIdentifier("2.5.4.4");
      GIVENNAME = new ASN1ObjectIdentifier("2.5.4.42");
      INITIALS = new ASN1ObjectIdentifier("2.5.4.43");
      GENERATION = new ASN1ObjectIdentifier("2.5.4.44");
      UNIQUE_IDENTIFIER = new ASN1ObjectIdentifier("2.5.4.45");
      BUSINESS_CATEGORY = new ASN1ObjectIdentifier("2.5.4.15");
      POSTAL_CODE = new ASN1ObjectIdentifier("2.5.4.17");
      DN_QUALIFIER = new ASN1ObjectIdentifier("2.5.4.46");
      PSEUDONYM = new ASN1ObjectIdentifier("2.5.4.65");
      DATE_OF_BIRTH = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.1");
      PLACE_OF_BIRTH = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.2");
      GENDER = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.3");
      COUNTRY_OF_CITIZENSHIP = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.4");
      COUNTRY_OF_RESIDENCE = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.5");
      NAME_AT_BIRTH = new ASN1ObjectIdentifier("1.3.36.8.3.14");
      POSTAL_ADDRESS = new ASN1ObjectIdentifier("2.5.4.16");
      DMD_NAME = new ASN1ObjectIdentifier("2.5.4.54");
      TELEPHONE_NUMBER = X509ObjectIdentifiers.id_at_telephoneNumber;
      NAME = X509ObjectIdentifiers.id_at_name;
      EmailAddress = PKCSObjectIdentifiers.pkcs_9_at_emailAddress;
      UnstructuredName = PKCSObjectIdentifiers.pkcs_9_at_unstructuredName;
      UnstructuredAddress = PKCSObjectIdentifiers.pkcs_9_at_unstructuredAddress;
      E = EmailAddress;
      DC = new ASN1ObjectIdentifier("0.9.2342.19200300.100.1.25");
      UID = new ASN1ObjectIdentifier("0.9.2342.19200300.100.1.1");
      DefaultSymbols = new Hashtable();
      DefaultLookUp = new Hashtable();
      DefaultSymbols.put(C, "C");
      DefaultSymbols.put(O, "O");
      DefaultSymbols.put(T, "T");
      DefaultSymbols.put(OU, "OU");
      DefaultSymbols.put(CN, "CN");
      DefaultSymbols.put(L, "L");
      DefaultSymbols.put(ST, "ST");
      DefaultSymbols.put(SN, "SERIALNUMBER");
      DefaultSymbols.put(EmailAddress, "E");
      DefaultSymbols.put(DC, "DC");
      DefaultSymbols.put(UID, "UID");
      DefaultSymbols.put(STREET, "STREET");
      DefaultSymbols.put(SURNAME, "SURNAME");
      DefaultSymbols.put(GIVENNAME, "GIVENNAME");
      DefaultSymbols.put(INITIALS, "INITIALS");
      DefaultSymbols.put(GENERATION, "GENERATION");
      DefaultSymbols.put(UnstructuredAddress, "unstructuredAddress");
      DefaultSymbols.put(UnstructuredName, "unstructuredName");
      DefaultSymbols.put(UNIQUE_IDENTIFIER, "UniqueIdentifier");
      DefaultSymbols.put(DN_QUALIFIER, "DN");
      DefaultSymbols.put(PSEUDONYM, "Pseudonym");
      DefaultSymbols.put(POSTAL_ADDRESS, "PostalAddress");
      DefaultSymbols.put(NAME_AT_BIRTH, "NameAtBirth");
      DefaultSymbols.put(COUNTRY_OF_CITIZENSHIP, "CountryOfCitizenship");
      DefaultSymbols.put(COUNTRY_OF_RESIDENCE, "CountryOfResidence");
      DefaultSymbols.put(GENDER, "Gender");
      DefaultSymbols.put(PLACE_OF_BIRTH, "PlaceOfBirth");
      DefaultSymbols.put(DATE_OF_BIRTH, "DateOfBirth");
      DefaultSymbols.put(POSTAL_CODE, "PostalCode");
      DefaultSymbols.put(BUSINESS_CATEGORY, "BusinessCategory");
      DefaultSymbols.put(TELEPHONE_NUMBER, "TelephoneNumber");
      DefaultSymbols.put(NAME, "Name");
      DefaultLookUp.put("c", C);
      DefaultLookUp.put("o", O);
      DefaultLookUp.put("t", T);
      DefaultLookUp.put("ou", OU);
      DefaultLookUp.put("cn", CN);
      DefaultLookUp.put("l", L);
      DefaultLookUp.put("st", ST);
      DefaultLookUp.put("sn", SN);
      DefaultLookUp.put("serialnumber", SN);
      DefaultLookUp.put("street", STREET);
      DefaultLookUp.put("emailaddress", E);
      DefaultLookUp.put("dc", DC);
      DefaultLookUp.put("e", E);
      DefaultLookUp.put("uid", UID);
      DefaultLookUp.put("surname", SURNAME);
      DefaultLookUp.put("givenname", GIVENNAME);
      DefaultLookUp.put("initials", INITIALS);
      DefaultLookUp.put("generation", GENERATION);
      DefaultLookUp.put("unstructuredaddress", UnstructuredAddress);
      DefaultLookUp.put("unstructuredname", UnstructuredName);
      DefaultLookUp.put("uniqueidentifier", UNIQUE_IDENTIFIER);
      DefaultLookUp.put("dn", DN_QUALIFIER);
      DefaultLookUp.put("pseudonym", PSEUDONYM);
      DefaultLookUp.put("postaladdress", POSTAL_ADDRESS);
      DefaultLookUp.put("nameofbirth", NAME_AT_BIRTH);
      DefaultLookUp.put("countryofcitizenship", COUNTRY_OF_CITIZENSHIP);
      DefaultLookUp.put("countryofresidence", COUNTRY_OF_RESIDENCE);
      DefaultLookUp.put("gender", GENDER);
      DefaultLookUp.put("placeofbirth", PLACE_OF_BIRTH);
      DefaultLookUp.put("dateofbirth", DATE_OF_BIRTH);
      DefaultLookUp.put("postalcode", POSTAL_CODE);
      DefaultLookUp.put("businesscategory", BUSINESS_CATEGORY);
      DefaultLookUp.put("telephonenumber", TELEPHONE_NUMBER);
      DefaultLookUp.put("name", NAME);
   }

   public ASN1Encodable stringToValue(ASN1ObjectIdentifier var1, String var2) {
      if (var2.length() != 0 && var2.charAt(0) == '#') {
         try {
            return IETFUtils.valueFromHexString(var2, 1);
         } catch (IOException var4) {
            throw new RuntimeException("can't recode value for oid " + var1.getId());
         }
      } else {
         if (var2.length() != 0 && var2.charAt(0) == '\\') {
            var2 = var2.substring(1);
         }

         if (!var1.equals(EmailAddress) && !var1.equals(DC)) {
            if (var1.equals(DATE_OF_BIRTH)) {
               return new ASN1GeneralizedTime(var2);
            } else {
               return (ASN1Encodable)(!var1.equals(C) && !var1.equals(SN) && !var1.equals(DN_QUALIFIER) && !var1.equals(TELEPHONE_NUMBER) ? new DERUTF8String(var2) : new DERPrintableString(var2));
            }
         } else {
            return new DERIA5String(var2);
         }
      }
   }

   public ASN1ObjectIdentifier attrNameToOID(String var1) {
      return IETFUtils.decodeAttrName(var1, DefaultLookUp);
   }

   public boolean areEqual(X500Name var1, X500Name var2) {
      RDN[] var3 = var1.getRDNs();
      RDN[] var4 = var2.getRDNs();
      if (var3.length != var4.length) {
         return false;
      } else {
         boolean var5 = false;
         if (var3[0].getFirst() != null && var4[0].getFirst() != null) {
            var5 = !var3[0].getFirst().getType().equals(var4[0].getFirst().getType());
         }

         for(int var6 = 0; var6 != var3.length; ++var6) {
            if (!this.foundMatch(var5, var3[var6], var4)) {
               return false;
            }
         }

         return true;
      }
   }

   private boolean foundMatch(boolean var1, RDN var2, RDN[] var3) {
      int var4;
      if (var1) {
         for(var4 = var3.length - 1; var4 >= 0; --var4) {
            if (var3[var4] != null && this.rdnAreEqual(var2, var3[var4])) {
               var3[var4] = null;
               return true;
            }
         }
      } else {
         for(var4 = 0; var4 != var3.length; ++var4) {
            if (var3[var4] != null && this.rdnAreEqual(var2, var3[var4])) {
               var3[var4] = null;
               return true;
            }
         }
      }

      return false;
   }

   protected boolean rdnAreEqual(RDN var1, RDN var2) {
      return IETFUtils.rDNAreEqual(var1, var2);
   }

   public RDN[] fromString(String var1) {
      return IETFUtils.rDNsFromString(var1, this);
   }

   public int calculateHashCode(X500Name var1) {
      int var2 = 0;
      RDN[] var3 = var1.getRDNs();

      for(int var4 = 0; var4 != var3.length; ++var4) {
         if (var3[var4].isMultiValued()) {
            AttributeTypeAndValue[] var5 = var3[var4].getTypesAndValues();

            for(int var6 = 0; var6 != var5.length; ++var6) {
               var2 ^= var5[var6].getType().hashCode();
               var2 ^= this.calcHashCode(var5[var6].getValue());
            }
         } else {
            var2 ^= var3[var4].getFirst().getType().hashCode();
            var2 ^= this.calcHashCode(var3[var4].getFirst().getValue());
         }
      }

      return var2;
   }

   private int calcHashCode(ASN1Encodable var1) {
      String var2 = IETFUtils.valueToString(var1);
      var2 = IETFUtils.canonicalize(var2);
      return var2.hashCode();
   }

   public String toString(X500Name var1) {
      StringBuffer var2 = new StringBuffer();
      boolean var3 = true;
      RDN[] var4 = var1.getRDNs();

      for(int var5 = 0; var5 < var4.length; ++var5) {
         if (var3) {
            var3 = false;
         } else {
            var2.append(',');
         }

         IETFUtils.appendRDN(var2, var4[var5], DefaultSymbols);
      }

      return var2.toString();
   }
}
