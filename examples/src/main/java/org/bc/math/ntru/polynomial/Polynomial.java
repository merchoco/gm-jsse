package org.bc.math.ntru.polynomial;

public interface Polynomial {
   IntegerPolynomial mult(IntegerPolynomial var1);

   IntegerPolynomial mult(IntegerPolynomial var1, int var2);

   IntegerPolynomial toIntegerPolynomial();

   BigIntPolynomial mult(BigIntPolynomial var1);
}
