package cn.gmssl.com.sun.crypto.provider;

import java.io.ObjectStreamException;
import javax.crypto.SealedObject;

final class ai extends SealedObject {
   static final long serialVersionUID = -7051502576727967444L;

   ai(SealedObject var1) {
      super(var1);
   }

   Object readResolve() throws ObjectStreamException {
      return new SealedObjectForKeyProtector(this);
   }
}
