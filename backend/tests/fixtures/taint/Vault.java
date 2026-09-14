package fixtures;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import javax.net.ssl.SSLContext;

public class Vault {
    private static final int LEGACY_BITS = 56;

    static KeyGenerator symmetric(String algo, int bits) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance(algo);
        kg.init(bits);
        return kg;
    }

    static KeyPairGenerator asymmetric(String algo, int bits) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algo);
        kpg.initialize(bits);
        return kpg;
    }

    static Cipher cipher(String transform) throws Exception {
        return Cipher.getInstance(transform);
    }

    static ECGenParameterSpec curve(String name) {
        return new ECGenParameterSpec(name);
    }

    static SSLContext tls(String proto) throws Exception {
        return SSLContext.getInstance(proto);
    }

    public void run() throws Exception {
        symmetric("DESede", LEGACY_BITS);
        asymmetric("RSA", 1024);
        cipher("DES/ECB/PKCS5Padding");
        curve("secp192r1");
        tls("SSLv3");
    }
}
