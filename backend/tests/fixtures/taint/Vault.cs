using System.Security.Cryptography;

class Vault {
    const int LegacyBits = 1024;

    static RSACryptoServiceProvider Build(int bits) {
        return new RSACryptoServiceProvider(bits);
    }

    static DSACryptoServiceProvider BuildDsa(int bits) {
        return new DSACryptoServiceProvider(bits);
    }

    static HashAlgorithm Digest(string name) {
        return HashAlgorithm.Create(name);
    }

    public void Run() {
        Build(LegacyBits);
        BuildDsa(1024);
        Digest("MD5");
    }
}
