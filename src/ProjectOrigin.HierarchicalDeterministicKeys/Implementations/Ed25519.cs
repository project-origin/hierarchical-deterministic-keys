using System;
using System.Text;
using NSec.Cryptography;
using ProjectOrigin.HierarchicalDeterministicKeys.Interfaces;

namespace ProjectOrigin.HierarchicalDeterministicKeys.Implementations;

public class Ed25519Algorithm : IPublicKeyAlgorithm
{
    private static readonly SignatureAlgorithm algorithm = SignatureAlgorithm.Ed25519;

    public IPrivateKey ImportPrivateKeyText(string keyText)
    {
        var bytes = Encoding.UTF8.GetBytes(keyText);
        var key = Key.Import(algorithm, bytes, KeyBlobFormat.PkixPrivateKeyText);
        return new Ed25519PrivateKey(key);
    }

    public IPrivateKey ImportPrivateKey(ReadOnlySpan<byte> privateKeySpan)
    {
        var key = Key.Import(algorithm, privateKeySpan, KeyBlobFormat.PkixPrivateKey);
        return new Ed25519PrivateKey(key);
    }

    public IPublicKey ImportPublicKeyText(string keyText)
    {
        var bytes = Encoding.UTF8.GetBytes(keyText);
        var key = PublicKey.Import(algorithm, bytes, KeyBlobFormat.PkixPublicKeyText);
        return new Ed25519PublicKey(key);
    }

    public IPublicKey ImportPublicKey(ReadOnlySpan<byte> span)
    {
        var key = PublicKey.Import(algorithm, span, KeyBlobFormat.PkixPublicKey);
        return new Ed25519PublicKey(key);
    }

    public IPrivateKey GenerateNewPrivateKey()
    {
        var key = new Key(algorithm, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        return new Ed25519PrivateKey(key);
    }

    public class Ed25519PrivateKey : IPrivateKey
    {
        private readonly Key _key;

        public Ed25519PrivateKey(Key key)
        {
            _key = key;
        }

        public IPublicKey PublicKey => new Ed25519PublicKey(_key.PublicKey);

        public ReadOnlySpan<byte> Export()
        {
            return _key.Export(KeyBlobFormat.PkixPrivateKey);
        }

        public string ExportPkixText()
        {
            return Encoding.UTF8.GetString(_key.Export(KeyBlobFormat.PkixPrivateKeyText));
        }

        public ReadOnlySpan<byte> Sign(ReadOnlySpan<byte> data)
        {
            return algorithm.Sign(_key, data);
        }
    }

    public class Ed25519PublicKey : IPublicKey
    {
        private readonly PublicKey _key;

        public Ed25519PublicKey(PublicKey key)
        {
            _key = key;
        }

        public ReadOnlySpan<byte> Export()
        {
            return _key.Export(KeyBlobFormat.PkixPublicKey);
        }

        public string ExportPkixText()
        {
            return Encoding.UTF8.GetString(_key.Export(KeyBlobFormat.PkixPublicKeyText));
        }

        public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        {
            return algorithm.Verify(_key, data, signature);
        }
    }
}
