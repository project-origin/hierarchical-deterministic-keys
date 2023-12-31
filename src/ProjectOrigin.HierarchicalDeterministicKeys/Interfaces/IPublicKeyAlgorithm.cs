using System;

namespace ProjectOrigin.HierarchicalDeterministicKeys.Interfaces;

/// <summary>
/// This is a simple interface for a Hierarchical Deterministic (HD) algorithm.
/// </summary>
/// <remarks>
/// This interface is used to abstract the HD algorithm from the rest of the application.
/// This allows for easy swapping of the HD algorithm in the future.
/// </remarks>
public interface IPublicKeyAlgorithm
{
    /// <summary>
    /// Generates a new private key.
    /// </summary>
    /// <returns>The generated key</returns>
    IPrivateKey GenerateNewPrivateKey();

    /// <summary>
    /// Import a private key from a byte array
    /// In the PKIX text format.
    /// </summary>
    IPrivateKey ImportPrivateKeyText(string keyText);

    /// <summary>
    /// Import a private key from a span
    /// In the PKIX binary format.
    /// </summary>
    IPrivateKey ImportPrivateKey(ReadOnlySpan<byte> privateKeySpan);

    /// <summary>
    /// Import a public key from a byte array
    /// In the PKIX text format.
    /// </summary>
    IPublicKey ImportPublicKeyText(string keyText);

    /// <summary>
    /// Import a private key from a byte array containg the key.
    /// In the PKIX binary format.
    /// </summary>
    IPublicKey ImportPublicKey(ReadOnlySpan<byte> span);
}

public interface IPrivateKey
{
    /// <summary>
    /// The public key that corresponds to this private key.
    /// </summary>
    public IPublicKey PublicKey { get; }

    /// <summary>
    /// Signs the given data with the private key.
    /// </summary>
    public ReadOnlySpan<byte> Sign(ReadOnlySpan<byte> data);

    /// <summary>
    /// Exports the private key as a byte array.
    /// </summary>
    public ReadOnlySpan<byte> Export();


    /// <summary>
    /// Export the private key as a span containing the textural Pkix format.
    /// -----BEGIN PUBLIC KEY-----
    /// BASE64 ENCODED DATA
    /// -----END PUBLIC KEY-----
    /// </summary>
    string ExportPkixText();
}

public interface IPublicKey
{
    /// <summary>
    /// Export the public key as a span.
    /// </summary>
    ReadOnlySpan<byte> Export();

    /// <summary>
    /// Export the public key as a span containing the textural Pkix format.
    /// -----BEGIN PUBLIC KEY-----
    /// BASE64 ENCODED DATA
    /// -----END PUBLIC KEY-----
    /// </summary>
    string ExportPkixText();

    /// <summary>
    /// Verify the given signature against the given data.
    /// </summary>
    bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);
}
