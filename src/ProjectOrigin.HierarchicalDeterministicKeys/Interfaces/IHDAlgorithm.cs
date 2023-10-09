using System;
using ProjectOrigin.HierarchicalDeterministicKeys.Implementations;

namespace ProjectOrigin.HierarchicalDeterministicKeys.Interfaces;

/// <summary>
/// This is a simple interface for a Hierarchical Deterministic (HD) algorithm.
/// </summary>
/// <remarks>
/// This interface is used to abstract the HD algorithm from the rest of the application.
/// This allows for easy swapping of the HD algorithm in the future.
/// </remarks>
public interface IHDAlgorithm
{
    private static Lazy<IHDAlgorithm> secp256k1 = new Lazy<IHDAlgorithm>(() => new Secp256k1Algorithm());
    public static IHDAlgorithm Secp256k1 => secp256k1.Value;

    /// <summary>
    /// Generates a new private key.
    /// </summary>
    IHDPrivateKey GenerateNewPrivateKey();

    /// <summary>
    /// Creates a new private key from a seed.
    /// </summary>
    /// <param name="seed">The seed to create the private key from, often a hex string is used.</param>
    IHDPrivateKey CreateFromSeed(Span<byte> seed);

    /// <summary>
    /// Import a hd private key from a byte array
    /// </summary>
    /// <param name="privateKeyBytes">The private key bytes to import.</param>
    IHDPrivateKey ImportHDPrivateKey(ReadOnlySpan<byte> privateKeyBytes);

    /// <summary>
    /// Import a hd public key from a byte array
    /// </summary>
    /// <param name="publicKeyBytes">The public key bytes to import.</param>
    IHDPublicKey ImportHDPublicKey(ReadOnlySpan<byte> publicKeyBytes);

    /// <summary>
    /// Import a public key from a byte array
    /// </summary>
    /// <param name="privateKeyBytes">The public key bytes to import.</param>
    IPublicKey ImportPublicKey(ReadOnlySpan<byte> privateKeyBytes);
}

/// <summary>
/// This is a simple interface for a Hierarchical Deterministic (HD) private key.
/// </summary>
public interface IHDPrivateKey : IPrivateKey
{
    /// <summary>
    /// The HD public key that corresponds to this private key.
    /// </summary>
    public IHDPublicKey Neuter();

    /// <summary>
    /// Derives a child private key from this private key.
    /// </summary>
    public IHDPrivateKey Derive(int position);
}

/// <summary>
/// This is a simple interface for a Hierarchical Deterministic (HD) public key.
/// </summary>
public interface IHDPublicKey
{
    /// <summary>
    /// Verifies the given signature against the given data.
    /// </summary>
    public ReadOnlySpan<byte> Export();

    /// <summary>
    /// Verifies the given signature against the given data.
    /// </summary>
    public IHDPublicKey Derive(int position);

    /// <summary>
    /// Verifies the given signature against the given data.
    /// </summary>
    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);

    /// <summary>
    /// Neuter the HD public key to a public key where it
    /// can not be used to derive any more child keys.
    /// </summary>
    public IPublicKey GetPublicKey();
}
