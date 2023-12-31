using System;
using ProjectOrigin.HierarchicalDeterministicKeys.Implementations;
using ProjectOrigin.HierarchicalDeterministicKeys.Interfaces;

namespace ProjectOrigin.HierarchicalDeterministicKeys;

/// <summary>
/// This is a simple interface for a Hierarchical Deterministic (HD) algorithm.
/// </summary>
/// <remarks>
/// This interface is used to abstract the HD algorithm from the rest of the application.
/// This allows for easy swapping of the HD algorithm in the future.
/// </remarks>
public static class Algorithms
{
    private static Lazy<IHDAlgorithm> secp256k1 = new Lazy<IHDAlgorithm>(() => new Secp256k1Algorithm());
    private static Lazy<IPublicKeyAlgorithm> ed25519 = new Lazy<IPublicKeyAlgorithm>(() => new Ed25519Algorithm());

    public static IPublicKeyAlgorithm Ed25519 => ed25519.Value;
    public static IHDAlgorithm Secp256k1 => secp256k1.Value;
}
