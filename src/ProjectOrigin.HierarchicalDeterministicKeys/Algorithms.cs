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
    public static IPublicKeyAlgorithm Ed25519 => IPublicKeyAlgorithm.Ed25519;
    public static IHDAlgorithm Secp256k1 => IHDAlgorithm.Secp256k1;
}
