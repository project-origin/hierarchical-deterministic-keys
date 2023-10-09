using System.Text;
using AutoFixture;
using FluentAssertions;
using ProjectOrigin.HierarchicalDeterministicKeys;
using Xunit;

namespace ProjectOrigin.Electricity.Tests;

public class Secp256k1Tests
{
    private Fixture _fixture;

    public Secp256k1Tests()
    {
        _fixture = new Fixture();
    }

    [Fact]
    public void signature_is_valid()
    {
        var key = Algorithms.Secp256k1.GenerateNewPrivateKey();
        var data = _fixture.Create<byte[]>();
        var signature = key.Sign(data).ToArray();

        var verifcationResult = key.PublicKey.Verify(data, signature);

        verifcationResult.Should().BeTrue();
    }

    [Fact]
    public void signature_is_invalid()
    {
        var key = Algorithms.Secp256k1.GenerateNewPrivateKey();
        var otherKey = Algorithms.Secp256k1.GenerateNewPrivateKey();
        var data = _fixture.Create<byte[]>();
        var signature = otherKey.Sign(data).ToArray();

        var verifcationResult = key.PublicKey.Verify(data, signature);

        verifcationResult.Should().BeFalse();
    }

    [Fact]
    public void Secp256k1_from_seed()
    {
        var data = _fixture.Create<byte[]>();

        var bytes = Encoding.UTF8.GetBytes("my seed hello world");

        var key1 = Algorithms.Secp256k1.CreateFromSeed(bytes);
        var signature1 = key1.Sign(data).ToArray();

        var key2 = Algorithms.Secp256k1.CreateFromSeed(bytes);
        var signature2 = key2.Sign(data).ToArray();

        signature1.Should().BeEquivalentTo(signature2);
    }
}
