namespace Certkor.CertOne.Tests;

/// <summary>The shared conformance fixtures (real control-plane responses), copied next to the test assembly.</summary>
internal static class Fixtures
{
    public static string Directory => Path.Combine(AppContext.BaseDirectory, "fixtures");

    public static string Read(string name) => File.ReadAllText(Path.Combine(Directory, name));

    public static IReadOnlyList<string> All() =>
        System.IO.Directory.GetFiles(Directory, "*.json").Select(Path.GetFileName).OfType<string>().Order(StringComparer.Ordinal).ToList();
}
