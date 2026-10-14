using KestrelAcme.Hosting;
using KestrelAcme.Storage;

namespace KestrelAcme.Tests;

public sealed class StorageTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("kestrelacme-store-").FullName;

    [Fact]
    public async Task Round_trips_values_and_returns_null_for_missing_keys()
    {
        var store = new FileSystemAcmeStore(_root);

        Assert.Null(await store.ReadAsync("certificates/ca/example.com.pfx", default));
        await store.WriteAsync("certificates/ca/example.com.pfx", [1, 2, 3], default);
        await store.WriteAsync("certificates/ca/example.com.pfx", [4, 5], default);

        Assert.Equal([4, 5], await store.ReadAsync("certificates/ca/example.com.pfx", default));
        Assert.Single(Directory.GetFiles(Path.Combine(_root, "certificates", "ca"))); // no temporary files left
    }

    [Fact]
    public async Task A_trailing_separator_in_the_storage_path_works()
    {
        var store = new FileSystemAcmeStore(_root + Path.DirectorySeparatorChar);

        await store.WriteAsync("accounts/ca/account.pem", [1], default);

        Assert.Equal([1], await store.ReadAsync("accounts/ca/account.pem", default));
    }

    [Fact]
    public async Task Deleting_removes_the_value_and_ignores_missing_ones()
    {
        var store = new FileSystemAcmeStore(_root);
        await store.WriteAsync("challenges/ca/http-01/token", [1], default);

        await store.DeleteAsync("challenges/ca/http-01/token", default);
        await store.DeleteAsync("challenges/ca/http-01/token", default);
        await store.DeleteAsync("nowhere/at/all", default);

        Assert.Null(await store.ReadAsync("challenges/ca/http-01/token", default));
    }

    [Fact]
    public async Task The_file_lock_has_one_holder_at_a_time()
    {
        // Two lock objects, as two instances sharing the folder would have.
        var first = new FileSystemAcmeLock(new FileSystemAcmeStore(_root));
        var second = new FileSystemAcmeLock(new FileSystemAcmeStore(_root));

        var held = await first.TryAcquireAsync("certificates/ca/example.com.pfx", default);
        Assert.NotNull(held);
        Assert.Null(await second.TryAcquireAsync("certificates/ca/example.com.pfx", default));
        await using (var other = await second.TryAcquireAsync("certificates/ca/other.com.pfx", default))
            Assert.NotNull(other); // other certificates aren't blocked

        await held!.DisposeAsync();
        await using var taken = await second.TryAcquireAsync("certificates/ca/example.com.pfx", default);
        Assert.NotNull(taken);
    }

    [Theory]
    [InlineData("../outside.pem")]
    [InlineData("accounts/../../outside.pem")]
    [InlineData(".")]
    public void Keys_cannot_escape_the_root(string key)
    {
        var store = new FileSystemAcmeStore(_root);
        Assert.Throws<ArgumentException>(() => store.Resolve(key));
    }

    [Fact]
    public async Task Files_are_readable_only_by_the_owner_on_unix()
    {
        if (OperatingSystem.IsWindows())
            return;

        var store = new FileSystemAcmeStore(_root);
        await store.WriteAsync("accounts/ca/account.pem", [1], default);

        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(Path.Combine(_root, "accounts", "ca", "account.pem")));
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(Path.Combine(_root, "accounts")));
    }

    [Fact]
    public async Task Directories_are_limited_to_owner_system_and_administrators_on_windows()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var store = new FileSystemAcmeStore(_root);
        await store.WriteAsync("accounts/ca/account.pem", [1], default);

        AssertOwnerOnly(Path.Combine(_root, "accounts"));
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void AssertOwnerOnly(string directory)
    {
        var security = new DirectoryInfo(directory).GetAccessControl();
        Assert.True(security.AreAccessRulesProtected);
        var sids = security.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier))
            .Cast<System.Security.AccessControl.FileSystemAccessRule>()
            .Select(r => r.IdentityReference.Value)
            .ToHashSet();
        Assert.Equal(3, sids.Count);
        Assert.Contains(System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value, sids);
    }

    [Theory]
    [InlineData("https://acme-v02.api.letsencrypt.org/directory", "acme-v02.api.letsencrypt.org_directory")]
    [InlineData("https://acme-staging-v02.api.letsencrypt.org/directory", "acme-staging-v02.api.letsencrypt.org_directory")]
    [InlineData("https://localhost:14000/dir", "localhost_14000_dir")]
    [InlineData("https://ca.example/acme/one/", "ca.example_acme_one")]
    public void Each_ca_directory_gets_its_own_folder_name(string directory, string expected)
    {
        Assert.Equal(expected, AcmeCertificateIssuer.StoreName(new Uri(directory)));
    }

    [Theory]
    [InlineData("example.com", "example.com")]
    [InlineData("*.example.com", "_wildcard.example.com")] // '*' is not allowed in Windows file names
    public void Certificate_file_names_are_valid_on_every_os(string domain, string expected)
    {
        Assert.Equal(expected, AcmeCertificateIssuer.FileName(domain));
    }

    [Fact]
    public void Dns01_record_is_the_hashed_key_authorization_under_acme_challenge()
    {
        var expected = Protocol.Base64Url.Encode(System.Security.Cryptography.SHA256.HashData("token.thumb"u8));

        Assert.Equal("_acme-challenge.example.com", AcmeCertificateIssuer.Dns01RecordName("example.com"));
        Assert.Equal(expected, AcmeCertificateIssuer.Dns01RecordValue("token.thumb"));
        Assert.Equal(43, expected.Length); // 32 bytes, unpadded base64url
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}
