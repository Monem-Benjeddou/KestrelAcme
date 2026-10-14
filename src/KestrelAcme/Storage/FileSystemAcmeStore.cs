using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Options;

namespace KestrelAcme.Storage;

/// <summary>
/// Stores values as files that only the current user can read: mode 0600/0700 on Linux and macOS, and on
/// Windows an ACL limited to the current user, SYSTEM and Administrators.
/// </summary>
internal sealed class FileSystemAcmeStore : IAcmeStore
{
    internal const UnixFileMode OwnerOnlyFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode OwnerOnlyDirectory = OwnerOnlyFile | UnixFileMode.UserExecute;

    private readonly string _root;

    public FileSystemAcmeStore(IOptions<AcmeOptions> options)
        : this(options.Value.StoragePath ?? GetDefaultPath())
    {
    }

    internal FileSystemAcmeStore(string root) => _root = Path.GetFullPath(root);

    internal static string GetDefaultPath()
    {
        var folder = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.Create);

        // Empty when the account has no home or profile (containers without HOME, systemd DynamicUser, some
        // Windows service accounts). Falling back to the working directory would scatter keys in unexpected places.
        if (string.IsNullOrEmpty(folder))
            throw new InvalidOperationException(
                "This account has no local application data folder. Set AcmeOptions.StoragePath to a writable directory.");

        return Path.Combine(folder, "KestrelAcme");
    }

    public async Task<byte[]?> ReadAsync(string key, CancellationToken cancellationToken)
    {
        var path = Resolve(key);
        try
        {
            return await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception e) when (e is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }
    }

    public async Task WriteAsync(string key, byte[] value, CancellationToken cancellationToken)
    {
        var path = Resolve(key);
        CreateDirectory(Path.GetDirectoryName(path)!);

        // Write to a temporary file first, so a crash never leaves a half-written key or certificate behind.
        var temporary = $"{path}.{Guid.NewGuid():N}.tmp";
        try
        {
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
            if (!OperatingSystem.IsWindows())
                options.UnixCreateMode = OwnerOnlyFile;

            await using (var stream = new FileStream(temporary, options))
                await stream.WriteAsync(value, cancellationToken).ConfigureAwait(false);

            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            File.Delete(temporary);
        }
    }

    public Task DeleteAsync(string key, CancellationToken cancellationToken)
    {
        try
        {
            File.Delete(Resolve(key)); // no error if the file doesn't exist
        }
        catch (DirectoryNotFoundException)
        {
        }
        return Task.CompletedTask;
    }

    /// <summary>Maps a key to a path inside the root, rejecting keys that would escape it.</summary>
    internal string Resolve(string key)
    {
        var path = Path.GetFullPath(Path.Combine(_root, key));
        var relative = Path.GetRelativePath(_root, path);
        if (relative == "." || relative == ".." || relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal)
            || Path.IsPathRooted(relative))
            throw new ArgumentException($"Invalid store key '{key}'.", nameof(key));
        return path;
    }

    internal static void CreateDirectory(string path)
    {
        if (Directory.Exists(path))
            return;

        // Create each missing level ourselves: the platform calls only protect the last one.
        var parent = Path.GetDirectoryName(path);
        if (parent is not null)
            CreateDirectory(parent);

        if (OperatingSystem.IsWindows())
            new DirectoryInfo(path).Create(OwnerOnlySecurity()); // files written inside inherit the ACL
        else
            Directory.CreateDirectory(path, OwnerOnlyDirectory);
    }

    [SupportedOSPlatform("windows")]
    private static DirectorySecurity OwnerOnlySecurity()
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        using var identity = WindowsIdentity.GetCurrent();
        var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        foreach (var sid in new[]
                 {
                     identity.User!,
                     new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                     new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                 })
        {
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        }
        return security;
    }
}
