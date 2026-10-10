using System.Collections.Concurrent;
using System.Net.Http.Json;

namespace KestrelAcme.IntegrationTests;

/// <summary>Publishes TXT records on pebble-challtestsrv, the DNS server Pebble resolves names with.</summary>
internal sealed class PebbleDnsProvider : IDnsChallengeProvider
{
    private static readonly Uri Management = new("http://127.0.0.1:8055/");
    private readonly HttpClient _http = new() { BaseAddress = Management };

    public ConcurrentDictionary<string, List<string>> Live { get; } = new();
    public ConcurrentBag<string> Added { get; } = [];

    public async Task AddTxtRecordAsync(string name, string value, CancellationToken cancellationToken)
    {
        (await _http.PostAsJsonAsync("set-txt", new { host = name + ".", value }, cancellationToken)).EnsureSuccessStatusCode();
        Live.AddOrUpdate(name, _ => [value], (_, values) => { lock (values) values.Add(value); return values; });
        Added.Add(name);
    }

    public async Task RemoveTxtRecordAsync(string name, string value, CancellationToken cancellationToken)
    {
        // challtestsrv can only clear every value of a name: put the others back afterwards.
        var values = Live.GetOrAdd(name, _ => []);
        List<string> remaining;
        lock (values)
        {
            values.Remove(value);
            remaining = [.. values];
        }

        (await _http.PostAsJsonAsync("clear-txt", new { host = name + "." }, cancellationToken)).EnsureSuccessStatusCode();
        foreach (var other in remaining)
            (await _http.PostAsJsonAsync("set-txt", new { host = name + ".", value = other }, cancellationToken)).EnsureSuccessStatusCode();
        if (remaining.Count == 0)
            Live.TryRemove(name, out _);
    }
}
