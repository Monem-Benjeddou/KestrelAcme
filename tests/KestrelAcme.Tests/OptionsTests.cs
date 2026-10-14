using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace KestrelAcme.Tests;

public class OptionsTests
{
    private static AcmeOptions Valid()
    {
        var options = new AcmeOptions { AcceptTermsOfService = true, Email = "ops@example.com" };
        options.Domains.Add("example.com");
        return options;
    }

    [Fact]
    public void Valid_options_pass()
    {
        Assert.True(new AcmeOptionsValidator().Validate(null, Valid()).Succeeded);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not a domain")]
    [InlineData("example.com.")]
    [InlineData("1.2.3.4")]
    [InlineData("*.example.com")] // no DNS provider registered
    public void Rejects_unusable_domains(string domain)
    {
        var options = Valid();
        options.Domains[0] = domain;
        Assert.True(new AcmeOptionsValidator().Validate(null, options).Failed);
    }

    [Fact]
    public void Wildcards_are_accepted_once_a_dns_provider_is_registered()
    {
        var options = Valid();
        options.Domains.Add("*.example.com");

        Assert.True(new AcmeOptionsValidator([new NoDns()]).Validate(null, options).Succeeded);

        options.Challenges = AcmeChallengeTypes.Http01 | AcmeChallengeTypes.TlsAlpn01;
        Assert.True(new AcmeOptionsValidator([new NoDns()]).Validate(null, options).Failed);
    }

    private sealed class NoDns : IDnsChallengeProvider
    {
        public Task AddTxtRecordAsync(string name, string value, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task RemoveTxtRecordAsync(string name, string value, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    [Fact]
    public void Reports_every_problem_at_once()
    {
        var options = new AcmeOptions
        {
            Email = "nope",
            DirectoryUri = new Uri("http://ca.example/directory"),
            Challenges = AcmeChallengeTypes.None,
            RenewBefore = TimeSpan.Zero,
        };

        var result = new AcmeOptionsValidator().Validate(null, options);

        Assert.Equal(6, result.Failures!.Count());
    }

    [Theory]
    [InlineData("c2VjcmV0LWtleQ")]     // base64url
    [InlineData("c2VjcmV0LWtleQ==")]   // standard base64, padded
    [InlineData("a+b/cw==")]           // standard alphabet
    public void Accepts_hmac_keys_in_either_base64_form(string key)
    {
        var options = Valid();
        options.ExternalAccountBinding = new ExternalAccountBinding("kid", key);
        Assert.True(new AcmeOptionsValidator().Validate(null, options).Succeeded);
    }

    [Fact]
    public void Rejects_an_hmac_key_that_does_not_decode()
    {
        var options = Valid();
        options.ExternalAccountBinding = new ExternalAccountBinding("kid", "not base64!");
        Assert.True(new AcmeOptionsValidator().Validate(null, options).Failed);
    }

    [Fact]
    public void Domains_are_lower_cased_converted_to_punycode_and_deduplicated()
    {
        var services = new ServiceCollection()
            .AddSingleton<IDnsChallengeProvider, NoDns>()
            .AddKestrelAcme(o =>
        {
            o.AcceptTermsOfService = true;
            o.Domains.Add(" Example.COM ");
            o.Domains.Add("example.com");
            o.Domains.Add("bücher.example");
            o.Domains.Add("*.Bücher.example");
        });

        var options = services.BuildServiceProvider().GetRequiredService<IOptions<AcmeOptions>>().Value;

        Assert.Equal(["example.com", "xn--bcher-kva.example", "*.xn--bcher-kva.example"], options.Domains);
    }

    [Fact]
    public void Kestrel_hook_runs_before_kestrel_configuration_registered_earlier()
    {
        var services = new ServiceCollection();
        services.Configure<Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions>(_ => { });

        services.AddKestrelAcme(o => o.Domains.Add("example.com"));

        var first = services.First(d => d.ServiceType == typeof(IConfigureOptions<Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions>));
        Assert.Equal(typeof(Hosting.KestrelOptionsSetup), first.ImplementationType);
    }

    [Fact]
    public void Binds_from_configuration()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Acme:Domains:0"] = "example.com",
            ["Acme:Domains:1"] = "www.example.com",
            ["Acme:Email"] = "ops@example.com",
            ["Acme:AcceptTermsOfService"] = "true",
            ["Acme:DirectoryUri"] = "https://acme-staging-v02.api.letsencrypt.org/directory",
            ["Acme:Challenges"] = "Http01",
            ["Acme:KeyAlgorithm"] = "Rsa2048",
            ["Acme:RenewBefore"] = "30.00:00:00",
            ["Acme:ExternalAccountBinding:KeyId"] = "kid",
            ["Acme:ExternalAccountBinding:HmacKey"] = "c2VjcmV0",
        }).Build();

        var services = new ServiceCollection().AddKestrelAcme(configuration.GetSection("Acme"));
        var options = services.BuildServiceProvider().GetRequiredService<IOptions<AcmeOptions>>().Value;

        Assert.Equal(["example.com", "www.example.com"], options.Domains);
        Assert.True(options.AcceptTermsOfService);
        Assert.Equal(AcmeDirectories.LetsEncryptStaging, options.DirectoryUri);
        Assert.Equal(AcmeChallengeTypes.Http01, options.Challenges);
        Assert.Equal(CertificateKeyAlgorithm.Rsa2048, options.KeyAlgorithm);
        Assert.Equal(TimeSpan.FromDays(30), options.RenewBefore);
        Assert.Equal(new ExternalAccountBinding("kid", "c2VjcmV0"), options.ExternalAccountBinding);
    }

    [Fact]
    public void Registering_twice_does_not_add_a_second_renewal_service()
    {
        var services = new ServiceCollection()
            .AddKestrelAcme(o => { o.Domains.Add("example.com"); o.AcceptTermsOfService = true; })
            .AddKestrelAcme(o => o.Domains.Add("www.example.com"));

        Assert.Single(services, d => d.ServiceType == typeof(Hosting.AcmeRenewalService));
        var options = services.BuildServiceProvider().GetRequiredService<IOptions<AcmeOptions>>().Value;
        Assert.Equal(["example.com", "www.example.com"], options.Domains);
    }

    [Theory]
    [InlineData("example.com", true)]
    [InlineData("*.example.com", true)]
    [InlineData("evil.example.com", false)]
    [InlineData("EXAMPLE.COM", false)]
    [InlineData("victim.example", false)]
    public void Identifiers_the_certificate_authority_asks_to_validate_must_have_been_ordered(string identifier, bool ordered)
    {
        List<string> domains = ["example.com", "*.example.com"];
        if (ordered)
            KestrelAcme.Hosting.AcmeCertificateIssuer.EnsureOrdered(domains, identifier);
        else
            Assert.Throws<AcmeException>(() => KestrelAcme.Hosting.AcmeCertificateIssuer.EnsureOrdered(domains, identifier));
    }
}
