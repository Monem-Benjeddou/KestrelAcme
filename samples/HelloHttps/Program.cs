using KestrelAcme;

// Run on a server whose DNS name points at it, with ports 80 and 443 open:
//   dotnet run -- --Acme:Domains:0=example.com --Acme:Email=you@example.com
var builder = WebApplication.CreateBuilder(args);

builder.WebHost.UseUrls("http://*:80", "https://*:443");
builder.Services.AddKestrelAcme(builder.Configuration.GetSection("Acme"));
builder.Services.AddHealthChecks().AddKestrelAcme();

var app = builder.Build();

app.UseHttpsRedirection(); // HTTP-01 challenges are answered before this runs.
app.MapGet("/", () => "Hello over HTTPS!");
app.MapHealthChecks("/healthz");

app.Run();
