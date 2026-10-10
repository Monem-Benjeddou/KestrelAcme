using KestrelAcme.Hosting;
using KestrelAcme.Protocol;

namespace KestrelAcme.Tests;

public class RenewalPlannerTests
{
    private static readonly DateTimeOffset Issued = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Expires = Issued.AddDays(90);

    [Fact]
    public void Without_ari_renews_with_a_third_of_the_lifetime_left()
    {
        var renewAt = RenewalPlanner.GetRenewalTime(Issued, Expires, window: null, renewBefore: null, random: 0.5);
        Assert.Equal(Issued.AddDays(60), renewAt);
    }

    [Theory]
    [InlineData(0.0, 0)]
    [InlineData(0.5, 12)]
    [InlineData(1.0, 24)]
    public void With_ari_picks_a_point_inside_the_window(double random, int hoursIntoWindow)
    {
        var window = new RenewalWindow(Issued.AddDays(59), Issued.AddDays(60));

        var renewAt = RenewalPlanner.GetRenewalTime(Issued, Expires, window, renewBefore: null, random);

        Assert.Equal(window.Start.AddHours(hoursIntoWindow), renewAt);
    }

    [Fact]
    public void Configured_margin_wins_over_ari()
    {
        var window = new RenewalWindow(Issued.AddDays(59), Issued.AddDays(60));

        var renewAt = RenewalPlanner.GetRenewalTime(Issued, Expires, window, TimeSpan.FromDays(10), random: 0.5);

        Assert.Equal(Expires.AddDays(-10), renewAt);
    }

    [Fact]
    public void An_inverted_window_is_ignored()
    {
        var window = new RenewalWindow(Issued.AddDays(60), Issued.AddDays(59));
        Assert.Equal(Issued.AddDays(60), RenewalPlanner.GetRenewalTime(Issued, Expires, window, null, 0.5));
    }

    [Fact]
    public void Waits_until_renewal_but_checks_again_at_least_every_interval()
    {
        var now = Issued.AddDays(1);

        Assert.Equal(RenewalPlanner.DefaultCheckInterval, RenewalPlanner.GetWaitTime(now, Issued.AddDays(60), serverRetryAfter: null));
        Assert.Equal(TimeSpan.FromHours(6), RenewalPlanner.GetWaitTime(now, Issued.AddDays(60), TimeSpan.FromHours(6)));
        Assert.Equal(TimeSpan.FromHours(2), RenewalPlanner.GetWaitTime(now, now.AddHours(2), null));
        Assert.Equal(TimeSpan.Zero, RenewalPlanner.GetWaitTime(now, now.AddHours(-2), null));
    }

    [Fact]
    public void Server_retry_after_is_clamped_to_sane_bounds()
    {
        var now = Issued.AddDays(1);
        var renewAt = Issued.AddDays(60);

        Assert.Equal(RenewalPlanner.MinCheckInterval, RenewalPlanner.GetWaitTime(now, renewAt, TimeSpan.FromSeconds(1)));
        Assert.Equal(RenewalPlanner.MaxCheckInterval, RenewalPlanner.GetWaitTime(now, renewAt, TimeSpan.FromDays(30)));
    }

    [Theory]
    [InlineData(0, 5)]
    [InlineData(1, 5)]
    [InlineData(2, 10)]
    [InlineData(3, 20)]
    [InlineData(7, 320)]
    [InlineData(8, 360)]
    [InlineData(1000, 360)]
    public void Backs_off_exponentially_up_to_six_hours(int failures, int expectedMinutes)
    {
        Assert.Equal(TimeSpan.FromMinutes(expectedMinutes), RenewalPlanner.GetRetryDelay(failures, serverRetryAfter: null));
    }

    [Fact]
    public void Backoff_honours_a_longer_retry_after_from_the_server()
    {
        Assert.Equal(TimeSpan.FromHours(3), RenewalPlanner.GetRetryDelay(1, TimeSpan.FromHours(3)));
        Assert.Equal(TimeSpan.FromMinutes(20), RenewalPlanner.GetRetryDelay(3, TimeSpan.FromSeconds(5)));

        // Rate limits can ask for days; retrying earlier only gets rate-limited again.
        Assert.Equal(TimeSpan.FromDays(3), RenewalPlanner.GetRetryDelay(1, TimeSpan.FromDays(3)));
        Assert.Equal(RenewalPlanner.MaxServerRetryAfter, RenewalPlanner.GetRetryDelay(1, TimeSpan.FromDays(30)));
    }
}
