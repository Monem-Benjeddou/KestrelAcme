using System.Buffers;
using System.Net.Security;
using System.Text;
using KestrelAcme.Hosting;

namespace KestrelAcme.Tests;

public class ClientHelloParserTests
{
    [Fact]
    public async Task Reads_server_name_and_acme_protocol_from_a_real_client_hello()
    {
        var bytes = await CaptureClientHelloAsync("Example.COM", [new SslApplicationProtocol("acme-tls/1")]);

        var result = ClientHelloParser.TryParse(new ReadOnlySequence<byte>(bytes), out var hello);

        Assert.Equal(ClientHelloParseResult.Success, result);
        Assert.Equal("example.com", hello!.ServerName);
        Assert.Equal(["acme-tls/1"], hello.ApplicationProtocols);
        Assert.True(hello.Offers("acme-tls/1"));
    }

    [Fact]
    public async Task Reads_several_protocols_in_order()
    {
        var bytes = await CaptureClientHelloAsync("example.com", [SslApplicationProtocol.Http2, SslApplicationProtocol.Http11]);

        ClientHelloParser.TryParse(new ReadOnlySequence<byte>(bytes), out var hello);

        Assert.Equal(["h2", "http/1.1"], hello!.ApplicationProtocols);
        Assert.False(hello.Offers("acme-tls/1"));
    }

    [Fact]
    public async Task No_server_name_when_connecting_to_an_ip_address()
    {
        var bytes = await CaptureClientHelloAsync("127.0.0.1", null);

        Assert.Equal(ClientHelloParseResult.Success, ClientHelloParser.TryParse(new ReadOnlySequence<byte>(bytes), out var hello));
        Assert.Null(hello!.ServerName);
        Assert.Empty(hello.ApplicationProtocols);
    }

    [Fact]
    public async Task Every_truncation_is_incomplete_not_an_error()
    {
        var bytes = await CaptureClientHelloAsync("example.com", [SslApplicationProtocol.Http2]);

        for (var length = 0; length < bytes.Length; length++)
            Assert.Equal(ClientHelloParseResult.Incomplete, ClientHelloParser.TryParse(new ReadOnlySequence<byte>(bytes, 0, length), out _));
    }

    [Fact]
    public async Task Reassembles_a_client_hello_split_across_records_and_buffer_segments()
    {
        var bytes = await CaptureClientHelloAsync("split.example", [new SslApplicationProtocol("acme-tls/1")]);
        var fragmented = SplitIntoRecords(bytes, fragmentSize: 50);

        var result = ClientHelloParser.TryParse(ToSegments(fragmented, segmentSize: 7), out var hello);

        Assert.Equal(ClientHelloParseResult.Success, result);
        Assert.Equal("split.example", hello!.ServerName);
        Assert.True(hello.Offers("acme-tls/1"));
    }

    [Theory]
    [InlineData("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")]
    [InlineData("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")]
    public void Plain_http_is_not_a_client_hello(string request)
    {
        var result = ClientHelloParser.TryParse(new ReadOnlySequence<byte>(Encoding.ASCII.GetBytes(request)), out _);
        Assert.Equal(ClientHelloParseResult.NotClientHello, result);
    }

    [Fact]
    public void Garbage_after_a_handshake_header_is_rejected()
    {
        byte[] bytes = [0x16, 0x03, 0x01, 0x00, 0x06, 0x01, 0x00, 0x00, 0x02, 0xFF, 0xFF];
        Assert.Equal(ClientHelloParseResult.NotClientHello, ClientHelloParser.TryParse(new ReadOnlySequence<byte>(bytes), out _));
    }

    /// <summary>Lets SslStream write its ClientHello into memory, then fails the handshake on purpose.</summary>
    internal static async Task<byte[]> CaptureClientHelloAsync(string targetHost, List<SslApplicationProtocol>? protocols)
    {
        var capture = new CaptureStream();
        await using var ssl = new SslStream(capture);
        try
        {
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = targetHost,
                ApplicationProtocols = protocols,
                RemoteCertificateValidationCallback = (_, _, _, _) => true,
            });
        }
        catch (Exception e) when (e is IOException or System.Security.Authentication.AuthenticationException)
        {
            // Expected: the "server" closes the connection.
        }
        return capture.Written.ToArray();
    }

    private static byte[] SplitIntoRecords(byte[] singleRecord, int fragmentSize)
    {
        var payload = singleRecord.AsSpan(5);
        var output = new List<byte>();
        for (var offset = 0; offset < payload.Length; offset += fragmentSize)
        {
            var fragment = payload.Slice(offset, Math.Min(fragmentSize, payload.Length - offset));
            output.AddRange([0x16, singleRecord[1], singleRecord[2], (byte)(fragment.Length >> 8), (byte)fragment.Length]);
            output.AddRange(fragment.ToArray());
        }
        return output.ToArray();
    }

    private static ReadOnlySequence<byte> ToSegments(byte[] data, int segmentSize)
    {
        Segment? first = null, last = null;
        for (var offset = 0; offset < data.Length; offset += segmentSize)
        {
            var memory = data.AsMemory(offset, Math.Min(segmentSize, data.Length - offset));
            if (first is null)
                first = last = new Segment(memory, 0);
            else
                last = last!.Append(memory);
        }
        return new ReadOnlySequence<byte>(first!, 0, last!, last!.Memory.Length);
    }

    private sealed class Segment : ReadOnlySequenceSegment<byte>
    {
        public Segment(ReadOnlyMemory<byte> memory, long runningIndex)
        {
            Memory = memory;
            RunningIndex = runningIndex;
        }

        public Segment Append(ReadOnlyMemory<byte> memory)
        {
            var next = new Segment(memory, RunningIndex + Memory.Length);
            Next = next;
            return next;
        }
    }

    private sealed class CaptureStream : Stream
    {
        public MemoryStream Written { get; } = new();

        public override void Write(byte[] buffer, int offset, int count) => Written.Write(buffer, offset, count);
        public override int Read(byte[] buffer, int offset, int count) => 0;
        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
