using System.Buffers;
using System.Buffers.Binary;
using System.Text;

namespace KestrelAcme.Hosting;

/// <summary>What the client asked for in its TLS ClientHello.</summary>
internal sealed record ClientHello(string? ServerName, IReadOnlyList<string> ApplicationProtocols)
{
    public bool Offers(string protocol) => ApplicationProtocols.Contains(protocol, StringComparer.Ordinal);
}

internal enum ClientHelloParseResult
{
    /// <summary>The ClientHello was read.</summary>
    Success,

    /// <summary>More bytes are needed.</summary>
    Incomplete,

    /// <summary>The bytes are not a TLS handshake (plain HTTP, for instance), or are malformed.</summary>
    NotClientHello,
}

/// <summary>
/// Reads the server name (SNI) and offered ALPN protocols from a TLS ClientHello (RFC 8446 §4.1.2), which
/// <see cref="System.Net.Security.SslClientHelloInfo"/> doesn't expose. Handshake messages split across several
/// TLS records are reassembled.
/// </summary>
internal static class ClientHelloParser
{
    private const byte HandshakeRecord = 0x16;
    private const byte ClientHelloMessage = 0x01;
    private const ushort ServerNameExtension = 0x0000;
    private const ushort AlpnExtension = 0x0010;
    private const int RecordHeaderLength = 5;
    private const int MaxRecordLength = 16384 + 2048;

    /// <summary>Gives up on ClientHellos bigger than this; real ones are a few kilobytes.</summary>
    public const int MaxClientHelloLength = 64 * 1024;

    public static ClientHelloParseResult TryParse(ReadOnlySequence<byte> data, out ClientHello? clientHello)
    {
        clientHello = null;
        var reader = new SequenceReader<byte>(data);
        var handshake = new ArrayBufferWriter<byte>();

        // Collect handshake-record payloads until the whole ClientHello message is there.
        while (true)
        {
            if (reader.Remaining < RecordHeaderLength)
                return reader.Consumed == 0 && reader.TryPeek(out var first) && first != HandshakeRecord
                    ? ClientHelloParseResult.NotClientHello
                    : ClientHelloParseResult.Incomplete;

            reader.TryRead(out var contentType);
            reader.TryRead(out var majorVersion);
            reader.Advance(1);
            reader.TryReadBigEndian(out short recordLength);

            if (contentType != HandshakeRecord || majorVersion != 3 || recordLength <= 0 || recordLength > MaxRecordLength)
                return ClientHelloParseResult.NotClientHello;
            if (reader.Remaining < recordLength)
                return ClientHelloParseResult.Incomplete;

            reader.UnreadSequence.Slice(0, recordLength).CopyTo(handshake.GetSpan(recordLength));
            handshake.Advance(recordLength);
            reader.Advance(recordLength);

            var message = handshake.WrittenSpan;
            if (message.Length < 4)
                continue;
            if (message[0] != ClientHelloMessage)
                return ClientHelloParseResult.NotClientHello;

            var messageLength = (message[1] << 16) | (message[2] << 8) | message[3];
            if (messageLength > MaxClientHelloLength)
                return ClientHelloParseResult.NotClientHello;
            if (message.Length - 4 < messageLength)
                continue;

            clientHello = ParseBody(message.Slice(4, messageLength));
            return clientHello is null ? ClientHelloParseResult.NotClientHello : ClientHelloParseResult.Success;
        }
    }

    private static ClientHello? ParseBody(ReadOnlySpan<byte> body)
    {
        var reader = new SpanReader(body);

        // legacy_version, random, legacy_session_id, cipher_suites, legacy_compression_methods
        if (!reader.Skip(2 + 32) || !reader.SkipVector8() || !reader.SkipVector16() || !reader.SkipVector8())
            return null;

        string? serverName = null;
        var protocols = new List<string>();

        // A ClientHello without extensions is legal (TLS 1.0–1.2), it just carries neither SNI nor ALPN.
        if (reader.IsEmpty)
            return new ClientHello(null, protocols);

        if (!reader.TryReadVector16(out var extensions))
            return null;

        var extensionReader = new SpanReader(extensions);
        while (!extensionReader.IsEmpty)
        {
            if (!extensionReader.TryReadUInt16(out var type) || !extensionReader.TryReadVector16(out var extension))
                return null;

            switch (type)
            {
                case ServerNameExtension:
                    serverName = ReadServerName(extension);
                    break;
                case AlpnExtension:
                    if (!ReadProtocols(extension, protocols))
                        return null;
                    break;
            }
        }

        return new ClientHello(serverName, protocols);
    }

    private static string? ReadServerName(ReadOnlySpan<byte> extension)
    {
        var reader = new SpanReader(extension);
        if (!reader.TryReadVector16(out var list))
            return null;

        var listReader = new SpanReader(list);
        while (listReader.TryReadByte(out var nameType) && listReader.TryReadVector16(out var name))
        {
            if (nameType == 0) // host_name
                return Encoding.ASCII.GetString(name).ToLowerInvariant();
        }
        return null;
    }

    private static bool ReadProtocols(ReadOnlySpan<byte> extension, List<string> protocols)
    {
        var reader = new SpanReader(extension);
        if (!reader.TryReadVector16(out var list))
            return false;

        var listReader = new SpanReader(list);
        while (!listReader.IsEmpty)
        {
            if (!listReader.TryReadVector8(out var protocol))
                return false;
            protocols.Add(Encoding.ASCII.GetString(protocol));
        }
        return true;
    }

    /// <summary>Reads big-endian integers and length-prefixed vectors, failing instead of throwing on short input.</summary>
    private ref struct SpanReader(ReadOnlySpan<byte> data)
    {
        private ReadOnlySpan<byte> _data = data;

        public readonly bool IsEmpty => _data.IsEmpty;

        public bool Skip(int count)
        {
            if (_data.Length < count)
                return false;
            _data = _data[count..];
            return true;
        }

        public bool TryReadByte(out byte value)
        {
            value = 0;
            if (_data.IsEmpty)
                return false;
            value = _data[0];
            _data = _data[1..];
            return true;
        }

        public bool TryReadUInt16(out ushort value)
        {
            value = 0;
            if (_data.Length < 2)
                return false;
            value = BinaryPrimitives.ReadUInt16BigEndian(_data);
            _data = _data[2..];
            return true;
        }

        public bool TryReadVector8(out ReadOnlySpan<byte> vector)
        {
            vector = default;
            return TryReadByte(out var length) && TryTake(length, out vector);
        }

        public bool TryReadVector16(out ReadOnlySpan<byte> vector)
        {
            vector = default;
            return TryReadUInt16(out var length) && TryTake(length, out vector);
        }

        public bool SkipVector8() => TryReadVector8(out _);

        public bool SkipVector16() => TryReadVector16(out _);

        private bool TryTake(int length, out ReadOnlySpan<byte> vector)
        {
            vector = default;
            if (_data.Length < length)
                return false;
            vector = _data[..length];
            _data = _data[length..];
            return true;
        }
    }
}
