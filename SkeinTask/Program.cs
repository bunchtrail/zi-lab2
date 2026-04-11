using System.Text;
using Org.BouncyCastle.Crypto.Digests;

const string Message = "Мир, вероятно, спасти уже не удастся, но отдельного человека — всегда можно.";

Console.OutputEncoding = Encoding.UTF8;
Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

Console.WriteLine($"Сообщение: {Message}");
Console.WriteLine("Нажмите Enter, чтобы вычислить хеш Skein...");
Console.ReadLine();

Encoding win1251 = Encoding.GetEncoding(1251);
byte[] messageBytes = win1251.GetBytes(Message);
byte[] hashBytes = GetSkeinHash(messageBytes);

Console.WriteLine($"Хеш Skein-512-512: {Convert.ToHexString(hashBytes)}");

return;

byte[] GetSkeinHash(byte[] data)
{
    // Берем вариант Skein с состоянием 512 бит и хешем 512 бит.
    SkeinDigest digest = new SkeinDigest(512, 512);
    digest.BlockUpdate(data, 0, data.Length);

    byte[] result = new byte[digest.GetDigestSize()];
    digest.DoFinal(result, 0);
    return result;
}
