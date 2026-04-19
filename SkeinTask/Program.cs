#region Что делает алгоритм
// Что делает алгоритм:
//
// 1. Берет исходные данные:
//    - текст сообщения;
//    - нужные кодировки для вывода и байтов.
//
// 2. Показывает сообщение:
//    - выводит текст на экран;
//    - ждет Enter перед расчетом.
//
// 3. Переводит сообщение в байты:
//    - берет кодировку Windows-1251;
//    - получает байты строки.
//
// 4. Считает хеш:
//    - создает Skein-512-512;
//    - передает в него байты сообщения.
//
// 5. Получает результат:
//    - записывает хеш в массив байтов;
//    - переводит его в hex-строку.
//
// 6. Показывает итог:
//    - выводит хеш Skein-512-512 на экран.
#endregion

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
