#region Что делает алгоритм
// Что делает алгоритм:
//
// 1. Берет исходные данные:
//    - простые числа p и q;
//    - число e;
//    - сообщение для подписи.
//
// 2. Считает ключи RSA:
//    - находит n как p * q;
//    - считает phi;
//    - находит секретное число d.
//
// 3. Готовит сообщение:
//    - переводит текст в байты Windows-1251;
//    - считает хеш Skein-512-512.
//
// 4. Делает число из хеша:
//    - переводит хеш в большое число;
//    - берет остаток по модулю n, чтобы число подошло для RSA.
//
// 5. Создает подпись:
//    - возводит хеш в степень d по модулю n;
//    - получает электронную подпись.
//
// 6. Проверяет подпись:
//    - возводит подпись в степень e по модулю n;
//    - сравнивает результат с хешем по модулю n.
//
// 7. Показывает результат:
//    - выводит ключи, хеш, подпись и значение проверки.
#endregion

using System.Numerics;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;

const int P = 607;
const int Q = 383;
const int E = 17;
const string Message = " На краю дороги стоял дуб.";

Console.OutputEncoding = Encoding.UTF8;
Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

Console.WriteLine($"Строка: {Message}");
Console.WriteLine($"p = {P}");
Console.WriteLine($"q = {Q}");
Console.WriteLine("Нажмите Enter, чтобы вычислить подпись...");
Console.ReadLine();

BigInteger n = P * Q;
BigInteger phi = (P - 1) * (Q - 1);
BigInteger d = GetModInverse(E, phi);

Encoding win1251 = Encoding.GetEncoding(1251);
byte[] messageBytes = win1251.GetBytes(Message);
byte[] hashBytes = GetSkeinHash(messageBytes);

// Хеш длиннее маленького учебного модуля, поэтому берем его по модулю n.
BigInteger hashValue = new BigInteger(hashBytes, isUnsigned: true, isBigEndian: true) % n;
BigInteger signature = BigInteger.ModPow(hashValue, d, n);
BigInteger checkValue = BigInteger.ModPow(signature, E, n);

Console.WriteLine($"n = {n}");
Console.WriteLine($"phi = {phi}");
Console.WriteLine($"Открытый ключ: ({E}, {n})");
Console.WriteLine($"Закрытый ключ: ({d}, {n})");
Console.WriteLine($"Хеш Skein-512-512: {Convert.ToHexString(hashBytes)}");
Console.WriteLine($"Хеш по модулю n: {hashValue}");
Console.WriteLine($"Подпись RSA: {signature}");
Console.WriteLine($"Проверка подписи: {checkValue}");

return;

byte[] GetSkeinHash(byte[] data)
{
    SkeinDigest digest = new SkeinDigest(512, 512);
    digest.BlockUpdate(data, 0, data.Length);

    byte[] result = new byte[digest.GetDigestSize()];
    digest.DoFinal(result, 0);
    return result;
}

BigInteger GetModInverse(BigInteger value, BigInteger modulus)
{
    BigInteger oldR = value;
    BigInteger r = modulus;
    BigInteger oldT = 1;
    BigInteger t = 0;

    // Обычный расширенный алгоритм Евклида.
    while (r != 0)
    {
        BigInteger quotient = oldR / r;

        BigInteger tempR = oldR - quotient * r;
        oldR = r;
        r = tempR;

        BigInteger tempT = oldT - quotient * t;
        oldT = t;
        t = tempT;
    }

    if (oldT < 0)
    {
        oldT += modulus;
    }

    return oldT;
}
