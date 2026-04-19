#region Что делает алгоритм
// Что делает алгоритм:
//
// 1. Берет исходные данные:
//    - простые числа p и q;
//    - число e;
//    - сообщение для шифрования.
//
// 2. Считает ключи RSA:
//    - находит n как p * q;
//    - считает phi;
//    - находит секретное число d.
//
// 3. Готовит сообщение:
//    - берет кодировку Windows-1251;
//    - переводит текст в байты.
//
// 4. Шифрует байты:
//    - берет каждый байт отдельно;
//    - возводит его в степень e по модулю n.
//
// 5. Собирает шифртекст:
//    - сохраняет полученные числа;
//    - выводит их через пробел.
//
// 6. Показывает результат:
//    - выводит открытый и закрытый ключи;
//    - выводит зашифрованное сообщение.
#endregion

using System.Numerics;
using System.Text;

const int P = 607;
const int Q = 383;
const int E = 17;
const string Message = "Чего сама-то боится, тем и других пугает.";

Console.OutputEncoding = Encoding.UTF8;
Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

Console.WriteLine($"p = {P}");
Console.WriteLine($"q = {Q}");
Console.WriteLine($"Сообщение: {Message}");
Console.WriteLine("Нажмите Enter, чтобы зашифровать...");
Console.ReadLine();

BigInteger n = P * Q;
BigInteger phi = (P - 1) * (Q - 1);
BigInteger d = GetModInverse(E, phi);

Encoding win1251 = Encoding.GetEncoding(1251);
byte[] messageBytes = win1251.GetBytes(Message);
BigInteger[] encryptedMessage = EncryptMessage(messageBytes, E, n);

Console.WriteLine($"n = {n}");
Console.WriteLine($"phi = {phi}");
Console.WriteLine($"Открытый ключ: ({E}, {n})");
Console.WriteLine($"Закрытый ключ: ({d}, {n})");
Console.WriteLine("Шифртекст:");
Console.WriteLine(string.Join(" ", encryptedMessage));

return;

BigInteger[] EncryptMessage(byte[] data, BigInteger e, BigInteger n)
{
    BigInteger[] result = new BigInteger[data.Length];

    // Шифруем каждый байт сообщения отдельно.
    for (int i = 0; i < data.Length; i++)
    {
        result[i] = BigInteger.ModPow(data[i], e, n);
    }

    return result;
}

BigInteger GetModInverse(BigInteger value, BigInteger modulus)
{
    BigInteger oldR = value;
    BigInteger r = modulus;
    BigInteger oldT = 1;
    BigInteger t = 0;

    // Расширенный алгоритм Евклида для поиска обратного элемента.
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
