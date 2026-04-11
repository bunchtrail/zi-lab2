using System.Text;

// Сообщение и ключ из варианта
string message = "Я не беру совсем никаких взяток.";
string keyHex = "00000000001256F08DF046D9FED637D232DA5BEED6CABD428CB27A362B4D8513";

// Таблица подстановки
byte[] Pi = {
    252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
    233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
    249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79,
    5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31,
    235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204,
    181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135,
    21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
    50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87,
    223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3,
    224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74,
    167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
    173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59,
    7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137,
    225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
    32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82,
    89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182
};

// Вектор для линейного преобразования L
byte[] LVec = { 148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1 };

Console.OutputEncoding = Encoding.UTF8;
Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

Console.WriteLine("Сообщение: " + message);
Console.WriteLine("Ключ (hex): " + keyHex);
Console.WriteLine();

// Переводим сообщение в байты через Windows-1251
Encoding win1251 = Encoding.GetEncoding(1251);
byte[] msgBytes = win1251.GetBytes(message);
Console.WriteLine("Сообщение в байтах: " + BitConverter.ToString(msgBytes));

// Переводим ключ из hex в массив байтов
byte[] key = new byte[32];
for (int i = 0; i < 32; i++)
    key[i] = Convert.ToByte(keyHex.Substring(i * 2, 2), 16);
Console.WriteLine("Ключ в байтах:      " + BitConverter.ToString(key));
Console.WriteLine();

// --- Развертка раундовых ключей ---
byte[][] roundKeys = ExpandKeys(key);
Console.WriteLine("Раундовые ключи:");
for (int i = 0; i < 10; i++)
    Console.WriteLine("  K[" + i + "] = " + BitConverter.ToString(roundKeys[i]));
Console.WriteLine();

// --- Вычисление имитовставки (CMAC на основе Кузнечика) ---

// Шифруем нулевой блок для получения подключей
byte[] r = EncryptBlock(new byte[16], roundKeys);
Console.WriteLine("R (шифр нулевого блока): " + BitConverter.ToString(r));

byte[] k1 = DoubleBlock(r);
byte[] k2 = DoubleBlock(k1);
Console.WriteLine("K1: " + BitConverter.ToString(k1));
Console.WriteLine("K2: " + BitConverter.ToString(k2));
Console.WriteLine();

// Разбиваем сообщение на блоки по 16 байт
int blockCount = (msgBytes.Length + 15) / 16;
Console.WriteLine("Количество блоков: " + blockCount);

byte[] state = new byte[16];

// Обрабатываем все блоки кроме последнего
for (int i = 0; i < blockCount - 1; i++)
{
    byte[] block = new byte[16];
    Array.Copy(msgBytes, i * 16, block, 0, 16);

    state = Xor(state, block);
    state = EncryptBlock(state, roundKeys);
    Console.WriteLine("После блока " + i + ": " + BitConverter.ToString(state));
}

// Обработка последнего блока
int lastLen = msgBytes.Length - (blockCount - 1) * 16;
byte[] lastBlock;

if (lastLen == 16)
{
    // Последний блок полный - XOR с k1
    lastBlock = new byte[16];
    Array.Copy(msgBytes, (blockCount - 1) * 16, lastBlock, 0, 16);
    lastBlock = Xor(lastBlock, k1);
}
else
{
    // Последний блок неполный - дополняем и XOR с k2
    lastBlock = new byte[16];
    Array.Copy(msgBytes, (blockCount - 1) * 16, lastBlock, 0, lastLen);
    lastBlock[lastLen] = 0x80; // бит дополнения
    lastBlock = Xor(lastBlock, k2);
}

state = Xor(state, lastBlock);
byte[] mac = EncryptBlock(state, roundKeys);

Console.WriteLine();
Console.WriteLine("Имитовставка: " + Convert.ToHexString(mac));


// === Функции алгоритма Кузнечик ===

// Развертка 256-битного ключа в 10 раундовых ключей
byte[][] ExpandKeys(byte[] masterKey)
{
    // Делим мастер-ключ на две половины
    byte[] left = new byte[16];
    byte[] right = new byte[16];
    Array.Copy(masterKey, 0, left, 0, 16);
    Array.Copy(masterKey, 16, right, 0, 16);

    byte[][] keys = new byte[10][];
    keys[0] = (byte[])left.Clone();
    keys[1] = (byte[])right.Clone();

    int idx = 2;
    for (int group = 0; group < 4; group++)
    {
        for (int step = 1; step <= 8; step++)
        {
            // Итерационная константа
            byte[] c = new byte[16];
            c[15] = (byte)(group * 8 + step);
            c = TransL(c);

            // Сеть Фейстеля
            byte[] temp = Xor(TransL(SubstS(Xor(left, c))), right);
            right = left;
            left = temp;
        }

        keys[idx++] = (byte[])left.Clone();
        keys[idx++] = (byte[])right.Clone();
    }

    return keys;
}

// Шифрование одного 128-битного блока
byte[] EncryptBlock(byte[] block, byte[][] keys)
{
    byte[] s = (byte[])block.Clone();

    for (int i = 0; i < 9; i++)
        s = TransL(SubstS(Xor(s, keys[i])));

    return Xor(s, keys[9]);
}

// Подстановка S (нелинейное преобразование)
byte[] SubstS(byte[] data)
{
    byte[] res = new byte[16];
    for (int i = 0; i < 16; i++)
        res[i] = Pi[data[i]];
    return res;
}

// Линейное преобразование L (16 раундов R)
byte[] TransL(byte[] data)
{
    byte[] res = (byte[])data.Clone();
    for (int i = 0; i < 16; i++)
        res = TransR(res);
    return res;
}

// Преобразование R (сдвиг + умножение в поле Галуа)
byte[] TransR(byte[] data)
{
    byte sum = 0;
    for (int i = 0; i < 16; i++)
        sum ^= MulGF(data[i], LVec[i]);

    byte[] res = new byte[16];
    res[0] = sum;
    for (int i = 1; i < 16; i++)
        res[i] = data[i - 1];
    return res;
}

// Умножение в поле Галуа GF(2^8) с полиномом x^8 + x^7 + x^6 + x + 1
byte MulGF(byte a, byte b)
{
    byte result = 0;
    byte temp = a;

    for (int i = 0; i < 8; i++)
    {
        if ((b & 1) != 0)
            result ^= temp;

        bool hi = (temp & 0x80) != 0;
        temp <<= 1;
        if (hi)
            temp ^= 0xC3;

        b >>= 1;
    }

    return result;
}

// Удвоение блока для CMAC (сдвиг влево на 1 бит в GF(2^128))
byte[] DoubleBlock(byte[] block)
{
    byte[] res = new byte[16];
    int carry = 0;

    for (int i = 15; i >= 0; i--)
    {
        int val = (block[i] << 1) | carry;
        res[i] = (byte)(val & 0xFF);
        carry = (block[i] & 0x80) != 0 ? 1 : 0;
    }

    if ((block[0] & 0x80) != 0)
        res[15] ^= 0x87;

    return res;
}

// XOR двух массивов байтов
byte[] Xor(byte[] a, byte[] b)
{
    byte[] res = new byte[a.Length];
    for (int i = 0; i < a.Length; i++)
        res[i] = (byte)(a[i] ^ b[i]);
    return res;
}
