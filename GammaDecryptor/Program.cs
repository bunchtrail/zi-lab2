#region Что делает алгоритм
// Что делает алгоритм:
//
// 1. Берет исходные данные:
//    - русский алфавит;
//    - зашифрованный текст;
//    - ключ.
//
// 2. Идет по шифртексту:
//    - берет буквы одну за другой;
//    - для каждой буквы ищет ее номер в алфавите.
//
// 3. Использует ключ:
//    - берет очередную букву ключа;
//    - если ключ закончился, начинает его сначала.
//
// 4. Расшифровывает букву:
//    - сдвигает букву назад по алфавиту;
//    - учитывает сдвиг на 1 позицию из задания.
//
// 5. Собирает ответ:
//    - добавляет найденную букву в строку;
//    - переходит к следующей букве.
//
// 6. Показывает результат:
//    - выводит открытый текст на экран.
#endregion

const string Alphabet = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";

const string CipherText = "НЛЛЕСЯУЪТШЪЬКЯРФНЫЪМВЬЫЬЦГККЛСИЗЕЭЬСНТЬАЧПЧЁЕЙ";
const string Key = "ЗЩЯЫЗМ";

Console.OutputEncoding = System.Text.Encoding.UTF8;

Console.WriteLine($"Шифртекст: {CipherText}");
Console.WriteLine($"Ключ: {Key}");
Console.WriteLine("Нажмите Enter, чтобы расшифровать...");
Console.ReadLine();

string decryptedText = Decrypt(CipherText, Key);

Console.WriteLine($"Расшифровка: {decryptedText}");

return;

string Decrypt(string cipherText, string key)
{
    string result = "";
    int keyPosition = 0;

    // Проходим по всему шифртексту посимвольно.
    foreach (char symbol in cipherText)
    {
        int cipherIndex = Alphabet.IndexOf(symbol);

        // Берем букву ключа. Ключ повторяется по кругу.
        char keySymbol = key[keyPosition % key.Length];
        int keyIndex = Alphabet.IndexOf(keySymbol);

        // В этом учебном варианте позиции букв считаются с 1, поэтому нужен сдвиг на -1.
        int plainIndex = (cipherIndex - keyIndex - 1 + Alphabet.Length) % Alphabet.Length;

        // Находим расшифрованную букву и добавляем ее в результат.
        result += Alphabet[plainIndex];

        // Индекс ключа двигаем только после обработки буквы из алфавита.
        keyPosition++;
    }

    return result;
}
