using Microsoft.Extensions.Logging;

using System.CommandLine;
using System.Security.Cryptography;

namespace ToXRSaveCryptor;

public class Program
{
    static int Main(string[] args)
    {
        Console.WriteLine("-----------------------------------------");
        Console.WriteLine($"- ToXRSaveCryptor by Nenkai");
        Console.WriteLine("-----------------------------------------");
        Console.WriteLine("- https://github.com/Nenkai");
        Console.WriteLine("- https://twitter.com/Nenkaai");
        Console.WriteLine("-----------------------------------------");
        Console.WriteLine("");

        if (args.Length == 1 && File.Exists(args[0]))
        {
            byte[] file = File.ReadAllBytes(args[0]);
            if (file.AsSpan().IndexOf("mVersion"u8) != -1)
            {
                Console.WriteLine($"ERROR: File is decrypted. Encrypt? [y/n]");
                if (Console.ReadKey().Key != ConsoleKey.Y)
                    return 0;

                EncryptSave(new FileInfo(args[0]));
            }
            else
            {
                Console.WriteLine($"ERROR: File is encrypted. Decrypt? [y/n]");
                if (Console.ReadKey().Key != ConsoleKey.Y)
                    return 0;

                DecryptSave(new FileInfo(args[0]));
            }

            return 0;
        }

        var rootCommand = new RootCommand("ToXRSaveCryptor");
        var inputOption = new Option<FileInfo>("--input", "-i") { Required = true, Description = "Input save file" };

        var decryptCommand = new Command("decrypt", "Decrypts the provided file.") { inputOption };
        decryptCommand.SetAction(parseResult =>
        {
            DecryptSave(parseResult.GetRequiredValue(inputOption));
        });
        rootCommand.Subcommands.Add(decryptCommand);

        var encryptCommand = new Command("encrypt", "Encrypts the provided file.") { inputOption };
        encryptCommand.SetAction(parseResult =>
        {
            EncryptSave(parseResult.GetRequiredValue(inputOption));
        });
        rootCommand.Subcommands.Add(encryptCommand);
        return rootCommand.Parse(args).Invoke();
    }

    private static void DecryptSave(FileInfo file)
    {
        if (!File.Exists(file.FullName))
        {
            Console.WriteLine($"ERROR: File {file.FullName} does not exist.");
            return;
        }

        byte[] bytes = File.ReadAllBytes(file.FullName);
        if (bytes.AsSpan().IndexOf("mVersion"u8) != -1)
        {
            Console.WriteLine($"ERROR: File is already decrypted.");
            return;
        }

        Console.WriteLine($"Decrypting: {file.FullName}...");

        byte[] decrypted = AES.Decrypt(bytes, AES.PASS);
        File.WriteAllBytes(file.FullName, decrypted);

        Console.WriteLine("File decrypted.");
    }

    private static void EncryptSave(FileInfo file)
    {
        if (!File.Exists(file.FullName))
        {
            Console.WriteLine($"ERROR: File {file.FullName} does not exist.");
            return;
        }

        byte[] bytes = File.ReadAllBytes(file.FullName);
        if (bytes.AsSpan().IndexOf("mVersion"u8) == -1)
        {
            Console.WriteLine($"ERROR: File is already encrypted.");
            return;
        }

        Console.WriteLine($"Encrypting: {file.FullName}...");


        byte[] encrypted = AES.Encrypt(bytes, AES.PASS);
        File.WriteAllBytes(file.FullName, encrypted);

        Console.WriteLine("File encrypted.");
    }
}

public class AES
{
    public const int BLOCK_SIZE = 128;
    public const int KEY_SIZE = 128;
    public const int SALT_SIZE = 16;
    public const string PASS = "guygdbkjnsdnfsl";

    public static byte[] Encrypt(byte[] src, string password)
    {
        var aes = Aes.Create(); // Original: AesManaged
        aes.BlockSize = BLOCK_SIZE;
        aes.KeySize = KEY_SIZE;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        var derive = new Rfc2898DeriveBytes(password, SALT_SIZE); // 1000 iterations
        aes.Key = derive.GetBytes(SALT_SIZE);
        aes.GenerateIV();

        ICryptoTransform encryptor = aes.CreateEncryptor();
        byte[] encrypted = encryptor.TransformFinalBlock(src, 0, src.Length);

        byte[] finalBuffer = new byte[derive.Salt.Length + aes.IV.Length + encrypted.Length];
        derive.Salt.AsSpan().CopyTo(finalBuffer.AsSpan(0x00));
        aes.IV.AsSpan().CopyTo(finalBuffer.AsSpan(0x10));
        encrypted.AsSpan().CopyTo(finalBuffer.AsSpan(0x20));
        return finalBuffer;
    }

    public static byte[] Decrypt(byte[] src, string password)
    {
        var aes = Aes.Create(); // Original: AesManaged
        aes.BlockSize = BLOCK_SIZE;
        aes.KeySize = KEY_SIZE;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        byte[] salt = src.AsSpan(0, SALT_SIZE).ToArray();
        byte[] iv = src.AsSpan(SALT_SIZE, 0x10).ToArray();
        var derive = new Rfc2898DeriveBytes(password, salt); // 1000 iterations
        aes.Key = derive.GetBytes(SALT_SIZE);
        aes.IV = iv;

        byte[] toDecrypt = new byte[src.Length - 0x20];
        src.AsSpan(0x20, toDecrypt.Length).CopyTo(toDecrypt);
        var dec = aes.CreateDecryptor();
        byte[] decrypted = dec.TransformFinalBlock(toDecrypt, 0, toDecrypt.Length);

        return decrypted;
    }
}
