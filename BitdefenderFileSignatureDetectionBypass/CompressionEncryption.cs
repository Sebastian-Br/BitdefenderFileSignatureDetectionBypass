using System;
using System.Collections.Generic;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace BitdefenderFileSignatureDetectionBypass;

internal class CompressionEncryption
{
    /// <summary>
    /// Compresses and encrypts a target file, creating two output files:
    /// The encrypted file and the XOR key file of equal size.
    /// </summary>
    /// <param name="inputFilePath">Full path to the file you want to encrypt</param>
    /// <param name="outputFilePath">Full output file path to write the encrypted file to</param>
    /// <param name="outKeyFilePath">Full output file path to write the key to</param>
    /// <returns>True: Operation was successful. False otherwise.</returns>
    public static bool CompressAndEncrypt(string inputFilePath, string outputFilePath, string outKeyFilePath)
    {
        if (string.IsNullOrWhiteSpace(inputFilePath))
        {
            throw new ArgumentNullException(nameof(inputFilePath));
        }

        if (string.IsNullOrWhiteSpace(outputFilePath))
        {
            throw new ArgumentNullException(nameof(outputFilePath));
        }

        if (string.IsNullOrWhiteSpace(outKeyFilePath))
        {
            throw new ArgumentNullException(nameof(outKeyFilePath));
        }

        if (!IsValidPath(outputFilePath))
        {
            throw new ArgumentException("Invalid output file path " + outputFilePath);
        }

        if (!IsValidPath(outKeyFilePath))
        {
            throw new ArgumentException("Invalid output key file path " + outKeyFilePath);
        }

        if (!File.Exists(inputFilePath))
        {
            throw new ArgumentException("Input file does not exist at " + inputFilePath);
        }

        byte[] fileBytes = File.ReadAllBytes(inputFilePath);
        byte[] compressedBytes = Compress(fileBytes);

        if (compressedBytes == null)
        {
            return false;
        }

        byte[] encryptedBytes = Encrypt(compressedBytes, outKeyFilePath);

        if (encryptedBytes == null)
        {
            return false;
        }

        File.WriteAllBytes(outputFilePath, encryptedBytes);
        return true;
    }

    public static byte[] DecompressAndDecrypt_ToMemory(string inputFilePath, string keyFilePath)
    {
        if (string.IsNullOrWhiteSpace(inputFilePath))
        {
            throw new ArgumentNullException(nameof(inputFilePath));
        }

        if (string.IsNullOrWhiteSpace(keyFilePath))
        {
            throw new ArgumentNullException(nameof(keyFilePath));
        }

        if (!File.Exists(inputFilePath))
        {
            throw new ArgumentException("Input file does not exist at " + inputFilePath);
        }

        if (!File.Exists(keyFilePath))
        {
            throw new ArgumentException("Key file does not exist at " + keyFilePath);
        }

        byte[] fileBytes = File.ReadAllBytes(inputFilePath);
        byte[] decryptedBytes = Decrypt(fileBytes, keyFilePath) ?? throw new InvalidOperationException("Decryption failed");
        byte[] decompressedBytes = Decompress(decryptedBytes) ?? throw new InvalidOperationException("Decompression failed");
        return decompressedBytes;
    }

    /// <summary>
    /// For debug purposes only
    /// </summary>
    /// <param name="inputFilePath"></param>
    /// <param name="keyFilePath"></param>
    /// <param name="outputFilePath"></param>
    /// <returns></returns>
    public static bool DecompressAndDecrypt_ToFile(string inputFilePath, string keyFilePath, string outputFilePath)
    {
        byte[] fileBytes = File.ReadAllBytes(inputFilePath);
        byte[] decryptedBytes = Decrypt(fileBytes, keyFilePath);

        if (decryptedBytes == null)
        {
            return false;
        }

        byte[] decompressedBytes = Decompress(decryptedBytes);
        if (decompressedBytes == null)
        {
            return false;
        }

        File.WriteAllBytes(outputFilePath, decompressedBytes);
        return true;
    }

    static byte[] GenerateKey(int length)
    {
        byte[] key = new byte[length];
        RandomNumberGenerator.Create().GetBytes(key);
        return key;
    }

    static byte[] Encrypt(byte[] dataToEncrypt, string keyFile)
    {
        try
        {
            byte[] key = GenerateKey(dataToEncrypt.Length);
            File.WriteAllBytes(keyFile, key);

            byte[] encryptedData = new byte[dataToEncrypt.Length];
            for (int i = 0; i < dataToEncrypt.Length; i++)
            {
                encryptedData[i] = (byte)(dataToEncrypt[i] ^ key[i]);
            }

            return encryptedData;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Encryption failed: {ex.Message}");
            return null;
        }
    }

    static byte[] Compress(byte[] data)
    {
        using MemoryStream ms = new();
        using (GZipStream gzip = new(ms, CompressionMode.Compress, true))
        {
            gzip.Write(data, 0, data.Length);
        }
        return ms.ToArray();
    }

    static byte[] Decrypt(byte[] encryptedData, string keyFile)
    {
        try
        {
            byte[] key = File.ReadAllBytes(keyFile);
            if (encryptedData.Length != key.Length)
            {
                throw new ArgumentException("Encrypted data size must be equal to key size.");
            }

            byte[] decryptedData = new byte[encryptedData.Length];
            for (int i = 0; i < encryptedData.Length; i++)
            {
                decryptedData[i] = (byte)(encryptedData[i] ^ key[i]);
            }

            return decryptedData;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Decryption failed: {ex.Message}");
            return null;
        }
    }

    static byte[] Decompress(byte[] data)
    {
        using MemoryStream compressedStream = new(data);
        using MemoryStream resultStream = new();
        using GZipStream gzip = new(compressedStream, CompressionMode.Decompress);
        gzip.CopyTo(resultStream);
        return resultStream.ToArray();
    }

    static bool IsValidPath(string path)
    {
        if(string.IsNullOrWhiteSpace(path))
            return false;

        char[] invalidChars = Path.GetInvalidPathChars();
        if (path.IndexOfAny(invalidChars) != -1)
        {
            return false;
        }

        try
        {
            Path.GetFullPath(path);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }
}