using LibSHA2.Factories;
using LibSHA2.Interfaces;
using System.Text;

string message = "Hello, World!";
Encoding encoding = Encoding.UTF8;

IHashAlgorithm sha224 = HashFactory.CreateSHA2(224);
string hash224 = sha224.ComputeHash(message, encoding);
Console.WriteLine($"SHA-224 Hash:\t{hash224}");
Console.WriteLine("Expected:\t72a23dfa411ba6fde01dbfabf3b00a709c93ebf273dc29e2d8b261ff\n");

IHashAlgorithm sha256 = HashFactory.CreateSHA2(256);
string hash256 = sha256.ComputeHash(message, encoding);
Console.WriteLine($"SHA-256 Hash:\t{hash256}");
Console.WriteLine("Expected:\tdffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f\n");

IHashAlgorithm sha384 = HashFactory.CreateSHA2(384);
string hash384 = sha384.ComputeHash(message, encoding);
Console.WriteLine($"SHA-384 Hash:\t{hash384}");
Console.WriteLine("Expected:\t5485cc9b3365b4305dfb4e8337e0a598a574f8242bf17289e0dd6c20a3cd44a089de16ab4ab308f63e44b1170eb5f515\n");

IHashAlgorithm sha512 = HashFactory.CreateSHA2(512);
string hash512 = sha512.ComputeHash(message, encoding);
Console.WriteLine($"SHA-512 Hash:\t{hash512}");
Console.WriteLine("Expected:\t374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387\n");
Console.ReadLine();
