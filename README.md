> [!TIP]
> To fully understand this code, it is highly recommended that you watch and practice the [SHA-2 tutorial](https://www.youtube.com/watch?v=SZwsj3YHp38&list=PLp9W_V_LID_9ucXbhk0FrMxHjFUBt4uU6&index=1).


# SHA-2 Hash Algorithm Implementation in C#
This project provides a simple and customizable C# implementation of the SHA-2 family of cryptographic hash functions, supporting SHA-224, SHA-256, SHA-384, and SHA-512. It is designed for educational purposes and lightweight use cases, offering flexibility for developers to understand and experiment with SHA-2 hash algorithms.

## Description

SHA-2 (Secure Hash Algorithm 2) is a set of cryptographic hash functions designed by the NSA, which includes SHA-224, SHA-256, SHA-384, and SHA-512. This repository contains a simple implementation of these algorithms in C#, allowing users to hash messages of any size and obtain secure, fixed-size hash values.

## Features

- Supports SHA-224, SHA-256, SHA-384, and SHA-512 hash functions.
- Clean and modular design, facilitating easy understanding and modification.
- Includes basic interface and factory pattern for creating hash algorithms.
- Lightweight and dependency-free.

## Uses and Applications

The LibSHA2 library implements hash algorithms from the SHA-2 family, specifically SHA-224, SHA-256, SHA-384, and SHA-512. These algorithms are widely used in cybersecurity to ensure data integrity by generating checksums (hashes). They are applied in areas such as file integrity verification, digital signatures, cryptographic key generation, and secure password storage.

### Compatibilities

LibSHA2 is designed to be compatible with any C# project that requires secure hash algorithms. It is compatible with .NET applications and can be easily integrated into systems that need SHA-2 algorithms for data security.

### File Structure

The LibSHA2 project structure is organized as follows:
```
LibSHA2
│
├── Algorithms
│   ├── SHA224.cs
│   ├── SHA256.cs
│   ├── SHA384.cs
│   └── SHA512.cs
│
├── Factories
│   └── HashFactory.cs
│
├── Interfaces
│   └── IHashFactory.cs
│
└── SHA2Base.cs
```

- **LibSHA2**: The main namespace containing the classes for the SHA-2 algorithms.
- **Algorithms**: Contains the specific implementations of each SHA-2 variant (SHA224, SHA256, SHA384, SHA512).
- **Factories**: Contains the HashFactory class, which facilitates the creation of SHA-2 algorithm instances.
- **Interfaces**: Defines the IHashAlgorithm interface, which ensures that all SHA-2 implementations follow a common contract.
- **SHA2Base.cs**: Abstract base class that provides the common functionality for all SHA-2 variants.

### Technical Details

#### Use of Abstract Classes and Their Structure

Abstract classes in LibSHA2 are used to define a common structure for all SHA-2 hash algorithms. SHA2Base<T> is an abstract class that defines the necessary properties and methods that must be implemented in derived classes, such as SHA224, SHA256, SHA384, and SHA512.

SHA2Base defines abstract properties like BlockSize, HashSize, and Rounds, which must be implemented by subclasses to specify the block size, hash size, and the number of rounds for each SHA-2 variant.

Additionally, it provides abstract methods such as InitialHashValues(), RoundConstants(), RightRotate(T x, int r), and others, which must be implemented by subclasses to provide the constants and operations specific to each SHA-2 algorithm.

These abstract methods and properties ensure that each SHA-2 variant follows a consistent pattern, allowing flexibility in implementing specific details.

#### Use of the IHashAlgorithm Interface and Its Importance

The IHashAlgorithm interface defines a contract for all hash algorithms in LibSHA2. Its main method is ComputeHash(string message, Encoding encoding), which takes a message and its encoding as input and returns the corresponding hash as a hexadecimal string.

This interface is crucial because it allows different hash algorithms (such as SHA-224, SHA-256, etc.) to be used interchangeably in the code, ensuring that any class implementing IHashAlgorithm can be used wherever a hash algorithm is expected, promoting flexibility and extensibility in the code.

#### Use of the <T> Parameter in SHA2Base.cs and Its Importance

The generic type parameter <T> in the SHA2Base abstract class allows the class to work with different data types (e.g., uint for SHA-224/256 and ulong for SHA-384/512). This is important because different SHA-2 variants use different word sizes (32-bit for uint and 64-bit for ulong), and the use of a generic parameter allows a single base implementation to handle both cases, reducing code duplication and increasing code reuse.

#### Justification for the GetSizeOfT() Method in SHA2Base.cs

The GetSizeOfT() method is a protected static method that determines the size in bytes of the type T used in the current instance of SHA2Base. This method is necessary because the SHA2Base class is used for both algorithms that operate on 32-bit words (uint) and 64-bit words (ulong), and it is crucial to know the size of the type to perform operations correctly and to construct the final hash accurately.

This method also facilitates writing the hash in its hexadecimal representation, ensuring that the correct number of bytes is used for each word type, which is essential for the accuracy and interoperability of the algorithm.

# Getting Started

## Prerequisites

To use or modify this project, you need the following installed:

- [.NET SDK](https://dotnet.microsoft.com/download) (version 5.0 or higher recommended)
- A code editor such as [Visual Studio](https://visualstudio.microsoft.com/) or [Visual Studio Code](https://code.visualstudio.com/)

## Usage
To use the SHA-2 implementation in your project, you can reference the LibSHA2 library in your solution.

```cs
using LibSHA2.Interfaces;
using LibSHA2.Factories;
using System.Text;

class Program
{
    static void Main()
    {
        IHashAlgorithm sha256 = HashFactory.CreateSHA2(256);
        string hash = sha256.ComputeHash("Hello, World!", Encoding.UTF8);
        Console.WriteLine($"SHA-256: {hash}");
    }
}
```
Compile and run the program to see the hashed output.

## Example
Here's a simple example demonstrating how to compute the SHA-256 hash of a string:

```cs
using System;
using System.Text;
using LibSHA2.Factories;
using LibSHA2.Interfaces;

class Example
{
    static void Main()
    {
        IHashAlgorithm sha256 = HashFactory.CreateSHA2(256);
        string input = "Sample text";
        string hash = sha256.ComputeHash(input, Encoding.UTF8);
        Console.WriteLine($"SHA-256 hash of '{input}' is: {hash}");
    }
}
```
Expected output:
```cs
SHA-256 hash of 'Sample text' is: 94ee059335e587e501cc4bf90613e0814f00a7b08bc7c648fd865a2af6a22cc2
```

> [!TIP]
> To fully understand this code, it is highly recommended that you watch and practice the [SHA-2 tutorial](https://www.youtube.com/watch?v=SZwsj3YHp38&list=PLp9W_V_LID_9ucXbhk0FrMxHjFUBt4uU6&index=1).
 
