using LibSHA2.Algorithms;
using LibSHA2.Interfaces;

namespace LibSHA2.Factories
{
    /// <summary>
    /// Factory class for creating instances of SHA-2 hash algorithms.
    /// </summary>
    public class HashFactory
    {
        /// <summary>
        /// Creates an instance of a SHA-2 hash algorithm based on the specified bit length.
        /// </summary>
        /// <param name="bits">The bit length of the SHA-2 algorithm. Valid values are 224, 256, 384, and 512.</param>
        /// <returns>An instance of a class implementing <see cref="IHashAlgorithm"/> corresponding to the specified bit length.</returns>
        /// <exception cref="ArgumentException">Thrown when an invalid bit length is provided.</exception>
        public static IHashAlgorithm CreateSHA2(int bits)
        {
            return bits switch
            {
                224 => new SHA224(),
                256 => new SHA256(),
                384 => new SHA384(),
                512 => new SHA512(),
                _ => throw new ArgumentException("Invalid SHA-2 bit length"),
            };
        }
    }
}
