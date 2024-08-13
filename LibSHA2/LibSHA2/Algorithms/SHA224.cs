using LibSHA2.Interfaces;

namespace LibSHA2.Algorithms
{
    /// <summary>
    /// Represents the SHA-224 hash algorithm, which is a variant of the SHA-2 family.
    /// Implements the <see cref="IHashAlgorithm"/> interface.
    /// </summary>
    internal class SHA224 : SHA2Base<uint>, IHashAlgorithm
    {
        /// <summary>
        /// Gets the block size in bits for the SHA-224 algorithm.
        /// </summary>
        protected override int BlockSize => 512;

        /// <summary>
        /// Gets the hash size in bytes for the SHA-224 algorithm.
        /// </summary>
        protected override int HashSize => 7;

        /// <summary>
        /// Gets the number of rounds for the SHA-224 algorithm.
        /// </summary>
        protected override int Rounds => 64;

        /// <summary>
        /// Initializes the hash values used in the SHA-224 algorithm.
        /// These initial hash values are derived from the fractional parts of the square roots of the first eight prime numbers.
        /// The values used are:
        /// 0xc1059ed8 (from the square root of 2),
        /// 0x367cd507 (from the square root of 3),
        /// 0x3070dd17 (from the square root of 5),
        /// 0xf70e5939 (from the square root of 7),
        /// 0xffc00b31 (from the square root of 11),
        /// 0x68581511 (from the square root of 13),
        /// 0x64f98fa7 (from the square root of 17),
        /// 0xbefa4fa4 (from the square root of 19).
        /// </summary>
        /// <returns>An array of initial hash values.</returns>
        protected override uint[] InitialHashValues() => new uint[]
        {
            0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
            0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
        };

        /// <summary>
        /// Provides the round constants used in the SHA-224 algorithm.
        /// These constants are derived from the fractional parts of the cube roots of the first 64 prime numbers.
        /// The values are:
        /// 0x428a2f98 (from the cube root of 2),
        /// 0x71374491 (from the cube root of 3),
        /// 0xb5c0fbcf (from the cube root of 5),
        /// 0xe9b5dba5 (from the cube root of 7),
        /// 0x3956c25b (from the cube root of 11),
        /// ... (remaining values follow similarly).
        /// </summary>
        /// <returns>An array of round constants.</returns>
        protected override uint[] RoundConstants() => new uint[]
        {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        /// <summary>
        /// Performs a right rotation on a 32-bit unsigned integer.
        /// </summary>
        /// <param name="x">The value to rotate.</param>
        /// <param name="r">The number of bits to rotate.</param>
        /// <returns>The rotated value.</returns>
        public override uint RightRotate(uint x, int r) => (x >> r) | (x << (32 - r));

        /// <summary>
        /// Performs a right shift on a 32-bit unsigned integer.
        /// </summary>
        /// <param name="x">The value to shift.</param>
        /// <param name="r">The number of bits to shift.</param>
        /// <returns>The shifted value.</returns>
        public override uint RightShift(uint x, int r) => x >> r;

        /// <summary>
        /// Adds two 32-bit unsigned integers.
        /// </summary>
        /// <param name="x">The first value.</param>
        /// <param name="y">The second value.</param>
        /// <returns>The sum of the values.</returns>
        public override uint Add(uint x, uint y) => x + y;

        /// <summary>
        /// Performs a bitwise AND operation on two 32-bit unsigned integers.
        /// </summary>
        /// <param name="x">The first value.</param>
        /// <param name="y">The second value.</param>
        /// <returns>The result of the AND operation.</returns>
        public override uint And(uint x, uint y) => x & y;

        /// <summary>
        /// Performs a bitwise XOR operation on two 32-bit unsigned integers.
        /// </summary>
        /// <param name="x">The first value.</param>
        /// <param name="y">The second value.</param>
        /// <returns>The result of the XOR operation.</returns>
        public override uint Xor(uint x, uint y) => x ^ y;

        /// <summary>
        /// Performs a bitwise NOT operation on a 32-bit unsigned integer.
        /// </summary>
        /// <param name="x">The value to negate.</param>
        /// <returns>The result of the NOT operation.</returns>
        public override uint Not(uint x) => ~x;
    }

}
