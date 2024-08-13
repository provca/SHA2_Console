using LibSHA2.Interfaces;
using System.Text;

namespace LibSHA2
{
    /// <summary>
    /// Base abstract class for implementing SHA-2 hash algorithms.
    /// </summary>
    /// <typeparam name="T">Type representing the word size used in the algorithm (e.g., uint for 32-bit, ulong for 64-bit).</typeparam>
    internal abstract class SHA2Base<T> : IHashAlgorithm where T : struct, IConvertible
    {
        /// <summary>
        /// Gets the block size in bits for the specific SHA-2 variant.
        /// </summary>
        protected abstract int BlockSize { get; }

        /// <summary>
        /// Gets the size of the hash output in words.
        /// </summary>
        protected abstract int HashSize { get; }

        /// <summary>
        /// Gets the number of rounds (compression function iterations) for the specific SHA-2 variant.
        /// </summary>
        protected abstract int Rounds { get; }

        /// <summary>
        /// Provides the initial hash values specific to the SHA-2 variant.
        /// </summary>
        /// <returns>An array of initial hash values.</returns>
        protected abstract T[] InitialHashValues();

        /// <summary>
        /// Provides the round constants specific to the SHA-2 variant.
        /// </summary>
        /// <returns>An array of round constants.</returns>
        protected abstract T[] RoundConstants();

        /// <summary>
        /// Performs a right rotation on the given value by a specified number of bits.
        /// </summary>
        /// <param name="x">The value to rotate.</param>
        /// <param name="r">The number of bits to rotate by.</param>
        /// <returns>The rotated value.</returns>
        public abstract T RightRotate(T x, int r);

        /// <summary>
        /// Performs a right shift on the given value by a specified number of bits.
        /// </summary>
        /// <param name="x">The value to shift.</param>
        /// <param name="r">The number of bits to shift by.</param>
        /// <returns>The shifted value.</returns>
        public abstract T RightShift(T x, int r);

        /// <summary>
        /// Adds two values together.
        /// </summary>
        /// <param name="x">The first value.</param>
        /// <param name="y">The second value.</param>
        /// <returns>The sum of the two values.</returns>
        public abstract T Add(T x, T y);

        /// <summary>
        /// Performs a bitwise AND operation on two values.
        /// </summary>
        /// <param name="x">The first value.</param>
        /// <param name="y">The second value.</param>
        /// <returns>The result of the AND operation.</returns>
        public abstract T And(T x, T y);

        /// <summary>
        /// Performs a bitwise XOR operation on two values.
        /// </summary>
        /// <param name="x">The first value.</param>
        /// <param name="y">The second value.</param>
        /// <returns>The result of the XOR operation.</returns>
        public abstract T Xor(T x, T y);

        /// <summary>
        /// Performs a bitwise NOT operation on a value.
        /// </summary>
        /// <param name="x">The value to negate.</param>
        /// <returns>The negated value.</returns>
        public abstract T Not(T x);

        /// <summary>
        /// Computes the hash of the input message using the specified encoding.
        /// </summary>
        /// <param name="message">The input message to hash.</param>
        /// <param name="encoding">The encoding to use for the input message.</param>
        /// <returns>A hexadecimal string representing the computed hash.</returns>
        public string ComputeHash(string message, Encoding encoding)
        {
            // Initialize hash values and constants
            T[] H = InitialHashValues();
            T[] K = RoundConstants();

            // Convert the message to a binary string
            StringBuilder sb = new StringBuilder();
            byte[] strTobt = encoding.GetBytes(message);
            foreach (byte bt in strTobt)
            {
                sb.Append(Convert.ToString(bt, 2).PadLeft(8, '0'));
            }

            // Append the length of the message in binary, padded to the appropriate length
            string sl = Convert.ToString(sb.Length, 2).PadLeft(typeof(T) == typeof(uint) ? 64 : 128, '0');
            sb.Append('1');

            // Pad with zeros until the message length is congruent to (BlockSize - 64) modulo BlockSize
            do
            {
                sb.Append('0');
            } while ((sb.Length + (typeof(T) == typeof(uint) ? 64 : 128)) % BlockSize != 0);

            // Append the length of the original message
            sb.Append(sl);

            // Divide the message into blocks
            int ac = 0;
            int l = sb.Length / BlockSize;
            string[] mChunks = new string[l];
            for (int i = 0; i < l; i++)
            {
                mChunks[i] = sb.ToString(ac, BlockSize);
                ac += BlockSize;
            }

            // Initialize the message schedule array
            T[,] W = new T[l, Rounds];

            for (int i = 0; i < l; i++)
            {
                // Initialize the first 16 words of the message schedule array
                for (int c = 0; c < 16; c++)
                {
                    W[i, c] = (T)Convert.ChangeType(Convert.ToUInt64(mChunks[i].Substring(c * (BlockSize / 16), (BlockSize / 16)), 2), typeof(T));
                }

                // Extend the first 16 words into the remaining words of the message schedule array
                for (int c = 16; c < Rounds; c++)
                {
                    int r0 = typeof(T) == typeof(uint) ? 7 : 1;
                    int r1 = typeof(T) == typeof(uint) ? 18 : 8;
                    int r2 = typeof(T) == typeof(uint) ? 3 : 7;
                    int r3 = typeof(T) == typeof(uint) ? 17 : 19;
                    int r4 = typeof(T) == typeof(uint) ? 19 : 61;
                    int r5 = typeof(T) == typeof(uint) ? 10 : 6;

                    T s0 = Xor(Xor(RightRotate(W[i, c - 15], r0), RightRotate(W[i, c - 15], r1)), RightShift(W[i, c - 15], r2));
                    T s1 = Xor(Xor(RightRotate(W[i, c - 2], r3), RightRotate(W[i, c - 2], r4)), RightShift(W[i, c - 2], r5));

                    W[i, c] = Add(Add(Add(W[i, c - 16], s0), W[i, c - 7]), s1);
                }
            }

            // Process each block
            for (int i = 0; i < l; i++)
            {
                T a = H[0];
                T b = H[1];
                T c = H[2];
                T d = H[3];
                T e = H[4];
                T f = H[5];
                T g = H[6];
                T h = H[7];

                // Perform the main hash computation
                for (int j = 0; j < Rounds; j++)
                {
                    int r0 = typeof(T) == typeof(uint) ? 6 : 14;
                    int r1 = typeof(T) == typeof(uint) ? 11 : 18;
                    int r2 = typeof(T) == typeof(uint) ? 25 : 41;
                    int r3 = typeof(T) == typeof(uint) ? 2 : 28;
                    int r4 = typeof(T) == typeof(uint) ? 13 : 34;
                    int r5 = typeof(T) == typeof(uint) ? 22 : 39;

                    T s1 = Xor(Xor(RightRotate(e, r0), RightRotate(e, r1)), RightRotate(e, r2));
                    T ch = Xor(And(e, f), And(Not(e), g));
                    T t0 = Add(Add(Add(Add(h, s1), ch), K[j]), W[i, j]);
                    T s0 = Xor(Xor(RightRotate(a, r3), RightRotate(a, r4)), RightRotate(a, r5));
                    T maj = Xor(Xor(And(a, b), And(a, c)), And(b, c));
                    T t1 = Add(s0, maj);

                    // Update the working variables
                    h = g;
                    g = f;
                    f = e;
                    e = Add(d, t0);
                    d = c;
                    c = b;
                    b = a;
                    a = Add(t0, t1);
                }

                // Update the hash values with the working variables
                H[0] = Add(H[0], a);
                H[1] = Add(H[1], b);
                H[2] = Add(H[2], c);
                H[3] = Add(H[3], d);
                H[4] = Add(H[4], e);
                H[5] = Add(H[5], f);
                H[6] = Add(H[6], g);
                if (HashSize == 8)
                    H[7] = Add(H[7], h);
            }

            // Convert the hash value to a hexadecimal string
            int byteSize = GetSizeOfT();

            StringBuilder hash = new StringBuilder();
            for (int i = 0; i < HashSize; i++)
            {
                hash.Append(((dynamic)H[i]).ToString("x").PadLeft(byteSize * 2, '0'));
            }
            return hash.ToString();
        }

        /// <summary>
        /// Determines the size in bytes of the type T.
        /// </summary>
        /// <returns>The size of the type T in bytes.</returns>
        protected static int GetSizeOfT()
        {
            if (typeof(T) == typeof(uint))
                return sizeof(uint);
            else if (typeof(T) == typeof(ulong))
                return sizeof(ulong);

            throw new InvalidOperationException("Unsupported type for T");
        }
    }
}
