using System.Text;
namespace LibSHA2.Interfaces
{
    /// <summary>
    /// Interface for hash algorithms.
    /// </summary>
    public interface IHashAlgorithm
    {
        /// <summary>
        /// Computes the hash of the specified message using the provided encoding.
        /// </summary>
        /// <param name="message">The input message to hash.</param>
        /// <param name="encoding">The encoding of the input message.</param>
        /// <returns>A hexadecimal string representing the computed hash.</returns>
        string ComputeHash(string message, Encoding encoding);
    }
}
