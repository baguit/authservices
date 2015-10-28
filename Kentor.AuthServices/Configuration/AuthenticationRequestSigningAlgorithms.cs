namespace Kentor.AuthServices.Configuration
{ 
    /// <summary>
    /// The supported signing algorithms for signing authentication request
    /// </summary>
    public enum AuthenticationRequestSigningAlgorithm
    {
        /// <summary>
        /// SHA-1 - signature algorithm http://www.w3.org/2000/09/xmldsig#rsa-sha1. 
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "Sha")]
        Sha1,
        /// <summary>
        /// SHA-256 - signature algorithm http://www.w3.org/2001/04/xmldsig-more#rsa-sha256.
        /// </summary>            
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "Sha")]
        Sha256
    }
}
