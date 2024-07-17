using Microsoft.VisualStudio.TestPlatform.TestHost;
using BitdefenderFileSignatureDetectionBypass;

namespace DotNetTests
{
    [TestClass]
    public class ArgumentTests
    {
        [TestMethod]
        [ExpectedException(typeof(System.NullReferenceException))]
        public void Test_NullArgument()
        {
            string[] args = null;
            BitdefenderFileSignatureDetectionBypass.Program.ProcessArguments(args);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Test_NoArguments()
        {
            string[] args = new string[] { };
            BitdefenderFileSignatureDetectionBypass.Program.ProcessArguments(args);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Test_InvalidSingleArgument()
        {
            string[] args = new string[] { "encrypt" };
            BitdefenderFileSignatureDetectionBypass.Program.ProcessArguments(args);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Test_Encrypt_Missing_OutKeyFile()
        {
            string[] args = new string[] { "encrypt", "-i", "plaintext", "-o", "encrypted", "-k" };
            BitdefenderFileSignatureDetectionBypass.Program.ProcessArguments(args);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void Test_Run_Missing_OutKeyFile()
        {
            string[] args = new string[] { "run", "-c", "encrypted", "-k" };
            BitdefenderFileSignatureDetectionBypass.Program.ProcessArguments(args);
        }
    }
}