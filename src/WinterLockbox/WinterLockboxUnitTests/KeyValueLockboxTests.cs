using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using WinterLockbox.InMem;
using FlowBasis.Crypto;
using WinterLockbox;

namespace WinterLockboxUnitTests
{
    [TestClass]
    public class KeyValueLockboxTests
    {
        [TestMethod]
        public void Test_Basic_Entry_Manipulation()
        {
            var sharedKey = SymmetricKey.FromPassword(SymmetricKeyType.AES, "my shared key", 256);
            var entryStore = new InMemLockboxEntryStore();

            var lockbox = new KeyValueLockbox(sharedKey, entryStore);

            lockbox.SetEntry("Hello", "World");
            lockbox.SetEntry("Blarg", "42");
            lockbox.SetEntry("Some other key", "this is the value to be encrypted");

            Assert.AreEqual("World", lockbox.GetEntryValueString("Hello"));
            Assert.AreEqual("42", lockbox.GetEntryValueString("Blarg"));
            Assert.AreEqual("this is the value to be encrypted", lockbox.GetEntryValueString("Some other key"));

            var keyList = lockbox.GetKeyList();
            Assert.AreEqual(3, keyList.Count);
            Assert.IsTrue(keyList.Contains("Hello"));
            Assert.IsTrue(keyList.Contains("Blarg"));
            Assert.IsTrue(keyList.Contains("Some other key"));

            lockbox.DeleteEntry("Blarg");

            Assert.AreEqual("World", lockbox.GetEntryValueString("Hello"));            
            Assert.AreEqual("this is the value to be encrypted", lockbox.GetEntryValueString("Some other key"));

            Exception caughtEx = null;
            try
            {
                lockbox.GetEntryValueString("Blarg");                
            }
            catch (Exception ex)
            {
                caughtEx = ex;
            }

            Assert.IsNotNull(caughtEx);

            keyList = lockbox.GetKeyList();
            Assert.AreEqual(2, keyList.Count);
            Assert.IsTrue(keyList.Contains("Hello"));            
            Assert.IsTrue(keyList.Contains("Some other key"));
        }
    }
}
