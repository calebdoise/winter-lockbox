using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using WinterLockbox.InMem;
using FlowBasis.Crypto;
using WinterLockbox;
using WinterLockbox.EntryStores;
using System.Data.SqlClient;
using System.IO;

namespace WinterLockboxUnitTests
{
    [TestClass]
    public class KeyValueLockboxTests
    {        
        [ClassInitialize]
        public static void SetUp(TestContext context)
        {
            AppDomain.CurrentDomain.SetData(
                "DataDirectory",
                context.TestDeploymentDir);
        }

        [TestMethod]
        public void Test_Basic_Entry_Manipulation_InMem()
        {
            var sharedKey = SymmetricKey.FromPassword(SymmetricKeyType.AES, "my shared key", 256);
            var entryStore = new InMemLockboxEntryStore();

            this.Test_Basic_Operations_With_Options(
                new KeyValueLockboxOptions
                {
                    GlobalSalt = SecureRandomBytes.GetRandomBytes(32),
                    SymmetricKey = sharedKey,
                    EntryStore = entryStore
                });
        }

        
        [TestMethod]
        public void Test_Basic_Entry_Manipulation_Sql()
        {
            string dataDir = AppDomain.CurrentDomain.GetData("DataDirectory") as string;
            string dbPath = Path.Combine(dataDir, "LockboxUnitTest.mdf");
            string dbName = "LockboxUnitTest";

            using (var connection = new SqlConnection(@"Data Source=(LocalDb)\v11.0;Initial Catalog=Master;Integrated Security=True"))
            {
                connection.Open();

                using (var cmd = connection.CreateCommand())
                {                    
                    cmd.CommandText = @"
                        IF EXISTS(SELECT * FROM sys.databases WHERE name = @dbName)
                        BEGIN
	                        ALTER DATABASE [" + dbName + @"]
	                        SET SINGLE_USER
	                        WITH ROLLBACK IMMEDIATE
	                        DROP DATABASE [" + dbName + @"]
                        END
             
                        EXEC ('CREATE DATABASE [' + @dbName + '] ON PRIMARY 
	                        (NAME = [' + @dbName + '], 
	                        FILENAME =''' + @filename + ''', 
	                        SIZE = 25MB, 
	                        MAXSIZE = 50MB, 
	                        FILEGROWTH = 5MB )')";

                    cmd.Parameters.AddWithValue("dbName", dbName);
                    cmd.Parameters.AddWithValue("filename", dbPath);

                    cmd.ExecuteNonQuery();
                }
            }

            string connectionString =
                @"Data Source=(LocalDb)\v11.0;Initial Catalog=LockboxUnitTest;Integrated Security=SSPI;"
                + @"AttachDBFilename=|DataDirectory|\LockboxUnitTest.mdf";

            SqlLockboxEntryStoreMigrator sqlMigrator = new SqlLockboxEntryStoreMigrator(connectionString);
            sqlMigrator.MigrateToLatest();
        }

        private void Test_Basic_Operations_With_Options(KeyValueLockboxOptions lockboxOptions)
        {
            var lockbox = new KeyValueLockbox(lockboxOptions);

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

            lockbox.SetEntry("blob data", new byte[] { 2, 4, 10, 42 });
            byte[] bytes = lockbox.GetEntryValueBlob("blob data");
            Assert.AreEqual(4, bytes.Length);
            Assert.AreEqual(2, bytes[0]);
            Assert.AreEqual(4, bytes[1]);
            Assert.AreEqual(10, bytes[2]);
            Assert.AreEqual(42, bytes[3]);
        }
    }
}
