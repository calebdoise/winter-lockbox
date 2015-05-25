using FlowBasis.Crypto;
using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Transactions;

namespace WinterLockbox.EntryStores
{
    public class SqlLockboxEntryStore : ILockboxEntryStore
    {
        private string connectionString;
        private string repositoryName;
        private int repositoryId;
        private byte[] globalSalt;

        public SqlLockboxEntryStore(string connectionString, string repositoryName)
        {
            this.connectionString = connectionString;
            this.repositoryName = repositoryName;
        }

        public byte[] GetGlobalSalt()
        {
            if (this.globalSalt != null)
            { 
                return (byte[])this.globalSalt.Clone();
            }
            else
            {
                return null;
            }
        }

        public void Connect()
        {
            using (var transactionScope = new TransactionScope())
            using (var connection = new SqlConnection(this.connectionString))
            {
                connection.Open();

                using (var cmd = connection.CreateCommand())
                {
                    cmd.CommandText = @"
                        DECLARE @id int = (SELECT 1 FROM LockboxRepository WHERE Name = @name);

                        IF (@id IS NULL)
                        BEGIN
                            INSERT INTO LockboxRepository (Name) VALUES (@name);
                            SET @id = (SELECT SCOPE_IDENTITY());
                        END;

                        SELECT Id, GlobalSalt FROM LockboxRepository WHERE Name = @name;
                        ";

                    cmd.Parameters.AddWithValue("name", this.repositoryName);

                    using (var reader = cmd.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            this.repositoryId = reader.GetInt32(0);
                            this.globalSalt = !reader.IsDBNull(1) ? (byte[])reader["GlobalSalt"] : (byte[])null;
                        }
                    }
                }

                if (this.globalSalt == null)
                {
                    // Generate global salt value to use for the repository.
                    this.globalSalt = SecureRandomBytes.GetRandomBytes(32);

                    using (var cmd = connection.CreateCommand())
                    {
                        cmd.CommandText = "UPDATE LockboxRepository SET GlobalSalt = @globalSalt WHERE Id = @repositoryId;";
                        cmd.Parameters.AddWithValue("globalSalt", this.globalSalt);
                        cmd.Parameters.AddWithValue("repositoryId", this.repositoryId);

                        cmd.ExecuteNonQuery();
                    }
                }

                transactionScope.Complete();
            }
        }

        public IList<LockboxEntry> GetEntriesForKeyHash(string keyHash)
        {
            List<LockboxEntry> resultList = new List<LockboxEntry>();

            using (var connection = new SqlConnection(this.connectionString))
            {
                connection.Open();

                using (var cmd = connection.CreateCommand())
                {
                    cmd.CommandText = @"
                        SELECT 
                            EntryGuid,                            
                            EncryptedKeyBytes,
                            KeyIV,  
                            EncryptedValueBytes,  
                            ValueIV,
                            ValueType
                        FROM LockboxEntry
                        WHERE RepositoryId = @repositoryId AND KeyHash = @keyHash;
                        ";

                    cmd.Parameters.AddWithValue("repositoryId", this.repositoryId);
                    cmd.Parameters.AddWithValue("keyHash", keyHash);

                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            string entryGuid = reader.GetString(0);
                            byte[] encryptedKeyBytes = !reader.IsDBNull(1) ? (byte[])reader["EncryptedKeyBytes"] : (byte[])null;
                            byte[] keyIV = !reader.IsDBNull(2) ? (byte[])reader["KeyIV"] : (byte[])null;
                            byte[] encryptedValueBytes =  !reader.IsDBNull(3) ? (byte[])reader["EncryptedValueBytes"] : (byte[])null;
                            byte[] valueIV = !reader.IsDBNull(4) ? (byte[])reader["ValueIV"] : (byte[])null;
                            int valueType = reader.GetInt32(5);

                            var entry = new LockboxEntry
                            {
                                EntryGuid = entryGuid,
                                KeyHash = keyHash,
                                EncryptedKey = new LockboxEntryEncryptedData
                                {
                                    EncryptedBytes = encryptedKeyBytes,
                                    IV = keyIV
                                },
                                EncryptedValue = new LockboxEntryEncryptedData
                                {
                                    EncryptedBytes = encryptedValueBytes,
                                    IV = valueIV
                                },
                                ValueType = (LockboxEntryValueType)valueType
                            };

                            resultList.Add(entry);
                        }
                    }
                }
            }

            return resultList;
        }

        public void SetEntry(LockboxEntry entry)
        {
            using (var transactionScope = new TransactionScope())
            using (var connection = new SqlConnection(this.connectionString))
            {
                connection.Open();

                using (var cmd = connection.CreateCommand())
                {
                    cmd.CommandText = @"
IF (EXISTS (SELECT 1 FROM LockboxEntry WHERE RepositoryId = @repositoryId AND EntryGuid = @entryGuid))
BEGIN
    DELETE FROM LockboxEntry WHERE RepositoryId = @repositoryId AND EntryGuid = @entryGuid;
END;

INSERT INTO LockboxEntry (RepositoryId, EntryGuid, KeyHash, EncryptedKeyBytes, KeyIV, EncryptedValueBytes, ValueIV, ValueType)
VALUES (@repositoryId, @entryGuid, @keyHash, @encryptedKeyBytes, @keyIV, @encryptedValueBytes, @valueIV, @valueType);
";

                    cmd.Parameters.AddWithValue("repositoryId", this.repositoryId);
                    cmd.Parameters.AddWithValue("entryGuid", entry.EntryGuid);
                    cmd.Parameters.AddWithValue("keyHash", entry.KeyHash);
                    cmd.Parameters.AddWithValue("encryptedKeyBytes", entry.EncryptedKey.EncryptedBytes);
                    cmd.Parameters.AddWithValue("keyIV", entry.EncryptedKey.IV);
                    cmd.Parameters.AddWithValue("encryptedValueBytes", entry.EncryptedValue.EncryptedBytes);
                    cmd.Parameters.AddWithValue("valueIV", entry.EncryptedValue.IV);
                    cmd.Parameters.AddWithValue("valueType", entry.ValueType);

                    cmd.ExecuteNonQuery();
                }

                transactionScope.Complete();
            }
        }

        public void DeleteEntryByGuid(string entryGuid)
        {
            using (var connection = new SqlConnection(this.connectionString))
            {
                connection.Open();

                using (var cmd = connection.CreateCommand())
                {
                    cmd.CommandText = "DELETE FROM LockboxEntry WHERE RepositoryId = @repositoryId AND EntryGuid = @entryGuid";

                    cmd.Parameters.AddWithValue("repositoryId", this.repositoryId);
                    cmd.Parameters.AddWithValue("entryGuid", entryGuid);

                    cmd.ExecuteNonQuery();
                }
            }
        }

        public IList<LockboxEntryEncryptedData> GetEncryptedKeyList()
        {
            List<LockboxEntryEncryptedData> resultList = new List<LockboxEntryEncryptedData>();

            using (var connection = new SqlConnection(this.connectionString))
            {
                connection.Open();

                using (var cmd = connection.CreateCommand())
                {
                    cmd.CommandText = @"
                        SELECT                                                  
                            EncryptedKeyBytes,
                            KeyIV                            
                        FROM LockboxEntry
                        WHERE RepositoryId = @repositoryId;
                        ";

                    cmd.Parameters.AddWithValue("repositoryId", this.repositoryId);                    

                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {                            
                            byte[] encryptedKeyBytes =  !reader.IsDBNull(0) ? (byte[])reader["EncryptedKeyBytes"] : (byte[])null;
                            byte[] keyIV = !reader.IsDBNull(1) ? (byte[])reader["KeyIV"] : (byte[])null;

                            var result = new LockboxEntryEncryptedData
                            {
                                EncryptedBytes = encryptedKeyBytes,
                                IV = keyIV
                            };

                            resultList.Add(result);
                        }
                    }
                }
            }

            return resultList;
        }      
    }
}
