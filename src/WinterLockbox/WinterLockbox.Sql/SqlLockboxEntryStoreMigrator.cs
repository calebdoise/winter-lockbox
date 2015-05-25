using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Transactions;

namespace WinterLockbox.EntryStores
{
    public class SqlLockboxEntryStoreMigrator
    {
        private string connectionString;

        public SqlLockboxEntryStoreMigrator(string connectionString)
        {
            this.connectionString = connectionString;     
        }       
 
        public void MigrateToLatest()
        {            
            using (TransactionScope scope = new TransactionScope())
            using (SqlConnection connection = new SqlConnection(this.connectionString))
            {
                connection.Open();

                long currentVersion = -1;
                try
                {
                    using (var cmd = connection.CreateCommand())
                    {
                        cmd.CommandText = "SELECT MAX(VersionNumber) FROM Version;";

                        object currentVersionObject = cmd.ExecuteScalar();
                        if (currentVersionObject != null)
                        {
                            currentVersion = Convert.ToInt64(currentVersionObject);
                        }
                    }
                }
                catch
                {
                }

                if (currentVersion < 1)
                {
                    Up_Migration_1(connection);
                }
            }            
        }

        private void Up_Migration_1(SqlConnection connection)
        {
            using (var cmd = connection.CreateCommand())
            {
                cmd.CommandText = @"CREATE TABLE Version (VersionNumber bigint NOT NULL PRIMARY KEY, MigratedAt datetime NOT NULL);";
                cmd.ExecuteNonQuery();
            }

            using (var cmd = connection.CreateCommand())
            {
                cmd.CommandText = @"
CREATE TABLE LockboxRepository(
    Id int NOT NULL PRIMARY KEY,
    Name nvarchar(255)
);

CREATE TABLE LockboxEntry(
    RepositoryId int NOT NULL,
    EntryGuid varchar(255) NOT NULL,
    KeyHash varchar(512) NOT NULL,
    EncryptedKeyBytes varbinary(max),
    KeyIV varbinary(max),  
    EncryptedValueBytes varbinary(max),  
    ValueIV varbinary(max),
    ValueType int NOT NULL,

    PRIMARY KEY 
    (
	    RepositoryId, 
        EntryGuid
    )
);

CREATE INDEX IX_LockboxEntry_KeyHash ON LockboxEntry (KeyHash);
";
                cmd.ExecuteNonQuery();
            }

            AddMigrationVersionNumber(connection, 1);
        }

        private void AddMigrationVersionNumber(SqlConnection connection, long versionNumber)
        {
            using (var cmd = connection.CreateCommand())
            {
                cmd.CommandText = @"INSERT INTO Version (VersionNumber, MigratedAt) VALUES (@versionNumber, GETUTCDATE());";
                cmd.Parameters.AddWithValue("versionNumber", versionNumber);

                cmd.ExecuteNonQuery();
            }
        }
    }
}
