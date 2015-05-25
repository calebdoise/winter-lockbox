using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WinterLockbox
{
    public interface ILockboxEntryStore
    {
        IList<LockboxEntry> GetEntriesForKeyHash(string keyHash);

        void SetEntry(LockboxEntry entry);

        void DeleteEntryByGuid(string entryGuid);

        IList<LockboxEntryEncryptedData> GetEncryptedKeyList();
    }

    public class LockboxEntry
    {
        public string KeyHash { get; set; }

        public string EntryGuid { get; set; }

        public LockboxEntryEncryptedData EncryptedKey { get; set; }

        public LockboxEntryEncryptedData EncryptedValue { get; set; }        
    }

    public class LockboxEntryEncryptedData
    {
        public byte[] EncryptedBytes { get; set; }
        public byte[] IV { get; set; }
    }
}
