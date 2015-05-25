using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WinterLockbox
{
    public class InMemLockboxEntryStore : ILockboxEntryStore
    {
        private object syncRoot = new Object();

        private Dictionary<string, List<LockboxEntry>> keyHashToEntryListMap = new Dictionary<string, List<LockboxEntry>>();
        private Dictionary<string, LockboxEntry> entryGuidToEntryMap = new Dictionary<string, LockboxEntry>();


        public InMemLockboxEntryStore()
        {
        }

        public IList<LockboxEntry> GetEntriesForKeyHash(string keyHash)
        {
            List<LockboxEntry> resultList = new List<LockboxEntry>();

            lock (this.syncRoot)
            {
                List<LockboxEntry> keyHashEntryList;
                if (keyHashToEntryListMap.TryGetValue(keyHash, out keyHashEntryList))
                {
                    foreach (var entry in keyHashEntryList)
                    {
                        // TODO: Add a clone of the entry.
                        resultList.Add(entry);
                    }
                }
            }

            return resultList;
        }

        public void SetEntry(LockboxEntry entry)
        {
            lock (this.syncRoot)
            {
                this.entryGuidToEntryMap[entry.EntryGuid] = entry;

                List<LockboxEntry> keyHashEntryList;
                if (!keyHashToEntryListMap.TryGetValue(entry.KeyHash, out keyHashEntryList))
                {
                    keyHashEntryList = new List<LockboxEntry>();
                    keyHashToEntryListMap[entry.KeyHash] = keyHashEntryList;
                }

                bool existingSlotFound = false;
                for (int co = 0; co < keyHashEntryList.Count; co++)
                {
                    var existingEntry = keyHashEntryList[co];
                    if (existingEntry.EntryGuid == entry.EntryGuid)
                    {
                        // We found a slot with the same entry guid, so overwrite it.                        
                        keyHashEntryList[co] = entry;
                        existingSlotFound = true;
                        break;
                    }
                }

                if (!existingSlotFound)
                {
                    keyHashEntryList.Add(entry);
                }
            }
        }

        public void DeleteEntryByGuid(string entryGuid)
        {
            lock(this.syncRoot)
            {
                LockboxEntry existingEntry = null;
                if (this.entryGuidToEntryMap.TryGetValue(entryGuid, out existingEntry))
                {
                    this.entryGuidToEntryMap.Remove(entryGuid);

                    List<LockboxEntry> keyHashEntryList;
                    if (keyHashToEntryListMap.TryGetValue(existingEntry.KeyHash, out keyHashEntryList))
                    {
                        var keyHashEntriesToRemove = keyHashEntryList.Where(e => e.EntryGuid == entryGuid).ToList();
                        foreach (var entry in keyHashEntriesToRemove)
                        {
                            keyHashEntryList.Remove(entry);
                        }
                    }
                }
            }            
        }


        public IList<LockboxEntryEncryptedData> GetEncryptedKeyList()
        {
            List<LockboxEntryEncryptedData> resultList = new List<LockboxEntryEncryptedData>();

            lock (this.syncRoot)
            {
                foreach (var entry in this.entryGuidToEntryMap.Values)
                {
                    var keyCopy = new LockboxEntryEncryptedData
                    {
                        EncryptedBytes = (byte[])entry.EncryptedKey.EncryptedBytes.Clone(),
                        IV = (byte[])entry.EncryptedKey.IV.Clone(),
                    };

                    resultList.Add(keyCopy);
                }
            }

            return resultList;
        }
    }
}
