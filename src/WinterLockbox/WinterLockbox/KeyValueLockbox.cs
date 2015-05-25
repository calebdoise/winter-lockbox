using FlowBasis.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace WinterLockbox.InMem
{
    public class KeyValueLockbox : IKeyValueLockbox
    {
        private byte[] globalSalt;

        private ISymmetricKey symmetricKey;
        private ILockboxEntryStore entryStore;
        

        public KeyValueLockbox(ISymmetricKey symmetricKey, ILockboxEntryStore entryStore)
        {
            this.globalSalt = SecureRandomBytes.GetRandomBytes(32);

            this.symmetricKey = symmetricKey;
            this.entryStore = entryStore;
        }

        public void SetEntry(string key, string value)
        {
            if (key == null)            
                throw new ArgumentNullException("key");            
            if (value == null)            
                throw new ArgumentNullException("value");            

            string keyHash = this.ComputeKeyHash(key);

            IList<LockboxEntry> lockboxEntryList = this.entryStore.GetEntriesForKeyHash(keyHash);

            LockboxEntry newEntry = new LockboxEntry
            {
                KeyHash = keyHash                
            };

            // See if the entry already exists.
            foreach (var existingEntry in lockboxEntryList)
            {
                string existingEntryKey = this.DecryptString(existingEntry.EncryptedKey.EncryptedBytes, existingEntry.EncryptedKey.IV);
                if (existingEntryKey == key)
                {
                    newEntry.EntryGuid = existingEntry.EntryGuid;
                }
            }

            if (newEntry.EntryGuid == null)
            {
                newEntry.EntryGuid = Guid.NewGuid().ToString();                                
            }

            byte[] encryptedKeyBytes;
            byte[] keyIV;
            this.EncryptString(key, out encryptedKeyBytes, out keyIV);

            newEntry.EncryptedKey = new LockboxEntryEncryptedData
            {
                EncryptedBytes = encryptedKeyBytes,
                IV = keyIV
            };           

            byte[] encryptedValueBytes;
            byte[] valueIV;
            this.EncryptString(value, out encryptedValueBytes, out valueIV);

            newEntry.EncryptedValue = new LockboxEntryEncryptedData
            {
                EncryptedBytes = encryptedValueBytes,
                IV = valueIV
            };

            this.entryStore.SetEntry(newEntry);
        }

        public string GetEntryValueString(string key)
        {
            LockboxEntry entry = TryFindLockboxEntry(key);
            if (entry != null)
            {
                string entryKey = this.DecryptString(entry.EncryptedKey.EncryptedBytes, entry.EncryptedKey.IV);
                if (entryKey == key)
                {
                    string entryValue = this.DecryptString(entry.EncryptedValue.EncryptedBytes, entry.EncryptedValue.IV);
                    return entryValue;
                }
            }                                             

            throw new Exception("Entry not found: " + key);
        }         

        public void DeleteEntry(string key)
        {
            LockboxEntry entry = TryFindLockboxEntry(key);
            if (entry != null)
            {
                this.entryStore.DeleteEntryByGuid(entry.EntryGuid);
            }
            else
            {
                throw new Exception("Entry not found.");
            }            
        }


        public IList<string> GetKeyList()
        {
            List<string> keyList = new List<string>();

            var encryptedKeyList = this.entryStore.GetEncryptedKeyList();
            foreach (var encryptedKey in encryptedKeyList)
            {
                string entryKey = this.DecryptString(encryptedKey.EncryptedBytes, encryptedKey.IV);
                keyList.Add(entryKey);
            }

            return keyList;
        }


        private LockboxEntry TryFindLockboxEntry(string key)
        {
            if (key == null)
                throw new ArgumentNullException("key");

            string keyHash = this.ComputeKeyHash(key);

            IList<LockboxEntry> lockboxEntryList = this.entryStore.GetEntriesForKeyHash(keyHash);

            foreach (var entry in lockboxEntryList)
            {
                string entryKey = this.DecryptString(entry.EncryptedKey.EncryptedBytes, entry.EncryptedKey.IV);
                if (entryKey == key)
                {
                    return entry;
                }
            }

            return null;
        }

        private string ComputeKeyHash(string key)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);

            byte[] combinedBytes = new byte[keyBytes.Length + globalSalt.Length];

            Buffer.BlockCopy(keyBytes, 0, combinedBytes, 0, keyBytes.Length);
            Buffer.BlockCopy(globalSalt, 0, combinedBytes, keyBytes.Length, globalSalt.Length);

            using (var sha = new SHA256Managed())
            {
                byte[] combinedHash = sha.ComputeHash(combinedBytes);
                return Convert.ToBase64String(combinedHash);
            }
        }


        private string DecryptString(byte[] encryptedBytes, byte[] iv)
        {
            byte[] decryptedBytes = this.symmetricKey.Decrypt(encryptedBytes, iv);

            string decryptedStr = Encoding.UTF8.GetString(decryptedBytes);
            return decryptedStr;
        }

        private void EncryptString(string str, out byte[] encryptedBytes, out byte[] iv)
        {
            byte[] strBytes = Encoding.UTF8.GetBytes(str);

            iv = this.symmetricKey.GenerateIV();
            encryptedBytes = this.symmetricKey.Encrypt(strBytes, iv);
        }       
    }
}
