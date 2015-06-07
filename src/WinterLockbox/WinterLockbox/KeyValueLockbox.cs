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
        // Used as placeholder entry to verify we have a valid lockbox store.
        private const string LockboxEntryKey = ".--lockbox";
        private const string LockboxEntryValue = "lockbox";

        private byte[] globalSalt;

        private ISymmetricKey symmetricKey;
        private ILockboxEntryStore entryStore;
        

        public KeyValueLockbox(KeyValueLockboxOptions options)
        {
            if (options == null)
                throw new ArgumentNullException("options");
            if (options.GlobalSalt == null)
                throw new ArgumentNullException("options.GlobalSalt");
            if (options.SymmetricKey == null)
                throw new ArgumentNullException("options.SymmetricKey");
            if (options.EntryStore == null)
                throw new ArgumentNullException("options.EntryStore");

            this.globalSalt = options.GlobalSalt;

            this.symmetricKey = options.SymmetricKey;
            this.entryStore = options.EntryStore;

            if (options.CreateNew)
            {
                // TODO: Verify that the lockbox entry does not already exist.
                SetEntry(LockboxEntryKey, LockboxEntryValue);
            }
            else
            {
                try
                {
                    string lockboxEntryValue = GetEntryValueString(LockboxEntryKey);
                    if (lockboxEntryValue != LockboxEntryValue)
                    {
                        throw new Exception("Unexpected lockbox entry value: " + lockboxEntryValue);
                    }
                }
                catch (Exception)
                {
                    throw new Exception("Invalid key or unable to connect to lockbox.");
                }
            }
        }

        public void SetEntry(string key, string value)
        {                 
            if (value == null)            
                throw new ArgumentNullException("value");

            byte[] strBytes = Encoding.UTF8.GetBytes(value);
            this.SetEntry(key, strBytes, LockboxEntryValueType.String);
        }

        public void SetEntry(string key, byte[] data)
        {
            this.SetEntry(key, data, LockboxEntryValueType.Blob);
        }

        private void SetEntry(string key, byte[] data, LockboxEntryValueType valueType)
        {
            if (key == null)
                throw new ArgumentNullException("key");
            if (data == null)
                throw new ArgumentNullException("data");

            string keyHash = this.ComputeKeyHash(key);

            LockboxEntry newEntry = new LockboxEntry
            {
                KeyHash = keyHash,
                ValueType = valueType
            };

            // See if the entry already exists.
            var existingEntry = this.TryFindLockboxEntry(key, keyHash);
            if (existingEntry != null)
            {
                newEntry.EntryGuid = existingEntry.EntryGuid;
            }
            else
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
            this.EncryptData(data, out encryptedValueBytes, out valueIV);

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
                    if (entry.ValueType == LockboxEntryValueType.String)
                    {
                        string entryValue = this.DecryptString(entry.EncryptedValue.EncryptedBytes, entry.EncryptedValue.IV);
                        return entryValue;
                    }
                    else
                    {
                        throw new Exception("Entry is not a string: " + key);
                    }
                }
            }                                             

            throw new Exception("Entry not found: " + key);
        }

        public byte[] GetEntryValueBlob(string key)
        {
            LockboxEntry entry = TryFindLockboxEntry(key);
            if (entry != null)
            {
                string entryKey = this.DecryptString(entry.EncryptedKey.EncryptedBytes, entry.EncryptedKey.IV);
                if (entryKey == key)
                {
                    byte[] decryptedBytes = this.symmetricKey.Decrypt(entry.EncryptedValue.EncryptedBytes, entry.EncryptedValue.IV);
                    return decryptedBytes;                    
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
                if (entryKey != LockboxEntryKey)
                {
                    keyList.Add(entryKey);
                }
            }

            return keyList;
        }


        private LockboxEntry TryFindLockboxEntry(string key)
        {
            if (key == null)
                throw new ArgumentNullException("key");

            string keyHash = this.ComputeKeyHash(key);

            return this.TryFindLockboxEntry(key, keyHash);
        }

        private LockboxEntry TryFindLockboxEntry(string key, string keyHash)
        {
            if (key == null)
                throw new ArgumentNullException("key");
            if (keyHash == null)
                throw new ArgumentNullException("keyHash");            

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

            this.EncryptData(strBytes, out encryptedBytes, out iv);
        }

        private void EncryptData(byte[] data, out byte[] encryptedBytes, out byte[] iv)
        {            
            iv = this.symmetricKey.GenerateIV();
            encryptedBytes = this.symmetricKey.Encrypt(data, iv);
        }    
    }


    public class KeyValueLockboxOptions
    {
        public byte[] GlobalSalt { get; set; }

        public ISymmetricKey SymmetricKey { get; set; }

        public ILockboxEntryStore EntryStore { get; set; }

        public bool CreateNew { get; set; }
    }
}
