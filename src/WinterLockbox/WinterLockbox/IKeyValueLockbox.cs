using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WinterLockbox
{
    public interface IKeyValueLockbox
    {
        void SetEntry(string key, string value);

        void SetEntry(string key, byte[] data);

        string GetEntryValueString(string key);
        byte[] GetEntryValueBlob(string key);

        void DeleteEntry(string key);


        IList<string> GetKeyList();
    }
}
