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

        string GetEntryValueString(string key);

        void DeleteEntry(string key);


        IList<string> GetKeyList();
    }
}
