// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

namespace NWebsec.Core.HttpHeaders
{
    public class HeaderResult
    {
        public enum ResponseAction
        {
            Set = 0,
            Remove = 1
        }

        public HeaderResult(ResponseAction action, string name, string value = null)
        {
            Action = action;
            Name = name;
            Value = value;
        }


        public ResponseAction Action { get; set; }
        public string Name { get; set; }
        public string Value { get; set; }
    }
}