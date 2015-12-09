// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

namespace NWebsec.Core.Helpers.X509
{
    internal class TlvTripletHeader
    {
        public byte Tag { get; set; }
        public int Length { get; set; }
        public byte[] RawData { get; set; }
    }
}