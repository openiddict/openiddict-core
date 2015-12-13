// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace NWebsec.Core.Helpers.X509
{
    public class X509Helper
    {
        private const byte AsnInteger = 0x02;
        private const byte AsnBitString = 0x03;
        private const byte AsnSequence = 0x30;
        private const byte AsnOptional = 0xA0;

        private static readonly byte[] AsnTags = { AsnInteger, AsnBitString, AsnSequence, AsnOptional };

        //TODO cleanup. Perhaps a test or two.
        //[System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands"), SecuritySafeCritical]
        public X509Certificate2 GetCertByThumbprint(string thumbprint, StoreLocation storeLocation, StoreName storeName)
        {
            X509Store certStore = null;
            X509Certificate2Collection certs = null;
            try
            {
                certStore = new X509Store(storeName, storeLocation);
                certStore.Open(OpenFlags.ReadOnly);
                certs = certStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);

                if (certs.Count > 1)
                {
                    var message = string.Format("Something went horribly wrong, found more than one cert with thumbprint {0} in store location {1}, storename {2}", thumbprint, storeLocation, storeName);
                    throw new Exception(message);
                }

                if (certs.Count == 0)
                {
                    var message = string.Format("No certificate with thumbprint {0} in store location {1}, storename {2}", thumbprint, storeLocation, storeName);
                    throw new ArgumentException(message);
                }

                //Returns new cert, all existing certs will be cleaned up
                return certs[0];
            }
            catch
            {
                if (certs != null)
                {
                    foreach (var cert in certs)
                    {
                        CleanupCert(cert);
                    }
                }
                if (certStore != null)
                {
                    foreach (var cert in certStore.Certificates)
                    {
                        CleanupCert(cert);
                    }
#if DNX451
                    certStore.Close();
#elif NET451
                    certStore.Close();
#else
                    certStore.Dispose();
#endif
                }
                throw;
            }
        }

        /// <summary>
        /// Returns a string suitable for inclusion in an HPKP header, including hash algoritm.
        /// </summary>
        /// <param name="cert"></param>
        /// <returns></returns>
        public string GetSubjectPublicKeyInfoPinValue(X509Certificate2 cert)
        {
            var spki = GetRawSubjectPublicKeyInfo(cert);
            using (var sha256 = SHA256.Create())
            {
                var hash = Convert.ToBase64String(sha256.ComputeHash(spki));
                return string.Format("sha256=\"" + hash + "\"");
            }
        }

        private static byte[] GetRawSubjectPublicKeyInfo(X509Certificate2 cert)
        {
            if (cert.Version != 3)
            {
                throw new ArgumentException("Only X.509 certificate version 3 is supported. This cert was version " + cert.Version);
            }

            var rawCert = cert.RawData;

            using (var ms = new MemoryStream(rawCert))
            {
                //Get outer cert sequence header
                var tlv = ReadTlvTripletHeader(ms);
                if (tlv.Tag != AsnSequence) throw new Exception("Expected ASN sequence, for start of certificate.");
                //Console.WriteLine("Got certficate sequence, parsed length: " + tlv.Length + " " + BitConverter.ToString(tlv.RawData));

                //Get tbs cert sequence header
                tlv = ReadTlvTripletHeader(ms);
                if (tlv.Tag != AsnSequence) throw new Exception("Expected ASN sequence, for start of tbc cert.");
                //Console.WriteLine("Got tbs certficate sequence, parsed length: " + tlv.Length + " " + BitConverter.ToString(tlv.RawData));

                //Get cert version integer header
                tlv = ReadTlvTripletHeader(ms);

                while (tlv.Tag == AsnOptional)
                {
                    //Console.WriteLine("Got optional TLV, parsed length: " + tlv.Length + " " + BitConverter.ToString(tlv.RawData));
                    tlv = ReadTlvTripletHeader(ms);
                }

                if (tlv.Tag != AsnInteger) throw new Exception("Expected ASN integer cert version.");
                //Console.WriteLine("Got the certficate version, parsed length: " + tlv.Length + " " + BitConverter.ToString(tlv.RawData));


                var version = ms.ReadByte();
                if (version == -1) throw new Exception("Could not read version byte");
                //Console.WriteLine("Cert version: " + version);

                //Get serial number
                tlv = ReadTlvTripletHeader(ms);
                if (tlv.Tag != AsnInteger) throw new Exception("Expected ASN integer serial number.");
                //Console.WriteLine("Got the cert serial number, parsed length: " + tlv.Length + " " + BitConverter.ToString(tlv.RawData));

                var serialNumber = new byte[tlv.Length];

                var read = ms.Read(serialNumber, 0, serialNumber.Length);

                if (read < serialNumber.Length) throw new Exception("Expected reading " + tlv.Length + " serial number bytes, got " + read);

                //Skip signature sequence
                tlv = ReadTlvTripletHeader(ms);
                if (tlv.Tag != AsnSequence) throw new Exception("Expected ASN sequence signature.");
                //Console.WriteLine("Got the cert signature sequence, parsed length: " + tlv.Length + " " + BitConverter.ToString(tlv.RawData));
                ms.Seek(tlv.Length, SeekOrigin.Current);
                //Console.WriteLine("Skipped ahead " + tlv.Length + " bytes.");

                //Skip issuer sequence
                tlv = ReadTlvTripletHeader(ms);
                if (tlv.Tag != AsnSequence) throw new Exception("Expected ASN sequence issuer.");
                //Console.WriteLine("Got the cert issuer sequence, parsed length: " + tlv.Length + " " + BitConverter.ToString(tlv.RawData));
                ms.Seek(tlv.Length, SeekOrigin.Current);
                //Console.WriteLine("Skipped ahead " + tlv.Length + " bytes.");

                //Skip validity sequence
                tlv = ReadTlvTripletHeader(ms);
                if (tlv.Tag != AsnSequence) throw new Exception("Expected ASN sequence validity.");
                //Console.WriteLine("Got the cert validity sequence, parsed length: " + tlv.Length + " " + BitConverter.ToString(tlv.RawData));
                ms.Seek(tlv.Length, SeekOrigin.Current);
                //Console.WriteLine("Skipped ahead " + tlv.Length + " bytes.");

                //Skip subject sequence
                tlv = ReadTlvTripletHeader(ms);
                if (tlv.Tag != AsnSequence) throw new Exception("Expected ASN sequence subject.");
                //Console.WriteLine("Got the cert subject sequence, parsed length: " + tlv.Length + " " + BitConverter.ToString(tlv.RawData));
                ms.Seek(tlv.Length, SeekOrigin.Current);
                //Console.WriteLine("Skipped ahead " + tlv.Length + " bytes.");

                //Skip subject sequence
                tlv = ReadTlvTripletHeader(ms);
                if (tlv.Tag != AsnSequence) throw new Exception("Expected ASN sequence SPKI.");
                //Console.WriteLine("Got the cert SPKI sequence, parsed length: " + tlv.Length + " " + BitConverter.ToString(tlv.RawData));

                //New array for both tlv bits and content bits.
                var spkiChunk = new byte[tlv.RawData.Length + tlv.Length];

                Array.Copy(tlv.RawData, spkiChunk, tlv.RawData.Length);

                read = ms.Read(spkiChunk, tlv.RawData.Length, tlv.Length);

                if (read > tlv.Length) throw new Exception("Got " + read + " SPKI bytes, expected " + spkiChunk.Length);

                return spkiChunk;
            }
        }

        private static TlvTripletHeader ReadTlvTripletHeader(MemoryStream ms)
        {
            var firstBytes = new byte[2];
            var read = ms.Read(firstBytes, 0, firstBytes.Length);

            if (read < 1)
            {
                throw new Exception("No data read!");
            }

            if (!AsnTags.Any(t => t == firstBytes[0])) throw new Exception("Unexptected ASN.1 tag byte: " + BitConverter.ToString(firstBytes, 0, 1));

            if (read < 2)
            {
                throw new Exception("No length byte read!");
            }

            if (firstBytes[1] < 0x80)
            {
                return new TlvTripletHeader() { Tag = firstBytes[0], Length = firstBytes[1], RawData = firstBytes };
            }

            //Handle multi-byte length.
            var numberOfLengthBytes = firstBytes[1] - 0x80;

            if (numberOfLengthBytes < 1) throw new Exception("Invalid length byte. Indicated multibyte length, with length 0.");
            if (numberOfLengthBytes > 4) throw new NotSupportedException("Leading length byte indicates more than 4 length bytes, which is not supported. Indicated length bytes: " + numberOfLengthBytes);

            //Get the bytes
            var lengthBytes = new byte[numberOfLengthBytes];
            var bytesRead = ms.Read(lengthBytes, 0, lengthBytes.Length);

            if (bytesRead != lengthBytes.Length) throw new Exception(string.Format("Expected {0} length bytes, got {1}", lengthBytes.Length, bytesRead));

            //Got the bytes, make an int.
            var length = 0;
            //Console.WriteLine("Adding length bytes: " + BitConverter.ToString(lengthBytes));
            foreach (var lengthByte in lengthBytes)
            {

                //Shift existing bytes so they become more significant. Avoid platform dependent bit fiddling.
                //Console.WriteLine("Length tweak starting: " + BitConverter.ToString(BitConverter.GetBytes(length)));

                length = length * 256;
                //Console.WriteLine("Shifted length to make room for next byte: " + BitConverter.ToString(BitConverter.GetBytes(length)));

                length += lengthByte;
                //Console.WriteLine("Added next byte: " + BitConverter.ToString(BitConverter.GetBytes(length)));
            }

            var rawbytes = new byte[firstBytes.Length + lengthBytes.Length];
            Array.Copy(firstBytes, rawbytes, firstBytes.Length);
            Array.Copy(lengthBytes, 0, rawbytes, firstBytes.Length, lengthBytes.Length);

            return new TlvTripletHeader { Tag = firstBytes[0], Length = length, RawData = rawbytes };
        }

        private void CleanupCert(X509Certificate2 cert)
        {
#if NET451
            cert.Reset();
#elif DNX451
            cert.Reset();
#else
            cert.Dispose();
#endif
        }
    }
}