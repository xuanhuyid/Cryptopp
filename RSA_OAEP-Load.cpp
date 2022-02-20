
#include "include/cryptopp/rsa.h"
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

#include "include/cryptopp/sha.h"
using CryptoPP::SHA512;

#include "include/cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::BufferedTransformation;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include "include/cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "include/cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "include/cryptopp/SecBlock.h"
using CryptoPP::SecByteBlock;

#include "include/cryptopp/cryptlib.h"
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;
using CryptoPP::Exception;
using CryptoPP::DecodingResult;

#include "include/cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "include/cryptopp/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

#include <string>
using std::wstring;
using std::string;

#include <exception>
using std::exception;

#include <iostream>
using std::wcin;
using std::wcout;
using std::cerr;
using std::endl;

#include <assert.h>

/* Set _setmode()*/ 
#ifdef _WIN32
    #include <io.h>
#elif __linux__
    #include <inttypes.h>
    #include <unistd.h>
    #define __int64 int64_t
    #define _close close
    #define _read read
    #define _lseek64 lseek64
    #define _O_RDONLY O_RDONLY
    #define _open open
    #define _lseeki64 lseek64
    #define _lseek lseek
    #define stricmp strcasecmp
#endif
#include <fcntl.h>
/* Convert string*/ 
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;
wstring string_to_wstring (const std::string& str);
string wstring_to_string (const std::wstring& str);

/*Reading key from file*/
#include "include/cryptopp/queue.h"
using CryptoPP::ByteQueue;
#include "include/cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;
void Load(const string& filename, BufferedTransformation& bt);
void LoadPrivateKey(const string& filename, PrivateKey& key);
void LoadPublicKey(const string& filename, PublicKey& key);
void Save(const string& filename, const BufferedTransformation& bt);
void SaveBase64(const string& filename, const BufferedTransformation& bt);
int main(int argc, char* argv[])
{
    try
    {
        /*Set mode support Vietnamese*/
        _setmode(_fileno(stdin), _O_U16TEXT);
 	    _setmode(_fileno(stdout), _O_U16TEXT);

        // Generate keys
        string encoded;
        AutoSeededRandomPool rng;
        RSA::PrivateKey privateKey;
        RSA::PublicKey publicKey;
        LoadPrivateKey("rsa-private.key", privateKey); 
        LoadPublicKey("rsa-public.key", publicKey);
        wstring wplain;
        string plain, cipher, recovered;
        wcout <<"Input plaintext: ";
        getline(wcin,wplain);
        plain=wstring_to_string(wplain);
        wcout << "plaintext: " << wplain << endl;
        ////////////////////////////////////////////////
        // Encryption
        RSAES_OAEP_SHA_Encryptor e(publicKey);
        StringSource( plain, true,
            new PK_EncryptorFilter(rng, e,
                new Base64Encoder(new StringSink(cipher))
            ) // PK_EncryptorFilter
         ); // StringSource
         
        /* Save cipher text to file  using StringSource - FileSink*/
        StringSource ss( cipher, true, new FileSink( "cipher.txt" ) );
        wcout << "cipher text: "<<string_to_wstring(cipher)<< endl;
        
        ////////////////////////////////////////////////
        // Decryption
        RSAES_OAEP_SHA_Decryptor d(privateKey);
       // Decode Base64 cipher be fore decryotion
       /* Load cipher text from file  using FileSource-StringSink*/
        string ciphers;
        FileSource("cipher.txt", true, new Base64Decoder(new StringSink(ciphers)));
        // Dencrypt ciphers
        StringSource( ciphers, true,
            new PK_DecryptorFilter(rng, d,
                new StringSink( recovered )
            ) // PK_EncryptorFilter
         ); // StringSource
        wcout << "recovered text:" << string_to_wstring(recovered) << endl;
        assert( plain == recovered );
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }

	return 0;
}

/* convert string to wstring */
wstring string_to_wstring (const std::string& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

/* convert wstring to string */
string wstring_to_string (const std::wstring& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}
void LoadPrivateKey(const string& filename, PrivateKey& key)
{
	ByteQueue queue;
	Load(filename, queue);
	key.Load(queue);	
}

void LoadPublicKey(const string& filename, PublicKey& key)
{
	ByteQueue queue;
	Load(filename, queue);
	key.Load(queue);	
}

void Save(const string& filename, const BufferedTransformation& bt)
{
	FileSink file(filename.c_str());

	bt.CopyTo(file);
	file.MessageEnd();
}
void SaveBase64(const string& filename, const BufferedTransformation& bt)
{
	Base64Encoder encoder;
	bt.CopyTo(encoder);
	encoder.MessageEnd();
	Save(filename, encoder);
}

void Load(const string& filename, BufferedTransformation& bt)
{
	FileSource file(filename.c_str(), true /*pumpAll*/);

	file.TransferTo(bt);
	bt.MessageEnd();
}