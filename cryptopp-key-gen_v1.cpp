// Linux help: http://www.cryptopp.com/wiki/Linux

// Debug:
// g++ -g -ggdb -O0 -Wall -Wextra -Wno-unused -Wno-type-limits -I. -I/usr/include/cryptopp cryptopp-key-gen.cpp -o cryptopp-key-gen.exe -lcryptopp

// Release:
// g++ -O2 -Wall -Wextra -Wno-unused -Wno-type-limits -I. -I/usr/include/cryptopp cryptopp-key-gen.cpp -o cryptopp-key-gen.exe -lcryptopp && strip --strip-all cryptopp-key-gen.exe

#include <iostream>
using std::cin;
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <stdexcept>
using std::runtime_error;

#include "include/cryptopp/queue.h"
using CryptoPP::ByteQueue;

#include "include/cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "include/cryptopp/dsa.h"
using CryptoPP::DSA;

#include "include/cryptopp/rsa.h"
using CryptoPP::RSA;

#include "include/cryptopp/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

#include "include/cryptopp/cryptlib.h"
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;

#include "include/cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

void SavePrivateKey(const string& filename, const PrivateKey& key);
void SavePublicKey(const string& filename, const PublicKey& key);

void SaveBase64PrivateKey(const string& filename, const PrivateKey& key);
void SaveBase64PublicKey(const string& filename, const PublicKey& key);

void SaveBase64(const string& filename, const BufferedTransformation& bt);
void Save(const string& filename, const BufferedTransformation& bt);

void LoadPrivateKey(const string& filename, PrivateKey& key);
void LoadPublicKey(const string& filename, PublicKey& key);

void LoadBase64PrivateKey(const string& filename, PrivateKey& key);
void LoadBase64PublicKey(const string& filename, PublicKey& key);

void LoadBase64(const string& filename, BufferedTransformation& bt);
void Load(const string& filename, BufferedTransformation& bt);

int main(int argc, char** argv)
{
	std::ios_base::sync_with_stdio(false);
	AutoSeededRandomPool rnd;

	try
	{
		AutoSeededRandomPool rng;
		CryptoPP::InvertibleRSAFunction params;
		//CryptoPP::Integer d("0x13");
		//params.SetPublicExponent(d);
		params.GenerateRandomWithKeySize(rng, 3072);
		const CryptoPP::Integer& n = params.GetModulus();
    	const CryptoPP::Integer& p = params.GetPrime1();
    	const CryptoPP::Integer& q = params.GetPrime2();
    	const CryptoPP::Integer& d = params.GetPrivateExponent();
    	const CryptoPP::Integer& e = params.GetPublicExponent();
		CryptoPP::RSA::PrivateKey rsaPrivate;
		rsaPrivate.Initialize(n, e, d);
		CryptoPP::RSA::PublicKey rsaPublic;
		rsaPublic.Initialize(n, e);
		//CryptoPP::RSAFunction rsaPublic(rsaPrivate);
		/* Write key to file*/
		SavePrivateKey("rsa-private.key", rsaPrivate);
		SavePublicKey("rsa-public.key", rsaPublic);

		////////////////////////////////////////////////////////////////////////////////////
		DSA::PrivateKey dsaPrivate;
		dsaPrivate.GenerateRandomWithKeySize(rnd, 2048); // p,q,n,d
		DSA::PublicKey dsaPublic;
		dsaPrivate.MakePublicKey(dsaPublic); // e, e.d =1 mode (p-1)(q-1)
		cout << "public key:" << e <<endl;
		cout << "private key:" << d <<endl;
		/* Wrire key to files*/
		SavePrivateKey("dsa-private.key", dsaPrivate);
		SavePublicKey("dsa-public.key", dsaPublic);

		////////////////////////////////////////////////////////////////////////////////////

		RSA::PrivateKey r1, r2;
		r1.GenerateRandomWithKeySize(rnd, 3072);

		SavePrivateKey("rsa-roundtrip.key", r1);
		LoadPrivateKey("rsa-roundtrip.key", r2);

		r1.Validate(rnd, 3);
		r2.Validate(rnd, 3);

		if(r1.GetModulus() != r2.GetModulus() ||
		   r1.GetPublicExponent() != r2.GetPublicExponent() ||
		   r1.GetPrivateExponent() != r2.GetPrivateExponent())
		{
			throw runtime_error("key data did not round trip");
		}
		
		////////////////////////////////////////////////////////////////////////////////////

		cout << "Successfully generated and saved RSA and DSA keys" << endl;
	}

	catch(CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		return -2;
	}

	catch(std::exception& e)
	{
		cerr << e.what() << endl;
		return -1;
	}

	return 0;
}

void SavePrivateKey(const string& filename, const PrivateKey& key)
{
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void SavePublicKey(const string& filename, const PublicKey& key)
{
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void Save(const string& filename, const BufferedTransformation& bt)
{
	FileSink file(filename.c_str());

	bt.CopyTo(file);
	file.MessageEnd();
}

void SaveBase64PrivateKey(const string& filename, const PrivateKey& key)
{
	ByteQueue queue;
	key.Save(queue);

	SaveBase64(filename, queue);
}

void SaveBase64PublicKey(const string& filename, const PublicKey& key)
{
	ByteQueue queue;
	key.Save(queue);
	SaveBase64(filename, queue);
}

void SaveBase64(const string& filename, const BufferedTransformation& bt)
{
	Base64Encoder encoder;
	bt.CopyTo(encoder);
	encoder.MessageEnd();
	Save(filename, encoder);
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

void Load(const string& filename, BufferedTransformation& bt)
{
	FileSource file(filename.c_str(), true /*pumpAll*/);

	file.TransferTo(bt);
	bt.MessageEnd();
}

void LoadBase64PrivateKey(const string& filename, PrivateKey& key)
{
	throw runtime_error("Not implemented");
}

void LoadBase64PublicKey(const string& filename, PublicKey& key)
{
	throw runtime_error("Not implemented");
}

void LoadBase64(const string& filename, BufferedTransformation& bt)
{
	throw runtime_error("Not implemented");
}

