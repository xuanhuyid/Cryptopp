// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptlib.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::AuthenticatedSymmetricCipher;

#include "secblock.h"
using CryptoPP::SecByteBlock;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "aes.h"
using CryptoPP::AES;

#include "eax.h"
using CryptoPP::EAX;

int main(int argc, char* argv[])
{
	const int TAG_SIZE = 16;

	// Encrypted, with Tag
	string cipher, encoded;

	// Recovered
	string radata, rpdata;

	/*********************************\
	\*********************************/

	//KEY 0000000000000000000000000000000000000000000000000000000000000000
	//IV  000000000000000000000000
	//HDR 00000000000000000000000000000000
	//PTX 00000000000000000000000000000000
	//CTX cea7403d4d606b6e074ec5d3baf39d18
	//TAG ae9b1771dba9cf62b39be017940330b4

	// Test Vector 003
	SecByteBlock key(32);

	byte iv[12];
	memset( iv, 0, sizeof(iv) );

	string adata( 16, (char)0x00 );
	string pdata( 16, (char)0x00 );

	/*********************************\
	\*********************************/

	// Pretty print
	encoded.clear();
	StringSource( key, key.size(), true,
		new HexEncoder(
			new StringSink( encoded )
		) // HexEncoder
	); // StringSource
	cout << "key: " << encoded << endl;

	// Pretty print
	encoded.clear();
	StringSource( iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink( encoded )
		) // HexEncoder
	); // StringSource
	cout << "iv: " << encoded << endl;

	// Pretty print
	encoded.clear();
	StringSource( adata, true,
		new HexEncoder(
			new StringSink( encoded )
		) // HexEncoder
	); // StringSource
	cout << "adata: " << encoded << endl;

	// Pretty print
	encoded.clear();
	StringSource( pdata, true,
		new HexEncoder(
			new StringSink( encoded )
		) // HexEncoder
	); // StringSource
	cout << "pdata: " << encoded << endl;

	/*********************************\
	\*********************************/

	try
	{
		EAX< AES >::Encryption e;
		e.SetKeyWithIV( key, key.size(), iv, sizeof(iv) );
		// Not required for EAX mode (but required for CCM mode)
		// e.SpecifyDataLengths( adata.size(), pdata.size(), 0 );

		AuthenticatedEncryptionFilter ef( e,
			new StringSink( cipher ),
			false, TAG_SIZE
		); // AuthenticatedEncryptionFilter

		// AuthenticatedEncryptionFilter::ChannelPut
		//  defines two channels: "" (empty) and "AAD"
		//   channel "" is encrypted and authenticated
		//   channel "AAD" is authenticated
		ef.ChannelPut( "AAD", (const byte*)adata.data(), adata.size() );
		ef.ChannelMessageEnd("AAD");

		// Authenticated data *must* be pushed before
		//  Confidential/Authenticated data. Otherwise
		//  we must catch the BadState exception
		ef.ChannelPut( "", (const byte*)pdata.data(), pdata.size() );
		ef.ChannelMessageEnd("");

		// Pretty print
		encoded.clear();
		StringSource( cipher, true,
			new HexEncoder(
				new StringSink( encoded )
			) // HexEncoder
		); // StringSource
		cout << "cipher: " << encoded << endl;
	}
	catch( CryptoPP::BufferedTransformation::NoChannelSupport& e )
	{
		// The tag must go in to the default channel:
		//  "unknown: this object doesn't support multiple channels"
		cerr << "Caught NoChannelSupport..." << endl;
		cerr << e.what() << endl;
		cerr << endl;
	}
	catch( CryptoPP::AuthenticatedSymmetricCipher::BadState& e )
	{
		// Pushing PDATA before ADATA results in:
		//  "GMC/AES: Update was called before State_IVSet"
		cerr << "Caught BadState..." << endl;
		cerr << e.what() << endl;
		cerr << endl;
	}
	catch( CryptoPP::InvalidArgument& e )
	{
		cerr << "Caught InvalidArgument..." << endl;
		cerr << e.what() << endl;
		cerr << endl;
	}

	/*********************************\
	\*********************************/

	// Attack the first and last byte
	//if( cipher.size() > 1 )
	//{
	//  cipher[ 0 ] ^= 0x01;
	//  cipher[ cipher.size()-1 ] ^= 0x01;
	//}

	/*********************************\
	\*********************************/

	try
	{
		EAX< AES >::Decryption d;
		d.SetKeyWithIV( key, key.size(), iv, sizeof(iv) );

		// Break the cipher text out into it's
		//  components: Encrypted Data and MAC Value
		string enc = cipher.substr( 0, cipher.length()-TAG_SIZE );
		string mac = cipher.substr( cipher.length()-TAG_SIZE );

		// Sanity checks
		assert( cipher.size() == enc.size() + mac.size() );
		assert( enc.size() == pdata.size() );
		assert( TAG_SIZE == mac.size() );

		// Not recovered - sent via clear channel
		radata = adata;

		AuthenticatedDecryptionFilter df( d, NULL,
			AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
			AuthenticatedDecryptionFilter::THROW_EXCEPTION, TAG_SIZE );

		// The order of the following calls are important
		df.ChannelPut( "", (const byte*)mac.data(), mac.size() );
		df.ChannelPut( "AAD", (const byte*)adata.data(), adata.size() ); 
		df.ChannelPut( "", (const byte*)enc.data(), enc.size() );			   

		// If the object throws, it will most likely occur
		//  during ChannelMessageEnd()
		df.ChannelMessageEnd( "AAD" );
		df.ChannelMessageEnd( "" );

		// If the object does not throw, here's the only
		//  opportunity to check the data's integrity
		bool b = false;
		b = df.GetLastResult();
		assert( true == b );

		// Remove data from channel
		string retrieved;
		size_t n = (size_t)-1;

		// Plain text recovered from enc.data()
		df.SetRetrievalChannel( "" );
		n = (size_t)df.MaxRetrievable();
		retrieved.resize( n );

		if( n > 0 ) { df.Get( (byte*)retrieved.data(), n ); }
		rpdata = retrieved;
		assert( rpdata == pdata );

		// All is well - work with data

		// Pretty print
		encoded.clear();
		StringSource( radata, true,
			new HexEncoder(
				new StringSink( encoded )
			) // HexEncoder
		); // StringSource
		cout << "adata (received): " << encoded << endl;

		encoded.clear();
		StringSource( rpdata, true,
			new HexEncoder(
				new StringSink( encoded )
			) // HexEncoder
		); // StringSource
		cout << "pdata (recovered): " << encoded << endl;
		
	}
	catch( CryptoPP::InvalidArgument& e )
	{
		cerr << "Caught InvalidArgument..." << endl;
		cerr << e.what() << endl;
		cerr << endl;
	}
	catch( CryptoPP::AuthenticatedSymmetricCipher::BadState& e )
	{
		// Pushing PDATA before ADATA results in:
		//  "GMC/AES: Update was called before State_IVSet"
		cerr << "Caught BadState..." << endl;
		cerr << e.what() << endl;
		cerr << endl;
	}
	catch( CryptoPP::HashVerificationFilter::HashVerificationFailed& e )
	{
		cerr << "Caught HashVerificationFailed..." << endl;
		cerr << e.what() << endl;
		cerr << endl;
	}

	/*********************************\
	\*********************************/

	return 0;
}
