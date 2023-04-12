#include "AFLMutationFunctions.hh"
#include <iostream>

using namespace AFLMutationFunctions;
using namespace AFLMutationFunctions::Details;

bool TestFunctionsDoMutate()
{
	using MutationType = Mutation< std::default_random_engine >;
	auto arrayMutationFunctions = GetMutationFunctions< std::default_random_engine >();
	auto random = std::default_random_engine { std::random_device {}() };
	int i = 0;
	const uint64_t ui64OriginalValue = 1;
	for( auto mutation : arrayMutationFunctions )
	{
		i++;
		uint64_t ui64Value = ui64OriginalValue;
		std::span< byte > spanBytes = std::as_writable_bytes( std::span { &ui64Value, 1 } );
		bool bMutated = false;
		for( int j = 0; j < 100; j++ )
		{
			std::span< byte > spanValue = spanBytes;
			if( mutation.IsIncreasing() )
				spanValue = spanBytes.subspan( 0, 6 );
			mutation( spanBytes, spanValue.size(), random );
			if( ui64Value != ui64OriginalValue )
			{
				bMutated = true;
				break;
			}
		}

		if( ! bMutated )
			return false;
	}

	return true;
}

bool TestHavoc( bool bPrint = false )
{
	uint64_t ui64Value = 0;
	auto bytes = std::as_writable_bytes( std::span { &ui64Value, 1 } );
	auto random = std::default_random_engine { std::random_device {}() };
	for( int i = 0; i < 50000; i++ )
	{
		Havoc( bytes, bytes.size(), random );
		if( bPrint )
			std::cout << std::hex << ui64Value << std::endl;
	}

	return ui64Value != 0;
}

int main()
{
	if( ! TestFunctionsDoMutate() )
	{
		std::cerr << "TestFunctionsDoMutate failed" << std::endl;
		return 1;
	}
	if( ! TestHavoc() )
	{
		std::cerr << "TestHavoc failed" << std::endl;
		return 1;
	}

	std::cout << "All tests passed" << std::endl;
	return 0;
}