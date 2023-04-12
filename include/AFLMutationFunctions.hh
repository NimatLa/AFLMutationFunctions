/*! \file
Implementations of the AFL mutation operations.

Original AFL mutation algorithms written by Michal Zalewski <lcamtuf@google.com>
No source code reused.
*/

#pragma once

#include <algorithm>
#include <cassert>
#include <concepts>
#include <cstdint>
#include <random>
#include <ranges>
#include <span>

#include "AFLMutationFunctions/Details.hh"

namespace AFLMutationFunctions
{

	using byte = std::byte;

	/*!
	Replaces an integer of random length with an interesting value. Randomly chooses endian.

	The input buffer must not be empty.
	*/
	template< class Gen >
		requires std::uniform_random_bit_generator< std::remove_reference_t< Gen > >
	void InterestingValue(
		std::span< std::byte > spanBuffer,  //!< Buffer that is mutated.
		Gen& generator  //!< Random number generator used as the source of randomness.
	)
	{
		// Get the max byte size of the interesting value.
		constexpr auto arrayInterestingInts { Details::GetInterestingArray() };
		using InterestingIntegral = std::ranges::range_value_t< decltype( arrayInterestingInts ) >;
		uint8_t ui8MaxSize = std::min( sizeof( InterestingIntegral ), spanBuffer.size_bytes() );
		uint8_t ui8ValueSize = std::uniform_int_distribution< unsigned short >( 1, ui8MaxSize )( generator );
		auto end = std::ranges::upper_bound( arrayInterestingInts, Details::MaxIntWithSize( ui8ValueSize ) );

		// Get a random interesting integer that fits in the buffer.
		std::ranges::subrange possible { arrayInterestingInts.begin(), end };
		InterestingIntegral interesting = Details::Ranges::SelectRandom( possible, generator );

		// Copy the interesting integer's bytes to a random location in the buffer.
		std::span< const byte > spanInterestingBytes = std::as_bytes( std::span { std::addressof( interesting ), 1 } );
		spanInterestingBytes = spanInterestingBytes.subspan( 0, ui8ValueSize );
		std::span< byte > spanRandomSubspan = Details::SelectRandomSubspan( spanBuffer, ui8ValueSize, generator );
		std::ranges::copy( spanInterestingBytes, spanRandomSubspan.begin() );
	}

	/*!
	Flips a random bit in the buffer.

	The input buffer must not be empty.
	*/
	template< class Gen >
		requires std::uniform_random_bit_generator< std::remove_reference_t< Gen > >
	void FlipBit(
		std::span< std::byte > spanBuffer,  //!< Buffer that is mutated.
		Gen& generator  //!< Random number generator used as the source of randomness.
	)
	{
		// Select a random byte and xor a random bit.
		byte& byteSelected = Details::Ranges::SelectRandom( spanBuffer, generator );
		byteSelected ^= byte { 1 } << std::uniform_int_distribution { 0, 7 }( generator );
	}

	/*!
	Mutates data using arithmetic operations.

	The input buffer must not be empty.
	*/
	template< class Gen, class Operation = std::plus< uint64_t > >
		requires std::uniform_random_bit_generator< std::remove_reference_t< Gen > >
	void Arithmetic(
		std::span< std::byte > spanBuffer,  //!< Buffer that is mutated.
		Gen& generator  //!< Random number generator used as the source of randomness.
	)
	{
		// Generate a 64-bit random number.
		uint64_t ui64Value = std::uniform_int_distribution< uint64_t > {}( generator );

		// Choose some bytes from the buffer into another 64-bit integer.
		uint64_t ui64Temporary { 0 };
		std::span< byte > spanTemporary = std::as_writable_bytes( std::span { &ui64Temporary, 1 } );
		size_t size = std::uniform_int_distribution< size_t >(
				1, std::min( sizeof( uint64_t ), spanBuffer.size() ) )( generator );
		std::span< byte > spanOut = Details::SelectRandomSubspan( spanBuffer, size, generator );
		std::ranges::copy( spanOut, spanTemporary.begin() );

		// Apply the arithmetic operation;
		ui64Temporary = Operation {}( ui64Temporary, ui64Value );

		// Copy the temporary value back to the buffer.
		std::ranges::copy( spanTemporary.subspan( 0, size ), spanOut.begin() );
	}

	/*!
	Replaces a random byte in the buffer with a random value.

	The buffer must not be empty.
	*/
	template< class Gen >
		requires std::uniform_random_bit_generator< std::remove_reference_t< Gen > >
	void RandomByteReplace(
		std::span< byte > spanBuffer,  //!< Buffer containing the data that is mutated.
		Gen& generator  //!< Random number generator used as the source of randomness.
	)
	{
		// Set a random byte to a random location in the buffer.
		byte& byteSelected = Details::Ranges::SelectRandom( spanBuffer, generator );
		byteSelected = static_cast< byte >(
				std::uniform_int_distribution< unsigned short > { 1, 255 }( generator ) );
	}

	/*!
	Removes a random block of bytes from the buffer.

	The buffer must not be empty.
	*/
	template< class Gen >
		requires std::uniform_random_bit_generator< std::remove_reference_t< Gen > >
	std::span< byte > RemoveRandomBlock(
		std::span< byte > spanBuffer,  //!< Buffer containing the data that is mutated.
		Gen& generator  //!< Random number generator used as the source of randomness.
	)
	{
		// Select random start end end positions in the buffer for a block to remove.
		auto randomStart = spanBuffer.begin() + std::uniform_int_distribution< size_t >( 0, spanBuffer.size() - 1 )( generator );
		auto randomEnd = randomStart + std::uniform_int_distribution< size_t >( 1, spanBuffer.end() - randomStart )( generator );

		// Move the data after the end of the block to the beginning of the block.
		// Because data is copied left, randomStart cannot be in the range [randomEnd, spanBufer.end()).
		// Therefore std::ranges::copy behavior is defined and can be usd.
		assert( randomEnd > randomStart );
		std::ranges::copy( randomEnd, spanBuffer.end(), randomStart );

		// Set the tail bytes as zeros.
		// If the mutated field is not variable-sized, this ensures that the value is reduced.
		auto tail = std::ranges::subrange( randomEnd, spanBuffer.end() );
		std::ranges::fill( tail, byte { 0 } );

		// Return a subspan of the reduced value.
		return spanBuffer.subspan( 0, randomStart - spanBuffer.begin() + tail.size() );
	}

	/*!
	Inserts a block to the buffer using either a cloned block or repeated random byte.

	The buffer will be mutated from [Head | Tail] to [Head | Random Block | Tail].
	*/
	template< class Gen >
		requires std::uniform_random_bit_generator< std::remove_reference_t< Gen > >
	std::span< byte > RandomBlockInsert(
		std::span< byte > spanBuffer,  //!< Buffer containing the data that is mutated.
		size_t sizeValue,  //!< Bounds of the value currently contained in buffer.
		Gen& generator  //!< Random number generator used as the source of randomness.
	)
	{
		// There must be some extra space in the buffer.
		assert( sizeValue < spanBuffer.size() );

		// Select a random position where the block will be inserted.
		auto spanValue = std::ranges::subrange( spanBuffer.begin(), spanBuffer.begin() + sizeValue );
		size_t sizeRandomBlock = std::uniform_int_distribution< size_t >( 1, spanBuffer.size() - sizeValue )( generator );
		auto randomBegin = spanBuffer.begin() + std::uniform_int_distribution< size_t >( 0, sizeValue )( generator );
		auto randomEnd = randomBegin + sizeRandomBlock;
		auto randomBlock = std::ranges::subrange( randomBegin, randomEnd );

		// Copy the tail end of the value to the end of the random block.
		// Data is copied right, so copy_backward must be used.
		auto valueEnd = spanBuffer.begin() + sizeValue;
		auto tailEnd = randomEnd + std::ranges::distance( randomBegin, valueEnd );
		assert( tailEnd <= spanBuffer.end() );
		assert( randomBegin <= valueEnd );
		assert( tailEnd > valueEnd );
		std::ranges::copy_backward( randomBegin, valueEnd, tailEnd );

		// Fill the middle block with random data.
		Details::FillSubrangeWithRandomValues( spanValue, randomBlock, generator );

		// Retrun the span of the new value.
		return spanBuffer.subspan( 0, sizeValue + randomBlock.size() );
	}

	//! Overwrites a block in the buffer with either a cloned block or repeated random byte.
	template< class Gen >
		requires std::uniform_random_bit_generator< std::remove_reference_t< Gen > >
	void RandomChunkOverwrite(
		std::span< byte > spanBuffer,  //!< Buffer containing the data that is mutated.
		Gen& generator  //!< Random number generator used as the source of randomness.
	)
	{
		assert( spanBuffer.size() > 0 );

		// Select a random subrange and fill it with random values.
		size_t sizeRandomBlock = std::uniform_int_distribution< size_t >( 1, spanBuffer.size() )( generator );
		auto subrange = Details::Ranges::SelectRandomSubrange( spanBuffer, sizeRandomBlock, generator );
		Details::FillSubrangeWithRandomValues( spanBuffer, subrange, generator );
	}

	// Gets mutation functions.
	template< class Gen >
	auto GetMutationFunctions()
	{
		using Details::Mutation;
		return std::to_array< Mutation< Gen > >(
				{
						Mutation< Gen > { FlipBit< Gen > },
						Mutation< Gen > { InterestingValue< Gen > },
						Mutation< Gen > { Arithmetic< Gen, std::plus< uint64_t > > },
						Mutation< Gen > { Arithmetic< Gen, std::minus< uint64_t > > },
						Mutation< Gen > { RandomByteReplace< Gen > },
						Mutation< Gen > { RemoveRandomBlock< Gen > },
						Mutation< Gen > { RandomBlockInsert< Gen > },
						Mutation< Gen > { RandomByteReplace< Gen > },
				} );
	}

	//! Applies a number of havoc mutations in place.
	template< unsigned int MaxIterationsPower = 5, class Gen >
		requires std::uniform_random_bit_generator< std::remove_reference_t< Gen > >
	std::span< std::byte > Havoc(
		std::span< std::byte > spanBuffer,  //!< Buffer containing the data that is mutated.
		size_t sizeValue,  //!< Bounds of the value currently contained in buffer.
		Gen& generator  //!< Random number generator used as the source of randomness.
	)
	{
		// Mutate the field using a random number of mutations.
		sizeValue = std::min( sizeValue, spanBuffer.size() );
		std::span< byte > spanValue { spanBuffer.subspan( 0, sizeValue ) };
		unsigned int uiHavocIterations = std::pow( 2, std::uniform_real_distribution< double >(
				0, MaxIterationsPower )( generator ) );

		// Create a range of possible mutations.
		auto arrayMutations = GetMutationFunctions< Gen >();

		// Apply a round of mutations.
		for( int i = 0; i < uiHavocIterations; i++ )
		{
			// Select s suitable mutation based on the and value sizes.
			using Details::Mutation;
			auto filtered = Details::Ranges::FilterMutations( arrayMutations, spanBuffer.size(), spanValue.size() );
			Mutation< Gen > mutationSelected = Details::Ranges::SelectRandom( filtered, generator );

			// Apply the mutation and get the new value size.
			spanValue = mutationSelected( spanBuffer, spanValue.size(), generator );
		}

		return spanValue;
	}
}