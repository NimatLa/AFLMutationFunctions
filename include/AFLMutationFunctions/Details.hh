/*! \file
Helpers for implementations of AFL mutation functions.
*/

#pragma once

#include <array>
#include <vector>
#include <span>
#include <algorithm>
#include <functional>
#include <concepts>

#include "AFLMutationFunctions.hh"

namespace AFLMutationFunctions::Details
{
	// TODO: remove this.
	using byte = std::byte;

	//! Swaps the endianness of an integral value.
	template< std::integral T >
	constexpr T SwapEndian(
		const T value  //!< Value whose endianness is swapped.
	) noexcept
	{
		// Create a byte array representation of the value and reverse it.
		auto bytes = std::bit_cast< std::array< byte, sizeof( T ) > >( value );
		std::reverse( std::begin( bytes ), std::end( bytes ) );
		return std::bit_cast< T >( bytes );
	}

	//! Reinterprets an integer as a larger integer type. The byte representation is not changed.
	template< std::integral To, std::integral From >
		requires( sizeof( To ) >= sizeof( From ) )
	constexpr To ReinterpretInt(
		From from  //!< Value that is reinterpreted.
	) noexcept
	{
		// Copyt the bytes to a larger integer.
		auto bytes = std::bit_cast< std::array< byte, sizeof( From ) > >( from );
		std::array< byte, sizeof( To ) > to { byte { 0 } };
		std::ranges::copy( bytes, to.begin() );
		return std::bit_cast< To >( to );
	}

	//! Copies integers values and their endian swapped versions to a vector.
	template< std::ranges::sized_range Range, std::integral T >
		requires( sizeof( std::ranges::range_value_t< Range > ) <= sizeof( T ) )
	constexpr void AddValuesAndTheirSwappedEndians(
		const Range& source,  //!< Range containing integers that are added to target.
		std::vector< T >& target  //!< Target vector where values are added.
	)
	{
		// Reserve space in the output vector.
		target.reserve( target.size() + ( std::ranges::size( source ) * 2 ) );

		// Add values from the source to the target vector.
		for( auto value : source )
		{
			// Add the value itself and its endian swapped version to the vector.
			target.push_back( ReinterpretInt< T >( value ) );
			target.push_back( ReinterpretInt< T >( SwapEndian( value ) ) );
		}
	}

	//! Gets a vector of interesting integer values.
	constexpr std::vector< uint64_t > GetInteresting()
	{
		// Set interesting 8-bit integers.
		int8_t pInteresting8Bit[] {
			std::numeric_limits< int8_t >::min(),
			-1,
			0,
			1,
			16,
			32,
			100,
			std::numeric_limits< int8_t >::max(),
		};

		// Set interesting 16-bit integers.
		int16_t pInteresting16Bit[] {
			-1,
			std::numeric_limits< int16_t >::min(),
			ReinterpretInt< int16_t >( std::numeric_limits< int8_t >::min() ) - 1,
			ReinterpretInt< int16_t >( std::numeric_limits< int8_t >::max() ) + 1,
			ReinterpretInt< int16_t >( std::numeric_limits< uint8_t >::max() ) + 1,
			1 << 9,
			1000,
			1 << 10,
			1 << 12,
			std::numeric_limits< int16_t >::min(),
		};

		// Set interesting 32-bit integers.
		int32_t pInteresting32Bit[] {
			-1,
			std::numeric_limits< int32_t >::min(),
			100663046,  // Large negative number (endian-agnostic).
			ReinterpretInt< int32_t >( std::numeric_limits< int16_t >::min() ) - 1,
			ReinterpretInt< int32_t >( std::numeric_limits< int16_t >::max() ) + 1,
			ReinterpretInt< int32_t >( std::numeric_limits< uint16_t >::max() ) + 1,
			100663045,  // Large positive number (endian-agnostic).
			std::numeric_limits< int32_t >::max(),
		};

		// Set interesting 64-bit integers.
		int64_t pInteresting64Bit[] {
			-1,
			std::numeric_limits< int64_t >::min(),
			ReinterpretInt< int64_t >( std::numeric_limits< int32_t >::min() ) - 1ll,
			ReinterpretInt< int64_t >( std::numeric_limits< int32_t >::max() ) + 1ll,
			std::numeric_limits< uint32_t >::max(),
			ReinterpretInt< int64_t >( std::numeric_limits< uint32_t >::max() ) + 1ll,
			std::numeric_limits< int64_t >::max(),
		};

		// AFL interesting values -mutation operations have 50-50 chance of using big or small endian.
		// Rather than calculating the inverted endian while running, precalculate them here.
		std::vector< uint64_t > vecInterestingInts;
		auto backinserter = std::back_inserter( vecInterestingInts );
		AddValuesAndTheirSwappedEndians( pInteresting8Bit, vecInterestingInts );
		AddValuesAndTheirSwappedEndians( pInteresting16Bit, vecInterestingInts );
		AddValuesAndTheirSwappedEndians( pInteresting32Bit, vecInterestingInts );
		AddValuesAndTheirSwappedEndians( pInteresting64Bit, vecInterestingInts );

		// Remove duplicates.
		std::ranges::sort( vecInterestingInts );
		auto removed = std::ranges::unique( vecInterestingInts );
		vecInterestingInts.erase( removed.begin(), removed.end() );
		return vecInterestingInts;
	}

	//! Gets an array of interesting integers.
	constexpr auto GetInterestingArray()
	{
		// Get the size of the interesting vector at compile-time to reserve correctly sized array.
		constexpr auto size = GetInteresting().size();
		std::array< uint64_t, size > array { uint64_t { 0 } };
		std::ranges::copy( GetInteresting(), array.begin() );
		return array;
	}

	//! Concept for a size-reducing mutation function.
	template< class F, class TByte, class Gen >
	concept Reducing = std::invocable< F, std::span< TByte >, Gen& > &&
			std::same_as< std::invoke_result_t< F, std::span< TByte >, Gen& >, std::span< TByte > >;

	//! Concept for a size-increasing mutation function.
	template< class F, class TByte, class Gen >
	concept Increasing = std::invocable< F, std::span< TByte >, size_t, Gen& > &&
			std::same_as< std::invoke_result_t< F, std::span< TByte >, size_t, Gen& >, std::span< TByte > >;

	//! Concept for a size-constant mutation function.
	template< class F, class TByte, class Gen >
	concept Constant = std::invocable< F, std::span< TByte >, Gen& > &&
			std::same_as< std::invoke_result_t< F, std::span< TByte >, Gen& >, void >;

	//! Class for treating mutation functions polymorphically.
	template< class Gen, class TByte = byte >
		requires std::uniform_random_bit_generator< std::remove_reference_t< Gen > >
	class Mutation
	{
	private:

		//! Types of mutation functions.
		enum class MutationType
		{
			Constant = 0,
			Reducing,
			Increasing
		};

		//! Function object that implements the mutation.
		std::function< std::span< TByte >( std::span< TByte >, size_t, Gen& ) > m_fMutation;

		//! Type of this mutation.
		MutationType m_mutationtype = MutationType::Constant;

	public:

		// Constructor for a size-constant mutation.
		explicit Mutation(
			Constant< TByte, Gen > auto&& constMutation  //!< Mutation implementation.
		)
		{
			// Create a lambda that fullfills the signature requirements.
			m_fMutation = [ constMutation ]( std::span< TByte > buffer, size_t size, Gen& generator ) {
				// Mutate the value and return the value span.
				std::span< TByte > value = buffer.subspan( 0, size );
				constMutation( value, generator );
				return value;
			};
		}

		//! Constructor for a size-increasing mutation.
		explicit Mutation(
			Increasing< TByte, Gen > auto&& increasingMutation  //!< Mutation implementation.
		) :
		m_fMutation { increasingMutation },
		m_mutationtype { MutationType::Increasing }
		{
		}

		//! Constructor for a size-reducing mutation.
		explicit Mutation(
			Reducing< TByte, Gen > auto&& reducingMutation  //!< Mutation implementation.
		) :
		m_mutationtype { MutationType::Reducing }
		{
			// Create a lambda that fullfills the signature requirements.
			m_fMutation = [ reducingMutation ]( std::span< TByte > buffer, size_t size, Gen& generator ) {
				// Mutate the value and return the result.
				std::span< TByte > value = buffer.subspan( 0, size );
				return reducingMutation( value, generator );
			};
		}

		//! Returns true if the mutation will reduce the size of the mutated value.
		bool IsReducing() const
		{
			return m_mutationtype == MutationType::Reducing;
		}

		//! Returns true if the mutation will increase the size of the mutated value.
		bool IsIncreasing() const
		{
			return m_mutationtype == MutationType::Increasing;
		}

		//! Returns true if the mutation won't change the size of the mutated value.
		bool IsConstant() const
		{
			return m_mutationtype == MutationType::Constant;
		}

		//! Invokes the mutation.
		std::span< TByte > operator()(
			std::span< TByte > buffer,  //! Buffer containing the value.
			size_t size,  //!< Bounds of the value currently contained in buffer.
			Gen& generator  //!< Random number generator used as the source of randomness.
		)
		{
			return m_fMutation( buffer, size, generator );
		}
	};

	//! Selects a random subspan of a specified size.
	template< class Gen, typename T >
		requires std::uniform_random_bit_generator< std::remove_reference_t< Gen > >
	std::span< T > SelectRandomSubspan(
		std::span< T > spanSource,  //!< Span where the subspan is taken.
		size_t size,  //!< Size of the subspan.
		Gen&& generator  //!< Random number generator used as the source of randomness.
	)
	{
		// Subspan cannot exceed the size of the source span.
		assert( size <= spanSource.size() );

		// Select a random position in the source where the tail end still fits the subspan size.
		size_t sizeOffset = std::uniform_int_distribution< size_t >( 0, spanSource.size() - size )( generator );
		assert( sizeOffset + size <= spanSource.size() );
		return spanSource.subspan( sizeOffset, size );
	}

	//! Gets the max value of a 8, 16, 32, or 64-bit integer based on width of the integer.
	inline constexpr uint64_t MaxIntWithSize(
		uint8_t ui8Width  //!< Width of the integer in bits.
	)
	{
		// Select the correct max value.
		if( ui8Width <= 8 )
			return std::numeric_limits< uint8_t >::max();
		else if( ui8Width <= 16 )
			return std::numeric_limits< uint16_t >::max();
		else if( ui8Width <= 32 )
			return std::numeric_limits< uint32_t >::max();
		else
			return std::numeric_limits< uint64_t >::max();
	}

	//! Helper functions that work with ranges.
	namespace Ranges
	{
		//! Selects a random value reference from a range.
		template< class Gen, std::ranges::range Range >
			requires std::uniform_random_bit_generator< std::remove_reference_t< Gen > > &&
				std::ranges::random_access_range< Range > &&
				std::ranges::sized_range< Range > &&
				std::indirectly_writable< std::ranges::iterator_t< Range >, std::ranges::range_value_t< Range > >
		std::ranges::range_value_t< Range >& SelectRandom(
			const Range& range,  //!< Range from where the random value is selected.
			Gen&& gen  //!< Random number generator used as the source of randomness.
		)
		{
			// Get an item from a random positon.
			return std::ranges::begin( range )[ std::uniform_int_distribution< int >( 0, std::ranges::size( range ) - 1 )( gen ) ];
		}

		//! Selects a random const value reference from a range.
		template< class Gen, std::ranges::range Range >
			requires std::uniform_random_bit_generator< std::remove_reference_t< Gen > > &&
				std::ranges::random_access_range< Range > &&
				std::ranges::sized_range< Range >
		const std::ranges::range_reference_t< Range > SelectRandom(
			const Range& range,  //!< Range from where the random value is selected.
			Gen&& gen  //!< Random number generator used as the source of randomness.
		)
		{
			// Get an item from a random positon.
			return std::ranges::begin( range )[ std::uniform_int_distribution< int >( 0, std::ranges::size( range ) - 1 )( gen ) ];
		}

		//! Selects a random value from a non-sized range.
		template< class Gen, std::ranges::range Range >
			requires ( std::uniform_random_bit_generator< std::remove_reference_t< Gen > > &&
				! std::ranges::random_access_range< Range > )
			std::ranges::range_value_t< Range > SelectRandom(
					Range & range,  //!< Range from where the random value is selected.
					Gen&& gen  //!< Random number generator used as the source of randomness.
		)
		{
			// Use std::ranges::sample to get a single random value.
			std::vector< std::ranges::range_value_t< Range > > vector;
			vector.reserve( 1 );
			std::ranges::sample( range, std::back_inserter( vector ), 1, gen );
			return vector.front();
		}

		// Concept for a mutation that may or may not modify value size in some way.
		template< class T >
		concept SizeModifying = requires( T t ) {
			{
				t.IsIncreasing()
			} -> std::convertible_to< bool >;
			{
				t.IsReducing()
			} -> std::convertible_to< bool >;
			{
				t.IsConstant()
			} -> std::convertible_to< bool >;
		};

		//! Filters out unsuitable mutations based on buffer and value sizes.
		template< std::ranges::range Range >
			requires SizeModifying< std::ranges::range_value_t< Range > >
		constexpr auto FilterMutations(
			const Range& mutations,  //!< The mutations to filter.
			size_t sizeBuffer,  //!< Size of the buffer containing the value.
			size_t sizeValue  //!< Size of the value in the buffer.
		)
		{
			// Do not use increasing mutations if there is no space in the buffer.
			bool bCanIncrease = sizeBuffer > sizeValue;

			// Use only increasing mutations if value size is 0.
			bool bMustIncrease = sizeValue == 0;

			// Reducing mutations can only be used if value size exceeds 0,
			// but bMustIncrease will already handle that filtering.

			// Use only reducing mutations if value size is greater than buffer size.
			bool bMustReduce = sizeBuffer < sizeValue;

			// Apply the conditional filters.
			using std::views::filter;
			return mutations |
					filter( [ = ]( const auto& m ) { return ! bMustIncrease || m.IsIncreasing(); } ) |
					filter( [ = ]( const auto& m ) { return ! bMustReduce || m.IsReducing(); } ) |
					filter( [ = ]( const auto& m ) { return bCanIncrease || ! m.IsIncreasing(); } );
		}

		//! Selects a subrange of specified size from a random position in source range.
		template< class Gen, std::ranges::range Range >
			requires std::uniform_random_bit_generator< std::remove_reference_t< Gen > >
		auto SelectRandomSubrange(
			const Range& source,  //!< Source range where the subrange is selected.
			size_t size,  //!< Size of the selected subrange.
			Gen&& generator  //!< Random number generator used as the source of randomness.
		)
		{
			// The subrange must fit into the range.
			auto sourceSize = std::ranges::size( source );
			assert( size <= sourceSize );

			// Select a starting position where the tail end will still fit the subrange.
			size_t sizeOffset = std::uniform_int_distribution< size_t >( 0, sourceSize - size )( generator );
			assert( sizeOffset + size <= std::ranges::size( source ) );
			auto begin = std::ranges::begin( source ) + sizeOffset;
			auto end = std::ranges::begin( source ) + sizeOffset + size;
			return std::ranges::subrange( begin, end );
		}
	}

	/*!
	Fills a subrange with random values. The random values may be copied from the subrange.

	std::ranges::begin( subrange ) must be within the range [std::ranges::begin( range ), std::ranges::end( range )).
	*/
	template< std::ranges::sized_range Range, std::ranges::sized_range SubRange, class Gen >
	void FillSubrangeWithRandomValues(
		const Range& range,  //!< Range that contains some values that may be used as the random data.
		const SubRange& subrange,  //!< Subrange in range (or super range or range) that is filled with random data.
		Gen&& generator  //!< Random number generator used as the source of randomness.
	)
	{
		// Clone bytes with 0.75 probability. Otherwise repeat a random byte.
		std::ranges::range_size_t< Range > rangeSize = std::ranges::size( range );
		if( rangeSize > 1 && std::uniform_int_distribution( 0, 3 )( generator ) != 0 )
		{
			// Clone a random block.

			// Select a random subspan from the value and copy those bytes to the random block.
			auto source = Ranges::SelectRandomSubrange(
					range, std::min( rangeSize, std::ranges::size( subrange ) ), generator );
			if( std::begin( source ) < std::begin( subrange ) )
			{
				// Copy right.
				auto copyEnd = std::begin( subrange ) + std::ranges::distance( source );
				assert( copyEnd > std::end( source ) );
				std::ranges::copy_backward( source, copyEnd );
			}
			else if( std::begin( source ) > std::begin( subrange ) )
			{
				// Copy left.
				std::ranges::copy( source, std::begin( subrange ) );
			}
		}
		else
		{
			// Repeat a random byte.

			// Either repatedly copy a random byte from the buffer or a randomly generated byte.
			byte byteRandom;
			if( rangeSize > 0 && std::uniform_int_distribution( 0, 1 )( generator ) == 0 )
				byteRandom = Details::Ranges::SelectRandom( range, generator );
			else
				byteRandom = static_cast< byte >( std::uniform_int_distribution( 0, 255 )( generator ) );

			// Fill the random block with the repeated byte.
			std::ranges::fill( subrange, byteRandom );
		}
	}
}
