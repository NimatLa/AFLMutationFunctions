#include "AFLMutationFunctions.hh"
#include <algorithm>
#include <cstdint>

using namespace AFLMutationFunctions;
using namespace AFLMutationFunctions::Details;

// Test swapping endian.
static_assert( SwapEndian< uint8_t >( 1 ) == 1 );
static_assert( SwapEndian< uint64_t >( 0x1000000000000000 ) == 0x10 );

// Test reinterpreting integers.
static_assert( ReinterpretInt< uint64_t, int8_t >( -1 ) == 0xff );

// Test getting a list of interesting integers.

//! Verifies that interesting integers vector contains an expected value.
consteval bool InterestingIntsContain( uint64_t expected )
{
	// Check if interesting integers vector contains expected.
	auto interesting = GetInteresting();
	return std::ranges::find( interesting, expected ) != interesting.end();
}
static_assert( InterestingIntsContain( uint64_t { 0x0 } ) );
static_assert( InterestingIntsContain( uint64_t { 0xff } ) );
static_assert( InterestingIntsContain( uint64_t { 0xffff } ) );
static_assert( InterestingIntsContain( uint64_t { 0xffffffff } ) );

//! Tests that interesting integers are sorted.
consteval bool InterestingIntsAreSorted()
{
	return std::ranges::is_sorted( GetInteresting() );
}
static_assert( InterestingIntsAreSorted() );

// Tests for MaxIntWithSize.
static_assert( MaxIntWithSize( 1 ) == 0xff );
static_assert( MaxIntWithSize( 9 ) == 0xffff );
static_assert( MaxIntWithSize( 18 ) == 0xffffffff );
static_assert( MaxIntWithSize( 33 ) == 0xffffffffffffffff );

// Test mutation filtering.
struct MockSizeModifying
{
	bool bIsIncreasing;
	bool bIsReducing;
	constexpr bool IsIncreasing() const { return bIsIncreasing; }
	constexpr bool IsReducing() const { return bIsReducing; }
	constexpr bool IsConstant() const { return !( bIsIncreasing || bIsReducing ); }
};
static_assert( Ranges::SizeModifying< MockSizeModifying > );
constexpr auto GetAllSizeMofiying()
{
	return std::to_array( { MockSizeModifying { false, false },
			MockSizeModifying { true, false },
			MockSizeModifying { false, true } } );
}
static_assert( std::ranges::none_of(
	Ranges::FilterMutations( GetAllSizeMofiying(), 5, 5 ),
	[]( auto m ) { return m.IsIncreasing(); } ) );
static_assert( std::ranges::distance( Ranges::FilterMutations( GetAllSizeMofiying(), 6, 5 ) ) == 3 );
static_assert( std::ranges::all_of(
	Ranges::FilterMutations( GetAllSizeMofiying(), 4, 5 ),
	[]( auto m ) { return m.IsReducing(); } ) );
static_assert( std::ranges::all_of(
	Ranges::FilterMutations( GetAllSizeMofiying(), 5, 0 ),
	[]( auto m ) { return m.IsIncreasing(); } ) );